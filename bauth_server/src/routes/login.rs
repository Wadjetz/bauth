use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::errors::{ApiError, AppJson, AppPath};
use crate::login_flow::{self, LoginResponse};
use crate::password;
use crate::pkce;
use crate::queries;
use crate::rate_limit::{self, ClientIp};

const FLOW_TTL: TimeDelta = TimeDelta::minutes(15);
const MAX_STATE_LEN: usize = 512;

#[derive(Deserialize, ToSchema)]
pub struct CreateFlowRequest {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    /// Opaque value echoed back to the app with the code (CSRF protection on redirects).
    state: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    Password,
    MagicLink,
}

#[derive(Serialize, ToSchema)]
pub struct FlowResponse {
    flow_id: Uuid,
    methods: Vec<LoginMethod>,
    expires_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/flows/login",
    tag = "Login",
    request_body = CreateFlowRequest,
    responses(
        (status = 201, description = "Flow started: show the screens for `methods`", body = FlowResponse),
        (status = 400, description = "`invalid_request`, `invalid_client`, `invalid_redirect_uri`, `invalid_code_challenge`", body = crate::errors::ErrorBody),
    )
)]
pub async fn create_flow(
    State(state): State<AppState>,
    AppJson(input): AppJson<CreateFlowRequest>,
) -> Result<(StatusCode, AppJson<FlowResponse>), ApiError> {
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(ApiError::InvalidClient)?;
    let mut methods = vec![LoginMethod::Password];
    // Never redirect anywhere, not even to report an error, before this check passes.
    if !client.allows_redirect_uri(&input.redirect_uri) {
        return Err(ApiError::InvalidRedirectUri);
    }
    if input.code_challenge_method != "S256" || !pkce::is_valid_challenge(&input.code_challenge) {
        return Err(ApiError::InvalidCodeChallenge);
    }
    if input
        .state
        .as_ref()
        .is_some_and(|s| s.len() > MAX_STATE_LEN)
    {
        return Err(ApiError::InvalidRequest(format!(
            "state must be at most {MAX_STATE_LEN} bytes"
        )));
    }

    let expires_at = Utc::now() + FLOW_TTL;
    let flow_id = queries::login_flows::create(
        &state.db,
        &client.id,
        &input.redirect_uri,
        &input.code_challenge,
        input.state.as_deref(),
        expires_at,
    )
    .await?;

    if client.magic_link_url.is_some() {
        methods.push(LoginMethod::MagicLink);
    }

    let response = FlowResponse {
        flow_id,
        methods,
        expires_at,
    };
    Ok((StatusCode::CREATED, AppJson(response)))
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordRequest {
    email: String,
    password: String,
}

#[utoipa::path(
    post,
    path = "/flows/login/{flow_id}/password",
    tag = "Login",
    params(("flow_id" = Uuid, Path, description = "Returned by `POST /flows/login`")),
    request_body = PasswordRequest,
    responses(
        (status = 200, description = "Exchange `code` on `/oauth/token`", body = LoginResponse),
        (status = 400, description = "`invalid_request`, `flow_expired`, `invalid_client`, `invalid_credentials`, `account_disabled`, `email_not_verified`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
pub async fn submit_password(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppPath(flow_id): AppPath<Uuid>,
    AppJson(input): AppJson<PasswordRequest>,
) -> Result<AppJson<LoginResponse>, ApiError> {
    // Before argon2: every attempt costs CPU, even on unknown accounts.
    state.rate_limits.login_per_ip.check(&client_ip.key())?;
    state
        .rate_limits
        .login_per_email
        .check(&rate_limit::email_key(&input.email))?;
    // Reject dead flows before spending CPU on argon2.
    if !queries::login_flows::is_pending(&state.db, flow_id).await? {
        return Err(ApiError::FlowExpired);
    }

    let Some(login) =
        queries::password_credentials::find_login_by_email(&state.db, &input.email).await?
    else {
        // Same cost as a real check, so timing doesn't reveal whether the account exists.
        password::verify_dummy(input.password).await;
        return Err(ApiError::InvalidCredentials);
    };
    if !password::verify(input.password, login.password_hash).await? {
        tracing::info!(user_id = %login.user_id, %flow_id, "invalid password");
        return Err(ApiError::InvalidCredentials);
    }
    // Only reveal the account state to someone who knows the password.
    if login.disabled_at.is_some() {
        return Err(ApiError::AccountDisabled);
    }
    if login.email_verified_at.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    let mut tx = state.db.begin().await?;
    let Some(response) = login_flow::complete(&mut tx, flow_id, login.user_id).await? else {
        // Expired during the check, or a concurrent request completed it first.
        return Err(ApiError::FlowExpired);
    };
    tx.commit().await?;

    tracing::info!(user_id = %login.user_id, %flow_id, "password login succeeded");
    Ok(AppJson(response))
}
