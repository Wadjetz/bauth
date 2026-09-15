use axum::extract::State;
use axum::http::StatusCode;
use chrono::{TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::db::DbConnection;
use crate::email;
use crate::emails;
use crate::errors::{ApiError, AppJson, AppPath};
use crate::login_flow::{self, LoginResponse};
use crate::magic_code;
use crate::queries;
use crate::rate_limit::{self, ClientIp};
use crate::token;

const MAGIC_LINK_TTL: TimeDelta = TimeDelta::minutes(15);
/// Each email brings a new code: capping them per flow caps the guesses on one flow.
const MAX_EMAILS_PER_FLOW: i32 = 3;
/// Wrong codes on one email before it is consumed.
const MAX_CODE_FAILURES_PER_EMAIL: i32 = 5;
/// Wrong codes on one account over a day, across flows. Emails are limited per address, not per
/// flow: without this, new flows would keep adding guesses. Once reached, codes stop working for
/// the account (links still do).
const MAX_CODE_FAILURES_PER_USER: i64 = 10;

#[derive(Deserialize, ToSchema)]
pub struct MagicLinkRequest {
    email: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MagicLinkStatus {
    MagicLinkSent,
}

#[derive(Serialize, ToSchema)]
pub struct MagicLinkResponse {
    status: MagicLinkStatus,
}

#[utoipa::path(
    post,
    path = "/flows/login/{flow_id}/magic-link",
    operation_id = "request_magic_link",
    tag = "Login",
    params(("flow_id" = Uuid, Path, description = "Returned by `POST /flows/login`")),
    request_body = MagicLinkRequest,
    responses(
        (status = 202, description = "Same answer whether the account exists or not", body = MagicLinkResponse),
        (status = 400, description = "`invalid_request`, `flow_expired`, `invalid_client`, `invalid_email`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`; after 3 emails on one flow, until the flow expires: start a new one", body = crate::errors::ErrorBody),
    )
)]
/// Emails a login link and a 6-digit code for this flow if the account exists. Always answers
/// the same way. A new email disables the code of the previous one.
pub async fn request(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppPath(flow_id): AppPath<Uuid>,
    AppJson(input): AppJson<MagicLinkRequest>,
) -> Result<(StatusCode, AppJson<MagicLinkResponse>), ApiError> {
    state.rate_limits.email_per_ip.check(&client_ip.key())?;
    if !email::is_valid(&input.email) {
        return Err(ApiError::InvalidEmail);
    }
    // Counted whether the account exists or not, so the limit doesn't reveal it.
    let Some(flow) = queries::login_flows::count_magic_link_request(&state.db, flow_id).await?
    else {
        return Err(ApiError::FlowExpired);
    };
    if flow.requests > MAX_EMAILS_PER_FLOW {
        let retry_after = (flow.expires_at - Utc::now()).to_std().unwrap_or_default();
        return Err(ApiError::RateLimited { retry_after });
    }
    let client = state
        .clients
        .get(&flow.client_id)
        .ok_or(ApiError::InvalidClient)?;
    let Some(magic_link_url) = client.magic_link_url.as_deref() else {
        return Err(ApiError::InvalidRequest(
            "magic link is not enabled for this client".into(),
        ));
    };
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&input.email))?;

    if let Some(user) = queries::users::find_by_email(&state.db, &input.email).await?
        && user.disabled_at.is_none()
    {
        let token = token::generate();
        let code = state.magic_code_key.generate(flow_id);
        let expires_at = Utc::now() + MAGIC_LINK_TTL;
        queries::magic_links::create(
            &state.db,
            flow_id,
            user.id,
            &user.email,
            &token.hash,
            &code.hash,
            expires_at,
        )
        .await?;
        let link = format!("{magic_link_url}#token={}", token.plain);
        state.mailer.send_in_background(emails::magic_link(
            &user.email,
            &client.name,
            &link,
            &code.plain,
        ));
        tracing::info!(user_id = %user.id, %flow_id, "magic link sent");
    }

    let response = MagicLinkResponse {
        status: MagicLinkStatus::MagicLinkSent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmRequest {
    token: String,
}

#[utoipa::path(
    post,
    path = "/magic-link/confirm",
    operation_id = "confirm_magic_link",
    tag = "Login",
    request_body = ConfirmRequest,
    responses(
        (status = 200, description = "Exchange `code` on `/oauth/token` with the flow's `code_verifier`", body = LoginResponse),
        (status = 400, description = "`invalid_request`, `invalid_token`, `account_disabled`, `flow_expired`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Called by the app page the link opens. Completes the login flow the link was requested from.
pub async fn confirm(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<ConfirmRequest>,
) -> Result<AppJson<LoginResponse>, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    let token_hash = token::hash(&input.token);

    let mut tx = state.db.begin().await?;
    let Some(link) = queries::magic_links::consume(&mut *tx, &token_hash).await? else {
        return Err(ApiError::InvalidToken);
    };
    let login = log_in(
        &mut tx,
        link.flow_id,
        link.user_id,
        &link.email,
        ApiError::InvalidToken,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(user_id = %link.user_id, flow_id = %link.flow_id, "magic link login succeeded");
    Ok(AppJson(login.notify(&state, &link.email)))
}

#[derive(Deserialize, ToSchema)]
pub struct MagicCodeRequest {
    /// The 6 digits of the magic link email, without spaces.
    #[schema(example = "042917")]
    code: String,
}

#[utoipa::path(
    post,
    path = "/flows/login/{flow_id}/magic-code",
    operation_id = "confirm_magic_code",
    tag = "Login",
    params(("flow_id" = Uuid, Path, description = "Returned by `POST /flows/login`")),
    request_body = MagicCodeRequest,
    responses(
        (status = 200, description = "Exchange `code` on `/oauth/token` with the flow's `code_verifier`", body = LoginResponse),
        (status = 400, description = "`invalid_request`, `invalid_code`, `account_disabled`, `flow_expired`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Completes the flow with the code of its magic link email, typed on the device that asked for it.
/// Only the newest email's code works, for 5 wrong attempts (10 per account a day). A wrong code,
/// an unknown flow and no email sent all answer `invalid_code`.
pub async fn confirm_code(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppPath(flow_id): AppPath<Uuid>,
    AppJson(input): AppJson<MagicCodeRequest>,
) -> Result<AppJson<LoginResponse>, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    if !magic_code::is_well_formed(&input.code) {
        return Err(ApiError::InvalidRequest("code must be 6 digits".into()));
    }

    let mut tx = state.db.begin().await?;
    let Some(link) = queries::magic_links::find_code_candidate(
        &mut tx,
        flow_id,
        MAX_CODE_FAILURES_PER_EMAIL,
        MAX_CODE_FAILURES_PER_USER,
    )
    .await?
    else {
        return Err(ApiError::InvalidCode);
    };
    if !state
        .magic_code_key
        .verify(flow_id, &input.code, &link.code_hash)
    {
        let failures = queries::magic_links::record_code_failure(
            &mut *tx,
            link.id,
            MAX_CODE_FAILURES_PER_EMAIL,
        )
        .await?;
        // The failure must be kept even though the request fails.
        tx.commit().await?;
        tracing::info!(user_id = %link.user_id, %flow_id, failures, "wrong magic code");
        return Err(ApiError::InvalidCode);
    }
    queries::magic_links::consume_by_id(&mut *tx, link.id).await?;
    let login = log_in(
        &mut tx,
        flow_id,
        link.user_id,
        &link.email,
        ApiError::InvalidCode,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(user_id = %link.user_id, %flow_id, "magic code login succeeded");
    Ok(AppJson(login.notify(&state, &link.email)))
}

struct MagicLogin {
    response: LoginResponse,
    /// The account was unverified and had a password, now removed.
    removed_password: bool,
}

impl MagicLogin {
    /// Once the transaction is committed: tells the owner if their password was removed.
    fn notify(self, state: &AppState, email: &str) -> LoginResponse {
        if self.removed_password {
            state
                .mailer
                .send_in_background(emails::unverified_password_removed(email));
        }
        self.response
    }
}

/// What a checked link or code does: logs the user in on the flow the email was requested from.
/// `stale` is the error when the email went to an address the account no longer uses.
async fn log_in(
    conn: &mut DbConnection,
    flow_id: Uuid,
    user_id: Uuid,
    email: &str,
    stale: ApiError,
) -> Result<MagicLogin, ApiError> {
    // Locked: a verification confirmed meanwhile must not be missed by the check below.
    let Some(user) = queries::users::lock_by_id(&mut *conn, user_id).await? else {
        return Err(stale);
    };
    if user.disabled_at.is_some() {
        return Err(ApiError::AccountDisabled);
    }
    if user.email != email {
        return Err(stale);
    }
    let mut removed_password = false;
    if user.email_verified_at.is_none() {
        // Anyone can register an address they don't own, with a password of their choosing.
        // Its owner proves they own it only now: nothing set up before can be trusted.
        removed_password = queries::password_credentials::delete(&mut *conn, user.id).await?;
        let revoked = queries::sessions::revoke_all_for_user(&mut *conn, user.id).await?;
        tracing::info!(user_id = %user.id, removed_password, revoked_sessions = revoked, "unverified account claimed by email");
    }
    // Receiving the email proves the user owns the address.
    queries::users::mark_email_verified(&mut *conn, user.id, &user.email).await?;
    let response = login_flow::complete(conn, flow_id, user.id)
        .await?
        .ok_or(ApiError::FlowExpired)?;
    Ok(MagicLogin {
        response,
        removed_password,
    })
}
