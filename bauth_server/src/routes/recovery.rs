use axum::extract::State;
use axum::http::StatusCode;
use chrono::TimeDelta;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::password;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};
use crate::token;

const RESET_TTL: TimeDelta = TimeDelta::minutes(30);

#[derive(Deserialize, ToSchema)]
pub struct RecoveryRequest {
    client_id: String,
    email: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    RecoverySent,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryResponse {
    status: RecoveryStatus,
}

#[utoipa::path(
    post,
    path = "/recovery",
    operation_id = "request_password_reset",
    tag = "Recovery",
    request_body = RecoveryRequest,
    responses(
        (status = 202, description = "Same answer whether the account exists or not", body = RecoveryResponse),
        (status = 400, description = "`invalid_request`, `invalid_client`, `invalid_email`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Sends a reset link if the account exists. Always answers the same way,
/// so this endpoint can't be used to find out which emails are registered.
pub async fn request(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<RecoveryRequest>,
) -> Result<(StatusCode, AppJson<RecoveryResponse>), ApiError> {
    state.rate_limits.email_per_ip.check(&client_ip.key())?;
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(ApiError::InvalidClient)?;
    let Some(reset_url) = client.password_reset_url.as_deref() else {
        return Err(ApiError::InvalidRequest(
            "password reset is not enabled for this client".into(),
        ));
    };
    if !email::is_valid(&input.email) {
        return Err(ApiError::InvalidEmail);
    }
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&input.email))?;

    if let Some(user) = queries::users::find_by_email(&state.db, &input.email).await?
        && user.disabled_at.is_none()
    {
        let token = token::generate();
        let expires_at = Utc::now() + RESET_TTL;
        queries::password_resets::create(&state.db, user.id, &user.email, &token.hash, expires_at)
            .await?;
        let link = format!("{reset_url}#token={}", token.plain);
        state
            .mailer
            .send_in_background(emails::password_reset(&user.email, &client.name, &link));
        tracing::info!(user_id = %user.id, client_id = %client.id, "password reset requested");
    }

    let response = RecoveryResponse {
        status: RecoveryStatus::RecoverySent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

#[derive(Deserialize, ToSchema)]
pub struct ResetRequest {
    token: String,
    password: String,
}

#[utoipa::path(
    post,
    path = "/recovery/reset",
    operation_id = "reset_password",
    tag = "Recovery",
    request_body = ResetRequest,
    responses(
        (status = 204, description = "Password set; every session revoked"),
        (status = 400, description = "`invalid_request`, `password_too_short`, `password_too_long`, `invalid_token`, `account_disabled`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Sets a new password from a reset link, then logs the user out everywhere.
pub async fn reset(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<ResetRequest>,
) -> Result<StatusCode, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    password::validate(&input.password)?;
    let token_hash = token::hash(&input.token);
    let password_hash = password::hash(input.password).await?;

    let mut tx = state.db.begin().await?;
    let Some(reset) = queries::password_resets::consume(&mut *tx, &token_hash).await? else {
        return Err(ApiError::InvalidToken);
    };
    let Some(user) = queries::users::find_by_id(&mut *tx, reset.user_id).await? else {
        return Err(ApiError::InvalidToken);
    };
    if user.disabled_at.is_some() {
        return Err(ApiError::AccountDisabled);
    }
    // The link was sent to an address the account no longer uses.
    if user.email != reset.email {
        return Err(ApiError::InvalidToken);
    }

    // Receiving the link proves the user owns the address. Before the password: the account row
    // is locked first, in the same order as a magic link login, so they can't deadlock.
    queries::users::mark_email_verified(&mut *tx, user.id, &user.email).await?;
    queries::password_credentials::upsert(&mut *tx, user.id, &password_hash).await?;
    queries::password_resets::consume_all_for_user(&mut *tx, user.id).await?;
    // Whoever knew the old password may have sessions open: close them all.
    let revoked = queries::sessions::revoke_all_for_user(&mut *tx, user.id).await?;
    tx.commit().await?;

    tracing::info!(user_id = %user.id, revoked_sessions = revoked, "password reset");
    state
        .mailer
        .send_in_background(emails::password_changed(&user.email));
    Ok(StatusCode::NO_CONTENT)
}
