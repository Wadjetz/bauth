use axum::extract::State;
use axum::http::StatusCode;
use chrono::TimeDelta;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use sqlx::Executor;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::clients::Client;
use crate::db::Db;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::mailer::Email;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};
use crate::token;

const VERIFICATION_TTL: TimeDelta = TimeDelta::hours(24);

/// The client's page for email confirmation links (`verification_url` in bauth.toml).
pub fn page(client: &Client) -> Result<&str, ApiError> {
    client.verification_url.as_deref().ok_or_else(|| {
        ApiError::InvalidRequest("email verification is not enabled for this client".into())
    })
}

/// Stores a new verification token for `email` and returns the email to send.
/// Send it only after the surrounding transaction commits.
pub async fn verification_email<'e, E>(
    executor: E,
    verification_url: &str,
    user_id: Uuid,
    email: &str,
) -> Result<Email, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let token = token::generate();
    let expires_at = Utc::now() + VERIFICATION_TTL;
    queries::email_verifications::create(executor, user_id, email, &token.hash, expires_at).await?;
    let link = format!("{verification_url}#token={}", token.plain);
    Ok(emails::verify_email(email, &link))
}

#[derive(Deserialize, ToSchema)]
pub struct ResendRequest {
    client_id: String,
    email: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResendStatus {
    VerificationSent,
}

#[derive(Serialize, ToSchema)]
pub struct ResendResponse {
    status: ResendStatus,
}

#[utoipa::path(
    post,
    path = "/verification",
    operation_id = "resend_verification",
    tag = "Registration",
    request_body = ResendRequest,
    responses(
        (status = 202, description = "Same answer whether a link was sent or not", body = ResendResponse),
        (status = 400, description = "`invalid_request`, `invalid_client`, `invalid_email`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Sends a new verification link if the account exists and isn't verified yet.
/// Always answers the same way, so it can't be used to find out which emails are registered.
pub async fn resend(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<ResendRequest>,
) -> Result<(StatusCode, AppJson<ResendResponse>), ApiError> {
    state.rate_limits.email_per_ip.check(&client_ip.key())?;
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(ApiError::InvalidClient)?;
    let page = page(client)?;
    if !email::is_valid(&input.email) {
        return Err(ApiError::InvalidEmail);
    }
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&input.email))?;

    if let Some(user) = queries::users::find_by_email(&state.db, &input.email).await?
        && user.disabled_at.is_none()
        && user.email_verified_at.is_none()
    {
        // Earlier links stay valid until they expire: whichever the user clicks works.
        let email = verification_email(&state.db, page, user.id, &user.email).await?;
        state.mailer.send_in_background(email);
        tracing::info!(user_id = %user.id, "verification email resent");
    }

    let response = ResendResponse {
        status: ResendStatus::VerificationSent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmRequest {
    token: String,
}

#[utoipa::path(
    post,
    path = "/verification/confirm",
    operation_id = "confirm_verification",
    tag = "Registration",
    request_body = ConfirmRequest,
    responses(
        (status = 204, description = "Email verified, or email change applied"),
        (status = 400, description = "`invalid_request`, `invalid_token`, `account_disabled`, `email_taken`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Confirms an email link: either verifying the account's address, or moving the account
/// to a new address (`POST /me/email`). Both use the same app page.
pub async fn confirm(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<ConfirmRequest>,
) -> Result<StatusCode, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    let token_hash = token::hash(&input.token);

    let mut tx = state.db.begin().await?;
    let Some(verification) = queries::email_verifications::consume(&mut *tx, &token_hash).await?
    else {
        tx.rollback().await?;
        return confirm_email_change(&state, &token_hash).await;
    };
    let verified =
        queries::users::mark_email_verified(&mut *tx, verification.user_id, &verification.email)
            .await?;
    if !verified {
        // The user changed address since the email was sent: this token proves nothing now.
        return Err(ApiError::InvalidToken);
    }
    tx.commit().await?;

    tracing::info!(user_id = %verification.user_id, "email verified");
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm_email_change(state: &AppState, token_hash: &[u8]) -> Result<StatusCode, ApiError> {
    let mut tx = state.db.begin().await?;
    let Some(change) = queries::email_changes::consume(&mut *tx, token_hash).await? else {
        return Err(ApiError::InvalidToken);
    };
    let Some(user) = queries::users::find_by_id(&mut *tx, change.user_id).await? else {
        return Err(ApiError::InvalidToken);
    };
    if user.disabled_at.is_some() {
        return Err(ApiError::AccountDisabled);
    }

    match queries::users::change_email(&mut *tx, user.id, &change.from_email, &change.to_email)
        .await
    {
        Ok(true) => {}
        // The account moved to another address since the request: this link is stale.
        Ok(false) => return Err(ApiError::InvalidToken),
        // Someone registered the new address after the request.
        Err(error)
            if error
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            return Err(ApiError::EmailTaken);
        }
        Err(error) => return Err(error.into()),
    }
    tx.commit().await?;

    tracing::info!(user_id = %user.id, "email changed");
    // Links already sent to the old address (reset, magic link, verification) stop working
    // on their own: each checks that the account still uses the address it was sent to.
    state
        .mailer
        .send_in_background(emails::email_changed(&change.from_email, &change.to_email));
    Ok(StatusCode::NO_CONTENT)
}
