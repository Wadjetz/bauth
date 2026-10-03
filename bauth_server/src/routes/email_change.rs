use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::clients::Client;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::token;

/// The client's page for email change confirmation links (`email_change_url` in bauth.toml).
pub fn page(client: &Client) -> Result<&str, ApiError> {
    client.email_change_url.as_deref().ok_or_else(|| {
        ApiError::InvalidRequest("email change is not enabled for this client".into())
    })
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmEmailChangeRequest {
    token: String,
}

#[utoipa::path(
    post,
    path = "/email-change/confirm",
    operation_id = "confirm_email_change",
    tag = "Me",
    request_body = ConfirmEmailChangeRequest,
    responses(
        (status = 204, description = "Email change applied"),
        (status = 400, description = "`invalid_request`, `invalid_token`, `account_disabled`, `email_taken`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Called by the app page the email change link opens (`email_change_url`): moves the account to
/// the new address (`POST /me/email`), which the link proves the user owns.
pub async fn confirm(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<ConfirmEmailChangeRequest>,
) -> Result<StatusCode, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    let token_hash = token::hash(&input.token);

    let mut tx = state.db.begin().await?;
    let Some(change) = queries::email_changes::consume(&mut *tx, &token_hash).await? else {
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
    // Links already sent to the old address (magic link) stop working
    // on their own: each checks that the account still uses the address it was sent to.
    state
        .mailer
        .send_in_background(emails::email_changed(&change.from_email, &change.to_email));
    Ok(StatusCode::NO_CONTENT)
}
