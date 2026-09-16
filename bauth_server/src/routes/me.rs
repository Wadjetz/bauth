use axum::extract::State;
use axum::http::StatusCode;
use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::current_user::CurrentUser;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::errors::AppPath;
use crate::password;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};
use crate::token;

const EMAIL_CHANGE_TTL: TimeDelta = TimeDelta::hours(1);

#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    id: Uuid,
    email: String,
    email_verified: bool,
    has_password: bool,
    created_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/me",
    operation_id = "get_me",
    tag = "Me",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = MeResponse),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
    )
)]
pub async fn get(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<AppJson<MeResponse>, ApiError> {
    let account = queries::users::find_by_id(&state.db, user.id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let has_password = queries::password_credentials::find_hash(&state.db, user.id)
        .await?
        .is_some();
    Ok(AppJson(MeResponse {
        id: account.id,
        email: account.email,
        email_verified: account.email_verified_at.is_some(),
        has_password,
        created_at: account.created_at,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[utoipa::path(
    post,
    path = "/me/password",
    tag = "Me",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed; other sessions revoked"),
        (status = 400, description = "`invalid_request`, `password_too_short`, `password_too_long`, `password_not_set`, `invalid_credentials`", body = crate::errors::ErrorBody),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Changes the password, then logs out every other session of the user.
pub async fn change_password(
    State(state): State<AppState>,
    client_ip: ClientIp,
    user: CurrentUser,
    AppJson(input): AppJson<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    password::validate(&input.new_password)?;
    // Accounts created by magic link have no password to check: they set one via password reset,
    // which proves they own the email. A stolen access token alone must not set a password.
    check_password(&state, &client_ip, &user, input.current_password).await?;
    let new_hash = password::hash(input.new_password).await?;

    let mut tx = state.db.begin().await?;
    queries::password_credentials::upsert(&mut *tx, user.id, &new_hash).await?;
    queries::password_resets::consume_all_for_user(&mut *tx, user.id).await?;
    let revoked =
        queries::sessions::revoke_all_for_user_except(&mut *tx, user.id, user.session_id).await?;
    tx.commit().await?;

    tracing::info!(user_id = %user.id, revoked_sessions = revoked, "password changed");
    state
        .mailer
        .send_in_background(emails::password_changed(&user.email));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct SessionResponse {
    id: Uuid,
    client_id: String,
    /// Display name from bauth.toml, `None` if the client was removed since.
    client_name: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// The session this request's access token belongs to.
    current: bool,
}

#[utoipa::path(
    get,
    path = "/me/sessions",
    tag = "Me",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = [SessionResponse]),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
    )
)]
pub async fn list_sessions(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<AppJson<Vec<SessionResponse>>, ApiError> {
    let sessions = queries::sessions::list_active_for_user(&state.db, user.id).await?;
    let response = sessions
        .into_iter()
        .map(|session| SessionResponse {
            client_name: state
                .clients
                .get(&session.client_id)
                .map(|client| client.name.clone()),
            current: session.id == user.session_id,
            id: session.id,
            client_id: session.client_id,
            created_at: session.created_at,
            last_used_at: session.last_used_at,
            expires_at: session.expires_at,
        })
        .collect();
    Ok(AppJson(response))
}

#[utoipa::path(
    delete,
    path = "/me/sessions/{session_id}",
    tag = "Me",
    security(("bearer_auth" = [])),
    params(("session_id" = Uuid, Path, description = "From `GET /me/sessions`")),
    responses(
        (status = 204, description = "Session revoked"),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 404, description = "`not_found`", body = crate::errors::ErrorBody),
    )
)]
/// Logs out one device. Revoking the current session works too.
pub async fn revoke_session(
    State(state): State<AppState>,
    user: CurrentUser,
    AppPath(session_id): AppPath<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !queries::sessions::revoke_for_user(&state.db, session_id, user.id).await? {
        return Err(ApiError::NotFound);
    }
    tracing::info!(user_id = %user.id, %session_id, "session revoked by user");
    Ok(StatusCode::NO_CONTENT)
}

/// Re-authentication for sensitive changes: an access token alone isn't enough.
async fn check_password(
    state: &AppState,
    client_ip: &ClientIp,
    user: &CurrentUser,
    password: String,
) -> Result<(), ApiError> {
    state.rate_limits.login_per_ip.check(&client_ip.key())?;
    state
        .rate_limits
        .login_per_email
        .check(&rate_limit::email_key(&user.email))?;
    let Some(hash) = queries::password_credentials::find_hash(&state.db, user.id).await? else {
        return Err(ApiError::PasswordNotSet);
    };
    if !password::verify(password, hash).await? {
        return Err(ApiError::InvalidCredentials);
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct ChangeEmailRequest {
    password: String,
    new_email: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeEmailStatus {
    ConfirmationSent,
}

#[derive(Serialize, ToSchema)]
pub struct ChangeEmailResponse {
    status: ChangeEmailStatus,
}

#[utoipa::path(
    post,
    path = "/me/email",
    tag = "Me",
    security(("bearer_auth" = [])),
    request_body = ChangeEmailRequest,
    responses(
        (status = 202, description = "Confirmation link sent to the new address (unless it is taken)", body = ChangeEmailResponse),
        (status = 400, description = "`invalid_request`, `invalid_email`, `password_not_set`, `invalid_credentials`", body = crate::errors::ErrorBody),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Sends a confirmation link to the new address. The account keeps its current address
/// until the link is used, on `POST /verification/confirm`.
pub async fn change_email(
    State(state): State<AppState>,
    client_ip: ClientIp,
    user: CurrentUser,
    AppJson(input): AppJson<ChangeEmailRequest>,
) -> Result<(StatusCode, AppJson<ChangeEmailResponse>), ApiError> {
    if !email::is_valid(&input.new_email) {
        return Err(ApiError::InvalidEmail);
    }
    let new_email_key = rate_limit::email_key(&input.new_email);
    if new_email_key == user.email {
        return Err(ApiError::InvalidRequest(
            "new_email is the current address".into(),
        ));
    }
    check_password(&state, &client_ip, &user, input.password).await?;
    state.rate_limits.email_per_address.check(&new_email_key)?;

    // Same answer whether the address is free or not: this must not reveal other accounts.
    // A taken address simply gets no link.
    if queries::users::find_by_email(&state.db, &input.new_email)
        .await?
        .is_none()
    {
        let token = token::generate();
        let expires_at = Utc::now() + EMAIL_CHANGE_TTL;
        queries::email_changes::create(
            &state.db,
            user.id,
            &user.email,
            &input.new_email,
            &token.hash,
            expires_at,
        )
        .await?;
        let link = format!("{}#token={}", state.config.verification_url, token.plain);
        state
            .mailer
            .send_in_background(emails::confirm_email_change(&new_email_key, &link));
        tracing::info!(user_id = %user.id, "email change requested");
    }

    let response = ChangeEmailResponse {
        status: ChangeEmailStatus::ConfirmationSent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    password: String,
}

#[utoipa::path(
    delete,
    path = "/me",
    tag = "Me",
    security(("bearer_auth" = [])),
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "Account deleted"),
        (status = 400, description = "`invalid_request`, `password_not_set`, `invalid_credentials`", body = crate::errors::ErrorBody),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Deletes the account right away, with every session and credential.
/// Access tokens already given to APIs stay valid until they expire (15 min).
pub async fn delete_account(
    State(state): State<AppState>,
    client_ip: ClientIp,
    user: CurrentUser,
    AppJson(input): AppJson<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    check_password(&state, &client_ip, &user, input.password).await?;
    queries::users::delete(&state.db, user.id).await?;

    tracing::info!(user_id = %user.id, "account deleted");
    state
        .mailer
        .send_in_background(emails::account_deleted(&user.email));
    Ok(StatusCode::NO_CONTENT)
}
