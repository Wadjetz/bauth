use axum::extract::State;
use axum::http::StatusCode;
use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::verification;
use crate::AppState;
use crate::current_user::CurrentUser;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::errors::AppPath;
use crate::magic_code;
use crate::password;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};
use crate::token;

const EMAIL_CHANGE_TTL: TimeDelta = TimeDelta::hours(1);
const CONFIRMATION_TTL: TimeDelta = TimeDelta::minutes(15);
/// Wrong codes on one confirmation email before it is consumed.
const MAX_CODE_FAILURES: i32 = 5;
/// Wrong codes on one account over a day: a code is only 10^6 values.
const MAX_CODE_FAILURES_PER_USER: i64 = 10;

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

/// What a code confirms. An account with no password proves itself by email instead.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationAction {
    ChangeEmail,
    DeleteAccount,
}

impl ConfirmationAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::ChangeEmail => "change_email",
            Self::DeleteAccount => "delete_account",
        }
    }

    /// Reads after "Pour …" in the email.
    fn describe(self) -> &'static str {
        match self {
            Self::ChangeEmail => "modifier l'adresse email de votre compte",
            Self::DeleteAccount => "supprimer votre compte",
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmationRequest {
    action: ConfirmationAction,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationStatus {
    ConfirmationSent,
}

#[derive(Serialize, ToSchema)]
pub struct ConfirmationResponse {
    status: ConfirmationStatus,
}

#[utoipa::path(
    post,
    path = "/me/confirmation",
    operation_id = "request_confirmation",
    tag = "Me",
    security(("bearer_auth" = [])),
    request_body = ConfirmationRequest,
    responses(
        (status = 202, description = "Code emailed to the account's address", body = ConfirmationResponse),
        (status = 400, description = "`invalid_request`", body = crate::errors::ErrorBody),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Emails a 6-digit code confirming `action`, to send back as `code` on that route. It is the way
/// accounts without a password (magic link only) confirm sensitive changes. The code only works
/// for this action, from this session, for 5 wrong attempts; a new one disables the previous.
pub async fn request_confirmation(
    State(state): State<AppState>,
    client_ip: ClientIp,
    user: CurrentUser,
    AppJson(input): AppJson<ConfirmationRequest>,
) -> Result<(StatusCode, AppJson<ConfirmationResponse>), ApiError> {
    state.rate_limits.email_per_ip.check(&client_ip.key())?;
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&user.email))?;

    let code = state.magic_code_key.generate(user.session_id);
    queries::confirmations::create(
        &state.db,
        user.id,
        user.session_id,
        input.action.as_str(),
        &user.email,
        &code.hash,
        Utc::now() + CONFIRMATION_TTL,
    )
    .await?;
    state.mailer.send_in_background(emails::confirmation_code(
        &user.email,
        input.action.describe(),
        &code.plain,
    ));

    tracing::info!(user_id = %user.id, action = input.action.as_str(), "confirmation code sent");
    let response = ConfirmationResponse {
        status: ConfirmationStatus::ConfirmationSent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

/// Re-authentication for sensitive changes: an access token alone isn't enough. The password, or
/// a code emailed by `POST /me/confirmation` for accounts that have none.
async fn confirm_sensitive(
    state: &AppState,
    client_ip: &ClientIp,
    user: &CurrentUser,
    action: ConfirmationAction,
    password: Option<String>,
    code: Option<String>,
) -> Result<(), ApiError> {
    match (code, password) {
        (Some(code), _) => check_code(state, client_ip, user, action, &code).await,
        (None, Some(password)) => check_password(state, client_ip, user, password).await,
        (None, None) => Err(ApiError::InvalidRequest(
            "password or code is required".into(),
        )),
    }
}

/// Spends one attempt on the newest code of this session for `action`, and consumes it if right.
async fn check_code(
    state: &AppState,
    client_ip: &ClientIp,
    user: &CurrentUser,
    action: ConfirmationAction,
    code: &str,
) -> Result<(), ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    if !magic_code::is_well_formed(code) {
        return Err(ApiError::InvalidRequest("code must be 6 digits".into()));
    }

    let mut tx = state.db.begin().await?;
    let Some(confirmation) = queries::confirmations::find_code_candidate(
        &mut tx,
        user.id,
        user.session_id,
        action.as_str(),
        MAX_CODE_FAILURES,
        MAX_CODE_FAILURES_PER_USER,
    )
    .await?
    else {
        return Err(ApiError::InvalidCode);
    };
    // The code was emailed to an address the account no longer uses.
    if confirmation.email != user.email {
        return Err(ApiError::InvalidCode);
    }
    if !state
        .magic_code_key
        .verify(user.session_id, code, &confirmation.code_hash)
    {
        let failures = queries::confirmations::record_code_failure(
            &mut *tx,
            confirmation.id,
            MAX_CODE_FAILURES,
        )
        .await?;
        // The failure must be kept even though the request fails.
        tx.commit().await?;
        tracing::info!(user_id = %user.id, action = action.as_str(), failures, "wrong confirmation code");
        return Err(ApiError::InvalidCode);
    }
    queries::confirmations::consume_by_id(&mut *tx, confirmation.id).await?;
    tx.commit().await?;
    Ok(())
}

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
    /// Current password, or `code` for an account that has none.
    password: Option<String>,
    /// 6-digit code from `POST /me/confirmation` with `action: "change_email"`.
    code: Option<String>,
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
        (status = 400, description = "`invalid_request`, `invalid_email`, `password_not_set`, `invalid_credentials`, `invalid_code`", body = crate::errors::ErrorBody),
        (status = 401, description = "`unauthorized`: refresh the access token", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
/// Sends a confirmation link to the new address. The account keeps its current address
/// until the link is used, on `POST /verification/confirm`. Confirmed by the current password,
/// or by a code from `POST /me/confirmation` when the account has none.
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
    // The confirmation link opens the page of the app the change was asked from.
    let page = state
        .clients
        .get(&user.client_id)
        .ok_or(ApiError::InvalidClient)
        .and_then(verification::page)?
        .to_owned();
    confirm_sensitive(
        &state,
        &client_ip,
        &user,
        ConfirmationAction::ChangeEmail,
        input.password,
        input.code,
    )
    .await?;
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
        let link = format!("{page}#token={}", token.plain);
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
    /// Current password, or `code` for an account that has none.
    password: Option<String>,
    /// 6-digit code from `POST /me/confirmation` with `action: "delete_account"`.
    code: Option<String>,
}

#[utoipa::path(
    delete,
    path = "/me",
    tag = "Me",
    security(("bearer_auth" = [])),
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "Account deleted"),
        (status = 400, description = "`invalid_request`, `password_not_set`, `invalid_credentials`, `invalid_code`", body = crate::errors::ErrorBody),
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
    confirm_sensitive(
        &state,
        &client_ip,
        &user,
        ConfirmationAction::DeleteAccount,
        input.password,
        input.code,
    )
    .await?;
    queries::users::delete(&state.db, user.id).await?;

    tracing::info!(user_id = %user.id, "account deleted");
    state
        .mailer
        .send_in_background(emails::account_deleted(&user.email));
    Ok(StatusCode::NO_CONTENT)
}
