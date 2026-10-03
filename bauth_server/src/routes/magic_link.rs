use axum::extract::State;
use axum::http::StatusCode;
use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::db::DbConnection;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::errors::AppPath;
use crate::login_flow::LoginResponse;
use crate::login_flow::{self};
use crate::magic_code;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};
use crate::token;

/// Each email brings a new code: capping them per flow caps the guesses on one flow.
const MAX_EMAILS_PER_FLOW: i32 = 3;

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
    /// When the flow expires now: each email keeps it alive as long as itself. Same value whether
    /// the account exists or not (it only depends on the flow).
    expires_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/flows/login/{flow_id}/magic-link",
    operation_id = "request_magic_link",
    tag = "Login",
    params(("flow_id" = Uuid, Path, description = "Returned by `POST /flows/login`")),
    request_body = MagicLinkRequest,
    responses(
        (status = 202, description = "Same answer whether the account exists, is created on first use, or no email is sent", body = MagicLinkResponse),
        (status = 400, description = "`invalid_request`, `flow_expired`, `invalid_client`, `invalid_email`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`; after 3 emails on one flow, until the flow expires: start a new one", body = crate::errors::ErrorBody),
    )
)]
/// Emails a link and a 6-digit code for this flow: to log in if the account exists, or to create
/// it (verified) when the client allows sign-up. Nothing is created before the
/// link or code is used. Always answers the same way. A new email disables the previous code.
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
    let Some(flow) = queries::login_flows::find_pending_magic_link_flow(&state.db, flow_id).await?
    else {
        return Err(ApiError::FlowExpired);
    };
    // Until the flow expires: the app starts a new one instead.
    let flow_exhausted = || ApiError::RateLimited {
        retry_after: (flow.expires_at - Utc::now()).to_std().unwrap_or_default(),
    };
    if flow.requests >= MAX_EMAILS_PER_FLOW {
        return Err(flow_exhausted());
    }
    let client = state
        .clients
        .get(&flow.client_id)
        .ok_or(ApiError::InvalidClient)?;
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&input.email))?;
    // Counted last, so a request refused above doesn't use one of the flow's emails; and whether
    // the account exists or not, so the limit doesn't reveal it. The flow lives as long as the
    // email (the 3-emails cap bounds it), or a link used at minute 14 would find it expired.
    let expires_at = Utc::now() + magic_code::CODE_TTL;
    let Some(flow_expires_at) = queries::login_flows::count_magic_link_request(
        &state.db,
        flow_id,
        MAX_EMAILS_PER_FLOW,
        expires_at,
    )
    .await?
    else {
        return Err(flow_exhausted());
    };

    let recipient = match queries::users::find_by_email(&state.db, &input.email).await? {
        Some(user) if user.disabled_at.is_none() => Some(Recipient::Account(user.id)),
        // Sign-up: the account is only created once the email proves the address is theirs.
        None if client.allow_signup => Some(Recipient::SignUp),
        // Disabled account, or no sign-up on this client: same answer, no email.
        _ => None,
    };
    if let Some(recipient) = recipient {
        let token = token::generate();
        let code = state.code_keys.magic_link.generate(flow_id);
        let user_id = match recipient {
            Recipient::Account(user_id) => Some(user_id),
            Recipient::SignUp => None,
        };
        let email = queries::magic_links::create(
            &state.db,
            flow_id,
            user_id,
            &input.email,
            &token.hash,
            &code.hash,
            expires_at,
        )
        .await?;
        let link = format!("{}#token={}", client.magic_link_url, token.plain);
        let message = match recipient {
            Recipient::Account(_) => emails::magic_link(&email, &client.name, &link, &code.plain),
            Recipient::SignUp => emails::magic_signup(&email, &client.name, &link, &code.plain),
        };
        state.mailer.send_in_background(message);
        tracing::info!(?user_id, %flow_id, "magic link sent");
    }

    let response = MagicLinkResponse {
        status: MagicLinkStatus::MagicLinkSent,
        expires_at: flow_expires_at,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}

enum Recipient {
    Account(Uuid),
    SignUp,
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
/// Called by the app page the link opens. Completes the login flow the link was requested from,
/// creating the account if the email was a sign-up.
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
    let (response, user_id) = log_in(
        &mut tx,
        link.flow_id,
        link.user_id,
        &link.email,
        ApiError::InvalidToken,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(%user_id, flow_id = %link.flow_id, "magic link login succeeded");
    Ok(AppJson(response))
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
/// Completes the flow with the code of its magic link email, typed on the device that asked for it,
/// creating the account if the email was a sign-up. Only the newest email's code works, for 5 wrong
/// attempts (10 per address a day). A wrong code, an unknown flow and no email sent all answer
/// `invalid_code`.
pub async fn confirm_code(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppPath(flow_id): AppPath<Uuid>,
    AppJson(input): AppJson<MagicCodeRequest>,
) -> Result<AppJson<LoginResponse>, ApiError> {
    state.rate_limits.token_per_ip.check(&client_ip.key())?;
    magic_code::check_format(&input.code)?;

    let mut tx = state.db.begin().await?;
    // Past the daily budget of the address, codes stop working; its links still do.
    let Some(link) = queries::magic_links::find_code_candidate(
        &mut tx,
        flow_id,
        magic_code::MAX_FAILURES_PER_CODE,
        magic_code::MAX_FAILURES_PER_DAY,
    )
    .await?
    else {
        return Err(ApiError::InvalidCode);
    };
    if !state
        .code_keys
        .magic_link
        .verify(flow_id, &input.code, &link.code_hash)
    {
        let failures = queries::magic_links::record_code_failure(
            &mut *tx,
            link.id,
            magic_code::MAX_FAILURES_PER_CODE,
        )
        .await?;
        // The failure must be kept even though the request fails.
        tx.commit().await?;
        tracing::info!(user_id = ?link.user_id, %flow_id, failures, "wrong magic code");
        return Err(ApiError::InvalidCode);
    }
    queries::magic_links::consume_by_id(&mut *tx, link.id).await?;
    let (response, user_id) = log_in(
        &mut tx,
        flow_id,
        link.user_id,
        &link.email,
        ApiError::InvalidCode,
    )
    .await?;
    tx.commit().await?;

    tracing::info!(%user_id, %flow_id, "magic code login succeeded");
    Ok(AppJson(response))
}

/// What a checked link or code does: logs the user in on the flow the email was requested from,
/// and returns the account. `user_id` is the account the email was sent for, `None` for a sign-up:
/// the account is created, or found by address if it was created meanwhile. Either way the email
/// proves the user owns the address. `stale` is the error when the email went to an address the
/// account no longer uses.
async fn log_in(
    conn: &mut DbConnection,
    flow_id: Uuid,
    user_id: Option<Uuid>,
    email: &str,
    stale: ApiError,
) -> Result<(LoginResponse, Uuid), ApiError> {
    let user = match user_id {
        Some(id) => queries::users::find_by_id(&mut *conn, id).await?,
        None => match queries::users::create(&mut *conn, email).await? {
            Some(user) => {
                tracing::info!(user_id = %user.id, "account created by email");
                Some(user)
            }
            None => queries::users::find_by_email(&mut *conn, email).await?,
        },
    };
    let Some(user) = user else {
        return Err(stale);
    };
    if user.disabled_at.is_some() {
        return Err(ApiError::AccountDisabled);
    }
    if user.email != email {
        return Err(stale);
    }
    queries::users::mark_email_verified(&mut *conn, user.id, &user.email).await?;
    let response = login_flow::complete(conn, flow_id, user.id)
        .await?
        .ok_or(ApiError::FlowExpired)?;
    Ok((response, user.id))
}
