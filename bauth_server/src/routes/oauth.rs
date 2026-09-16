use axum::Json;
use axum::extract::FromRequest;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::access_token;
use crate::pkce;
use crate::queries;
use crate::sessions;
use crate::token;

/// Errors of the token endpoint, in the format OAuth libraries expect (RFC 6749 §5.2).
#[derive(Debug)]
pub enum OAuthError {
    InvalidRequest(String),
    InvalidClient,
    InvalidGrant(&'static str),
    UnsupportedGrantType,
    ServerError(Box<dyn std::error::Error + Send + Sync>),
}

/// RFC 6749 §5.2 error.
#[derive(Serialize, ToSchema)]
pub struct OAuthErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            Self::InvalidRequest(description) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(description),
            ),
            Self::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client", None),
            Self::InvalidGrant(description) => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some(description.to_owned()),
            ),
            Self::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type", None),
            Self::ServerError(source) => {
                tracing::error!(error = %source, "token endpoint error");
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
            }
        };
        let body = OAuthErrorBody {
            error,
            error_description: description,
        };
        (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
    }
}

impl From<FormRejection> for OAuthError {
    fn from(rejection: FormRejection) -> Self {
        Self::InvalidRequest(rejection.body_text())
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(error: sqlx::Error) -> Self {
        Self::ServerError(error.into())
    }
}

impl From<access_token::IssueError> for OAuthError {
    fn from(error: access_token::IssueError) -> Self {
        Self::ServerError(error.into())
    }
}

/// `axum::Form` with rejections in the OAuth error format.
#[derive(FromRequest)]
#[from_request(via(axum::Form), rejection(OAuthError))]
pub struct OAuthForm<T>(pub T);

/// `application/x-www-form-urlencoded`, as required by RFC 6749 §4.1.3.
#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    grant_type: String,
    client_id: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
}

fn required(value: Option<String>, name: &str) -> Result<String, OAuthError> {
    value.ok_or_else(|| OAuthError::InvalidRequest(format!("missing `{name}`")))
}

#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "OAuth",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "`invalid_request`, `invalid_grant`, `unsupported_grant_type`", body = super::oauth::OAuthErrorBody),
        (status = 401, description = "`invalid_client`", body = super::oauth::OAuthErrorBody),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    OAuthForm(input): OAuthForm<TokenRequest>,
) -> Result<Response, OAuthError> {
    match input.grant_type.as_str() {
        "authorization_code" => authorization_code(state, input).await,
        "refresh_token" => refresh_token(state, input).await,
        _ => Err(OAuthError::UnsupportedGrantType),
    }
}

async fn authorization_code(state: AppState, input: TokenRequest) -> Result<Response, OAuthError> {
    let code = required(input.code, "code")?;
    let redirect_uri = required(input.redirect_uri, "redirect_uri")?;
    let code_verifier = required(input.code_verifier, "code_verifier")?;
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(OAuthError::InvalidClient)?;
    let code_hash = token::hash(&code);

    let mut tx = state.db.begin().await?;
    let Some(consumed) = queries::authorization_codes::consume(&mut *tx, &code_hash).await? else {
        tx.rollback().await?;
        return Err(reject_unusable_code(&state, &code_hash).await?);
    };

    // Any mismatch rolls back: the code stays usable by the legitimate app until it expires.
    if consumed.client_id != client.id {
        return Err(OAuthError::InvalidGrant(
            "code was issued to another client",
        ));
    }
    if consumed.redirect_uri != redirect_uri {
        return Err(OAuthError::InvalidGrant("redirect_uri does not match"));
    }
    if !pkce::verify(&code_verifier, &consumed.code_challenge) {
        return Err(OAuthError::InvalidGrant("code_verifier does not match"));
    }
    // The account may have been disabled in the seconds since the password check.
    let user = queries::users::find_by_id(&mut *tx, consumed.user_id).await?;
    if user.is_none_or(|user| user.disabled_at.is_some()) {
        return Err(OAuthError::InvalidGrant("account is disabled"));
    }

    let session = sessions::open(&mut tx, consumed.user_id, &client.id, consumed.id).await?;
    let access = access_token::issue(
        &state.signing_keys.load(),
        &state.config.issuer,
        consumed.user_id,
        session.session_id,
        client,
        Utc::now(),
    )?;
    tx.commit().await?;

    tracing::info!(user_id = %consumed.user_id, session_id = %session.session_id, client_id = %client.id, "tokens issued");
    let response = TokenResponse {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: access.expires_in,
        refresh_token: session.refresh_token,
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(response)).into_response())
}

/// The code can't be exchanged. If it was already used, someone replayed it:
/// revoke the session it opened (RFC 6749 §4.1.2), since those tokens may be in the wrong hands.
async fn reject_unusable_code(
    state: &AppState,
    code_hash: &[u8],
) -> Result<OAuthError, OAuthError> {
    if let Some(code_id) = queries::authorization_codes::find_consumed(&state.db, code_hash).await?
        && queries::sessions::revoke_by_authorization_code(&state.db, code_id).await?
    {
        tracing::warn!(%code_id, "authorization code replayed, session revoked");
    }
    Ok(OAuthError::InvalidGrant(
        "code is invalid, expired or already used",
    ))
}

async fn refresh_token(state: AppState, input: TokenRequest) -> Result<Response, OAuthError> {
    let refresh_token = required(input.refresh_token, "refresh_token")?;
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(OAuthError::InvalidClient)?;
    let token_hash = token::hash(&refresh_token);
    let now = Utc::now();

    let mut tx = state.db.begin().await?;
    let Some(current) = queries::refresh_tokens::find_for_update(&mut *tx, &token_hash).await?
    else {
        return Err(OAuthError::InvalidGrant("refresh token is invalid"));
    };
    if current.client_id != client.id {
        return Err(OAuthError::InvalidGrant(
            "refresh token was issued to another client",
        ));
    }
    if current.session_revoked_at.is_some() || current.session_expires_at <= now {
        return Err(OAuthError::InvalidGrant("session is expired or revoked"));
    }

    let stolen = match (current.superseded_at, current.rotated_at) {
        // Replaced by a retry of its parent: the retry came from a copy of the parent.
        (Some(_), _) => true,
        (None, None) => {
            queries::refresh_tokens::mark_rotated(&mut *tx, current.id).await?;
            false
        }
        // Two tabs refreshed with the same token at the same time: let the second one through.
        (None, Some(rotated_at)) if now - rotated_at <= sessions::REFRESH_REUSE_GRACE => false,
        // A retry after a lost response (flaky mobile network) is fine as long as the app
        // never used what we sent. If it did, this token is a stolen copy.
        (None, Some(_)) => {
            let stolen = queries::refresh_tokens::has_used_successor(&mut *tx, current.id).await?;
            if !stolen {
                queries::refresh_tokens::supersede_unused_successors(&mut *tx, current.id).await?;
            }
            stolen
        }
    };
    if stolen {
        // Two parties hold tokens of this session and we can't tell which one is legitimate:
        // kill the whole session so neither copy keeps working.
        queries::sessions::revoke(&mut *tx, current.session_id).await?;
        tx.commit().await?;
        tracing::warn!(session_id = %current.session_id, user_id = %current.user_id, "refresh token reused, session revoked");
        return Err(OAuthError::InvalidGrant("refresh token was already used"));
    }

    let user = queries::users::find_by_id(&mut *tx, current.user_id).await?;
    if user.is_none_or(|user| user.disabled_at.is_some()) {
        queries::sessions::revoke(&mut *tx, current.session_id).await?;
        tx.commit().await?;
        return Err(OAuthError::InvalidGrant("account is disabled"));
    }

    let new_refresh_token =
        sessions::new_refresh_token(&mut tx, current.session_id, Some(current.id)).await?;
    let access = access_token::issue(
        &state.signing_keys.load(),
        &state.config.issuer,
        current.user_id,
        current.session_id,
        client,
        now,
    )?;
    tx.commit().await?;

    tracing::debug!(session_id = %current.session_id, "tokens refreshed");
    let response = TokenResponse {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: access.expires_in,
        refresh_token: new_refresh_token,
    };
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(response)).into_response())
}

/// RFC 7009. `token_type_hint` is accepted and ignored: only refresh tokens can be revoked,
/// access tokens are JWTs that stay valid until they expire (15 min).
#[derive(Deserialize, ToSchema)]
pub struct RevokeRequest {
    token: String,
    client_id: String,
}

#[utoipa::path(
    post,
    path = "/oauth/revoke",
    tag = "OAuth",
    request_body(content = RevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revoked, or nothing to revoke (RFC 7009)"),
        (status = 400, description = "`invalid_request`", body = super::oauth::OAuthErrorBody),
        (status = 401, description = "`invalid_client`", body = super::oauth::OAuthErrorBody),
    )
)]
/// Logout: revokes the session behind a refresh token, with every token rotated from it.
pub async fn revoke(
    State(state): State<AppState>,
    OAuthForm(input): OAuthForm<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(OAuthError::InvalidClient)?;
    let token_hash = token::hash(&input.token);

    if let Some(session_id) =
        queries::sessions::revoke_by_refresh_token(&state.db, &token_hash, &client.id).await?
    {
        tracing::info!(%session_id, client_id = %client.id, "session revoked by client");
    }
    // Same answer for unknown, already revoked or foreign tokens (RFC 7009 §2.2):
    // the endpoint must not tell a caller whether a token exists.
    Ok(StatusCode::OK)
}
