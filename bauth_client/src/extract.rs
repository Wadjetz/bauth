//! `AuthUser` as an axum extractor. The `Verifier` comes from a request extension:
//!
//! ```no_run
//! use axum::routing::get;
//! use axum::{Extension, Router};
//! use bauth_client::{AuthUser, Verifier};
//!
//! async fn list_recipes(user: AuthUser) -> String {
//!     format!("recipes of {}", user.id)
//! }
//!
//! async fn feed(user: Option<AuthUser>) -> &'static str {
//!     if user.is_some() { "personal feed" } else { "public feed" }
//! }
//!
//! let app: Router = Router::new()
//!     .route("/recipes", get(list_recipes))
//!     .route("/feed", get(feed))
//!     .layer(Extension(Verifier::new("https://auth.example.com", "my-app")));
//! ```

use axum::Json;
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::{AuthUser, Verifier, VerifyError};

/// Why `AuthUser` couldn't be extracted. Answers like bauth: `{ "code", "message" }`.
#[derive(Debug, thiserror::Error)]
pub enum AuthRejection {
    #[error("missing bearer token")]
    MissingToken,
    #[error(transparent)]
    InvalidToken(VerifyError),
    #[error("no bauth_client::Verifier extension: add `.layer(Extension(verifier))` to the router")]
    MissingVerifier,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::MissingToken
            | Self::InvalidToken(VerifyError::Malformed)
            | Self::InvalidToken(VerifyError::UnknownKey)
            | Self::InvalidToken(VerifyError::Invalid(_)) => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            }
            // bauth can't be reached and no key is cached: the token may well be valid.
            Self::InvalidToken(VerifyError::Jwks(_)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "auth_unavailable")
            }
            Self::MissingVerifier => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        if status != StatusCode::UNAUTHORIZED {
            tracing::error!(error = %self, "cannot authenticate request");
        }
        let body = Json(serde_json::json!({ "code": code, "message": self.to_string() }));
        let mut response = (status, body).into_response();
        if status == StatusCode::UNAUTHORIZED {
            // RFC 6750 §3: tells clients to refresh their access token.
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        response
    }
}

/// `Authorization: Bearer <token>` (scheme is case-insensitive, RFC 7235).
fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

async fn verify(parts: &Parts, token: &str) -> Result<AuthUser, AuthRejection> {
    let verifier = parts
        .extensions
        .get::<Verifier>()
        .ok_or(AuthRejection::MissingVerifier)?;
    verifier
        .verify(token)
        .await
        .map_err(AuthRejection::InvalidToken)
}

/// Requires a valid access token; rejects the request otherwise.
impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(AuthRejection::MissingToken)?;
        verify(parts, token).await
    }
}

/// `Option<AuthUser>`: `None` without a token, but an invalid token is still rejected,
/// so a client with an expired token learns it must refresh.
impl<S: Send + Sync> OptionalFromRequestParts<S> for AuthUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match bearer_token(parts) {
            None => Ok(None),
            Some(token) => verify(parts, token).await.map(Some),
        }
    }
}
