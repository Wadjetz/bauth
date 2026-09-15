use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{FromRequest, FromRequestParts};
use std::time::Duration;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use crate::password::{self, HashingError, PolicyError};

/// Errors returned to API clients. `code()` is the stable contract; `message` is for developers.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error("email address is invalid")]
    InvalidEmail,
    #[error("password must be at least {} characters", password::MIN_CHARS)]
    PasswordTooShort,
    #[error("password must be at most {} characters", password::MAX_CHARS)]
    PasswordTooLong,
    #[error("token is invalid, expired or already used")]
    InvalidToken,
    #[error("code is incorrect, expired or already used")]
    InvalidCode,
    #[error("unknown client_id")]
    InvalidClient,
    #[error("redirect_uri is not registered for this client")]
    InvalidRedirectUri,
    #[error("code_challenge must be a S256 challenge (43 base64url characters)")]
    InvalidCodeChallenge,
    #[error("email or password is incorrect")]
    InvalidCredentials,
    #[error("email address must be verified before logging in")]
    EmailNotVerified,
    #[error("account is disabled")]
    AccountDisabled,
    #[error("login flow is unknown, expired or already completed")]
    FlowExpired,
    #[error("missing, invalid or expired access token")]
    Unauthorized,
    #[error("this account has no password: use password reset to set one")]
    PasswordNotSet,
    #[error("not found")]
    NotFound,
    #[error("email address is already used by another account")]
    EmailTaken,
    #[error("this client does not allow creating accounts")]
    SignupDisabled,
    #[error("too many attempts, retry in {} seconds", retry_after_seconds(*retry_after))]
    RateLimited { retry_after: Duration },
    #[error("internal server error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidEmail => "invalid_email",
            Self::PasswordTooShort => "password_too_short",
            Self::PasswordTooLong => "password_too_long",
            Self::InvalidToken => "invalid_token",
            Self::InvalidCode => "invalid_code",
            Self::InvalidClient => "invalid_client",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidCodeChallenge => "invalid_code_challenge",
            Self::InvalidCredentials => "invalid_credentials",
            Self::EmailNotVerified => "email_not_verified",
            Self::AccountDisabled => "account_disabled",
            Self::FlowExpired => "flow_expired",
            Self::Unauthorized => "unauthorized",
            Self::PasswordNotSet => "password_not_set",
            Self::NotFound => "not_found",
            Self::EmailTaken => "email_taken",
            Self::SignupDisabled => "signup_disabled",
            Self::RateLimited { .. } => "rate_limited",
            Self::Internal(_) => "internal_error",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_)
            | Self::InvalidEmail
            | Self::PasswordTooShort
            | Self::PasswordTooLong
            | Self::InvalidToken
            | Self::InvalidCode
            | Self::InvalidClient
            | Self::InvalidRedirectUri
            | Self::InvalidCodeChallenge
            | Self::InvalidCredentials
            | Self::EmailNotVerified
            | Self::AccountDisabled
            | Self::FlowExpired => StatusCode::BAD_REQUEST,
            Self::PasswordNotSet | Self::EmailTaken | Self::SignupDisabled => {
                StatusCode::BAD_REQUEST
            }
            // 401 tells SDKs to refresh the access token and retry.
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Error of every app route. Apps translate `code`, which is stable; `message` is for developers.
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    #[schema(example = "invalid_credentials")]
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(source) = &self {
            // Details stay in the logs; clients only get `internal_error`.
            tracing::error!(error = %source, "internal error");
        }
        let body = ErrorBody {
            code: self.code(),
            message: self.to_string(),
        };
        let mut response = (self.status(), Json(body)).into_response();
        if let Self::Unauthorized = self {
            // RFC 6750 §3.
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer error=\"invalid_token\""),
            );
        }
        if let Self::RateLimited { retry_after } = self {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after_seconds(retry_after)),
            );
        }
        response
    }
}

/// Whole seconds, rounded up: `Retry-After: 0` would invite an immediate retry.
fn retry_after_seconds(retry_after: Duration) -> u64 {
    retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0)
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self::InvalidRequest(rejection.body_text())
    }
}

impl From<PolicyError> for ApiError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::TooShort => Self::PasswordTooShort,
            PolicyError::TooLong => Self::PasswordTooLong,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<HashingError> for ApiError {
    fn from(error: HashingError) -> Self {
        Self::Internal(error.into())
    }
}

impl From<PathRejection> for ApiError {
    fn from(rejection: PathRejection) -> Self {
        Self::InvalidRequest(rejection.body_text())
    }
}

/// `axum::extract::Path`, with rejections turned into `ApiError`.
#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub struct AppPath<T>(pub T);

/// `axum::Json`, but rejections are turned into `ApiError` so every error has the same shape.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct AppJson<T>(pub T);

impl<T: Serialize> IntoResponse for AppJson<T> {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use axum::routing::post;
    use serde::Deserialize;
    use tower::ServiceExt;

    use super::*;

    #[derive(Deserialize)]
    struct Input {
        #[allow(dead_code)]
        email: String,
    }

    async fn handler(AppJson(_input): AppJson<Input>) -> Result<StatusCode, ApiError> {
        Err(ApiError::PasswordTooShort)
    }

    async fn call(body: &'static str, content_type: &str) -> (StatusCode, String) {
        let app = Router::new().route("/", post(handler));
        let request = Request::post("/")
            .header("content-type", content_type)
            .body(Body::from(body))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn handler_error_has_stable_code() {
        let (status, body) = call(r#"{"email":"a@b.c"}"#, "application/json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains(r#""code":"password_too_short""#), "{body}");
    }

    #[tokio::test]
    async fn json_rejection_uses_same_shape() {
        let (status, body) = call(r#"{"nope":1}"#, "application/json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains(r#""code":"invalid_request""#), "{body}");

        let (_, body) = call(r#"{"email":"a@b.c"}"#, "text/plain").await;
        assert!(body.contains(r#""code":"invalid_request""#), "{body}");
    }

    #[test]
    fn internal_error_hides_details() {
        let error = ApiError::from(sqlx::Error::PoolTimedOut);
        assert_eq!(error.to_string(), "internal server error");
        assert_eq!(error.code(), "internal_error");
    }
}
