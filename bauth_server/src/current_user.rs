use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use bauth_core::AccessTokenClaims;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use uuid::Uuid;

use crate::AppState;
use crate::errors::ApiError;
use crate::queries;

/// Tolerated clock difference, same as `bauth_client`.
const LEEWAY_SECONDS: u64 = 30;

/// The user behind `Authorization: Bearer <access token>`, for bauth's own `/me` routes.
///
/// Unlike an API using `bauth_client`, bauth checks the session in the database on every
/// request: a password change or a logout locks tokens out immediately, not after 15 minutes.
pub struct CurrentUser {
    pub id: Uuid,
    pub email: String,
    pub session_id: Uuid,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let token_header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
        if token_header.alg != Algorithm::EdDSA || token_header.typ.as_deref() != Some("at+jwt") {
            return Err(ApiError::Unauthorized);
        }
        let key = token_header
            .kid
            .and_then(|kid| state.signing_keys.load().decoding_key(&kid))
            .ok_or(ApiError::Unauthorized)?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&state.config.issuer]);
        // Any audience: tokens are issued for an app's API, and the user may use any of them
        // to manage their own account. Sensitive changes ask for the password again.
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.leeway = LEEWAY_SECONDS;
        let claims = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|_| ApiError::Unauthorized)?
            .claims;

        let session = queries::sessions::find_authenticated(&state.db, claims.sid)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if session.user_id != claims.sub {
            return Err(ApiError::Unauthorized);
        }

        Ok(Self {
            id: session.user_id,
            email: session.email,
            session_id: claims.sid,
        })
    }
}
