//! Types shared by the bauth server and the crates that talk to it.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Claims of a bauth access token (RFC 9068, JWT profile for OAuth 2.0 access tokens).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    /// User id.
    pub sub: Uuid,
    /// API the token is meant for.
    pub aud: String,
    pub client_id: String,
    /// Session the token was issued from: lets bauth reject tokens of revoked sessions.
    pub sid: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}
