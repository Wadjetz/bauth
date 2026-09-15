use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;
use crate::errors::AppJson;

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "Well-known",
    responses((status = 200, description = "JWK Set (RFC 7517) with the Ed25519 keys signing access tokens", body = Object))
)]
/// Public keys to verify access tokens. Apps cache this; keep `max-age` far below
/// the 24 h a new key is published before it starts signing.
pub async fn jwks(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        AppJson(&state.signing_keys.load().jwks),
    )
        .into_response()
}

/// RFC 8414 metadata, so OAuth libraries can find endpoints and capabilities from the issuer alone.
#[derive(Serialize, ToSchema)]
pub struct AuthorizationServerMetadata {
    issuer: String,
    token_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    #[schema(value_type = Vec<String>)]
    response_types_supported: [&'static str; 1],
    #[schema(value_type = Vec<String>)]
    grant_types_supported: [&'static str; 2],
    #[schema(value_type = Vec<String>)]
    code_challenge_methods_supported: [&'static str; 1],
    #[schema(value_type = Vec<String>)]
    token_endpoint_auth_methods_supported: [&'static str; 1],
    #[schema(value_type = Vec<String>)]
    revocation_endpoint_auth_methods_supported: [&'static str; 1],
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-authorization-server",
    tag = "Well-known",
    responses((status = 200, description = "RFC 8414 metadata", body = AuthorizationServerMetadata))
)]
pub async fn authorization_server_metadata(State(state): State<AppState>) -> Response {
    let issuer = &state.config.issuer;
    let metadata = AuthorizationServerMetadata {
        issuer: issuer.clone(),
        token_endpoint: format!("{issuer}/oauth/token"),
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        // Public clients only for now: no client secret, PKCE protects the code.
        token_endpoint_auth_methods_supported: ["none"],
        revocation_endpoint_auth_methods_supported: ["none"],
    };
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        AppJson(metadata),
    )
        .into_response()
}
