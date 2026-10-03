use axum::Router;
use axum::routing::delete;
use axum::routing::get;
use axum::routing::post;

use crate::AppState;

mod email_change;
mod login;
mod magic_link;
mod me;
mod oauth;
mod openapi;
mod well_known;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/email-change/confirm", post(email_change::confirm))
        .route("/flows/login", post(login::create_flow))
        .route(
            "/flows/login/{flow_id}/magic-link",
            post(magic_link::request),
        )
        .route(
            "/flows/login/{flow_id}/magic-code",
            post(magic_link::confirm_code),
        )
        .route("/magic-link/confirm", post(magic_link::confirm))
        .route("/me", get(me::get).delete(me::delete_account))
        .route("/me/confirmation", post(me::request_confirmation))
        .route("/me/email", post(me::change_email))
        .route("/me/sessions", get(me::list_sessions))
        .route("/me/sessions/{session_id}", delete(me::revoke_session))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke))
        .route("/openapi.json", get(openapi::openapi_json))
        .route("/.well-known/jwks.json", get(well_known::jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(well_known::authorization_server_metadata),
        )
}
