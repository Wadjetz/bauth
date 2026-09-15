use std::sync::LazyLock;

use axum::http::header;
use axum::response::IntoResponse;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

/// The API contract. `bauth_server/openapi.json` is generated from it and used to build the SDKs.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "bauth",
        description = "Headless authentication server. App routes answer errors with `ErrorBody` \
                       and a stable `code`; `/oauth/*` follows RFC 6749."
    ),
    paths(
        crate::live,
        crate::ready,
        super::registration::register,
        super::verification::resend,
        super::verification::confirm,
        super::login::create_flow,
        super::login::submit_password,
        super::magic_link::request,
        super::magic_link::confirm,
        super::magic_link::confirm_code,
        super::oauth::token,
        super::oauth::revoke,
        super::recovery::request,
        super::recovery::reset,
        super::me::get,
        super::me::delete_account,
        super::me::change_password,
        super::me::change_email,
        super::me::list_sessions,
        super::me::revoke_session,
        super::well_known::jwks,
        super::well_known::authorization_server_metadata,
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Access token from `/oauth/token`"))
                    .build(),
            ),
        );
    }
}

static OPENAPI_JSON: LazyLock<String> = LazyLock::new(|| {
    ApiDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI document serializes")
});

pub async fn openapi_json() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        OPENAPI_JSON.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json");

    /// Keeps the committed contract in sync with the code. Regenerate with:
    /// `UPDATE_OPENAPI=1 cargo test -p bauth_server openapi`
    #[test]
    fn openapi_json_is_up_to_date() {
        let generated = format!("{}\n", OPENAPI_JSON.as_str());
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(COMMITTED, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(COMMITTED).unwrap_or_default();
        assert!(
            committed == generated,
            "bauth_server/openapi.json is stale: run `UPDATE_OPENAPI=1 cargo test -p bauth_server openapi`"
        );
    }
}
