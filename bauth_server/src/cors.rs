use std::collections::BTreeSet;
use std::time::Duration;

use axum::http::{HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Browsers may call bauth only from the registered apps' origins.
/// No cookies are involved (tokens travel in headers and bodies), so no credentials either.
pub fn layer(origins: &BTreeSet<String>) -> CorsLayer {
    let origins = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok());
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        // So apps can read how long to wait, and why a Bearer token was refused.
        .expose_headers([header::RETRY_AFTER, header::WWW_AUTHENTICATE])
        .max_age(Duration::from_secs(60 * 60))
}
