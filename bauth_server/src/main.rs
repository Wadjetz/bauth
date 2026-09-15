mod access_token;
mod clients;
mod config;
mod cors;
mod current_user;
mod db;
mod email;
mod emails;
mod errors;
mod jobs;
mod login_flow;
mod magic_code;
mod mailer;
mod master_key;
mod models;
mod password;
mod pkce;
mod queries;
mod rate_limit;
mod routes;
mod sessions;
mod signing_keys;
#[cfg(test)]
mod tests;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use dotenvy::dotenv;
use envconfig::Envconfig;
use tokio::net::TcpListener;

use crate::clients::Clients;
use crate::config::ServerConfig;
use crate::db::DbPool;
use crate::magic_code::MagicCodeKey;
use crate::mailer::Mailer;
use crate::master_key::MasterKey;
use crate::rate_limit::RateLimits;
use crate::signing_keys::SharedSigningKeys;

#[derive(Clone)]
struct AppState {
    db: DbPool,
    mailer: Mailer,
    config: Arc<ServerConfig>,
    clients: Arc<Clients>,
    signing_keys: SharedSigningKeys,
    rate_limits: Arc<RateLimits>,
    magic_code_key: Arc<MagicCodeKey>,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    // First, so every startup log below is printed.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = ServerConfig::init_from_env().expect("Failed to init config");
    config::validate_issuer(&config.issuer).expect("Invalid BAUTH_ISSUER");
    let config = Arc::new(config);

    let clients = Clients::load(&config.config_path).expect("Invalid bauth.toml");
    tracing::info!(path = %config.config_path.display(), "clients loaded");

    let master_key =
        Arc::new(MasterKey::from_base64(&config.master_key).expect("Invalid BAUTH_MASTER_KEY"));
    let trusted_proxies = rate_limit::parse_trusted_proxies(&config.trusted_proxies)
        .expect("Invalid BAUTH_TRUSTED_PROXIES");
    let rate_limits = Arc::new(RateLimits::new(trusted_proxies));

    let db = db::connect(&config.database_url)
        .await
        .expect("Failed to connect to database");
    db::migrate(&db).await.expect("Failed to run migrations");

    let mailer =
        Mailer::new(&config.smtp_url, &config.mail_from).expect("Invalid mail configuration");

    let signing_keys = signing_keys::ensure_and_load(&db, &master_key)
        .await
        .expect("Failed to load signing keys");
    tracing::info!(
        published = signing_keys.jwks.keys.len(),
        "signing keys loaded"
    );
    let signing_keys: SharedSigningKeys = Arc::new(arc_swap::ArcSwap::from_pointee(signing_keys));

    rate_limits.clone().spawn_cleanup();
    // Kept alive until the server stops.
    let _scheduler = jobs::start(db.clone(), master_key.clone(), signing_keys.clone())
        .await
        .expect("Failed to start background jobs");

    let app = app(AppState {
        db,
        mailer,
        config: config.clone(),
        clients: Arc::new(clients),
        signing_keys,
        rate_limits,
        magic_code_key: Arc::new(MagicCodeKey::new(&master_key)),
    });

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .expect("Failed to bind address");

    // ConnectInfo gives handlers the TCP peer address, needed for per-IP rate limits.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Failed to serve");
}

/// The whole HTTP API. Shared by `main` and the integration tests.
fn app(state: AppState) -> Router {
    let mut origins = state.clients.origins();
    // The verification page also calls bauth from the browser.
    if let Ok(url) = url::Url::parse(&state.config.verification_url)
        && matches!(url.scheme(), "http" | "https")
        && let Some(origin) = clients::origin_of(&url)
    {
        origins.insert(origin);
    }
    tracing::info!(?origins, "CORS allowed origins");

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .merge(routes::router())
        .layer(cors::layer(&origins))
        .with_state(state)
}

#[utoipa::path(get, path = "/health/live", tag = "Health", responses((status = 200, description = "Process is up")))]
async fn live() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, description = "Database reachable"),
        (status = 503, description = "Database unreachable"),
    )
)]
async fn ready(State(state): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
