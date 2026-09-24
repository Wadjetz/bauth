//! Integration tests: the real router against a fresh Postgres database per test (`#[sqlx::test]`).
//!
//! `DATABASE_URL` must point to a database where sqlx may create throwaway databases:
//! locally the `postgres-test` service of docker-compose.yml (`podman compose up -d postgres-test`).

mod accounts;
mod jobs;
mod key_rotation;
mod me;
mod oauth;
mod protections;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use axum::Router;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::http::HeaderName;
use axum::http::Method;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header;
use axum::http::request;
use serde_json::Value;
use serde_json::json;
use tower::ServiceExt;

use crate::AppState;
use crate::app;
use crate::clients::Clients;
use crate::config::ServerConfig;
use crate::db::DbPool;
use crate::magic_code::MagicCodeKey;
use crate::mailer::Email;
use crate::mailer::Mailer;
use crate::master_key::MasterKey;
use crate::rate_limit::RateLimits;
use crate::signing_keys::SharedSigningKeys;
use crate::signing_keys::{self};

pub const ISSUER: &str = "http://localhost:8401";
pub const CLIENT_ID: &str = "my-app";
pub const REDIRECT_URI: &str = "http://localhost:8025/auth/callback";
pub const APP_ORIGIN: &str = "http://localhost:8025";
/// RFC 7636 appendix B.
pub const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const PASSWORD: &str = "correct horse battery";

const CLIENTS: &str = r#"
[[clients]]
id = "my-app"
name = "My App"
redirect_uris = ["http://localhost:8025/auth/callback"]
allow_signup = true
password_reset_url = "http://localhost:8025/auth/reset-password"
magic_link_url = "http://localhost:8025/auth/magic-link"
verification_url = "http://localhost:8025/auth/verify-email"

[[clients]]
id = "closed"
name = "Closed"
redirect_uris = ["https://closed.example.com/callback"]
magic_link_url = "https://closed.example.com/auth/magic-link"
"#;

pub struct TestApp {
    pub db: DbPool,
    pub master_key: Arc<MasterKey>,
    pub keys: SharedSigningKeys,
    router: Router,
    outbox: Arc<Mutex<Vec<Email>>>,
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl TestResponse {
    /// `code` of an app error, or `error` of an OAuth error.
    pub fn code(&self) -> &str {
        self.body["code"]
            .as_str()
            .or(self.body["error"].as_str())
            .unwrap_or_default()
    }

    pub fn str(&self, field: &str) -> String {
        self.body[field]
            .as_str()
            .unwrap_or_else(|| panic!("no `{field}` in {}", self.body))
            .to_owned()
    }
}

pub struct Tokens {
    pub access: String,
    pub refresh: String,
}

pub struct TestRequest<'a> {
    app: &'a TestApp,
    request: request::Builder,
    body: Body,
}

impl TestRequest<'_> {
    pub fn json(mut self, body: Value) -> Self {
        self.request = self
            .request
            .header(header::CONTENT_TYPE, "application/json");
        self.body = Body::from(body.to_string());
        self
    }

    pub fn form(mut self, fields: &[(&str, &str)]) -> Self {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.request = self
            .request
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.body = Body::from(encoded);
        self
    }

    pub fn bearer(self, access_token: &str) -> Self {
        self.header(header::AUTHORIZATION, &format!("Bearer {access_token}"))
    }

    pub fn header(mut self, name: HeaderName, value: &str) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    pub async fn send(self) -> TestResponse {
        let mut request = self.request.body(self.body).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50000))));
        let response = self.app.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        TestResponse {
            status,
            headers,
            body,
        }
    }
}

impl TestApp {
    pub async fn new(db: DbPool) -> Self {
        Self::with_trusted_proxies(db, Vec::new()).await
    }

    pub async fn with_trusted_proxies(db: DbPool, trusted_proxies: Vec<IpAddr>) -> Self {
        let master_key = Arc::new(
            MasterKey::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap(),
        );
        let keys = signing_keys::ensure_and_load(&db, &master_key)
            .await
            .unwrap();
        let keys: SharedSigningKeys = Arc::new(arc_swap::ArcSwap::from_pointee(keys));
        let (mailer, outbox) = Mailer::capture();
        let config = ServerConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            database_url: String::new(),
            smtp_url: String::new(),
            mail_from: String::new(),
            config_path: Default::default(),
            master_key: String::new(),
            issuer: ISSUER.to_owned(),
            trusted_proxies: String::new(),
        };
        let state = AppState {
            db: db.clone(),
            mailer,
            config: Arc::new(config),
            clients: Arc::new(Clients::from_toml(CLIENTS).unwrap()),
            signing_keys: keys.clone(),
            rate_limits: Arc::new(RateLimits::new(trusted_proxies)),
            magic_code_key: Arc::new(MagicCodeKey::new(&master_key)),
        };
        Self {
            db,
            master_key,
            keys,
            router: app(state),
            outbox,
        }
    }

    /// What the hourly reload job does.
    pub async fn reload_keys(&self) {
        signing_keys::reload(&self.db, &self.master_key, &self.keys)
            .await
            .unwrap();
    }

    fn request(&self, method: Method, path: &str) -> TestRequest<'_> {
        TestRequest {
            app: self,
            request: Request::builder().method(method).uri(path),
            body: Body::empty(),
        }
    }

    pub fn get(&self, path: &str) -> TestRequest<'_> {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: &str) -> TestRequest<'_> {
        self.request(Method::POST, path)
    }

    pub fn delete(&self, path: &str) -> TestRequest<'_> {
        self.request(Method::DELETE, path)
    }

    pub fn options(&self, path: &str) -> TestRequest<'_> {
        self.request(Method::OPTIONS, path)
    }

    pub async fn sql(&self, query: &'static str) {
        sqlx::query(query).execute(&self.db).await.unwrap();
    }

    // Emails

    pub fn emails_to(&self, to: &str) -> Vec<Email> {
        let outbox = self.outbox.lock().unwrap();
        outbox
            .iter()
            .filter(|email| email.to == to)
            .cloned()
            .collect()
    }

    /// Token of the last link emailed to `to`.
    pub fn last_token(&self, to: &str) -> String {
        let emails = self.emails_to(to);
        let email = emails.last().unwrap_or_else(|| panic!("no email to {to}"));
        let start = email.text.find("#token=").expect("email has a link") + "#token=".len();
        email.text[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect()
    }

    /// 6-digit code of the last magic link emailed to `to`: the line made of six digits.
    pub fn last_magic_code(&self, to: &str) -> String {
        let emails = self.emails_to(to);
        let email = emails.last().unwrap_or_else(|| panic!("no email to {to}"));
        email
            .text
            .lines()
            .find(|line| line.len() == 6 && line.bytes().all(|b| b.is_ascii_digit()))
            .expect("email has a code")
            .to_owned()
    }

    // Flows

    pub async fn register(&self, email: &str) -> TestResponse {
        self.post("/registration")
            .json(json!({ "client_id": CLIENT_ID, "email": email, "password": PASSWORD }))
            .send()
            .await
    }

    pub async fn register_verified(&self, email: &str) {
        assert_eq!(self.register(email).await.status, StatusCode::ACCEPTED);
        let confirm = self.confirm_verification(&self.last_token(email)).await;
        assert_eq!(confirm.status, StatusCode::NO_CONTENT);
    }

    pub async fn confirm_verification(&self, token: &str) -> TestResponse {
        self.post("/verification/confirm")
            .json(json!({ "token": token }))
            .send()
            .await
    }

    pub async fn start_flow(&self) -> String {
        self.start_flow_for(CLIENT_ID, REDIRECT_URI).await
    }

    pub async fn start_flow_for(&self, client_id: &str, redirect_uri: &str) -> String {
        let flow = self
            .post("/flows/login")
            .json(json!({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "S256",
            }))
            .send()
            .await;
        assert_eq!(flow.status, StatusCode::CREATED, "{}", flow.body);
        flow.str("flow_id")
    }

    pub async fn submit_password(
        &self,
        flow_id: &str,
        email: &str,
        password: &str,
    ) -> TestResponse {
        self.post(&format!("/flows/login/{flow_id}/password"))
            .json(json!({ "email": email, "password": password }))
            .send()
            .await
    }

    pub async fn request_magic_link(&self, flow_id: &str, email: &str) -> TestResponse {
        self.post(&format!("/flows/login/{flow_id}/magic-link"))
            .json(json!({ "email": email }))
            .send()
            .await
    }

    pub async fn submit_magic_code(&self, flow_id: &str, code: &str) -> TestResponse {
        self.post(&format!("/flows/login/{flow_id}/magic-code"))
            .json(json!({ "code": code }))
            .send()
            .await
    }

    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> TestResponse {
        self.post("/oauth/token")
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT_ID),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
    }

    pub async fn login(&self, email: &str, password: &str) -> Tokens {
        let flow_id = self.start_flow().await;
        let login = self.submit_password(&flow_id, email, password).await;
        assert_eq!(login.status, StatusCode::OK, "{}", login.body);
        let tokens = self
            .exchange(&login.str("code"), CODE_VERIFIER, REDIRECT_URI)
            .await;
        assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
        Tokens {
            access: tokens.str("access_token"),
            refresh: tokens.str("refresh_token"),
        }
    }

    /// Signs up (or logs in) with the magic code, like an account that has no password.
    pub async fn login_with_code(&self, email: &str) -> Tokens {
        let flow_id = self.start_flow().await;
        self.request_magic_link(&flow_id, email).await;
        let login = self
            .submit_magic_code(&flow_id, &self.last_magic_code(email))
            .await;
        assert_eq!(login.status, StatusCode::OK, "{}", login.body);
        let tokens = self
            .exchange(&login.str("code"), CODE_VERIFIER, REDIRECT_URI)
            .await;
        assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
        Tokens {
            access: tokens.str("access_token"),
            refresh: tokens.str("refresh_token"),
        }
    }

    /// Emails a confirmation code for a sensitive change, and returns it.
    pub async fn confirmation_code(&self, access_token: &str, action: &str, email: &str) -> String {
        let sent = self
            .post("/me/confirmation")
            .bearer(access_token)
            .json(json!({ "action": action }))
            .send()
            .await;
        assert_eq!(sent.status, StatusCode::ACCEPTED, "{}", sent.body);
        self.last_magic_code(email)
    }

    pub async fn refresh(&self, refresh_token: &str) -> TestResponse {
        self.post("/oauth/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
    }

    /// Pretends every rotation happened long ago, past the reuse grace period.
    pub async fn age_rotations(&self) {
        self.sql("UPDATE bauth.refresh_tokens SET rotated_at = rotated_at - interval '5 minutes' WHERE rotated_at IS NOT NULL")
            .await;
    }
}
