//! A bauth issuer for the tests of an API (`test-support` feature).
//!
//! `FakeBauth` serves a JWKS and `GET /me` on a random local port and signs access tokens with its
//! own Ed25519 key, so the API's `Verifier` checks them exactly as in production, signature
//! included. It runs on its own thread and runtime: one instance can outlive every test runtime,
//! so a `static` shared by the whole test binary works.
//!
//! ```no_run
//! use std::sync::LazyLock;
//!
//! use bauth_client::testing::FakeBauth;
//! use uuid::Uuid;
//!
//! static BAUTH: LazyLock<FakeBauth> = LazyLock::new(FakeBauth::start);
//!
//! let verifier = BAUTH.verifier("my-api"); // layer it on the router under test
//! let user_id = Uuid::now_v7();
//! BAUTH.set_account(user_id, "alice@example.com", true); // what `GET /me` answers
//! let token = BAUTH.access_token(user_id, "my-api"); // `Authorization: Bearer {token}`
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use aws_lc_rs::signature::Ed25519KeyPair;
use aws_lc_rs::signature::KeyPair;
use axum::Json;
use axum::Router;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bauth_core::AccessTokenClaims;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use serde_json::json;
use uuid::Uuid;

use crate::Verifier;
use crate::extract::bearer_token;

/// PKCS#8 (v1) header of an Ed25519 private key, in front of its 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// What `GET /me` knows: the email of each user, and whether it is verified.
type Accounts = Arc<Mutex<HashMap<Uuid, (String, bool)>>>;

pub struct FakeBauth {
    issuer: String,
    kid: String,
    encoding_key: EncodingKey,
    accounts: Accounts,
    jwks_fetches: Arc<AtomicUsize>,
}

impl FakeBauth {
    /// Starts the issuer with a fresh key, on its own thread. Panics if it can't bind a port.
    pub fn start() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS random number generator is available");
        let public = Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("32-byte seed")
            .public_key()
            .as_ref()
            .to_vec();
        let kid = Uuid::now_v7().to_string();
        let jwks = json!({ "keys": [{
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "kid": kid, "x": URL_SAFE_NO_PAD.encode(public),
        }] });

        let accounts = Accounts::default();
        let jwks_fetches = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/.well-known/jwks.json",
                get({
                    let fetches = jwks_fetches.clone();
                    move || {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        let jwks = jwks.clone();
                        async move { Json(jwks) }
                    }
                }),
            )
            .route(
                "/me",
                get({
                    let accounts = accounts.clone();
                    move |headers: HeaderMap| {
                        let accounts = accounts.clone();
                        async move { me(&accounts, &headers) }
                    }
                }),
            );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free local port");
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        let issuer = format!("http://{}", listener.local_addr().expect("bound address"));
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
                    axum::serve(listener, app).await.expect("fake bauth serves");
                });
        });

        Self {
            issuer,
            kid,
            encoding_key: EncodingKey::from_ed_der(
                &[ED25519_PKCS8_PREFIX.as_slice(), &seed].concat(),
            ),
            accounts,
            jwks_fetches,
        }
    }

    /// Base URL of this issuer: the `iss` of its tokens.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// A `Verifier` of this issuer for `audience`.
    pub fn verifier(&self, audience: &str) -> Verifier {
        Verifier::new(&self.issuer, audience)
    }

    /// The claims of a valid access token for `user_id`: an hour left, client `test-client`.
    /// Change them and `sign` to test expired tokens, another audience…
    pub fn claims(&self, user_id: Uuid, audience: &str) -> AccessTokenClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs() as i64;
        AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: user_id,
            aud: audience.to_owned(),
            client_id: "test-client".to_owned(),
            sid: Uuid::now_v7(),
            iat: now,
            exp: now + 3600,
            jti: Uuid::now_v7(),
        }
    }

    /// A valid access token for `user_id`, for `audience`.
    pub fn access_token(&self, user_id: Uuid, audience: &str) -> String {
        self.sign(&self.claims(user_id, audience))
    }

    /// Signs `claims` as bauth does: EdDSA, this issuer's `kid`, `typ: at+jwt`.
    pub fn sign(&self, claims: &AccessTokenClaims) -> String {
        self.sign_with_type(claims, "at+jwt")
    }

    /// Signs with another `typ`, to check that only access tokens are accepted.
    pub fn sign_with_type(&self, claims: &AccessTokenClaims, typ: &str) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_owned());
        encode(&header, claims, &self.encoding_key).expect("Ed25519 signing")
    }

    /// Gives `user_id` an account, as `GET /me` then answers for their tokens.
    pub fn set_account(&self, user_id: Uuid, email: &str, email_verified: bool) {
        self.accounts
            .lock()
            .expect("accounts lock")
            .insert(user_id, (email.to_owned(), email_verified));
    }

    /// How many times the JWKS was served, to test caching.
    pub fn jwks_fetches(&self) -> usize {
        self.jwks_fetches.load(Ordering::SeqCst)
    }
}

/// `GET /me`: the account of the bearer token's `sub`. The token is only decoded, not verified:
/// the API under test already verified it, and this is a stand-in for bauth.
fn me(accounts: &Accounts, headers: &HeaderMap) -> Response {
    let user_id = bearer_token(headers)
        .and_then(|token| token.split('.').nth(1))
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|payload| serde_json::from_slice::<AccessTokenClaims>(&payload).ok())
        .map(|claims| claims.sub);
    let account = user_id.and_then(|id| accounts.lock().ok()?.get(&id).cloned().map(|a| (id, a)));
    match account {
        Some((id, (email, email_verified))) => Json(json!({
            "id": id,
            "email": email,
            "email_verified": email_verified,
            "has_password": false,
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}
