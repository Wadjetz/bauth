use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bauth_client::{AccessTokenClaims, Verifier, VerifyError};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use uuid::Uuid;

const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

struct TestKey {
    kid: String,
    encoding_key: EncodingKey,
    jwk: serde_json::Value,
}

fn test_key() -> TestKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let public = Ed25519KeyPair::from_seed_unchecked(&seed)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let kid = Uuid::now_v7().to_string();
    TestKey {
        encoding_key: EncodingKey::from_ed_der(&[ED25519_PKCS8_PREFIX.as_slice(), &seed].concat()),
        jwk: serde_json::json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid, "x": URL_SAFE_NO_PAD.encode(public)}),
        kid,
    }
}

struct FakeBauth {
    issuer: String,
    fetches: Arc<AtomicUsize>,
}

/// Serves `/.well-known/jwks.json` on a random port and counts requests.
async fn fake_bauth(keys: Vec<serde_json::Value>) -> FakeBauth {
    let fetches = Arc::new(AtomicUsize::new(0));
    let jwks: JwkSet = serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap();
    let state = (Arc::new(jwks), fetches.clone());
    let app = Router::new()
        .route(
            "/.well-known/jwks.json",
            get(
                |State((jwks, fetches)): State<(Arc<JwkSet>, Arc<AtomicUsize>)>| async move {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    axum::Json((*jwks).clone())
                },
            ),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    FakeBauth { issuer, fetches }
}

fn token(key: &TestKey, issuer: &str, audience: &str, typ: &str, exp_offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = AccessTokenClaims {
        iss: issuer.to_owned(),
        sub: Uuid::now_v7(),
        aud: audience.to_owned(),
        client_id: "my-app-web".to_owned(),
        sid: Uuid::now_v7(),
        iat: now,
        exp: now + exp_offset,
        jti: Uuid::now_v7(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(key.kid.clone());
    header.typ = Some(typ.to_owned());
    encode(&header, &claims, &key.encoding_key).unwrap()
}

#[tokio::test]
async fn verifies_valid_token_and_caches_jwks() {
    let key = test_key();
    let bauth = fake_bauth(vec![key.jwk.clone()]).await;
    let verifier = Verifier::new(&bauth.issuer, "my-app");

    for _ in 0..3 {
        let user = verifier
            .verify(&token(&key, &bauth.issuer, "my-app", "at+jwt", 900))
            .await
            .unwrap();
        assert_eq!(user.client_id, "my-app-web");
        assert_eq!(user.id, user.claims.sub);
    }
    assert_eq!(
        bauth.fetches.load(Ordering::SeqCst),
        1,
        "JWKS should be fetched once"
    );
}

#[tokio::test]
async fn rejects_wrong_audience_issuer_type_or_expired() {
    let key = test_key();
    let bauth = fake_bauth(vec![key.jwk.clone()]).await;
    let verifier = Verifier::new(&bauth.issuer, "my-app");

    let cases = [
        (
            "wrong audience",
            token(&key, &bauth.issuer, "other-api", "at+jwt", 900),
        ),
        (
            "wrong issuer",
            token(&key, "https://evil.example", "my-app", "at+jwt", 900),
        ),
        (
            "not an access token",
            token(&key, &bauth.issuer, "my-app", "JWT", 900),
        ),
        (
            "expired",
            token(&key, &bauth.issuer, "my-app", "at+jwt", -120),
        ),
        ("garbage", "not.a.jwt".to_owned()),
    ];
    for (name, token) in cases {
        assert!(
            verifier.verify(&token).await.is_err(),
            "{name} should be rejected"
        );
    }
}

#[tokio::test]
async fn unknown_key_is_rejected_and_refetch_is_rate_limited() {
    let published = test_key();
    let unpublished = test_key();
    let bauth = fake_bauth(vec![published.jwk.clone()]).await;
    let verifier = Verifier::new(&bauth.issuer, "my-app");

    for _ in 0..5 {
        let result = verifier
            .verify(&token(&unpublished, &bauth.issuer, "my-app", "at+jwt", 900))
            .await;
        assert!(matches!(result, Err(VerifyError::UnknownKey)));
    }
    assert_eq!(
        bauth.fetches.load(Ordering::SeqCst),
        1,
        "unknown kids must not refetch on every request"
    );
}

#[tokio::test]
async fn unreachable_bauth_is_an_error_not_a_panic() {
    let key = test_key();
    let verifier = Verifier::new("http://127.0.0.1:9", "my-app");
    let result = verifier
        .verify(&token(&key, "http://127.0.0.1:9", "my-app", "at+jwt", 900))
        .await;
    assert!(matches!(result, Err(VerifyError::Jwks(_))));
}

#[cfg(feature = "axum")]
mod axum_extractor {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use axum::{Extension, Router};
    use bauth_client::AuthUser;
    use tower::ServiceExt;

    use super::*;

    async fn call(
        app: Router,
        path: &str,
        authorization: Option<String>,
    ) -> (StatusCode, Option<String>, String) {
        let mut request = Request::get(path);
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let www_authenticate = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_owned());
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            www_authenticate,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    fn app(verifier: Option<Verifier>) -> Router {
        let router = Router::new()
            .route(
                "/required",
                get(|user: AuthUser| async move { user.client_id }),
            )
            .route(
                "/optional",
                get(|user: Option<AuthUser>| async move {
                    user.map_or("anonymous".to_owned(), |u| u.client_id)
                }),
            );
        match verifier {
            Some(verifier) => router.layer(Extension(verifier)),
            None => router,
        }
    }

    #[tokio::test]
    async fn extracts_user_or_rejects_with_401() {
        let key = test_key();
        let bauth = fake_bauth(vec![key.jwk.clone()]).await;
        let app = app(Some(Verifier::new(&bauth.issuer, "my-app")));
        let valid = token(&key, &bauth.issuer, "my-app", "at+jwt", 900);

        let (status, _, body) =
            call(app.clone(), "/required", Some(format!("Bearer {valid}"))).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "my-app-web"));
        let (status, _, _) = call(app.clone(), "/required", Some(format!("bearer {valid}"))).await;
        assert_eq!(status, StatusCode::OK, "scheme is case-insensitive");

        let (status, www, body) = call(app.clone(), "/required", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www.as_deref(), Some("Bearer error=\"invalid_token\""));
        assert!(body.contains("\"code\":\"unauthorized\""), "{body}");

        let expired = token(&key, &bauth.issuer, "my-app", "at+jwt", -120);
        let (status, _, _) =
            call(app.clone(), "/required", Some(format!("Bearer {expired}"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _, _) = call(app.clone(), "/required", Some(format!("Basic {valid}"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn optional_user() {
        let key = test_key();
        let bauth = fake_bauth(vec![key.jwk.clone()]).await;
        let app = app(Some(Verifier::new(&bauth.issuer, "my-app")));

        let (status, _, body) = call(app.clone(), "/optional", None).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "anonymous"));
        let valid = token(&key, &bauth.issuer, "my-app", "at+jwt", 900);
        let (_, _, body) = call(app.clone(), "/optional", Some(format!("Bearer {valid}"))).await;
        assert_eq!(body, "my-app-web");
        let (status, _, _) = call(app, "/optional", Some("Bearer garbage".to_owned())).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a bad token is rejected, not ignored"
        );
    }

    #[tokio::test]
    async fn unreachable_bauth_is_503_and_missing_verifier_is_500() {
        let key = test_key();
        let valid = token(&key, "http://127.0.0.1:9", "my-app", "at+jwt", 900);
        let (status, _, body) = call(
            app(Some(Verifier::new("http://127.0.0.1:9", "my-app"))),
            "/required",
            Some(format!("Bearer {valid}")),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("auth_unavailable"), "{body}");

        let (status, _, _) = call(app(None), "/required", Some(format!("Bearer {valid}"))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
