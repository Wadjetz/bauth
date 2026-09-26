//! `Verifier`, `Verifier::me` and the axum extractor, against `testing::FakeBauth`.

use axum::routing::get;
use bauth_client::MeError;
use bauth_client::Verifier;
use bauth_client::VerifyError;
use bauth_client::testing::FakeBauth;
use uuid::Uuid;

#[tokio::test]
async fn verifies_valid_token_and_caches_jwks() {
    let bauth = FakeBauth::start();
    let verifier = bauth.verifier("my-app");
    let user_id = Uuid::now_v7();

    for _ in 0..3 {
        let token = bauth.access_token(user_id, "my-app");
        let user = verifier.verify(&token).await.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.client_id, "test-client");
        assert_eq!(user.access_token(), token, "the raw token is kept");
    }
    assert_eq!(bauth.jwks_fetches(), 1, "JWKS should be fetched once");
}

#[tokio::test]
async fn the_token_never_shows_in_debug_output() {
    let bauth = FakeBauth::start();
    let token = bauth.access_token(Uuid::now_v7(), "my-app");
    let user = bauth.verifier("my-app").verify(&token).await.unwrap();
    let debug = format!("{user:?}");
    assert!(!debug.contains(&token), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

#[tokio::test]
async fn rejects_wrong_audience_issuer_type_or_expired() {
    let bauth = FakeBauth::start();
    let verifier = bauth.verifier("my-app");
    let claims = bauth.claims(Uuid::now_v7(), "my-app");

    let cases = [
        (
            "wrong audience",
            bauth.access_token(Uuid::now_v7(), "other-api"),
        ),
        (
            "wrong issuer",
            bauth.sign(&bauth_client::AccessTokenClaims {
                iss: "https://evil.example".into(),
                ..claims.clone()
            }),
        ),
        ("not an access token", bauth.sign_with_type(&claims, "JWT")),
        (
            "expired",
            bauth.sign(&bauth_client::AccessTokenClaims {
                exp: claims.iat - 120,
                ..claims.clone()
            }),
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
    let bauth = FakeBauth::start();
    // Same issuer and audience, but signed by a key bauth never published.
    let other_key = FakeBauth::start();
    let verifier = bauth.verifier("my-app");
    let token = other_key.sign(&bauth.claims(Uuid::now_v7(), "my-app"));

    for _ in 0..5 {
        let result = verifier.verify(&token).await;
        assert!(matches!(result, Err(VerifyError::UnknownKey)));
    }
    assert_eq!(
        bauth.jwks_fetches(),
        1,
        "unknown kids must not refetch on every request"
    );
}

#[tokio::test]
async fn unreachable_bauth_is_an_error_not_a_panic() {
    let bauth = FakeBauth::start();
    let unreachable = "http://127.0.0.1:9";
    let token = bauth.sign(&bauth_client::AccessTokenClaims {
        iss: unreachable.into(),
        ..bauth.claims(Uuid::now_v7(), "my-app")
    });
    let verifier = Verifier::new(unreachable, "my-app");
    assert!(matches!(
        verifier.verify(&token).await,
        Err(VerifyError::Jwks(_))
    ));
    assert!(matches!(
        verifier.me(&token).await,
        Err(MeError::Unavailable(_))
    ));
}

#[tokio::test]
async fn me_answers_the_account_of_the_token() {
    let bauth = FakeBauth::start();
    let verifier = bauth.verifier("my-app");
    let user_id = Uuid::now_v7();
    let token = bauth.access_token(user_id, "my-app");

    assert!(matches!(
        verifier.me(&token).await,
        Err(MeError::Unauthorized)
    ));
    bauth.set_account(user_id, "alice@example.com", true);
    let me = verifier.me(&token).await.unwrap();
    assert_eq!(
        (me.id, me.email.as_str(), me.email_verified),
        (user_id, "alice@example.com", true)
    );
}

mod axum_extractor {
    use axum::Extension;
    use axum::Router;
    use axum::body::Body;
    use axum::body::to_bytes;
    use axum::http::HeaderMap;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::http::header;
    use bauth_client::AuthUser;
    use bauth_client::bearer_token;
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
            )
            .route(
                "/email",
                get(
                    |Extension(verifier): Extension<Verifier>, user: AuthUser| async move {
                        verifier.me(user.access_token()).await.map(|me| me.email)
                    },
                ),
            );
        match verifier {
            Some(verifier) => router.layer(Extension(verifier)),
            None => router,
        }
    }

    #[tokio::test]
    async fn extracts_user_or_rejects_with_401() {
        let bauth = FakeBauth::start();
        let app = app(Some(bauth.verifier("my-app")));
        let valid = bauth.access_token(Uuid::now_v7(), "my-app");

        let (status, _, body) =
            call(app.clone(), "/required", Some(format!("Bearer {valid}"))).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "test-client"));
        let (status, _, _) = call(app.clone(), "/required", Some(format!("bearer {valid}"))).await;
        assert_eq!(status, StatusCode::OK, "scheme is case-insensitive");

        let (status, www, body) = call(app.clone(), "/required", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www.as_deref(), Some("Bearer error=\"invalid_token\""));
        assert!(body.contains("\"code\":\"unauthorized\""), "{body}");

        let (status, _, _) = call(app.clone(), "/required", Some(format!("Basic {valid}"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn optional_user() {
        let bauth = FakeBauth::start();
        let app = app(Some(bauth.verifier("my-app")));

        let (status, _, body) = call(app.clone(), "/optional", None).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "anonymous"));
        let valid = bauth.access_token(Uuid::now_v7(), "my-app");
        let (_, _, body) = call(app.clone(), "/optional", Some(format!("Bearer {valid}"))).await;
        assert_eq!(body, "test-client");
        let (status, _, _) = call(app, "/optional", Some("Bearer garbage".to_owned())).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a bad token is rejected, not ignored"
        );
    }

    #[tokio::test]
    async fn me_from_a_handler_and_its_errors_as_responses() {
        let bauth = FakeBauth::start();
        let app = app(Some(bauth.verifier("my-app")));
        let user_id = Uuid::now_v7();
        let token = format!("Bearer {}", bauth.access_token(user_id, "my-app"));

        // bauth doesn't know the session any more: 401, so the client refreshes.
        let (status, www, body) = call(app.clone(), "/email", Some(token.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(www.is_some());
        assert!(body.contains("\"code\":\"unauthorized\""), "{body}");

        bauth.set_account(user_id, "alice@example.com", false);
        let (status, _, body) = call(app, "/email", Some(token)).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "alice@example.com")
        );
    }

    #[tokio::test]
    async fn unreachable_bauth_is_503_and_missing_verifier_is_500() {
        let bauth = FakeBauth::start();
        let unreachable = "http://127.0.0.1:9";
        let valid = bauth.sign(&bauth_client::AccessTokenClaims {
            iss: unreachable.into(),
            ..bauth.claims(Uuid::now_v7(), "my-app")
        });
        let (status, _, body) = call(
            app(Some(Verifier::new(unreachable, "my-app"))),
            "/required",
            Some(format!("Bearer {valid}")),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("auth_unavailable"), "{body}");

        let (status, _, _) = call(app(None), "/required", Some(format!("Bearer {valid}"))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn bearer_token_reads_the_authorization_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "BEARER  abc ".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }
}
