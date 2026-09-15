use axum::http::StatusCode;
use bauth_core::AccessTokenClaims;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn password_login_issues_tokens_verifiable_with_the_jwks(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let tokens = app.login("alice@example.com", PASSWORD).await;

    // What an API does with bauth_client: verify against the published keys.
    let jwks: JwkSet =
        serde_json::from_value(app.get("/.well-known/jwks.json").send().await.body).unwrap();
    let kid = decode_header(&tokens.access).unwrap().kid.unwrap();
    let key = DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT_ID]);
    let claims = decode::<AccessTokenClaims>(&tokens.access, &key, &validation)
        .unwrap()
        .claims;

    let me = app.get("/me").bearer(&tokens.access).send().await;
    assert_eq!(me.body["id"], claims.sub.to_string());
    assert_eq!(me.body["email"], "alice@example.com");
    assert_eq!(claims.client_id, CLIENT_ID);
}

#[sqlx::test]
async fn authorization_code_is_bound_to_pkce_and_single_use(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let flow_id = app.start_flow().await;
    let code = app
        .submit_password(&flow_id, "alice@example.com", PASSWORD)
        .await
        .str("code");

    // A stolen code is useless without the verifier, and mistakes don't burn the code.
    let wrong_verifier = app.exchange(&code, &"x".repeat(43), REDIRECT_URI).await;
    assert_eq!(wrong_verifier.code(), "invalid_grant");
    let wrong_redirect = app
        .exchange(&code, CODE_VERIFIER, "http://localhost:8025/other")
        .await;
    assert_eq!(wrong_redirect.code(), "invalid_grant");

    let tokens = app.exchange(&code, CODE_VERIFIER, REDIRECT_URI).await;
    assert_eq!(tokens.status, StatusCode::OK);

    // Replaying the code means it leaked: the session it opened is revoked.
    assert_eq!(
        app.exchange(&code, CODE_VERIFIER, REDIRECT_URI)
            .await
            .code(),
        "invalid_grant"
    );
    assert_eq!(
        app.refresh(&tokens.str("refresh_token")).await.code(),
        "invalid_grant"
    );
}

#[sqlx::test]
async fn refresh_retry_after_a_lost_response_keeps_the_user_logged_in(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let first = app.login("alice@example.com", PASSWORD).await.refresh;

    let lost = app.refresh(&first).await.str("refresh_token");
    app.age_rotations().await;

    // The app never received `lost` and retries with the old token.
    let retried = app.refresh(&first).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.body);
    let next = app.refresh(&retried.str("refresh_token")).await;
    assert_eq!(next.status, StatusCode::OK);

    // If `lost` ever shows up, someone else had a copy: the whole session goes.
    assert_eq!(app.refresh(&lost).await.code(), "invalid_grant");
    assert_eq!(
        app.refresh(&next.str("refresh_token")).await.code(),
        "invalid_grant"
    );
}

#[sqlx::test]
async fn reusing_an_already_used_refresh_token_revokes_the_session(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let stolen = app.login("alice@example.com", PASSWORD).await.refresh;

    let legit = app.refresh(&stolen).await.str("refresh_token");
    let latest = app.refresh(&legit).await.str("refresh_token");
    app.age_rotations().await;

    assert_eq!(app.refresh(&stolen).await.code(), "invalid_grant");
    assert_eq!(
        app.refresh(&latest).await.code(),
        "invalid_grant",
        "legit copy is revoked too"
    );
}

#[sqlx::test]
async fn two_tabs_refreshing_at_once_both_keep_working(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let shared = app.login("alice@example.com", PASSWORD).await.refresh;

    let tab1 = app.refresh(&shared).await.str("refresh_token");
    let tab2 = app.refresh(&shared).await.str("refresh_token");

    assert_eq!(app.refresh(&tab1).await.status, StatusCode::OK);
    assert_eq!(app.refresh(&tab2).await.status, StatusCode::OK);
}

#[sqlx::test]
async fn logout_revokes_the_session(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let tokens = app.login("alice@example.com", PASSWORD).await;

    let revoke = app
        .post("/oauth/revoke")
        .form(&[("client_id", CLIENT_ID), ("token", &tokens.refresh)])
        .send()
        .await;
    assert_eq!(revoke.status, StatusCode::OK);

    assert_eq!(app.refresh(&tokens.refresh).await.code(), "invalid_grant");
    assert_eq!(
        app.get("/me").bearer(&tokens.access).send().await.status,
        StatusCode::UNAUTHORIZED
    );
}
