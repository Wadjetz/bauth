use axum::http::StatusCode;
use jsonwebtoken::decode_header;
use sqlx::PgPool;

use super::*;
use crate::jobs::purge;

fn kid(token: &str) -> String {
    decode_header(token).unwrap().kid.unwrap()
}

async fn published_kids(app: &TestApp) -> Vec<String> {
    let jwks = app.get("/.well-known/jwks.json").send().await.body;
    let mut kids: Vec<String> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["kid"].as_str().unwrap().to_owned())
        .collect();
    kids.sort();
    kids
}

fn sorted(mut kids: Vec<String>) -> Vec<String> {
    kids.sort();
    kids
}

#[sqlx::test]
async fn rotation_publishes_first_hands_over_then_unpublishes(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let old_token = app.login("alice@example.com", PASSWORD).await.access;
    let old_kid = kid(&old_token);

    let rotate = || signing_keys::rotate_if_due(&app.db, &app.master_key);
    assert_eq!(rotate().await.unwrap(), None, "the key is fresh");
    app.sql("UPDATE bauth.signing_keys SET active_at = now() - interval '31 days'")
        .await;
    let new_kid = rotate()
        .await
        .unwrap()
        .expect("rotation is due")
        .to_string();
    assert_eq!(rotate().await.unwrap(), None, "a key is already pending");

    // Day 0: the new key is published but doesn't sign yet.
    app.reload_keys().await;
    assert_eq!(
        published_kids(&app).await,
        sorted(vec![old_kid.clone(), new_kid.clone()])
    );
    assert_eq!(
        kid(&app.login("alice@example.com", PASSWORD).await.access),
        old_kid
    );

    // Day 1: handover. Tokens signed by the old key remain valid.
    app.sql("UPDATE bauth.signing_keys SET active_at = now() - interval '1 second' WHERE active_at > now()").await;
    app.sql("UPDATE bauth.signing_keys SET retired_at = now() - interval '1 second' WHERE retired_at IS NOT NULL").await;
    app.reload_keys().await;
    let new_token = app.login("alice@example.com", PASSWORD).await.access;
    assert_eq!(kid(&new_token), new_kid);
    assert_eq!(
        app.get("/me").bearer(&old_token).send().await.status,
        StatusCode::OK
    );

    // Day 2: the old key leaves the JWKS; its tokens (long expired in real life) stop verifying.
    app.sql("UPDATE bauth.signing_keys SET retired_at = now() - interval '25 hours' WHERE retired_at IS NOT NULL").await;
    app.reload_keys().await;
    assert_eq!(published_kids(&app).await, vec![new_kid]);
    assert_eq!(
        app.get("/me").bearer(&old_token).send().await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get("/me").bearer(&new_token).send().await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn retiring_every_key_by_hand_creates_a_new_one_and_purge_drops_old_keys(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let compromised = kid(&app.login("alice@example.com", PASSWORD).await.access);

    // Emergency: the key leaked. Retire it long enough ago that it leaves the JWKS at once.
    app.sql("UPDATE bauth.signing_keys SET retired_at = now() - interval '31 days'")
        .await;
    app.reload_keys().await;
    let replacement = kid(&app.login("alice@example.com", PASSWORD).await.access);
    assert_ne!(replacement, compromised);
    assert_eq!(published_kids(&app).await, vec![replacement]);

    let report = purge::run(&app.db).await.unwrap().unwrap();
    assert_eq!(report.signing_keys, 1);
}
