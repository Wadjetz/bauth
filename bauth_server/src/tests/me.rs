use axum::http::StatusCode;
use axum::http::header;
use serde_json::json;
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn revoked_sessions_are_locked_out_immediately(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;

    let no_token = app.get("/me").send().await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);
    assert!(no_token.headers.contains_key(header::WWW_AUTHENTICATE));

    let laptop = app.login("alice@example.com", PASSWORD).await;
    let phone = app.login("alice@example.com", PASSWORD).await;
    let sessions = app
        .get("/me/sessions")
        .bearer(&laptop.access)
        .send()
        .await
        .body;
    let sessions = sessions.as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    let phone_session = sessions.iter().find(|s| s["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let revoke = app
        .delete(&format!("/me/sessions/{phone_session}"))
        .bearer(&laptop.access)
        .send()
        .await;
    assert_eq!(revoke.status, StatusCode::NO_CONTENT);

    // No need to wait for the 15-minute access token to expire.
    assert_eq!(
        app.get("/me").bearer(&phone.access).send().await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get("/me").bearer(&laptop.access).send().await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn changing_password_keeps_only_the_current_session(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let laptop = app.login("alice@example.com", PASSWORD).await;
    let phone = app.login("alice@example.com", PASSWORD).await;

    let change = |current: &'static str| {
        app.post("/me/password")
            .bearer(&laptop.access)
            .json(json!({ "current_password": current, "new_password": "a brand new password" }))
            .send()
    };
    assert_eq!(
        change("not my password").await.code(),
        "invalid_credentials"
    );
    assert_eq!(change(PASSWORD).await.status, StatusCode::NO_CONTENT);

    assert_eq!(
        app.get("/me").bearer(&laptop.access).send().await.status,
        StatusCode::OK
    );
    assert_eq!(
        app.get("/me").bearer(&phone.access).send().await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(app.refresh(&phone.refresh).await.code(), "invalid_grant");
}

#[sqlx::test]
async fn deleting_the_account_removes_everything(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let tokens = app.login("alice@example.com", PASSWORD).await;

    let delete = |password: &'static str| {
        app.delete("/me")
            .bearer(&tokens.access)
            .json(json!({ "password": password }))
            .send()
    };
    assert_eq!(
        delete("not my password").await.code(),
        "invalid_credentials"
    );
    assert_eq!(delete(PASSWORD).await.status, StatusCode::NO_CONTENT);

    assert_eq!(
        app.get("/me").bearer(&tokens.access).send().await.status,
        StatusCode::UNAUTHORIZED
    );
    let (users, sessions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM bauth.users), (SELECT count(*) FROM bauth.sessions)",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!((users, sessions), (0, 0));
    // The address is free again.
    assert_eq!(
        app.register("alice@example.com").await.status,
        StatusCode::ACCEPTED
    );
}
