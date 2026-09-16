use axum::http::StatusCode;
use axum::http::header;
use serde_json::Value;
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

#[sqlx::test]
async fn an_account_without_password_confirms_sensitive_changes_with_a_code(db: PgPool) {
    let app = TestApp::new(db).await;
    let tokens = app.login_with_code("carol@example.com").await;
    let change_email = |body: Value| {
        app.post("/me/email")
            .bearer(&tokens.access)
            .json(body)
            .send()
    };

    let nothing = change_email(json!({ "new_email": "carol@new.example.com" })).await;
    assert_eq!(nothing.code(), "invalid_request");
    let password =
        change_email(json!({ "password": PASSWORD, "new_email": "carol@new.example.com" })).await;
    assert_eq!(password.code(), "password_not_set");
    let no_code =
        change_email(json!({ "code": "123456", "new_email": "carol@new.example.com" })).await;
    assert_eq!(no_code.code(), "invalid_code", "no code was asked for");

    let code = app
        .confirmation_code(&tokens.access, "change_email", "carol@example.com")
        .await;
    // A code is good for one action only.
    let wrong_action = app
        .delete("/me")
        .bearer(&tokens.access)
        .json(json!({ "code": code }))
        .send()
        .await;
    assert_eq!(wrong_action.code(), "invalid_code");

    let changed = change_email(json!({ "code": code, "new_email": "carol@new.example.com" })).await;
    assert_eq!(changed.status, StatusCode::ACCEPTED, "{}", changed.body);
    let confirm = app
        .confirm_verification(&app.last_token("carol@new.example.com"))
        .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT);
    let reused =
        change_email(json!({ "code": code, "new_email": "carol@other.example.com" })).await;
    assert_eq!(reused.code(), "invalid_code", "codes are single use");

    let code = app
        .confirmation_code(&tokens.access, "delete_account", "carol@new.example.com")
        .await;
    let deleted = app
        .delete("/me")
        .bearer(&tokens.access)
        .json(json!({ "code": code }))
        .send()
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
    let me = app.get("/me").bearer(&tokens.access).send().await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn confirmation_codes_are_bound_to_their_session_and_limited(db: PgPool) {
    let app = TestApp::new(db).await;
    let first = app.login_with_code("carol@example.com").await;
    let second = app.login_with_code("carol@example.com").await;

    let code = app
        .confirmation_code(&first.access, "delete_account", "carol@example.com")
        .await;
    let other_session = app
        .delete("/me")
        .bearer(&second.access)
        .json(json!({ "code": code }))
        .send()
        .await;
    assert_eq!(other_session.code(), "invalid_code");

    // Five wrong codes consume the confirmation, even the right one afterwards.
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    for _ in 0..5 {
        let attempt = app
            .delete("/me")
            .bearer(&first.access)
            .json(json!({ "code": wrong }))
            .send()
            .await;
        assert_eq!(attempt.code(), "invalid_code");
    }
    let too_late = app
        .delete("/me")
        .bearer(&first.access)
        .json(json!({ "code": code }))
        .send()
        .await;
    assert_eq!(too_late.code(), "invalid_code");
}
