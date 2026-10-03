use axum::http::StatusCode;
use axum::http::header;
use serde_json::Value;
use serde_json::json;
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn revoked_sessions_are_locked_out_immediately(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;

    let no_token = app.get("/me").send().await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);
    assert!(no_token.headers.contains_key(header::WWW_AUTHENTICATE));

    let laptop = app.login("alice@example.com").await;
    let phone = app.login("alice@example.com").await;
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
async fn deleting_the_account_removes_everything(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    let tokens = app.login("alice@example.com").await;

    let code = app
        .confirmation_code(&tokens.access, "delete_account", "alice@example.com")
        .await;
    let delete = |code: String| {
        app.delete("/me")
            .bearer(&tokens.access)
            .json(json!({ "code": code }))
            .send()
    };
    let wrong = wrong_code(&code);
    assert_eq!(delete(wrong).await.code(), "invalid_code");
    assert_eq!(delete(code).await.status, StatusCode::NO_CONTENT);

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
    // The address is free again: logging in creates a new account.
    let again = app.login("alice@example.com").await;
    let me = app.get("/me").bearer(&again.access).send().await;
    assert_eq!(me.status, StatusCode::OK);
}

#[sqlx::test]
async fn sensitive_changes_are_confirmed_by_an_emailed_code(db: PgPool) {
    let app = TestApp::new(db).await;
    let tokens = app.login("carol@example.com").await;
    let change_email = |body: Value| {
        app.post("/me/email")
            .bearer(&tokens.access)
            .json(body)
            .send()
    };

    let nothing = change_email(json!({ "new_email": "carol@new.example.com" })).await;
    assert_eq!(nothing.code(), "invalid_request");
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
        .confirm_email_change(&app.last_token("carol@new.example.com"))
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
    let first = app.login("carol@example.com").await;
    let second = app.login("carol@example.com").await;

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
    let wrong = wrong_code(&code);
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

#[sqlx::test]
async fn a_rate_limited_email_change_keeps_the_confirmation_code(db: PgPool) {
    let app = TestApp::new(db).await;
    let tokens = app.login("carol@example.com").await;
    let code = app
        .confirmation_code(&tokens.access, "change_email", "carol@example.com")
        .await;

    // The new address has used up its email budget (5), here through sign-up emails.
    for emails in [3, 2] {
        let flow_id = app.start_flow().await;
        for _ in 0..emails {
            app.request_magic_link(&flow_id, "busy@example.com").await;
        }
    }
    let limited = app
        .post("/me/email")
        .bearer(&tokens.access)
        .json(json!({ "code": code, "new_email": "busy@example.com" }))
        .send()
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    // The code wasn't spent: it still works for another address.
    let changed = app
        .post("/me/email")
        .bearer(&tokens.access)
        .json(json!({ "code": code, "new_email": "carol@new.example.com" }))
        .send()
        .await;
    assert_eq!(changed.status, StatusCode::ACCEPTED, "{}", changed.body);
}
