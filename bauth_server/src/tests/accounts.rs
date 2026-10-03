use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn magic_link_logs_in_and_verifies_the_email(db: PgPool) {
    let app = TestApp::new(db).await;
    // An account whose address was never verified (imported, for instance).
    app.sql("INSERT INTO bauth.users (email) VALUES ('alice@example.com')")
        .await;
    let flow_id = app.start_flow().await;

    app.post(&format!("/flows/login/{flow_id}/magic-link"))
        .json(json!({ "email": "alice@example.com" }))
        .send()
        .await;
    let token = app.last_token("alice@example.com");
    let confirm = app
        .post("/magic-link/confirm")
        .json(json!({ "token": token }))
        .send()
        .await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.body);

    let tokens = app
        .exchange(&confirm.str("code"), CODE_VERIFIER, REDIRECT_URI)
        .await;
    let me = app
        .get("/me")
        .bearer(&tokens.str("access_token"))
        .send()
        .await;
    assert_eq!(me.body["email_verified"], true);
    let again = app
        .post("/magic-link/confirm")
        .json(json!({ "token": token }))
        .send()
        .await;
    assert_eq!(again.code(), "invalid_token");
}

#[sqlx::test]
async fn magic_code_logs_in_on_the_device_that_asked(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    let flow_id = app.start_flow().await;

    app.request_magic_link(&flow_id, "alice@example.com").await;
    let code = app.last_magic_code("alice@example.com");
    let token = app.last_token("alice@example.com");
    // Bound to its flow: the same code on another flow is refused.
    let other_flow = app.start_flow().await;
    assert_eq!(
        app.submit_magic_code(&other_flow, &code).await.code(),
        "invalid_code"
    );

    let login = app.submit_magic_code(&flow_id, &code).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
    let tokens = app
        .exchange(&login.str("code"), CODE_VERIFIER, REDIRECT_URI)
        .await;
    let me = app
        .get("/me")
        .bearer(&tokens.str("access_token"))
        .send()
        .await;
    assert_eq!(me.body["email_verified"], true);

    // The code and the link are one: using either consumes both.
    assert_eq!(
        app.submit_magic_code(&flow_id, &code).await.code(),
        "invalid_code"
    );
    let link = app
        .post("/magic-link/confirm")
        .json(json!({ "token": token }))
        .send()
        .await;
    assert_eq!(link.code(), "invalid_token");
}

#[sqlx::test]
async fn magic_code_allows_few_attempts_on_the_newest_email_only(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    let flow_id = app.start_flow().await;

    app.request_magic_link(&flow_id, "alice@example.com").await;
    let old_code = app.last_magic_code("alice@example.com");
    app.request_magic_link(&flow_id, "alice@example.com").await;
    let code = app.last_magic_code("alice@example.com");
    let mut attempts = 0;
    if old_code != code {
        let old = app.submit_magic_code(&flow_id, &old_code).await;
        assert_eq!(
            old.code(),
            "invalid_code",
            "a new email disables older codes"
        );
        attempts += 1;
    }

    for _ in attempts..5 {
        let attempt = app.submit_magic_code(&flow_id, &wrong_code(&code)).await;
        assert_eq!(attempt.code(), "invalid_code");
    }
    let right = app.submit_magic_code(&flow_id, &code).await;
    assert_eq!(
        right.code(),
        "invalid_code",
        "too late: the email is consumed"
    );
    let link = app
        .post("/magic-link/confirm")
        .json(json!({ "token": app.last_token("alice@example.com") }))
        .send()
        .await;
    assert_eq!(link.code(), "invalid_token");

    // A new email brings new attempts.
    app.request_magic_link(&flow_id, "alice@example.com").await;
    let login = app
        .submit_magic_code(&flow_id, &app.last_magic_code("alice@example.com"))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
}

#[sqlx::test]
async fn magic_code_failures_are_capped_per_account_across_flows(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    app.create_account("bob@example.com").await;

    // Two flows, two emails, 5 wrong codes each: the account's daily budget is spent.
    for _ in 0..2 {
        let flow_id = app.start_flow().await;
        app.request_magic_link(&flow_id, "alice@example.com").await;
        let code = app.last_magic_code("alice@example.com");
        for _ in 0..5 {
            let attempt = app.submit_magic_code(&flow_id, &wrong_code(&code)).await;
            assert_eq!(attempt.code(), "invalid_code");
        }
    }

    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "alice@example.com").await;
    let right = app
        .submit_magic_code(&flow_id, &app.last_magic_code("alice@example.com"))
        .await;
    assert_eq!(
        right.code(),
        "invalid_code",
        "codes are off for this account"
    );
    let link = app
        .post("/magic-link/confirm")
        .json(json!({ "token": app.last_token("alice@example.com") }))
        .send()
        .await;
    assert_eq!(link.status, StatusCode::OK, "the link still works");

    let bob_flow = app.start_flow().await;
    app.request_magic_link(&bob_flow, "bob@example.com").await;
    let bob = app
        .submit_magic_code(&bob_flow, &app.last_magic_code("bob@example.com"))
        .await;
    assert_eq!(
        bob.status,
        StatusCode::OK,
        "other accounts are not affected"
    );
}

#[sqlx::test]
async fn concurrent_magic_codes_cannot_exceed_the_account_budget(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    let mut flows = Vec::new();
    for _ in 0..3 {
        let flow_id = app.start_flow().await;
        app.request_magic_link(&flow_id, "alice@example.com").await;
        flows.push((
            flow_id,
            wrong_code(&app.last_magic_code("alice@example.com")),
        ));
    }

    // 15 wrong codes at once, 5 per email, interleaved across emails: only 10 may be counted.
    let app = Arc::new(app);
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..5 {
        for (flow_id, code) in flows.clone() {
            let app = app.clone();
            requests.spawn(async move { app.submit_magic_code(&flow_id, &code).await.status });
        }
    }
    while let Some(status) = requests.join_next().await {
        assert_eq!(status.unwrap(), StatusCode::BAD_REQUEST);
    }

    let failures: i64 =
        sqlx::query_scalar("SELECT sum(code_failures)::bigint FROM bauth.magic_links")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(failures, 10);
}

#[sqlx::test]
async fn email_login_signs_up_an_unknown_address_with_a_single_email(db: PgPool) {
    let app = TestApp::new(db).await;
    let flow_id = app.start_flow().await;
    let sent = app.request_magic_link(&flow_id, " Carol@Example.com").await;
    assert_eq!(sent.status, StatusCode::ACCEPTED);
    let emails = app.emails_to("carol@example.com");
    assert_eq!(emails.len(), 1, "one email, to the normalized address");
    assert!(emails[0].subject.contains("Crée"), "{}", emails[0].subject);
    let count_users = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM bauth.users")
            .fetch_one(&app.db)
            .await
            .unwrap()
    };
    assert_eq!(
        count_users().await,
        0,
        "nothing exists before the code is used"
    );

    let login = app
        .submit_magic_code(&flow_id, &app.last_magic_code("carol@example.com"))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
    let tokens = app
        .exchange(&login.str("code"), CODE_VERIFIER, REDIRECT_URI)
        .await;
    let me = app
        .get("/me")
        .bearer(&tokens.str("access_token"))
        .send()
        .await;
    assert_eq!(me.body["email"], "carol@example.com");
    assert_eq!(me.body["email_verified"], true);
    assert_eq!(
        app.emails_to("carol@example.com").len(),
        1,
        "one email for the whole sign-up"
    );

    // Next time it is a login to the same account.
    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "carol@example.com").await;
    let email = app.emails_to("carol@example.com").pop().unwrap();
    assert!(!email.subject.contains("Crée"), "{}", email.subject);
    let again = app
        .submit_magic_code(&flow_id, &app.last_magic_code("carol@example.com"))
        .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(count_users().await, 1);
}

#[sqlx::test]
async fn magic_code_answers_the_same_without_account_or_email(db: PgPool) {
    let app = TestApp::new(db).await;
    // A client without sign-up: no email goes to an unknown address.
    let flow_id = app
        .start_flow_for("closed", "https://closed.example.com/callback")
        .await;
    assert_eq!(
        app.submit_magic_code(&flow_id, "123456").await.code(),
        "invalid_code"
    );
    let unknown = app.request_magic_link(&flow_id, "nobody@example.com").await;
    assert_eq!(unknown.status, StatusCode::ACCEPTED);
    assert!(app.emails_to("nobody@example.com").is_empty());
    assert_eq!(
        app.submit_magic_code(&flow_id, "123456").await.code(),
        "invalid_code"
    );
    let unknown_flow = app
        .submit_magic_code("0199a6b0-0000-7000-8000-000000000000", "123456")
        .await;
    assert_eq!(unknown_flow.code(), "invalid_code");
    assert_eq!(
        app.submit_magic_code(&flow_id, "12 34 56").await.code(),
        "invalid_request"
    );
}

#[sqlx::test]
async fn a_magic_link_email_keeps_its_flow_alive_as_long_as_itself(db: PgPool) {
    let app = TestApp::new(db).await;
    let flow_id = app.start_flow().await;
    let flow_uuid: uuid::Uuid = flow_id.parse().unwrap();
    // Asked for at the end of the flow's life: the email still says 15 minutes.
    sqlx::query(
        "UPDATE bauth.login_flows SET expires_at = now() + interval '1 minute' WHERE id = $1",
    )
    .bind(flow_uuid)
    .execute(&app.db)
    .await
    .unwrap();
    let sent = app.request_magic_link(&flow_id, "carol@example.com").await;

    let (flow_expires, link_expires, long_enough): (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        bool,
    ) = sqlx::query_as(
        "SELECT f.expires_at, l.expires_at, f.expires_at > now() + interval '14 minutes'
             FROM bauth.login_flows f JOIN bauth.magic_links l ON l.flow_id = f.id WHERE f.id = $1",
    )
    .bind(flow_uuid)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        flow_expires, link_expires,
        "the flow lives exactly as long as the email"
    );
    // The app learns the new expiry, to keep continuing this flow rather than start another.
    let announced: chrono::DateTime<chrono::Utc> = sent.str("expires_at").parse().unwrap();
    assert_eq!(announced, flow_expires);
    assert!(long_enough);

    // Never shortened: a flow that outlives the email keeps its expiry.
    sqlx::query(
        "UPDATE bauth.login_flows SET expires_at = now() + interval '1 hour' WHERE id = $1",
    )
    .bind(flow_uuid)
    .execute(&app.db)
    .await
    .unwrap();
    app.request_magic_link(&flow_id, "carol@example.com").await;
    let still_an_hour: bool = sqlx::query_scalar(
        "SELECT expires_at > now() + interval '59 minutes' FROM bauth.login_flows WHERE id = $1",
    )
    .bind(flow_uuid)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(still_an_hour);

    let login = app
        .submit_magic_code(&flow_id, &app.last_magic_code("carol@example.com"))
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
}

#[sqlx::test]
async fn an_email_change_moves_the_account_and_stales_old_links(db: PgPool) {
    let app = TestApp::new(db).await;
    app.create_account("alice@example.com").await;
    let tokens = app.login("alice@example.com").await;
    // A magic link sent to the old address before the change.
    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "alice@example.com").await;
    let old_link = app.last_token("alice@example.com");

    let code = app
        .confirmation_code(&tokens.access, "change_email", "alice@example.com")
        .await;
    let change = app
        .post("/me/email")
        .bearer(&tokens.access)
        .json(json!({ "code": code, "new_email": "alice@new.example.com" }))
        .send()
        .await;
    assert_eq!(change.status, StatusCode::ACCEPTED, "{}", change.body);
    // The confirmation link opens the `email_change_url` of the client the session belongs to.
    let link = app.emails_to("alice@new.example.com").pop().unwrap();
    assert!(
        link.text
            .contains("http://localhost:8025/auth/email-change#token="),
        "{}",
        link.text
    );
    let confirm = app
        .confirm_email_change(&app.last_token("alice@new.example.com"))
        .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT);

    let me = app.get("/me").bearer(&tokens.access).send().await;
    assert_eq!(me.str("email"), "alice@new.example.com");
    let stale = app
        .post("/magic-link/confirm")
        .json(json!({ "token": old_link }))
        .send()
        .await;
    assert_eq!(
        stale.code(),
        "invalid_token",
        "sent to an address the account left"
    );
    let notice = app.emails_to("alice@example.com").pop().unwrap();
    assert!(
        notice.text.contains("alice@new.example.com"),
        "old address is told where the account moved"
    );
}
