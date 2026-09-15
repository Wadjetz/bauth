use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn password_login_requires_a_verified_email(db: PgPool) {
    let app = TestApp::new(db).await;
    assert_eq!(
        app.register("alice@example.com").await.status,
        StatusCode::ACCEPTED
    );

    let flow_id = app.start_flow().await;
    let login = app
        .submit_password(&flow_id, "alice@example.com", PASSWORD)
        .await;
    assert_eq!(login.code(), "email_not_verified");

    // Lost the first email: ask for another one.
    let resend = app
        .post("/verification")
        .json(json!({ "email": "alice@example.com" }))
        .send()
        .await;
    assert_eq!(resend.status, StatusCode::ACCEPTED);
    assert_eq!(app.emails_to("alice@example.com").len(), 2);

    let token = app.last_token("alice@example.com");
    assert_eq!(
        app.confirm_verification(&token).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.confirm_verification(&token).await.code(),
        "invalid_token",
        "links are single use"
    );

    let login = app
        .submit_password(&flow_id, "alice@example.com", PASSWORD)
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
}

#[sqlx::test]
async fn registration_and_recovery_do_not_reveal_which_accounts_exist(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;

    let new_account = app.register("bob@example.com").await;
    let existing = app.register(" Alice@Example.com").await;
    assert_eq!(
        (existing.status, &existing.body),
        (new_account.status, &new_account.body)
    );
    // Only the real owner learns that someone tried.
    let warning = app.emails_to("alice@example.com").pop().unwrap();
    assert!(warning.subject.contains("Tentative"), "{}", warning.subject);

    let unknown = app
        .post("/recovery")
        .json(json!({ "client_id": CLIENT_ID, "email": "nobody@example.com" }))
        .send()
        .await;
    let known = app
        .post("/recovery")
        .json(json!({ "client_id": CLIENT_ID, "email": "alice@example.com" }))
        .send()
        .await;
    assert_eq!((unknown.status, &unknown.body), (known.status, &known.body));
    assert!(app.emails_to("nobody@example.com").is_empty());

    let closed = app
        .post("/registration")
        .json(json!({ "client_id": "closed", "email": "carol@example.com", "password": PASSWORD }))
        .send()
        .await;
    assert_eq!(closed.code(), "signup_disabled");
}

#[sqlx::test]
async fn password_reset_logs_out_everywhere(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let before = app.login("alice@example.com", PASSWORD).await;

    app.post("/recovery")
        .json(json!({ "client_id": CLIENT_ID, "email": "alice@example.com" }))
        .send()
        .await;
    let reset = app
        .post("/recovery/reset")
        .json(json!({ "token": app.last_token("alice@example.com"), "password": "a brand new password" }))
        .send()
        .await;
    assert_eq!(reset.status, StatusCode::NO_CONTENT);

    assert_eq!(app.refresh(&before.refresh).await.code(), "invalid_grant");
    let flow_id = app.start_flow().await;
    assert_eq!(
        app.submit_password(&flow_id, "alice@example.com", PASSWORD)
            .await
            .code(),
        "invalid_credentials"
    );
    app.login("alice@example.com", "a brand new password").await;
    let notice = app.emails_to("alice@example.com").pop().unwrap();
    assert!(notice.subject.contains("modifié"), "{}", notice.subject);
}

#[sqlx::test]
async fn magic_link_logs_in_and_verifies_the_email(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register("alice@example.com").await;
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

/// Any code but `code`.
fn wrong_code(code: &str) -> String {
    format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000)
}

#[sqlx::test]
async fn magic_code_logs_in_on_the_device_that_asked(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register("alice@example.com").await;
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
    app.register_verified("alice@example.com").await;
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
    app.register_verified("alice@example.com").await;
    app.register_verified("bob@example.com").await;

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
    app.register_verified("alice@example.com").await;
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
        "no verification email"
    );

    // Next time it is a login to the same account, and there is no password to guess.
    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "carol@example.com").await;
    let email = app.emails_to("carol@example.com").pop().unwrap();
    assert!(!email.subject.contains("Crée"), "{}", email.subject);
    let again = app
        .submit_magic_code(&flow_id, &app.last_magic_code("carol@example.com"))
        .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(count_users().await, 1);
    let password = app
        .submit_password(&app.start_flow().await, "carol@example.com", PASSWORD)
        .await;
    assert_eq!(password.code(), "invalid_credentials");
}

#[sqlx::test]
async fn sign_up_link_joins_an_account_registered_meanwhile(db: PgPool) {
    let app = TestApp::new(db).await;
    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "dave@example.com").await;
    let token = app.last_token("dave@example.com");
    // Someone registers the address with their own password before the owner uses the link.
    app.register("dave@example.com").await;

    let login = app
        .post("/magic-link/confirm")
        .json(json!({ "token": token }))
        .send()
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
    let squatter = app
        .submit_password(&app.start_flow().await, "dave@example.com", PASSWORD)
        .await;
    assert_eq!(squatter.code(), "invalid_credentials");
    let notice = app.emails_to("dave@example.com").pop().unwrap();
    assert!(
        notice.subject.contains("mot de passe"),
        "{}",
        notice.subject
    );
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
async fn email_login_on_an_unverified_account_drops_the_password_chosen_before(db: PgPool) {
    let app = TestApp::new(db).await;
    // Someone registers the victim's address with a password of their own; it stays unverified.
    app.register("victim@example.com").await;

    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "victim@example.com").await;
    let login = app
        .post("/magic-link/confirm")
        .json(json!({ "token": app.last_token("victim@example.com") }))
        .send()
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);

    let flow_id = app.start_flow().await;
    let squatter = app
        .submit_password(&flow_id, "victim@example.com", PASSWORD)
        .await;
    assert_eq!(squatter.code(), "invalid_credentials");
    let notice = app.emails_to("victim@example.com").pop().unwrap();
    assert!(
        notice.subject.contains("mot de passe"),
        "{}",
        notice.subject
    );

    // A verified account keeps its password, whichever email login is used.
    app.register_verified("alice@example.com").await;
    let flow_id = app.start_flow().await;
    app.request_magic_link(&flow_id, "alice@example.com").await;
    let code = app.last_magic_code("alice@example.com");
    let login = app.submit_magic_code(&flow_id, &code).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
    app.login("alice@example.com", PASSWORD).await;
    assert_eq!(app.emails_to("alice@example.com").len(), 2, "no notice");
}

#[sqlx::test]
async fn links_sent_to_a_previous_address_stop_working(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    let tokens = app.login("alice@example.com", PASSWORD).await;

    app.post("/recovery")
        .json(json!({ "client_id": CLIENT_ID, "email": "alice@example.com" }))
        .send()
        .await;
    let old_reset_token = app.last_token("alice@example.com");

    let change = app
        .post("/me/email")
        .bearer(&tokens.access)
        .json(json!({ "password": PASSWORD, "new_email": "alice@new.example.com" }))
        .send()
        .await;
    assert_eq!(change.status, StatusCode::ACCEPTED);
    let confirm = app
        .confirm_verification(&app.last_token("alice@new.example.com"))
        .await;
    assert_eq!(confirm.status, StatusCode::NO_CONTENT);

    let reset = app
        .post("/recovery/reset")
        .json(json!({ "token": old_reset_token, "password": "a brand new password" }))
        .send()
        .await;
    assert_eq!(reset.code(), "invalid_token");
    let notice = app.emails_to("alice@example.com").pop().unwrap();
    assert!(
        notice.text.contains("alice@new.example.com"),
        "old address is told where the account moved"
    );
}
