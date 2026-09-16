use axum::http::StatusCode;
use axum::http::header;
use serde_json::json;
use sqlx::PgPool;

use super::*;

#[sqlx::test]
async fn password_guessing_is_slowed_down_per_account(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;
    app.register_verified("bob@example.com").await;
    let flow_id = app.start_flow().await;

    for _ in 0..10 {
        let attempt = app
            .submit_password(&flow_id, "alice@example.com", "wrong password!!")
            .await;
        assert_eq!(attempt.code(), "invalid_credentials");
    }
    let limited = app
        .submit_password(&flow_id, "alice@example.com", PASSWORD)
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key(header::RETRY_AFTER));

    // Other accounts, even from the same IP, are not affected.
    let other = app
        .submit_password(&flow_id, "bob@example.com", "wrong password!!")
        .await;
    assert_eq!(other.code(), "invalid_credentials");
}

async fn register_from(app: &TestApp, i: usize, forwarded_for: &str) -> StatusCode {
    app.post("/registration")
        .header(header::HeaderName::from_static("x-forwarded-for"), forwarded_for)
        .json(json!({ "client_id": CLIENT_ID, "email": format!("user{i}@example.com"), "password": PASSWORD }))
        .send()
        .await
        .status
}

#[sqlx::test]
async fn forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy(db: PgPool) {
    // Anyone can send X-Forwarded-For: without a trusted proxy, all these requests share one budget.
    let direct = TestApp::new(db.clone()).await;
    let mut statuses = Vec::new();
    for i in 0..21 {
        statuses.push(register_from(&direct, i, &format!("198.51.100.{i}")).await);
    }
    assert_eq!(statuses.last(), Some(&StatusCode::TOO_MANY_REQUESTS));

    // Behind a trusted proxy, each forwarded client gets its own budget.
    let proxied = TestApp::with_trusted_proxies(db, vec!["127.0.0.1".parse().unwrap()]).await;
    for i in 100..121 {
        assert_eq!(
            register_from(&proxied, i, &format!("198.51.100.{i}")).await,
            StatusCode::ACCEPTED
        );
    }
}

#[sqlx::test]
async fn cors_only_allows_client_origins(db: PgPool) {
    let app = TestApp::new(db).await;
    let preflight = |origin: &'static str| {
        app.options("/flows/login")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .send()
    };

    let allowed = preflight(APP_ORIGIN).await;
    assert_eq!(
        allowed.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        APP_ORIGIN
    );
    let refused = preflight("https://evil.example.com").await;
    assert!(
        !refused
            .headers
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
}

#[sqlx::test]
async fn magic_link_emails_are_capped_per_flow_whether_the_account_exists_or_not(db: PgPool) {
    let app = TestApp::new(db).await;
    app.register_verified("alice@example.com").await;

    for email in ["alice@example.com", "nobody@example.com"] {
        let flow_id = app.start_flow().await;
        for _ in 0..3 {
            let sent = app.request_magic_link(&flow_id, email).await;
            assert_eq!(sent.status, StatusCode::ACCEPTED, "{}", sent.body);
        }
        let capped = app.request_magic_link(&flow_id, email).await;
        assert_eq!(capped.status, StatusCode::TOO_MANY_REQUESTS, "{email}");
        assert!(capped.headers.contains_key(header::RETRY_AFTER));
    }
    assert_eq!(
        app.emails_to("alice@example.com").len(),
        1 + 3,
        "verification + 3 links"
    );
}
