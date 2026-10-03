use axum::http::StatusCode;
use axum::http::header;
use serde_json::json;
use sqlx::PgPool;

use super::*;

/// Asks for a magic link email (limited per IP), as if from `forwarded_for`.
async fn email_from(app: &TestApp, i: usize, forwarded_for: &str) -> StatusCode {
    let flow_id = app.start_flow().await;
    app.post(&format!("/flows/login/{flow_id}/magic-link"))
        .header(
            header::HeaderName::from_static("x-forwarded-for"),
            forwarded_for,
        )
        .json(json!({ "email": format!("user{i}@example.com") }))
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
        statuses.push(email_from(&direct, i, &format!("198.51.100.{i}")).await);
    }
    assert_eq!(statuses.last(), Some(&StatusCode::TOO_MANY_REQUESTS));

    // Behind a trusted proxy, each forwarded client gets its own budget.
    let proxied = TestApp::with_trusted_proxies(db, vec!["127.0.0.1".parse().unwrap()]).await;
    for i in 100..121 {
        assert_eq!(
            email_from(&proxied, i, &format!("198.51.100.{i}")).await,
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
    app.create_account("alice@example.com").await;

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
    assert_eq!(app.emails_to("alice@example.com").len(), 3, "3 links");
}

#[sqlx::test]
async fn a_refused_magic_link_request_does_not_use_one_of_the_flow_emails(db: PgPool) {
    let app = TestApp::new(db).await;
    // Use up the per-address budget (5 emails) of busy@example.com.
    for _ in 0..2 {
        let flow_id = app.start_flow().await;
        for _ in 0..3 {
            app.request_magic_link(&flow_id, "busy@example.com").await;
        }
    }
    assert_eq!(app.emails_to("busy@example.com").len(), 5);

    let flow_id = app.start_flow().await;
    let refused = app.request_magic_link(&flow_id, "busy@example.com").await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);

    // The flow still has its 3 emails.
    for _ in 0..3 {
        let sent = app.request_magic_link(&flow_id, "other@example.com").await;
        assert_eq!(sent.status, StatusCode::ACCEPTED, "{}", sent.body);
    }
    let capped = app.request_magic_link(&flow_id, "other@example.com").await;
    assert_eq!(capped.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.emails_to("other@example.com").len(), 3);
}
