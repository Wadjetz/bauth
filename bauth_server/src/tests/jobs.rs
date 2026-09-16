use sqlx::PgPool;
use uuid::Uuid;

use crate::jobs::purge::PurgeReport;
use crate::jobs::purge::{self};

async fn user(db: &PgPool, email: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO bauth.users (email) VALUES ($1) RETURNING id")
        .bind(email)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn user_created(db: &PgPool, email: &str, since: &'static str, verified: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO bauth.users (email, created_at, email_verified_at)
         VALUES ($1, now() - $2::interval, CASE WHEN $3 THEN now() - $2::interval END) RETURNING id",
    )
    .bind(email)
    .bind(since)
    .bind(verified)
    .fetch_one(db)
    .await
    .unwrap()
}

async fn flow(db: &PgPool, user_id: Uuid, expired_since: &'static str) -> Uuid {
    let flow_id: Uuid = sqlx::query_scalar(
        "INSERT INTO bauth.login_flows (client_id, redirect_uri, code_challenge, expires_at)
         VALUES ('my-app', 'https://app.test/cb', 'challenge', now() - $1::interval) RETURNING id",
    )
    .bind(expired_since)
    .fetch_one(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bauth.authorization_codes (code_hash, flow_id, user_id, expires_at)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, $2, now() - $3::interval)",
    )
    .bind(flow_id)
    .bind(user_id)
    .bind(expired_since)
    .execute(db)
    .await
    .unwrap();
    flow_id
}

/// A session whose first refresh token was rotated long ago, as in a long-lived login.
async fn session(
    db: &PgPool,
    user_id: Uuid,
    expires_in: &'static str,
    revoked_since: Option<&'static str>,
) -> Uuid {
    let session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO bauth.sessions (user_id, client_id, expires_at, revoked_at)
         VALUES ($1, 'my-app', now() + $2::interval, now() - $3::interval) RETURNING id",
    )
    .bind(user_id)
    .bind(expires_in)
    .bind(revoked_since)
    .fetch_one(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bauth.refresh_tokens (session_id, token_hash, rotated_at, created_at)
         VALUES ($1, sha256(gen_random_uuid()::text::bytea), now() - interval '20 days', now() - interval '25 days')",
    )
    .bind(session_id)
    .execute(db)
    .await
    .unwrap();
    session_id
}

async fn count(db: &PgPool, table: &'static str) -> i64 {
    let query = format!("SELECT count(*) FROM bauth.{table}");
    sqlx::query_scalar(sqlx::AssertSqlSafe(query))
        .fetch_one(db)
        .await
        .unwrap()
}

#[sqlx::test]
async fn purge_deletes_only_rows_past_their_retention(db: PgPool) {
    let alice = user(&db, "alice@example.com").await;
    let squatter = user_created(&db, "squatted@example.com", "8 days", false).await; // purged
    user_created(&db, "signup@example.com", "6 days", false).await;
    user_created(&db, "old@example.com", "1 year", true).await;
    sqlx::query(
        "INSERT INTO bauth.password_credentials (user_id, password_hash) VALUES ($1, 'hash')",
    )
    .bind(squatter)
    .execute(&db)
    .await
    .unwrap();

    flow(&db, alice, "2 days").await; // purged
    let recent_flow = flow(&db, alice, "1 hour").await;

    sqlx::query(
        "INSERT INTO bauth.email_verifications (user_id, email, token_hash, expires_at, consumed_at) VALUES
         ($1, 'alice@example.com', sha256(gen_random_uuid()::text::bytea), now() + interval '1 day', now() - interval '8 days'),
         ($1, 'alice@example.com', sha256(gen_random_uuid()::text::bytea), now() - interval '10 days', NULL),
         ($1, 'alice@example.com', sha256(gen_random_uuid()::text::bytea), now() + interval '1 day', now() - interval '1 day')",
    )
    .bind(alice)
    .execute(&db)
    .await
    .unwrap();

    session(&db, alice, "-40 days", None).await; // expired long ago: purged with its token
    session(&db, alice, "10 days", Some("31 days")).await; // revoked long ago: purged
    let revoked_recently = session(&db, alice, "10 days", Some("2 days")).await;
    let live = session(&db, alice, "10 days", None).await;

    sqlx::query(
        "INSERT INTO bauth.confirmations (user_id, session_id, action, email, code_hash, expires_at, consumed_at) VALUES
         ($1, $2, 'delete_account', 'alice@example.com', sha256('a'::bytea), now() - interval '8 days', NULL),
         ($1, $2, 'change_email', 'alice@example.com', sha256('b'::bytea), now() + interval '1 hour', NULL)",
    )
    .bind(alice)
    .bind(live)
    .execute(&db)
    .await
    .unwrap();

    let report = purge::run(&db).await.unwrap().expect("lock is free");
    assert_eq!(
        report,
        PurgeReport {
            login_flows: 1,
            email_verifications: 2,
            password_resets: 0,
            email_changes: 0,
            confirmations: 1,
            sessions: 2,
            signing_keys: 0,
            unverified_users: 1,
        }
    );
    assert_eq!(count(&db, "users").await, 3);
    assert_eq!(count(&db, "password_credentials").await, 0, "cascade");

    // Cascades: the purged flow took its code, the purged sessions their refresh tokens.
    assert_eq!(count(&db, "authorization_codes").await, 1);
    let remaining_flow: Uuid = sqlx::query_scalar("SELECT id FROM bauth.login_flows")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(remaining_flow, recent_flow);
    let mut sessions: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM bauth.sessions")
        .fetch_all(&db)
        .await
        .unwrap();
    sessions.sort();
    let mut expected = vec![revoked_recently, live];
    expected.sort();
    assert_eq!(sessions, expected);
    // The live session keeps its old rotated token: theft detection depends on it.
    assert_eq!(count(&db, "refresh_tokens").await, 2);

    assert_eq!(
        purge::run(&db).await.unwrap(),
        Some(PurgeReport::default()),
        "nothing left to purge"
    );
}

#[sqlx::test]
async fn purge_skips_when_another_instance_holds_the_lock(db: PgPool) {
    let mut other_instance = db.acquire().await.unwrap();
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(purge::LOCK_KEY)
        .fetch_one(&mut *other_instance)
        .await
        .unwrap();
    assert!(locked);

    assert_eq!(purge::run(&db).await.unwrap(), None);

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(purge::LOCK_KEY)
        .execute(&mut *other_instance)
        .await
        .unwrap();
    assert!(purge::run(&db).await.unwrap().is_some());
}
