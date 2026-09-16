//! Deletes rows that stopped being useful, so token tables don't grow forever.
//!
//! | Rows                                         | Deleted once …                         |
//! |----------------------------------------------|----------------------------------------|
//! | login flows (+ their codes and magic links)  | expired for 1 day                      |
//! | email verifications, password resets, email changes, confirmations | expired or used for 7 days |
//! | sessions (+ their refresh tokens)            | expired or revoked for 30 days         |
//! | signing keys                                 | retired for 30 days (long gone from the JWKS) |
//! | users never verified (+ everything of theirs) | created 7 days ago                    |
//!
//! Refresh tokens are never deleted on their own: rotated tokens of a live session are what
//! detects a stolen token coming back.
//!
//! An unverified account can't log in with its password, and an email link would verify it: after
//! a week it is an abandoned sign-up or someone squatting an address that isn't theirs.

use crate::db::DbPool;

/// Rows per `DELETE`: keeps each statement short, even after a long pause.
const BATCH_SIZE: i64 = 1000;
/// `pg_try_advisory_lock` key, so only one instance purges at a time.
pub(crate) const LOCK_KEY: i64 = 0x6261_7574_6870_7572; // "bauthpur"

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub login_flows: u64,
    pub email_verifications: u64,
    pub password_resets: u64,
    pub email_changes: u64,
    pub confirmations: u64,
    pub sessions: u64,
    pub signing_keys: u64,
    pub unverified_users: u64,
}

impl PurgeReport {
    pub fn log(&self) {
        tracing::info!(
            login_flows = self.login_flows,
            email_verifications = self.email_verifications,
            password_resets = self.password_resets,
            email_changes = self.email_changes,
            confirmations = self.confirmations,
            sessions = self.sessions,
            signing_keys = self.signing_keys,
            unverified_users = self.unverified_users,
            "purged expired rows"
        );
    }
}

/// `None` if another instance holds the purge lock.
pub async fn run(db: &DbPool) -> Result<Option<PurgeReport>, sqlx::Error> {
    // Advisory locks belong to a connection: take and release it on the same one.
    let mut conn = db.acquire().await?;
    let locked = sqlx::query_scalar!(r#"SELECT pg_try_advisory_lock($1) AS "locked!""#, LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        return Ok(None);
    }
    // The lock stays held by `conn` while the deletes run on other pool connections.
    let report = purge(db).await;
    sqlx::query_scalar!(r#"SELECT pg_advisory_unlock($1) AS "unlocked!""#, LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    report.map(Some)
}

async fn purge(db: &DbPool) -> Result<PurgeReport, sqlx::Error> {
    let login_flows = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.login_flows WHERE id IN (
                SELECT id FROM bauth.login_flows
                WHERE expires_at < now() - interval '1 day'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let email_verifications = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.email_verifications WHERE id IN (
                SELECT id FROM bauth.email_verifications
                WHERE expires_at < now() - interval '7 days' OR consumed_at < now() - interval '7 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let password_resets = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.password_resets WHERE id IN (
                SELECT id FROM bauth.password_resets
                WHERE expires_at < now() - interval '7 days' OR consumed_at < now() - interval '7 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let email_changes = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.email_changes WHERE id IN (
                SELECT id FROM bauth.email_changes
                WHERE expires_at < now() - interval '7 days' OR consumed_at < now() - interval '7 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let confirmations = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.confirmations WHERE id IN (
                SELECT id FROM bauth.confirmations
                WHERE expires_at < now() - interval '7 days' OR consumed_at < now() - interval '7 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let sessions = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.sessions WHERE id IN (
                SELECT id FROM bauth.sessions
                WHERE expires_at < now() - interval '30 days' OR revoked_at < now() - interval '30 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    let unverified_users = in_batches(move || {
        sqlx::query!(
            r#"
            DELETE FROM bauth.users WHERE id IN (
                SELECT id FROM bauth.users
                WHERE email_verified_at IS NULL AND created_at < now() - interval '7 days'
                LIMIT $1
            )
            "#,
            BATCH_SIZE
        )
        .execute(db)
    })
    .await?;

    // A handful of rows at most: no batching needed.
    let signing_keys = sqlx::query!(
        "DELETE FROM bauth.signing_keys WHERE retired_at < now() - interval '30 days'"
    )
    .execute(db)
    .await?
    .rows_affected();

    Ok(PurgeReport {
        login_flows,
        email_verifications,
        password_resets,
        email_changes,
        confirmations,
        sessions,
        signing_keys,
        unverified_users,
    })
}

/// Repeats a batched `DELETE` until a batch comes back short. Returns the total deleted.
async fn in_batches<F, Fut>(mut delete_batch: F) -> Result<u64, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<sqlx::postgres::PgQueryResult, sqlx::Error>>,
{
    let mut total = 0;
    loop {
        let deleted = delete_batch().await?.rows_affected();
        total += deleted;
        if deleted < BATCH_SIZE as u64 {
            return Ok(total);
        }
    }
}
