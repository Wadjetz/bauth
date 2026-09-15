use chrono::{DateTime, Utc};
use sqlx::Executor;
use uuid::Uuid;

use crate::db::{Db, DbConnection};

/// `user_id` is `None` for an address without an account. Returns the normalized address.
pub async fn create<'e, E>(
    executor: E,
    flow_id: Uuid,
    user_id: Option<Uuid>,
    email: &str,
    token_hash: &[u8],
    code_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<String, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        INSERT INTO bauth.magic_links (flow_id, user_id, email, token_hash, code_hash, expires_at)
        VALUES ($1, $2, lower(btrim($3)), $4, $5, $6)
        RETURNING email
        "#,
        flow_id,
        user_id,
        email,
        token_hash,
        code_hash,
        expires_at
    )
    .fetch_one(executor)
    .await
}

pub struct ConsumedMagicLink {
    pub flow_id: Uuid,
    /// `None` if the address had no account when the email was sent.
    pub user_id: Option<Uuid>,
    pub email: String,
}

/// Marks the link as used. `None` if unknown, expired or already used.
pub async fn consume<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<ConsumedMagicLink>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ConsumedMagicLink,
        r#"
        UPDATE bauth.magic_links
        SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING flow_id, user_id, email
        "#,
        token_hash
    )
    .fetch_optional(executor)
    .await
}

pub struct CodeCandidate {
    pub id: Uuid,
    /// `None` if the address had no account when the email was sent.
    pub user_id: Option<Uuid>,
    pub email: String,
    pub code_hash: Vec<u8>,
}

/// The link a code typed on this flow is checked against: the newest link of the flow (each new
/// email would otherwise add attempts), still pending, under `max_link_failures`, and whose address
/// is under `max_address_failures` over the last day. Takes a lock on the address until the
/// transaction ends, so concurrent attempts on any of its links are checked one after another. The
/// address, not the account: a sign-up email has no account yet.
pub async fn find_code_candidate(
    conn: &mut DbConnection,
    flow_id: Uuid,
    max_link_failures: i32,
    max_address_failures: i64,
) -> Result<Option<CodeCandidate>, sqlx::Error> {
    let Some(email) = sqlx::query_scalar!(
        r#"
        SELECT email FROM bauth.magic_links
        WHERE flow_id = $1
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        "#,
        flow_id
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    // Separate statement: the next one must see failures committed while waiting for the lock.
    sqlx::query!(
        r#"SELECT 1 AS "locked!" FROM pg_advisory_xact_lock(hashtextextended('bauth.magic_code:' || $1, 0))"#,
        email
    )
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query_as!(
        CodeCandidate,
        r#"
        SELECT id, user_id, email, code_hash
        FROM bauth.magic_links
        WHERE id = (
            SELECT id FROM bauth.magic_links
            WHERE flow_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        )
        AND email = $2
        AND consumed_at IS NULL AND expires_at > now() AND code_failures < $3
        AND (
            SELECT coalesce(sum(code_failures), 0) FROM bauth.magic_links
            WHERE email = $2 AND created_at > now() - interval '1 day'
        ) < $4
        "#,
        flow_id,
        email,
        max_link_failures,
        max_address_failures
    )
    .fetch_optional(&mut *conn)
    .await
}

/// Counts a wrong code on a link from `find_code_candidate`; consumes it at `max_link_failures`.
pub async fn record_code_failure<'e, E>(
    executor: E,
    id: Uuid,
    max_link_failures: i32,
) -> Result<i32, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        UPDATE bauth.magic_links
        SET code_failures = code_failures + 1,
            consumed_at = CASE WHEN code_failures + 1 >= $2 THEN now() END
        WHERE id = $1
        RETURNING code_failures
        "#,
        id,
        max_link_failures
    )
    .fetch_one(executor)
    .await
}

/// Marks a link from `find_code_candidate` as used, which disables its code and its token.
pub async fn consume_by_id<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        "UPDATE bauth.magic_links SET consumed_at = now() WHERE id = $1",
        id
    )
    .execute(executor)
    .await?;
    Ok(())
}
