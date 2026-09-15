use chrono::{DateTime, Utc};
use sqlx::Executor;
use uuid::Uuid;

use crate::db::{Db, DbConnection};

pub async fn create<'e, E>(
    executor: E,
    flow_id: Uuid,
    user_id: Uuid,
    email: &str,
    token_hash: &[u8],
    code_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.magic_links (flow_id, user_id, email, token_hash, code_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        flow_id,
        user_id,
        email,
        token_hash,
        code_hash,
        expires_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub struct ConsumedMagicLink {
    pub flow_id: Uuid,
    pub user_id: Uuid,
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
    pub user_id: Uuid,
    pub email: String,
    pub code_hash: Vec<u8>,
}

/// The link a code typed on this flow is checked against: the newest link of the flow (each new
/// email would otherwise add attempts), still pending, under `max_link_failures`, and whose user
/// is under `max_user_failures` over the last day. Locks the user until the transaction ends, so
/// concurrent attempts on any of their links are checked one after another.
pub async fn find_code_candidate(
    conn: &mut DbConnection,
    flow_id: Uuid,
    max_link_failures: i32,
    max_user_failures: i64,
) -> Result<Option<CodeCandidate>, sqlx::Error> {
    let Some(user_id) = sqlx::query_scalar!(
        r#"
        SELECT user_id FROM bauth.magic_links
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
        "SELECT id FROM bauth.users WHERE id = $1 FOR NO KEY UPDATE",
        user_id
    )
    .fetch_optional(&mut *conn)
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
        AND user_id = $2
        AND consumed_at IS NULL AND expires_at > now() AND code_failures < $3
        AND (
            SELECT coalesce(sum(code_failures), 0) FROM bauth.magic_links
            WHERE user_id = $2 AND created_at > now() - interval '1 day'
        ) < $4
        "#,
        flow_id,
        user_id,
        max_link_failures,
        max_user_failures
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
