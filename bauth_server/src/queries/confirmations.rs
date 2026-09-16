use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;
use crate::db::DbConnection;

pub async fn create<'e, E>(
    executor: E,
    user_id: Uuid,
    session_id: Uuid,
    action: &str,
    email: &str,
    code_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.confirmations (user_id, session_id, action, email, code_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        user_id,
        session_id,
        action,
        email,
        code_hash,
        expires_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub struct CodeCandidate {
    pub id: Uuid,
    pub email: String,
    pub code_hash: Vec<u8>,
}

/// The confirmation a code is checked against: the newest one of this session for this action
/// (a new email disables the previous code), still pending, under `max_code_failures`, and whose
/// account is under `max_user_failures` over the last day. Locks the account until the transaction
/// ends, so concurrent guesses are checked one after another.
pub async fn find_code_candidate(
    conn: &mut DbConnection,
    user_id: Uuid,
    session_id: Uuid,
    action: &str,
    max_code_failures: i32,
    max_user_failures: i64,
) -> Result<Option<CodeCandidate>, sqlx::Error> {
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
        SELECT id, email, code_hash
        FROM bauth.confirmations
        WHERE id = (
            SELECT id FROM bauth.confirmations
            WHERE session_id = $1 AND action = $2
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        )
        AND consumed_at IS NULL AND expires_at > now() AND code_failures < $3
        AND (
            SELECT coalesce(sum(code_failures), 0) FROM bauth.confirmations
            WHERE user_id = $4 AND created_at > now() - interval '1 day'
        ) < $5
        "#,
        session_id,
        action,
        max_code_failures,
        user_id,
        max_user_failures
    )
    .fetch_optional(&mut *conn)
    .await
}

/// Counts a wrong code on a confirmation from `find_code_candidate`; consumes it at the limit.
pub async fn record_code_failure<'e, E>(
    executor: E,
    id: Uuid,
    max_code_failures: i32,
) -> Result<i32, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        UPDATE bauth.confirmations
        SET code_failures = code_failures + 1,
            consumed_at = CASE WHEN code_failures + 1 >= $2 THEN now() END
        WHERE id = $1
        RETURNING code_failures
        "#,
        id,
        max_code_failures
    )
    .fetch_one(executor)
    .await
}

/// Marks a confirmation from `find_code_candidate` as used.
pub async fn consume_by_id<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        "UPDATE bauth.confirmations SET consumed_at = now() WHERE id = $1",
        id
    )
    .execute(executor)
    .await?;
    Ok(())
}
