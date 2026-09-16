use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub struct ConsumedVerification {
    pub user_id: Uuid,
    pub email: String,
}

pub async fn create<'e, E>(
    executor: E,
    user_id: Uuid,
    email: &str,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.email_verifications (user_id, email, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id,
        email,
        token_hash,
        expires_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Marks the token as used and returns what it proves.
/// `None` if unknown, expired or already consumed — the three look the same to the caller.
pub async fn consume<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<ConsumedVerification>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ConsumedVerification,
        r#"
        UPDATE bauth.email_verifications
        SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING user_id, email
        "#,
        token_hash
    )
    .fetch_optional(executor)
    .await
}
