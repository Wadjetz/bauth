use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub async fn create<'e, E>(
    executor: E,
    user_id: Uuid,
    from_email: &str,
    to_email: &str,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.email_changes (user_id, from_email, to_email, token_hash, expires_at)
        VALUES ($1, $2, lower(btrim($3)), $4, $5)
        "#,
        user_id,
        from_email,
        to_email,
        token_hash,
        expires_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub struct ConsumedEmailChange {
    pub user_id: Uuid,
    pub from_email: String,
    pub to_email: String,
}

/// Marks the token as used. `None` if unknown, expired or already used.
pub async fn consume<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<ConsumedEmailChange>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ConsumedEmailChange,
        r#"
        UPDATE bauth.email_changes
        SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING user_id, from_email, to_email
        "#,
        token_hash
    )
    .fetch_optional(executor)
    .await
}
