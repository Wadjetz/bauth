use chrono::{DateTime, Utc};
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

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
        INSERT INTO bauth.password_resets (user_id, email, token_hash, expires_at)
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

pub struct ConsumedReset {
    pub user_id: Uuid,
    pub email: String,
}

/// Marks the token as used. `None` if unknown, expired or already used.
pub async fn consume<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<ConsumedReset>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ConsumedReset,
        r#"
        UPDATE bauth.password_resets
        SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING user_id, email
        "#,
        token_hash
    )
    .fetch_optional(executor)
    .await
}

/// Invalidates every other pending reset link of the user.
pub async fn consume_all_for_user<'e, E>(executor: E, user_id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        UPDATE bauth.password_resets
        SET consumed_at = now()
        WHERE user_id = $1 AND consumed_at IS NULL
        "#,
        user_id
    )
    .execute(executor)
    .await?;
    Ok(())
}
