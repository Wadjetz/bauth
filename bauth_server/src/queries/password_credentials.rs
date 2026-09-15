use chrono::{DateTime, Utc};
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

/// Inserts or replaces the user's password hash.
pub async fn upsert<'e, E>(
    executor: E,
    user_id: Uuid,
    password_hash: &str,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.password_credentials (user_id, password_hash)
        VALUES ($1, $2)
        ON CONFLICT (user_id) DO UPDATE
        SET password_hash = EXCLUDED.password_hash, updated_at = now()
        "#,
        user_id,
        password_hash
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Removes the user's password. `true` if they had one.
pub async fn delete<'e, E>(executor: E, user_id: Uuid) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        "DELETE FROM bauth.password_credentials WHERE user_id = $1",
        user_id
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn find_hash<'e, E>(executor: E, user_id: Uuid) -> Result<Option<String>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        SELECT password_hash
        FROM bauth.password_credentials
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_optional(executor)
    .await
}

pub struct PasswordLogin {
    pub user_id: Uuid,
    pub password_hash: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
}

/// Everything the password login needs, in one query. `None` if no account or no password.
pub async fn find_login_by_email<'e, E>(
    executor: E,
    email: &str,
) -> Result<Option<PasswordLogin>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        PasswordLogin,
        r#"
        SELECT u.id AS user_id, p.password_hash, u.email_verified_at, u.disabled_at
        FROM bauth.users u
        JOIN bauth.password_credentials p ON p.user_id = u.id
        WHERE u.email = lower(btrim($1))
        "#,
        email
    )
    .fetch_optional(executor)
    .await
}
