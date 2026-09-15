use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;
use crate::models::user::User;

pub async fn create<'e, E>(executor: E, email: &str) -> Result<Option<User>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        User,
        r#"
        INSERT INTO bauth.users (email)
        VALUES (lower(btrim($1)))
        ON CONFLICT (email) DO NOTHING
        RETURNING id, email, email_verified_at, disabled_at, created_at
        "#,
        email
    )
    .fetch_optional(executor)
    .await
}

pub async fn find_by_email<'e, E>(executor: E, email: &str) -> Result<Option<User>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email, email_verified_at, disabled_at, created_at
        FROM bauth.users
        WHERE email = lower(btrim($1))
        "#,
        email
    )
    .fetch_optional(executor)
    .await
}

/// `find_by_id`, locking the account until the transaction ends.
pub async fn lock_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<User>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email, email_verified_at, disabled_at, created_at
        FROM bauth.users
        WHERE id = $1
        FOR NO KEY UPDATE
        "#,
        id
    )
    .fetch_optional(executor)
    .await
}

pub async fn find_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<User>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email, email_verified_at, disabled_at, created_at
        FROM bauth.users
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(executor)
    .await
}

/// Marks `email` as verified, only if it is still the user's current address.
/// Idempotent: returns `true` even if it was already verified.
pub async fn mark_email_verified<'e, E>(
    executor: E,
    id: Uuid,
    email: &str,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.users
        SET email_verified_at = COALESCE(email_verified_at, now()), updated_at = now()
        WHERE id = $1 AND email = $2
        "#,
        id,
        email
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Moves the account to a new, now verified, address, only if it still uses `from_email`.
/// `false` if the address changed since. Fails with a unique violation if `to_email` is taken.
pub async fn change_email<'e, E>(
    executor: E,
    id: Uuid,
    from_email: &str,
    to_email: &str,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.users
        SET email = $3, email_verified_at = now(), updated_at = now()
        WHERE id = $1 AND email = $2
        "#,
        id,
        from_email,
        to_email
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Deletes the account; every credential, token and session goes with it (ON DELETE CASCADE).
pub async fn delete<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!("DELETE FROM bauth.users WHERE id = $1", id)
        .execute(executor)
        .await?;
    Ok(())
}
