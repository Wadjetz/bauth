use chrono::{DateTime, Utc};
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub struct SigningKeyRow {
    pub id: Uuid,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub active_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

pub async fn insert<'e, E>(
    executor: E,
    id: Uuid,
    public_key: &[u8],
    encrypted_private_key: &[u8],
    active_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.signing_keys (id, algorithm, public_key, encrypted_private_key, active_at)
        VALUES ($1, 'EdDSA', $2, $3, $4)
        "#,
        id,
        public_key,
        encrypted_private_key,
        active_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Keys that must appear in the JWKS: not retired, or retired less than `grace` ago.
/// Newest first.
pub async fn list_published<'e, E>(
    executor: E,
    now: DateTime<Utc>,
    grace: chrono::TimeDelta,
) -> Result<Vec<SigningKeyRow>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let retired_after = now - grace;
    sqlx::query_as!(
        SigningKeyRow,
        r#"
        SELECT id, public_key, encrypted_private_key, active_at, retired_at
        FROM bauth.signing_keys
        WHERE retired_at IS NULL OR retired_at > $1
        ORDER BY active_at DESC
        "#,
        retired_after
    )
    .fetch_all(executor)
    .await
}

/// Stops every other key from signing at `retired_at`, when the new key takes over.
pub async fn retire_all_except<'e, E>(
    executor: E,
    keep: Uuid,
    retired_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        UPDATE bauth.signing_keys
        SET retired_at = $2
        WHERE id <> $1 AND (retired_at IS NULL OR retired_at > $2)
        "#,
        keep,
        retired_at
    )
    .execute(executor)
    .await?;
    Ok(())
}
