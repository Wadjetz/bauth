use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub async fn create<'e, E>(
    executor: E,
    code_hash: &[u8],
    flow_id: Uuid,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.authorization_codes (code_hash, flow_id, user_id, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
        code_hash,
        flow_id,
        user_id,
        expires_at
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub struct ConsumedCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
}

/// Marks the code used and returns what it was issued for.
/// `None` if unknown, expired or already used.
pub async fn consume<'e, E>(
    executor: E,
    code_hash: &[u8],
) -> Result<Option<ConsumedCode>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ConsumedCode,
        r#"
        UPDATE bauth.authorization_codes AS c
        SET consumed_at = now()
        FROM bauth.login_flows AS f
        WHERE c.flow_id = f.id
          AND c.code_hash = $1
          AND c.consumed_at IS NULL
          AND c.expires_at > now()
        RETURNING c.id, c.user_id, f.client_id, f.redirect_uri, f.code_challenge
        "#,
        code_hash
    )
    .fetch_optional(executor)
    .await
}

/// Id of a code that was already exchanged: seeing it again means it leaked.
pub async fn find_consumed<'e, E>(
    executor: E,
    code_hash: &[u8],
) -> Result<Option<Uuid>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        SELECT id FROM bauth.authorization_codes
        WHERE code_hash = $1 AND consumed_at IS NOT NULL
        "#,
        code_hash
    )
    .fetch_optional(executor)
    .await
}
