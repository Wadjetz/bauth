use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub async fn create<'e, E>(
    executor: E,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        INSERT INTO bauth.login_flows (client_id, redirect_uri, code_challenge, state, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
        client_id,
        redirect_uri,
        code_challenge,
        state,
        expires_at
    )
    .fetch_one(executor)
    .await
}

/// Cheap check before hashing: is this flow still waiting for credentials?
pub async fn is_pending<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM bauth.login_flows
            WHERE id = $1 AND completed_at IS NULL AND expires_at > now()
        ) AS "pending!"
        "#,
        id
    )
    .fetch_one(executor)
    .await
}

/// Atomically marks the flow completed. `false` if it expired or was completed concurrently.
pub async fn complete<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.login_flows
        SET completed_at = now()
        WHERE id = $1 AND completed_at IS NULL AND expires_at > now()
        "#,
        id
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub struct MagicLinkRequest {
    pub client_id: String,
    /// Including this one.
    pub requests: i32,
    pub expires_at: DateTime<Utc>,
}

/// Counts a magic link request on a flow still waiting for credentials, whether the account
/// exists or not. `None` if the flow is unknown, expired or completed.
pub async fn count_magic_link_request<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<MagicLinkRequest>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        MagicLinkRequest,
        r#"
        UPDATE bauth.login_flows
        SET magic_link_requests = magic_link_requests + 1
        WHERE id = $1 AND completed_at IS NULL AND expires_at > now()
        RETURNING client_id, magic_link_requests AS requests, expires_at
        "#,
        id
    )
    .fetch_optional(executor)
    .await
}
