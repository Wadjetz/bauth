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

pub struct PendingMagicLinkFlow {
    pub client_id: String,
    /// Magic link emails already asked for on this flow.
    pub requests: i32,
    pub expires_at: DateTime<Utc>,
}

/// A flow still waiting for credentials, with its magic link count. `None` if the flow is
/// unknown, expired or completed. Reads only: the request is counted by
/// `count_magic_link_request`, once it is sure to go through.
pub async fn find_pending_magic_link_flow<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<PendingMagicLinkFlow>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        PendingMagicLinkFlow,
        r#"
        SELECT client_id, magic_link_requests AS requests, expires_at
        FROM bauth.login_flows
        WHERE id = $1 AND completed_at IS NULL AND expires_at > now()
        "#,
        id
    )
    .fetch_optional(executor)
    .await
}

/// Counts a magic link request, whether the account exists or not, if the flow is still pending
/// and under `max` requests. The check is in the `UPDATE`, so concurrent requests can't go past
/// `max`. Also keeps the flow alive until `link_expires_at`: the email's
/// link and code complete this flow, so it must not expire before them. Returns the flow's new
/// expiry, `None` when the request isn't counted.
pub async fn count_magic_link_request<'e, E>(
    executor: E,
    id: Uuid,
    max: i32,
    link_expires_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        UPDATE bauth.login_flows
        SET magic_link_requests = magic_link_requests + 1,
            expires_at = greatest(expires_at, $3)
        WHERE id = $1 AND completed_at IS NULL AND expires_at > now() AND magic_link_requests < $2
        RETURNING expires_at
        "#,
        id,
        max,
        link_expires_at
    )
    .fetch_optional(executor)
    .await
}
