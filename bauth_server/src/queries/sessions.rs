use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

pub async fn create<'e, E>(
    executor: E,
    user_id: Uuid,
    client_id: &str,
    authorization_code_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        INSERT INTO bauth.sessions (user_id, client_id, authorization_code_id, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        user_id,
        client_id,
        authorization_code_id,
        expires_at
    )
    .fetch_one(executor)
    .await
}

/// Revokes the session opened with this authorization code, if any.
pub async fn revoke_by_authorization_code<'e, E>(
    executor: E,
    authorization_code_id: Uuid,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.sessions
        SET revoked_at = now()
        WHERE authorization_code_id = $1 AND revoked_at IS NULL
        "#,
        authorization_code_id
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn revoke<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        UPDATE bauth.sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
        "#,
        id
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Revokes the session this refresh token belongs to, if the token was issued to `client_id`.
/// Returns the revoked session, or `None` if there was nothing to revoke.
pub async fn revoke_by_refresh_token<'e, E>(
    executor: E,
    token_hash: &[u8],
    client_id: &str,
) -> Result<Option<Uuid>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        UPDATE bauth.sessions AS s
        SET revoked_at = now()
        FROM bauth.refresh_tokens AS r
        WHERE r.session_id = s.id
          AND r.token_hash = $1
          AND s.client_id = $2
          AND s.revoked_at IS NULL
        RETURNING s.id
        "#,
        token_hash,
        client_id
    )
    .fetch_optional(executor)
    .await
}

/// Logs the user out everywhere. Returns how many sessions were revoked.
pub async fn revoke_all_for_user<'e, E>(executor: E, user_id: Uuid) -> Result<u64, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.sessions
        SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL
        "#,
        user_id
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Who is behind an access token, if its session is still usable.
pub struct AuthenticatedSession {
    pub user_id: Uuid,
    pub email: String,
}

pub async fn find_authenticated<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<AuthenticatedSession>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        AuthenticatedSession,
        r#"
        SELECT s.user_id, u.email
        FROM bauth.sessions s
        JOIN bauth.users u ON u.id = s.user_id
        WHERE s.id = $1
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
          AND u.disabled_at IS NULL
        "#,
        id
    )
    .fetch_optional(executor)
    .await
}

pub struct ActiveSession {
    pub id: Uuid,
    pub client_id: String,
    pub created_at: DateTime<Utc>,
    /// When a refresh token was last issued: roughly when the app was last used.
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn list_active_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<Vec<ActiveSession>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        ActiveSession,
        r#"
        SELECT s.id, s.client_id, s.created_at, s.expires_at,
               COALESCE(max(r.created_at), s.created_at) AS "last_used_at!"
        FROM bauth.sessions s
        LEFT JOIN bauth.refresh_tokens r ON r.session_id = s.id
        WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
        GROUP BY s.id
        ORDER BY "last_used_at!" DESC
        "#,
        user_id
    )
    .fetch_all(executor)
    .await
}

/// Revokes one of the user's sessions. `false` if it doesn't exist, isn't theirs or is already revoked.
pub async fn revoke_for_user<'e, E>(
    executor: E,
    id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.sessions
        SET revoked_at = now()
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
        "#,
        id,
        user_id
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Logs the user out everywhere except `keep`. Returns how many sessions were revoked.
pub async fn revoke_all_for_user_except<'e, E>(
    executor: E,
    user_id: Uuid,
    keep: Uuid,
) -> Result<u64, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    let result = sqlx::query!(
        r#"
        UPDATE bauth.sessions
        SET revoked_at = now()
        WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
        "#,
        user_id,
        keep
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
