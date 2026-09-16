use chrono::DateTime;
use chrono::Utc;
use sqlx::Executor;
use uuid::Uuid;

use crate::db::Db;

/// `parent_id`: the token this one replaces, `None` for the first token of a session.
pub async fn create<'e, E>(
    executor: E,
    session_id: Uuid,
    token_hash: &[u8],
    parent_id: Option<Uuid>,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        INSERT INTO bauth.refresh_tokens (session_id, token_hash, parent_id)
        VALUES ($1, $2, $3)
        "#,
        session_id,
        token_hash,
        parent_id
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// A refresh token with the session it belongs to.
pub struct RefreshTokenWithSession {
    pub id: Uuid,
    pub rotated_at: Option<DateTime<Utc>>,
    pub superseded_at: Option<DateTime<Utc>>,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub session_expires_at: DateTime<Utc>,
    pub session_revoked_at: Option<DateTime<Utc>>,
}

/// Locks the token row until the transaction ends, so two concurrent refreshes
/// with the same token run one after the other instead of both seeing it unrotated.
pub async fn find_for_update<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<RefreshTokenWithSession>, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_as!(
        RefreshTokenWithSession,
        r#"
        SELECT r.id, r.rotated_at, r.superseded_at, s.id AS session_id, s.user_id, s.client_id,
               s.expires_at AS session_expires_at, s.revoked_at AS session_revoked_at
        FROM bauth.refresh_tokens r
        JOIN bauth.sessions s ON s.id = r.session_id
        WHERE r.token_hash = $1
        FOR UPDATE OF r
        "#,
        token_hash
    )
    .fetch_optional(executor)
    .await
}

pub async fn mark_rotated<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        UPDATE bauth.refresh_tokens SET rotated_at = now() WHERE id = $1 AND rotated_at IS NULL
        "#,
        id
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Has a token rotated from this one already been used? Then the app that did the rotation
/// received its response, and whoever presents this token again holds a stolen copy.
pub async fn has_used_successor<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM bauth.refresh_tokens
            WHERE parent_id = $1 AND rotated_at IS NOT NULL
        ) AS "used!"
        "#,
        id
    )
    .fetch_one(executor)
    .await
}

/// A retried refresh replaces the successors nobody used: they must never come back.
pub async fn supersede_unused_successors<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Db>,
{
    sqlx::query!(
        r#"
        UPDATE bauth.refresh_tokens
        SET superseded_at = now()
        WHERE parent_id = $1 AND rotated_at IS NULL AND superseded_at IS NULL
        "#,
        id
    )
    .execute(executor)
    .await?;
    Ok(())
}
