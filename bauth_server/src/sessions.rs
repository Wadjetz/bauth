use chrono::TimeDelta;
use chrono::Utc;
use uuid::Uuid;

use crate::db::DbConnection;
use crate::queries;
use crate::token;

/// How long a login lasts before the user must enter their password again.
pub const SESSION_TTL: TimeDelta = TimeDelta::days(30);
/// A rotated refresh token still works this long without invalidating the tokens issued
/// from it, so two tabs refreshing at the same moment both keep a working token.
pub const REFRESH_REUSE_GRACE: TimeDelta = TimeDelta::seconds(30);

pub struct OpenedSession {
    pub session_id: Uuid,
    /// Opaque, give it to the app once. Only its hash is stored.
    pub refresh_token: String,
}

/// Opens a session and its first refresh token. Call inside the transaction that
/// consumes the authorization code, so both happen or neither does.
pub async fn open(
    conn: &mut DbConnection,
    user_id: Uuid,
    client_id: &str,
    authorization_code_id: Uuid,
) -> Result<OpenedSession, sqlx::Error> {
    let expires_at = Utc::now() + SESSION_TTL;
    let session_id = queries::sessions::create(
        &mut *conn,
        user_id,
        client_id,
        authorization_code_id,
        expires_at,
    )
    .await?;

    let refresh_token = new_refresh_token(conn, session_id, None).await?;
    Ok(OpenedSession {
        session_id,
        refresh_token,
    })
}

/// Adds a refresh token to the session and returns it. Only its hash is stored.
/// `parent_id` is the token it replaces, if any.
pub async fn new_refresh_token(
    conn: &mut DbConnection,
    session_id: Uuid,
    parent_id: Option<Uuid>,
) -> Result<String, sqlx::Error> {
    let refresh_token = token::generate();
    queries::refresh_tokens::create(&mut *conn, session_id, &refresh_token.hash, parent_id).await?;
    Ok(refresh_token.plain)
}
