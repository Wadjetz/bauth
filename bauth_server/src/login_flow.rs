use chrono::{TimeDelta, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::DbConnection;
use crate::queries;
use crate::token;

const CODE_TTL: TimeDelta = TimeDelta::seconds(60);

/// What a login method returns once the user is authenticated.
#[derive(Serialize, ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginResponse {
    /// Exchange `code` on `/oauth/token` with the PKCE `code_verifier`.
    Completed { code: String },
}

/// Marks the flow completed and issues its authorization code, whatever the login method.
/// `None` if the flow expired or was completed concurrently.
pub async fn complete(
    conn: &mut DbConnection,
    flow_id: Uuid,
    user_id: Uuid,
) -> Result<Option<LoginResponse>, sqlx::Error> {
    if !queries::login_flows::complete(&mut *conn, flow_id).await? {
        return Ok(None);
    }
    let code = token::generate();
    queries::authorization_codes::create(
        &mut *conn,
        &code.hash,
        flow_id,
        user_id,
        Utc::now() + CODE_TTL,
    )
    .await?;
    Ok(Some(LoginResponse::Completed { code: code.plain }))
}
