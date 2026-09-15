use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
