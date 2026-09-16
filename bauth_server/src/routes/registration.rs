use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

use super::verification;
use crate::AppState;
use crate::email;
use crate::emails;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::password;
use crate::queries;
use crate::rate_limit::ClientIp;
use crate::rate_limit::{self};

#[derive(Deserialize, ToSchema)]
pub struct RegistrationRequest {
    client_id: String,
    email: String,
    password: String,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    VerificationSent,
}

#[derive(Serialize, ToSchema)]
pub struct RegistrationResponse {
    status: RegistrationStatus,
}

#[utoipa::path(
    post,
    path = "/registration",
    tag = "Registration",
    request_body = RegistrationRequest,
    responses(
        (status = 202, description = "Same answer whether the email is free or taken", body = RegistrationResponse),
        (status = 400, description = "`invalid_request`, `invalid_client`, `signup_disabled`, `invalid_email`, `password_too_short`, `password_too_long`", body = crate::errors::ErrorBody),
        (status = 429, description = "`rate_limited`", body = crate::errors::ErrorBody),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    client_ip: ClientIp,
    AppJson(input): AppJson<RegistrationRequest>,
) -> Result<(StatusCode, AppJson<RegistrationResponse>), ApiError> {
    state.rate_limits.email_per_ip.check(&client_ip.key())?;
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(ApiError::InvalidClient)?;
    if !client.allow_signup {
        return Err(ApiError::SignupDisabled);
    }
    if !email::is_valid(&input.email) {
        return Err(ApiError::InvalidEmail);
    }
    state
        .rate_limits
        .email_per_address
        .check(&rate_limit::email_key(&input.email))?;
    password::validate(&input.password)?;

    // Hash before touching the database: the expensive part costs the same
    // whether the email is free or taken, so timing doesn't reveal accounts.
    let password_hash = password::hash(input.password).await?;

    let mut tx = state.db.begin().await?;
    let email = match queries::users::create(&mut *tx, &input.email).await? {
        Some(user) => {
            queries::password_credentials::upsert(&mut *tx, user.id, &password_hash).await?;
            tracing::info!(user_id = %user.id, "user registered");
            verification::verification_email(
                &mut *tx,
                &state.config.verification_url,
                user.id,
                &user.email,
            )
            .await?
        }
        // Email taken: answer exactly as if it succeeded, but warn the real owner.
        None => match queries::users::find_by_email(&mut *tx, &input.email).await? {
            Some(user) => emails::account_already_exists(&user.email),
            None => {
                return Err(ApiError::Internal(
                    "user vanished during registration".into(),
                ));
            }
        },
    };
    tx.commit().await?;

    state.mailer.send_in_background(email);

    let response = RegistrationResponse {
        status: RegistrationStatus::VerificationSent,
    };
    Ok((StatusCode::ACCEPTED, AppJson(response)))
}
