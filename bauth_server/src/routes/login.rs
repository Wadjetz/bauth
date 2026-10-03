use axum::extract::State;
use axum::http::StatusCode;
use chrono::DateTime;
use chrono::TimeDelta;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::errors::ApiError;
use crate::errors::AppJson;
use crate::pkce;
use crate::queries;

const FLOW_TTL: TimeDelta = TimeDelta::minutes(15);
const MAX_STATE_LEN: usize = 512;

#[derive(Deserialize, ToSchema)]
pub struct CreateFlowRequest {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    /// Opaque value echoed back to the app with the code (CSRF protection on redirects).
    state: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    MagicLink,
}

#[derive(Serialize, ToSchema)]
pub struct FlowResponse {
    flow_id: Uuid,
    methods: Vec<LoginMethod>,
    expires_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/flows/login",
    tag = "Login",
    request_body = CreateFlowRequest,
    responses(
        (status = 201, description = "Flow started: show the screens for `methods`", body = FlowResponse),
        (status = 400, description = "`invalid_request`, `invalid_client`, `invalid_redirect_uri`, `invalid_code_challenge`", body = crate::errors::ErrorBody),
    )
)]
pub async fn create_flow(
    State(state): State<AppState>,
    AppJson(input): AppJson<CreateFlowRequest>,
) -> Result<(StatusCode, AppJson<FlowResponse>), ApiError> {
    let client = state
        .clients
        .get(&input.client_id)
        .ok_or(ApiError::InvalidClient)?;
    // Never redirect anywhere, not even to report an error, before this check passes.
    if !client.allows_redirect_uri(&input.redirect_uri) {
        return Err(ApiError::InvalidRedirectUri);
    }
    if input.code_challenge_method != "S256" || !pkce::is_valid_challenge(&input.code_challenge) {
        return Err(ApiError::InvalidCodeChallenge);
    }
    if input
        .state
        .as_ref()
        .is_some_and(|s| s.len() > MAX_STATE_LEN)
    {
        return Err(ApiError::InvalidRequest(format!(
            "state must be at most {MAX_STATE_LEN} bytes"
        )));
    }

    let expires_at = Utc::now() + FLOW_TTL;
    let flow_id = queries::login_flows::create(
        &state.db,
        &client.id,
        &input.redirect_uri,
        &input.code_challenge,
        input.state.as_deref(),
        expires_at,
    )
    .await?;

    let response = FlowResponse {
        flow_id,
        // Every client has a `magic_link_url`; Google will be optional.
        methods: vec![LoginMethod::MagicLink],
        expires_at,
    };
    Ok((StatusCode::CREATED, AppJson(response)))
}
