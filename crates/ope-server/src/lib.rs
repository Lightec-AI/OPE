//! Axum HTTP server for `ope.md` §14 APIs.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use ope_attest::{CreateAttestationRequest, CreateAttestationResponse, MockAttester};
use ope_gateway::{GatewayConfig, GatewayError, verify_envelope_request};
use ope_http::{parse_content_type, CONTENT_TYPE_JSON};

#[derive(Clone)]
pub struct AppState {
    pub attester: Arc<MockAttester>,
    pub gateway: GatewayConfig,
    pub seen_nonces: Arc<Mutex<HashSet<(String, String)>>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/ope/attestations", post(create_attestation))
        .route("/v1/ope/verifications:verifyEnvelope", post(verify_envelope))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr) -> Result<(), std::io::Error> {
    let state = AppState {
        attester: Arc::new(MockAttester::default()),
        gateway: GatewayConfig::default(),
        seen_nonces: Arc::new(Mutex::new(HashSet::new())),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn create_attestation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAttestationRequest>,
) -> Result<(StatusCode, Json<CreateAttestationResponse>), ApiError> {
    ensure_json(&headers)?;
    match state.attester.create(req) {
        Ok(resp) => Ok((StatusCode::CREATED, Json(resp))),
        Err(ope_attest::Error::ReplayDetected) => Err(ApiError::status(
            StatusCode::CONFLICT,
            "ope_replay_detected",
            "nonce replay detected on attestation issuance",
        )),
        Err(e) => Err(ApiError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ope_attestation_invalid",
            &e.to_string(),
        )),
    }
}

async fn verify_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ope_attest::VerifyEnvelopeRequest>,
) -> Result<Json<ope_attest::VerificationVerdict>, ApiError> {
    ensure_json(&headers)?;
    let mut cache = state.seen_nonces.lock().unwrap();
    let verdict = verify_envelope_request(&req, &state.gateway, &mut cache)
        .map_err(|e| ApiError::from_gateway(e))?;
    Ok(Json(verdict))
}

fn ensure_json(headers: &HeaderMap) -> Result<(), ApiError> {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    parse_content_type(ct).map_err(|e| {
        ApiError::status(
            StatusCode::BAD_REQUEST,
            "ope_invalid_request",
            &e.to_string(),
        )
    })?;
    Ok(())
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: serde_json::Value,
}

impl ApiError {
    fn status(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({
                "error": { "code": code, "message": message }
            }),
        }
    }

    fn from_gateway(err: GatewayError) -> Self {
        Self::status(StatusCode::BAD_REQUEST, "ope_verification_failed", &err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            [(axum::http::header::CONTENT_TYPE, CONTENT_TYPE_JSON)],
            Json(self.body),
        )
            .into_response()
    }
}
