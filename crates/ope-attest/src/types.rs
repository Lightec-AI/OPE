use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    #[serde(flatten)]
    pub inner: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub ope_version: String,
    pub attester: String,
    pub kid: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub claims: Value,
    pub ts: String,
    pub exp: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttestationRequest {
    pub ope_version: String,
    pub kid: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub nonce: String,
    pub evidence: Value,
    pub requested_ttl_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttestationResponse {
    pub attestation_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub attestation: Attestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEnvelopeRequest {
    pub envelope: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationVerdict {
    pub verified: bool,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<VerificationCheck>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<VerificationError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Value>,
}

impl Attestation {
    pub const VERSION: &'static str = "1.0";
}
