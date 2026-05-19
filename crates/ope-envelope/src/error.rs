use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ope crypto error: {0}")]
    Crypto(#[from] ope_crypto::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization error: {0}")]
    Canonical(String),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("unsupported ope_version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported alg: {0}")]
    UnsupportedAlg(String),
    #[error("unsupported enc: {0}")]
    UnsupportedEnc(String),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("replay detected for kid={kid} nonce={nonce}")]
    ReplayDetected { kid: String, nonce: String },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("payload hash mismatch")]
    PayloadHashMismatch,
    #[error("invalid model id: {0}")]
    InvalidModelId(String),
}
