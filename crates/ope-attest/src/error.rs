use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("attestation not implemented")]
    NotImplemented,
    #[error("canonicalization error: {0}")]
    Canonical(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("attestation expired: {0}")]
    Expired(String),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("nonce replay detected")]
    ReplayDetected,
    #[error("envelope error: {0}")]
    Envelope(#[from] ope_envelope::Error),
    #[error("kid mismatch")]
    KidMismatch,
}
