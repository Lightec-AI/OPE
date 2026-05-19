//! OPE L3: attestation and verification APIs (stub for P3).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("attestation not implemented")]
    NotImplemented,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationVerdict {
    pub verified: bool,
    pub decision: String,
}

/// Placeholder for `POST /v1/ope/verifications:verifyEnvelope`.
pub fn verify_envelope_stub() -> Result<VerificationVerdict, Error> {
    Err(Error::NotImplemented)
}
