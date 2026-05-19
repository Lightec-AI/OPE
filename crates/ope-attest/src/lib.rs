//! OPE L3: attestation issuance and verification (`ope.md` §14).

mod canonical;
mod error;
mod mock;
mod sign;
mod types;
mod verify;

pub use error::Error;
pub use mock::{allow_verdict, checks_from_results, deny_verdict, MockAttester};
pub use sign::{issue_attestation, sign_attestation};
pub use types::{
    Attestation, CreateAttestationRequest, CreateAttestationResponse, VerificationCheck,
    VerificationError, VerificationVerdict, VerifyEnvelopeRequest,
};
pub use verify::verify_attestation;
