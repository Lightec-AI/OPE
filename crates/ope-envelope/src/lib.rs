//! OPE L1: envelope format, JCS canonicalization, Ed25519 signatures.

mod canonical;
mod envelope;
mod error;
mod model;
mod sign;
mod verify;

pub use envelope::Envelope;
pub use error::Error;
pub use model::parse_routed_model;
pub use sign::sign_envelope;
pub use verify::{verify_envelope, VerifyOptions};
