//! OPE L1: envelope format, JCS canonicalization, Ed25519 signatures.

pub mod canonical;
mod encrypt;
mod envelope;
mod error;
mod model;
mod sign;
mod verify;

pub use envelope::Envelope;
pub use error::Error;
pub use model::parse_routed_model;
pub use encrypt::{decrypt_envelope, encrypt_envelope};
pub use sign::sign_envelope;
pub use verify::{verify_envelope, VerifyOptions};
