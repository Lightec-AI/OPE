//! OPE L1: envelope format, JCS canonicalization, Ed25519 signatures.

pub mod canonical;
mod encrypt;
mod envelope;
mod error;
mod model;
#[cfg(feature = "verify-open")]
mod open;
mod sign;
#[cfg(feature = "transcript")]
mod transcript;
mod verify;

pub use encrypt::{decrypt_envelope, encrypt_envelope};
pub use envelope::Envelope;
pub use error::Error;
pub use model::parse_routed_model;
pub use sign::sign_envelope;
pub use verify::{verify_envelope, VerifyOptions};

/// RB-05: atomic verify → reserve → open. Additive; `verify_envelope` is unchanged.
#[cfg(feature = "verify-open")]
pub use open::{
    verify_and_open, Capability, KeyResolver, MemoryReplayStore, OpenError, OpenOptions,
    ReplayError, ReplayStore,
};

/// RB-06: signed response header plus hash-chained frames.
#[cfg(feature = "transcript")]
pub use transcript::{
    SignedTranscriptHeader, TranscriptError, TranscriptExpectations, TranscriptFrame,
    TranscriptHeader, TranscriptReader, TranscriptWriter, DOMAIN_FRAME, DOMAIN_HEADER,
    TRANSCRIPT_VERSION,
};
