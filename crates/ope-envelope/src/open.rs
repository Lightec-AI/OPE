//! RB-05: atomic request admission — verify, reserve the nonce, then decrypt.
//!
//! [`verify_envelope`](crate::verify_envelope) leaves two things to the caller,
//! and both have bitten us:
//!
//!   1. **The replay check is not atomic.** It is handed a snapshot of the seen
//!      set and the caller inserts afterwards, so two concurrent copies of the
//!      same envelope can both observe "not seen" and both be admitted. A
//!      replay window that only opens under load is the kind that survives
//!      testing.
//!   2. **It decrypts while deciding.** When a content key is supplied the
//!      payload is decrypted inside the verification in order to check
//!      `payload_hash`, so a malformed or hostile envelope reaches the AEAD
//!      before every admission check has run.
//!
//! [`verify_and_open`] fixes the ordering rather than the checks. Nothing
//! touches ciphertext until the envelope is structurally sound, addressed to
//! this recipient, fresh, signed by a key this recipient already trusts for
//! that `kid`, and holding a nonce this recipient has just reserved. The
//! reservation happens *after* signature verification on purpose: reserving
//! first would let an unauthenticated sender burn arbitrary nonces and lock out
//! the real ones.
//!
//! The capability returned is the admission decision made concrete — a caller
//! that has one is holding proof that every gate passed, rather than a promise
//! that someone called the right function first.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use ope_crypto::{decode, verify, PublicKey};
use serde_json::Value;
use thiserror::Error;

use crate::canonical::{payload_hash, signing_bytes};
use crate::encrypt::decrypt_envelope;
use crate::envelope::Envelope;
use crate::model::parse_routed_model;
use crate::verify::verify_timestamp;
use crate::Error;

/// Recipient-side key material. Both lookups are the recipient's own policy:
/// an unknown `kid` is a refusal, never a wildcard.
pub trait KeyResolver {
    /// Sender verification key for `kid`, or `None` when this recipient does
    /// not accept that sender.
    fn sender_key(&self, kid: &str) -> Option<PublicKey>;

    /// Content key for recipient-local `enc`. Returning `None` for an encrypted
    /// envelope means this recipient cannot open it — which is the correct
    /// answer for a gateway relaying `e2e-hybrid-pq` to an engine.
    fn content_key(&self, _envelope: &Envelope) -> Option<[u8; 32]> {
        None
    }
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("nonce already used")]
    Duplicate,
    /// Store unreachable. Distinct from `Duplicate` because "cannot check" must
    /// fail closed without being reported as a detected replay.
    #[error("replay store unavailable: {0}")]
    Unavailable(String),
}

/// Single-use nonce reservation.
///
/// Implementations must make the "has it been seen / record it" pair atomic.
/// The signature takes `&self` so the lock lives inside the store and callers
/// cannot accidentally split the two halves across a scheduling boundary.
pub trait ReplayStore {
    fn reserve(&self, kid: &str, nonce: &str) -> Result<(), ReplayError>;
}

/// In-memory reservation store for a single process (tests, single-node dev).
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    seen: Mutex<HashSet<(String, String)>>,
}

impl MemoryReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayStore for MemoryReplayStore {
    fn reserve(&self, kid: &str, nonce: &str) -> Result<(), ReplayError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| ReplayError::Unavailable("replay store lock poisoned".into()))?;
        if seen.insert((kid.to_string(), nonce.to_string())) {
            Ok(())
        } else {
            Err(ReplayError::Duplicate)
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpenOptions {
    /// Allowed clock skew on `ts`.
    pub max_skew: Duration,
    /// Required `recipient` value. `None` disables the binding check, which is
    /// only appropriate for tooling.
    pub expected_recipient: Option<String>,
    /// Require `payload.model` (or `meta.model` when opaque) in routed form.
    pub require_routed_model: bool,
    /// Admit `e2e-hybrid-pq` without opening it (gateway relay position).
    pub allow_opaque_e2e: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            max_skew: Duration::from_secs(300),
            expected_recipient: None,
            require_routed_model: false,
            allow_opaque_e2e: false,
        }
    }
}

/// Proof that an envelope passed every admission gate, plus whatever plaintext
/// this recipient was able to open.
#[derive(Debug, Clone)]
pub struct Capability {
    pub kid: String,
    pub recipient: String,
    pub engine_id: Option<String>,
    pub nonce: String,
    pub ts: String,
    pub enc: String,
    /// `None` when the recipient relayed an opaque `e2e-hybrid-pq` envelope.
    pub payload: Option<Value>,
    /// Routed model id when one was required and found.
    pub model: Option<String>,
}

impl Capability {
    /// True when this recipient never held the plaintext.
    pub fn is_opaque(&self) -> bool {
        self.payload.is_none()
    }
}

#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Envelope(#[from] Error),
    #[error("no trusted key for kid {0}")]
    UnknownKid(String),
    #[error("replay detected for kid={kid} nonce={nonce}")]
    Replay { kid: String, nonce: String },
    #[error("replay store unavailable: {0}")]
    ReplayStoreUnavailable(String),
    #[error("recipient cannot open enc={0}")]
    NoContentKey(String),
}

impl OpenError {
    /// Stable code for logs and API error bodies.
    pub fn code(&self) -> &'static str {
        match self {
            OpenError::UnknownKid(_) => "ope_unknown_kid",
            OpenError::Replay { .. } => "ope_replay_detected",
            OpenError::ReplayStoreUnavailable(_) => "ope_replay_store_unavailable",
            OpenError::NoContentKey(_) => "ope_no_content_key",
            OpenError::Envelope(Error::InvalidRecipient { .. }) => "ope_invalid_recipient",
            OpenError::Envelope(Error::InvalidTimestamp(_)) => "ope_invalid_timestamp",
            OpenError::Envelope(Error::InvalidSignature) => "ope_invalid_signature",
            OpenError::Envelope(Error::PayloadHashMismatch) => "ope_payload_hash_mismatch",
            OpenError::Envelope(Error::InvalidModelId(_)) => "ope_invalid_model_id",
            OpenError::Envelope(Error::Decryption(_)) => "ope_decryption_failed",
            OpenError::Envelope(_) => "ope_verification_failed",
        }
    }
}

/// Verify, reserve, then open — in that order, with no plaintext produced
/// before the reservation succeeds.
pub fn verify_and_open<R: KeyResolver + ?Sized, S: ReplayStore + ?Sized>(
    envelope: &Envelope,
    key_resolver: &R,
    replay_store: &S,
    options: &OpenOptions,
) -> Result<Capability, OpenError> {
    // 1. Shape. Everything below assumes the required fields for this `enc` are
    //    present, including `sig`.
    envelope.validate_structure()?;

    // 2. Recipient binding, before anything expensive: an envelope addressed
    //    elsewhere is not this recipient's to judge, and relaying it as if it
    //    were is the substitution RB-05 is about.
    if let Some(expected) = &options.expected_recipient {
        if &envelope.recipient != expected {
            return Err(Error::InvalidRecipient {
                expected: expected.clone(),
                actual: envelope.recipient.clone(),
            }
            .into());
        }
    }

    // 3. Freshness. A stale envelope is refused whether or not its signature is
    //    good — a captured-and-held request is exactly what the window bounds.
    verify_timestamp(&envelope.ts, options.max_skew)?;

    // 4. Sender key by kid. No wildcard fallback: if this recipient has no key
    //    for the kid, there is no sender it is willing to admit.
    let public = key_resolver
        .sender_key(&envelope.kid)
        .ok_or_else(|| OpenError::UnknownKid(envelope.kid.clone()))?;

    // 5. Signature over the canonical signed fields.
    let sig_b64 = envelope.sig.as_ref().ok_or(Error::InvalidSignature)?;
    let sig_bytes = decode(sig_b64).map_err(|_| Error::InvalidSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let message = signing_bytes(envelope)?;
    verify(&public, &message, &sig_arr).map_err(|_| Error::InvalidSignature)?;

    // 6. Reserve the nonce, atomically, and only now that the envelope is known
    //    to come from a trusted sender. Reserving before step 5 would let any
    //    unauthenticated party burn a nonce and have the genuine request
    //    rejected as a replay.
    //
    //    A failure after this point does not release the reservation: the
    //    envelope was authentic and single-use, so a retry of the same bytes
    //    must still be refused.
    match replay_store.reserve(&envelope.kid, &envelope.nonce) {
        Ok(()) => {}
        Err(ReplayError::Duplicate) => {
            return Err(OpenError::Replay {
                kid: envelope.kid.clone(),
                nonce: envelope.nonce.clone(),
            })
        }
        Err(ReplayError::Unavailable(why)) => return Err(OpenError::ReplayStoreUnavailable(why)),
    }

    // 7. Plaintext. First point at which any ciphertext is touched.
    let opaque = envelope.enc == Envelope::ENC_E2E_HYBRID_PQ && options.allow_opaque_e2e;
    let payload = if envelope.enc == Envelope::ENC_NONE {
        envelope.payload.clone()
    } else if opaque {
        None
    } else {
        let key = key_resolver
            .content_key(envelope)
            .ok_or_else(|| OpenError::NoContentKey(envelope.enc.clone()))?;
        Some(decrypt_envelope(envelope, &key)?)
    };

    // 8. Bind the plaintext to what was signed. The signature covers
    //    `payload_hash`, so this is what stops a swapped ciphertext under an
    //    authentic header.
    let mut model = None;
    if let Some(payload) = &payload {
        if payload_hash(payload)? != envelope.payload_hash {
            return Err(Error::PayloadHashMismatch.into());
        }
        if options.require_routed_model {
            let raw = payload
                .get("model")
                .and_then(|m| m.as_str())
                .ok_or_else(|| Error::InvalidModelId("payload.model missing".into()))?;
            parse_routed_model(raw)?;
            model = Some(raw.to_string());
        }
    } else if options.require_routed_model {
        let raw = envelope
            .meta
            .as_ref()
            .and_then(|m| m.get("model"))
            .and_then(|m| m.as_str())
            .ok_or_else(|| Error::InvalidModelId("meta.model missing for opaque e2e".into()))?;
        parse_routed_model(raw)?;
        model = Some(raw.to_string());
    }

    Ok(Capability {
        kid: envelope.kid.clone(),
        recipient: envelope.recipient.clone(),
        engine_id: envelope.engine_id.clone(),
        nonce: envelope.nonce.clone(),
        ts: envelope.ts.clone(),
        enc: envelope.enc.clone(),
        payload,
        model,
    })
}
