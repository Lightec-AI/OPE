//! RB-06: authenticated response transcript — a signed header plus a hash chain
//! over the frames that follow it.
//!
//! An OPE response today is a sequence of independently encrypted frames whose
//! only ordering is a `seq` integer the relay could rewrite. Each frame's AEAD
//! proves *that frame* came from a holder of the session key; nothing proves the
//! sequence is the one the engine produced. A relay can therefore drop the tail,
//! duplicate a frame, reorder two, or splice frames from a different response to
//! the same client, and every individual frame still authenticates.
//!
//! The shape here is deliberately small:
//!
//!   - **One signature, at the front.** The header names the request the
//!     transcript answers, and it is signed before any frame exists. A client
//!     that cannot verify the header never processes a frame — that is the
//!     verify-before-first-frame property, and it is enforced by construction:
//!     [`TranscriptReader`] is only obtainable from a verified header.
//!   - **A hash chain, not per-frame signatures.** Each link commits to the
//!     previous one, the frame's position, whether it is the last, and the
//!     frame bytes. Substitution, reorder, duplication, and injection all break
//!     the chain at the first offending frame; truncation is caught because the
//!     stream is not complete until a frame marked final has been accepted.
//!   - **Domain separation on both hashes**, so a header digest can never be
//!     replayed as a frame digest, or the reverse.
//!
//! This is the transport skeleton. It does not encrypt (frames arrive already
//! sealed by the session AEAD) and it does not itself carry usage accounting —
//! both belong to layers that can now assume an ordered, complete stream.

use ope_crypto::{decode, encode, sha256, sign, verify, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::canonical::canonicalize_json;

pub const TRANSCRIPT_VERSION: &str = "1.0";

/// Domain tag for the header signature and the first chain link.
pub const DOMAIN_HEADER: &[u8] = b"OPE-RESPONSE-TRANSCRIPT-HEADER-v1";
/// Domain tag for every subsequent chain link.
pub const DOMAIN_FRAME: &[u8] = b"OPE-RESPONSE-TRANSCRIPT-FRAME-v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TranscriptError {
    #[error("unsupported transcript version: {0}")]
    UnsupportedVersion(String),
    #[error("invalid transcript header signature")]
    InvalidHeaderSignature,
    #[error("transcript answers request {actual}, expected {expected}")]
    RequestMismatch { expected: String, actual: String },
    #[error("transcript is from engine {actual}, expected {expected}")]
    EngineMismatch { expected: String, actual: String },
    #[error("transcript is for epoch {actual}, expected {expected}")]
    EpochMismatch { expected: String, actual: String },
    #[error("frame out of order: expected seq {expected}, got {actual}")]
    OutOfOrder { expected: u64, actual: u64 },
    #[error("frame {seq} chain value does not match the transcript")]
    ChainMismatch { seq: u64 },
    #[error("frame {seq} arrived after the final frame")]
    AfterFinal { seq: u64 },
    #[error("transcript ended after {received} frames without a final frame")]
    Truncated { received: u64 },
    #[error("invalid base64url in {0}")]
    InvalidEncoding(&'static str),
    #[error("canonicalization error: {0}")]
    Canonical(String),
}

/// What the response is an answer to. Every field is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptHeader {
    pub ope_transcript: String,
    /// The request nonce this transcript answers — what stops a genuine
    /// response to one request being replayed as the answer to another.
    pub request_nonce: String,
    pub engine_id: String,
    pub epoch_id: String,
    /// AEAD used for the frame payloads, so a downgrade is visible in the
    /// signed header rather than inferred per frame.
    pub content_alg: String,
}

impl TranscriptHeader {
    pub fn new(
        request_nonce: impl Into<String>,
        engine_id: impl Into<String>,
        epoch_id: impl Into<String>,
        content_alg: impl Into<String>,
    ) -> Self {
        Self {
            ope_transcript: TRANSCRIPT_VERSION.to_string(),
            request_nonce: request_nonce.into(),
            engine_id: engine_id.into(),
            epoch_id: epoch_id.into(),
            content_alg: content_alg.into(),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TranscriptError> {
        let value = json!({
            "ope_transcript": self.ope_transcript,
            "request_nonce": self.request_nonce,
            "engine_id": self.engine_id,
            "epoch_id": self.epoch_id,
            "content_alg": self.content_alg,
        });
        canonicalize_json(&value).map_err(|e| TranscriptError::Canonical(e.to_string()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, TranscriptError> {
        let mut out = Vec::from(DOMAIN_HEADER);
        out.push(0x00);
        out.extend_from_slice(&self.canonical_bytes()?);
        Ok(out)
    }

    /// First chain link. Bound to the same bytes the signature covers, so a
    /// frame chain cannot be re-anchored onto a different header.
    fn genesis(&self) -> Result<[u8; 32], TranscriptError> {
        Ok(sha256(&self.signing_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTranscriptHeader {
    #[serde(flatten)]
    pub header: TranscriptHeader,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptFrame {
    pub seq: u64,
    /// Frame payload as it goes on the wire (already sealed by the session AEAD).
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not", rename = "final")]
    pub final_: bool,
    /// Chain value after this frame, base64url.
    pub chain: String,
}

fn link(previous: &[u8; 32], seq: u64, final_: bool, ciphertext: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DOMAIN_FRAME.len() + 32 + 9 + ciphertext.len());
    buf.extend_from_slice(DOMAIN_FRAME);
    buf.push(0x00);
    buf.extend_from_slice(previous);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.push(u8::from(final_));
    buf.extend_from_slice(ciphertext);
    sha256(&buf)
}

/// Engine side: sign the header once, then chain each frame as it is produced.
#[derive(Debug)]
pub struct TranscriptWriter {
    chain: [u8; 32],
    next_seq: u64,
    closed: bool,
}

impl TranscriptWriter {
    /// Sign the header and open the chain. The signature exists before the
    /// first frame does, which is what lets the client verify before consuming.
    pub fn begin(
        header: TranscriptHeader,
        secret: &SecretKey,
    ) -> Result<(SignedTranscriptHeader, Self), TranscriptError> {
        let sig = sign(secret, &header.signing_bytes()?);
        let chain = header.genesis()?;
        Ok((
            SignedTranscriptHeader {
                header,
                sig: encode(&sig),
            },
            Self {
                chain,
                next_seq: 0,
                closed: false,
            },
        ))
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Append a frame. Returns the wire frame including its chain value.
    pub fn push(
        &mut self,
        ciphertext: &[u8],
        final_: bool,
    ) -> Result<TranscriptFrame, TranscriptError> {
        if self.closed {
            return Err(TranscriptError::AfterFinal { seq: self.next_seq });
        }
        let seq = self.next_seq;
        self.chain = link(&self.chain, seq, final_, ciphertext);
        self.next_seq += 1;
        self.closed = final_;
        Ok(TranscriptFrame {
            seq,
            ciphertext: encode(ciphertext),
            final_,
            chain: encode(&self.chain),
        })
    }
}

/// What the client already knows about the response it asked for.
#[derive(Debug, Clone, Default)]
pub struct TranscriptExpectations {
    pub request_nonce: Option<String>,
    pub engine_id: Option<String>,
    pub epoch_id: Option<String>,
}

/// Client side. Only obtainable from a header that verified, so there is no
/// call order in which a frame is processed before the signature is checked.
#[derive(Debug)]
pub struct TranscriptReader {
    chain: [u8; 32],
    next_seq: u64,
    complete: bool,
    header: TranscriptHeader,
}

impl TranscriptReader {
    pub fn begin(
        signed: &SignedTranscriptHeader,
        public: &PublicKey,
        expected: &TranscriptExpectations,
    ) -> Result<Self, TranscriptError> {
        if signed.header.ope_transcript != TRANSCRIPT_VERSION {
            return Err(TranscriptError::UnsupportedVersion(
                signed.header.ope_transcript.clone(),
            ));
        }
        let sig_bytes = decode(&signed.sig).map_err(|_| TranscriptError::InvalidHeaderSignature)?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TranscriptError::InvalidHeaderSignature)?;
        verify(public, &signed.header.signing_bytes()?, &sig)
            .map_err(|_| TranscriptError::InvalidHeaderSignature)?;

        // A signature by the right engine over the wrong request is still a
        // relay substituting one answer for another.
        if let Some(expected_nonce) = &expected.request_nonce {
            if &signed.header.request_nonce != expected_nonce {
                return Err(TranscriptError::RequestMismatch {
                    expected: expected_nonce.clone(),
                    actual: signed.header.request_nonce.clone(),
                });
            }
        }
        if let Some(engine) = &expected.engine_id {
            if &signed.header.engine_id != engine {
                return Err(TranscriptError::EngineMismatch {
                    expected: engine.clone(),
                    actual: signed.header.engine_id.clone(),
                });
            }
        }
        if let Some(epoch) = &expected.epoch_id {
            if &signed.header.epoch_id != epoch {
                return Err(TranscriptError::EpochMismatch {
                    expected: epoch.clone(),
                    actual: signed.header.epoch_id.clone(),
                });
            }
        }

        Ok(Self {
            chain: signed.header.genesis()?,
            next_seq: 0,
            complete: false,
            header: signed.header.clone(),
        })
    }

    pub fn header(&self) -> &TranscriptHeader {
        &self.header
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn frames_accepted(&self) -> u64 {
        self.next_seq
    }

    /// Accept the next frame, returning its ciphertext bytes for decryption.
    ///
    /// The chain is only advanced when the frame is accepted, so a rejected
    /// frame leaves the reader able to receive the genuine one — a client that
    /// retries a stream is not punished for a relay's injection.
    pub fn accept(&mut self, frame: &TranscriptFrame) -> Result<Vec<u8>, TranscriptError> {
        if self.complete {
            return Err(TranscriptError::AfterFinal { seq: frame.seq });
        }
        if frame.seq != self.next_seq {
            return Err(TranscriptError::OutOfOrder {
                expected: self.next_seq,
                actual: frame.seq,
            });
        }
        let ciphertext = decode(&frame.ciphertext)
            .map_err(|_| TranscriptError::InvalidEncoding("ciphertext"))?;
        let expected_chain = link(&self.chain, frame.seq, frame.final_, &ciphertext);
        let declared =
            decode(&frame.chain).map_err(|_| TranscriptError::InvalidEncoding("chain"))?;
        if declared.as_slice() != expected_chain.as_slice() {
            return Err(TranscriptError::ChainMismatch { seq: frame.seq });
        }

        self.chain = expected_chain;
        self.next_seq += 1;
        self.complete = frame.final_;
        Ok(ciphertext)
    }

    /// Refuse a stream that stopped without a final frame.
    pub fn finish(&self) -> Result<(), TranscriptError> {
        if self.complete {
            Ok(())
        } else {
            Err(TranscriptError::Truncated {
                received: self.next_seq,
            })
        }
    }
}
