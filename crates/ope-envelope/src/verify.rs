use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use ope_crypto::{decode, verify, PublicKey};

use crate::canonical::{payload_hash, signing_bytes};
use crate::envelope::Envelope;
use crate::Error;

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Allowed clock skew (default 300s).
    pub max_skew: Duration,
    /// If set, reject duplicate (kid, nonce) pairs.
    pub seen_nonces: Option<HashSet<(String, String)>>,
}

impl VerifyOptions {
    pub fn with_defaults() -> Self {
        Self {
            max_skew: Duration::from_secs(300),
            seen_nonces: None,
        }
    }
}

/// Verify envelope structure, freshness, optional replay cache, payload hash, and signature.
pub fn verify_envelope(
    envelope: &Envelope,
    public: &PublicKey,
    options: &VerifyOptions,
) -> Result<(), Error> {
    envelope.validate_structure()?;

    verify_timestamp(&envelope.ts, options.max_skew)?;

    if let Some(cache) = &options.seen_nonces {
        let key = (envelope.kid.clone(), envelope.nonce.clone());
        if cache.contains(&key) {
            return Err(Error::ReplayDetected {
                kid: envelope.kid.clone(),
                nonce: envelope.nonce.clone(),
            });
        }
    }

    if let Some(payload) = &envelope.payload {
        let expected = payload_hash(payload)?;
        if expected != envelope.payload_hash {
            return Err(Error::PayloadHashMismatch);
        }
    }

    let sig_b64 = envelope.sig.as_ref().unwrap();
    let sig_bytes = decode(sig_b64).map_err(|_| Error::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let message = signing_bytes(envelope)?;
    verify(public, &message, &sig_arr).map_err(|_| Error::InvalidSignature)?;

    Ok(())
}

fn verify_timestamp(ts: &str, max_skew: Duration) -> Result<(), Error> {
    let parsed: DateTime<Utc> = ts
        .parse()
        .map_err(|_| Error::InvalidTimestamp(format!("invalid RFC3339: {ts}")))?;
    let envelope_time = SystemTime::from(parsed);
    let now = SystemTime::now();
    let skew = now
        .duration_since(envelope_time)
        .or_else(|_| envelope_time.duration_since(now))
        .unwrap_or(Duration::ZERO);
    if skew > max_skew {
        return Err(Error::InvalidTimestamp(format!(
            "ts outside ±{}s window",
            max_skew.as_secs()
        )));
    }
    Ok(())
}
