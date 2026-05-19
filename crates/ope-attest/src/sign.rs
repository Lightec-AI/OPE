use chrono::{Duration, Utc};
use ope_crypto::{encode, sign, SecretKey};

use crate::canonical::signing_bytes;
use crate::types::Attestation;
use crate::Error;

pub fn sign_attestation(att: &mut Attestation, secret: &SecretKey) -> Result<(), Error> {
    let message = signing_bytes(att)?;
    let signature = sign(secret, &message);
    att.sig = Some(encode(&signature));
    Ok(())
}

pub fn issue_attestation(
    attester_id: &str,
    kid: &str,
    subject: &str,
    recipient: Option<String>,
    claims: serde_json::Value,
    nonce: &str,
    ttl_sec: u64,
    secret: &SecretKey,
) -> Result<Attestation, Error> {
    let now = Utc::now();
    let exp = now + Duration::seconds(ttl_sec as i64);
    let mut att = Attestation {
        ope_version: Attestation::VERSION.into(),
        attester: attester_id.into(),
        kid: kid.into(),
        subject: subject.into(),
        recipient,
        claims,
        ts: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        exp: exp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        nonce: nonce.into(),
        sig: None,
    };
    sign_attestation(&mut att, secret)?;
    Ok(att)
}
