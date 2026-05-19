use crate::types::Attestation;
use crate::Error;

pub fn signing_bytes(att: &Attestation) -> Result<Vec<u8>, Error> {
    let mut obj = serde_json::json!({
        "ope_version": att.ope_version,
        "attester": att.attester,
        "kid": att.kid,
        "subject": att.subject,
        "claims": att.claims,
        "ts": att.ts,
        "exp": att.exp,
        "nonce": att.nonce,
    });
    if let Some(r) = &att.recipient {
        obj["recipient"] = serde_json::json!(r);
    }
    ope_envelope::canonical::canonicalize_json(&obj).map_err(|e| Error::Canonical(e.to_string()))
}
