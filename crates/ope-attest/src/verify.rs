use chrono::{DateTime, Utc};
use ope_crypto::{decode, verify, PublicKey};

use crate::canonical::signing_bytes;
use crate::types::Attestation;
use crate::Error;

pub fn verify_attestation(att: &Attestation, public: &PublicKey) -> Result<(), Error> {
    if att.ope_version != Attestation::VERSION {
        return Err(Error::UnsupportedVersion(att.ope_version.clone()));
    }
    let sig_b64 = att.sig.as_ref().ok_or(Error::InvalidSignature)?;
    let sig_bytes = decode(sig_b64).map_err(|_| Error::InvalidSignature)?;
    if sig_bytes.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let exp: DateTime<Utc> = att
        .exp
        .parse()
        .map_err(|_| Error::Expired("invalid exp".into()))?;
    if Utc::now() > exp {
        return Err(Error::Expired("attestation is expired".into()));
    }

    let message = signing_bytes(att)?;
    verify(public, &message, &sig_arr).map_err(|_| Error::InvalidSignature)?;
    Ok(())
}
