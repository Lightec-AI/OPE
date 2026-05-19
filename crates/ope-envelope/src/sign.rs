use ope_crypto::{encode, sign, SecretKey};

use crate::canonical::{payload_hash, signing_bytes};
use crate::envelope::Envelope;
use crate::Error;

/// Sign an envelope in place (sets `payload_hash` and `sig`).
pub fn sign_envelope(envelope: &mut Envelope, secret: &SecretKey) -> Result<(), Error> {
    if envelope.enc == Envelope::ENC_NONE {
        if let Some(payload) = &envelope.payload {
            envelope.payload_hash = payload_hash(payload)?;
        }
    } else if envelope.payload_hash.is_empty() {
        return Err(Error::InvalidEnvelope(
            "encrypted envelope requires payload_hash before signing".into(),
        ));
    }

    let message = signing_bytes(envelope)?;
    let signature = sign(secret, &message);
    envelope.sig = Some(encode(&signature));
    Ok(())
}
