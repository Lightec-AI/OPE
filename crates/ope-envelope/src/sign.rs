use ope_crypto::{encode, sign, SecretKey};

use crate::canonical::{payload_hash, signing_bytes};
use crate::envelope::Envelope;
use crate::Error;

/// Sign an envelope in place (sets `payload_hash` and `sig`).
pub fn sign_envelope(envelope: &mut Envelope, secret: &SecretKey) -> Result<(), Error> {
    if let Some(payload) = &envelope.payload {
        envelope.payload_hash = payload_hash(payload)?;
    }

    let message = signing_bytes(envelope)?;
    let signature = sign(secret, &message);
    envelope.sig = Some(encode(&signature));
    Ok(())
}
