use ope_crypto::{decode, encrypt, encode, EncMode, AeadError};
use rand::RngCore;
use serde_json::Value;

use crate::canonical::payload_hash;
use crate::envelope::Envelope;
use crate::Error;

/// Encrypt `payload` in place: sets `payload_hash`, `ciphertext`, `iv`, clears `payload`.
pub fn encrypt_envelope(
    envelope: &mut Envelope,
    content_key: &[u8; 32],
) -> Result<(), Error> {
    let mode = EncMode::parse(&envelope.enc).map_err(|e| Error::Encryption(e.to_string()))?;
    let payload = envelope
        .payload
        .take()
        .ok_or_else(|| Error::InvalidEnvelope("encrypt requires payload".into()))?;

    envelope.payload_hash = payload_hash(&payload)?;
    let plaintext = serde_json::to_vec(&payload).map_err(|e| Error::Encryption(e.to_string()))?;

    let mut iv = vec![0u8; mode.iv_len()];
    rand::thread_rng().fill_bytes(&mut iv);

    let ct = encrypt(mode, content_key, &iv, &plaintext)
        .map_err(|e| Error::Encryption(e.to_string()))?;

    envelope.iv = Some(encode(&iv));
    envelope.ciphertext = Some(encode(&ct));
    Ok(())
}

/// Decrypt ciphertext into JSON `payload` (caller should verify `payload_hash` after).
pub fn decrypt_envelope(envelope: &Envelope, content_key: &[u8; 32]) -> Result<Value, Error> {
    let mode = EncMode::parse(&envelope.enc).map_err(|e| Error::Decryption(e.to_string()))?;
    let iv_b64 = envelope
        .iv
        .as_ref()
        .ok_or_else(|| Error::Decryption("missing iv".into()))?;
    let ct_b64 = envelope
        .ciphertext
        .as_ref()
        .ok_or_else(|| Error::Decryption("missing ciphertext".into()))?;

    let iv = decode(iv_b64).map_err(|_| Error::Decryption("invalid iv encoding".into()))?;
    let ct = decode(ct_b64).map_err(|_| Error::Decryption("invalid ciphertext encoding".into()))?;

    let plaintext = decrypt_payload(mode, content_key, &iv, &ct)?;
    let payload: Value =
        serde_json::from_slice(&plaintext).map_err(|e| Error::Decryption(e.to_string()))?;
    Ok(payload)
}

fn decrypt_payload(
    mode: EncMode,
    key: &[u8; 32],
    iv: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, Error> {
    ope_crypto::decrypt(mode, key, iv, ct).map_err(|e: AeadError| Error::Decryption(e.to_string()))
}
