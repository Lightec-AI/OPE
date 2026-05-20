//! ChaCha20-Poly1305 streaming chunks (`chacha20poly1305-stream`).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ope_crypto::encode;

use crate::Error;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Encrypt one stream chunk; `seq` mixed into first 4 bytes of `iv_base`.
pub fn encrypt_chunk(
    key: &[u8; 32],
    iv_base: &[u8; NONCE_LEN],
    seq: u32,
    plaintext: &[u8],
) -> Result<String, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = chunk_nonce(iv_base, seq);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &seq.to_be_bytes(),
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(encode(&ct))
}

/// Decrypt one stream chunk.
pub fn decrypt_chunk(
    key: &[u8; 32],
    iv_base: &[u8; NONCE_LEN],
    seq: u32,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, Error> {
    let ct = ope_crypto::decode(ciphertext_b64)
        .map_err(|_| Error::E2e("chunk ciphertext".into()))?;
    if ct.len() < TAG_LEN {
        return Err(Error::E2e("chunk too short".into()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let nonce = chunk_nonce(iv_base, seq);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ct,
                aad: &seq.to_be_bytes(),
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))
}

fn chunk_nonce(iv_base: &[u8; NONCE_LEN], seq: u32) -> Nonce {
    let mut n = *iv_base;
    n[0..4].copy_from_slice(&seq.to_be_bytes());
    Nonce::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let key = [7u8; 32];
        let iv = [1u8; 12];
        let ct = encrypt_chunk(&key, &iv, 0, b"hello stream").unwrap();
        let pt = decrypt_chunk(&key, &iv, 0, &ct).unwrap();
        assert_eq!(pt, b"hello stream");
    }
}
