//! HKDF bridge from hybrid shared secret toward TLS 1.3–style record keys (OPE profile).

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use crate::sizes::X25519MLKEM768_SHARED_SECRET_LEN;

#[derive(Debug, Clone)]
pub struct RecordKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub client_iv: [u8; 12],
    pub server_iv: [u8; 12],
}

#[derive(Debug, Error)]
pub enum HkdfError {
    #[error("invalid hybrid secret length (expected {X25519MLKEM768_SHARED_SECRET_LEN})")]
    InvalidSecretLength,
    #[error("hkdf expand failed")]
    ExpandFailed,
}

/// Derive AES-256-GCM record keys from the 64-byte `X25519MLKEM768` combined secret.
///
/// Labels follow an OPE-local profile aligned with TLS 1.3 key separation (client/server write).
/// Production stacks SHOULD use a full TLS 1.3 implementation; this API is for tests and gateways
/// that terminate OPE transport in-process.
pub fn derive_record_keys(
    hybrid_shared_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<RecordKeys, HkdfError> {
    if hybrid_shared_secret.len() != X25519MLKEM768_SHARED_SECRET_LEN {
        return Err(HkdfError::InvalidSecretLength);
    }

    let hk = Hkdf::<Sha256>::new(Some(b"ope-tls-extract"), hybrid_shared_secret);
    let mut info = Vec::with_capacity(16 + client_random.len() + server_random.len());
    info.extend_from_slice(b"ope record keys");
    info.extend_from_slice(client_random);
    info.extend_from_slice(server_random);
    let mut material = [0u8; 88];
    hk.expand(&info, &mut material)
        .map_err(|_| HkdfError::ExpandFailed)?;

    Ok(RecordKeys {
        client_write_key: material[0..32].try_into().unwrap(),
        server_write_key: material[32..64].try_into().unwrap(),
        client_iv: material[64..76].try_into().unwrap(),
        server_iv: material[76..88].try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let secret = [0xABu8; 64];
        let c = [1u8; 32];
        let s = [2u8; 32];
        let k1 = derive_record_keys(&secret, &c, &s).unwrap();
        let k2 = derive_record_keys(&secret, &c, &s).unwrap();
        assert_eq!(k1.client_write_key, k2.client_write_key);
        assert_ne!(k1.client_write_key, k1.server_write_key);
    }
}
