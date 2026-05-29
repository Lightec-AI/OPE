//! Hybrid shared secrets for request (static engine) and response (ephemeral) directions.

use kem::Encapsulate;
use ml_kem::ml_kem_768::Ciphertext;
use ope_transport::{
    client_shared_secret, combine_shared_secrets, ClientKeyExchange, ServerKeyExchange,
    X25519_SHARE_LEN,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
// PublicKey used for deriving public bytes from ephemeral secret

use crate::identity::{parse_mlkem_encapsulation_key, EngineIdentity, EngineStaticSecret};
use crate::Error;

pub const DIRECTION_REQUEST: &[u8] = b"request";
pub const DIRECTION_RESPONSE: &[u8] = b"response";

/// Client → static engine: encapsulate to engine ML-KEM key + X25519 ECDH.
pub fn client_request_shared_secret(
    engine: &EngineIdentity,
    client_x25519_secret: [u8; X25519_SHARE_LEN],
) -> Result<([u8; 64], Vec<u8>), Error> {
    let encap_bytes = engine.mlkem_encap_bytes()?;
    let encap_key = parse_mlkem_encapsulation_key(&encap_bytes)?;
    let (ciphertext, mlkem_ss): (Ciphertext, _) = encap_key.encapsulate();

    let engine_x25519 = engine.x25519_public_bytes()?;
    let secret = StaticSecret::from(client_x25519_secret);
    let peer = X25519Public::from(engine_x25519);
    let x25519_ss = secret.diffie_hellman(&peer);

    let shared = combine_shared_secrets(mlkem_ss.as_ref(), x25519_ss.as_bytes());
    let ct_vec: Vec<u8> = ciphertext.iter().copied().collect();
    Ok((shared, ct_vec))
}

/// Engine → client ephemeral (streaming response).
pub fn engine_response_shared_secret(
    engine: &EngineStaticSecret,
    client: &ClientKeyExchange,
) -> Result<([u8; 64], ServerKeyExchange), Error> {
    engine.respond_to_client(client)
}

/// Client decrypt path for response.
pub fn client_response_shared_secret(
    client: &ClientKeyExchange,
    server: &ServerKeyExchange,
) -> Result<[u8; 64], Error> {
    client_shared_secret(client, server).map_err(Into::into)
}

/// Derive 32-byte AEAD key from hybrid secret + context.
pub fn derive_content_key(
    shared: &[u8; 64],
    direction: &[u8],
    engine_id: &str,
    kid: &str,
    nonce: &str,
) -> Result<[u8; 32], Error> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::new();
    info.extend_from_slice(b"OPE-E2E-v1");
    info.extend_from_slice(direction);
    info.extend_from_slice(engine_id.as_bytes());
    info.extend_from_slice(kid.as_bytes());
    info.extend_from_slice(nonce.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| Error::E2e("hkdf expand".into()))?;
    Ok(key)
}

/// Convenience: request key from engine identity + fresh client X25519 ephemeral.
pub fn derive_request_content_key(
    engine: &EngineIdentity,
    kid: &str,
    envelope_nonce: &str,
) -> Result<([u8; 32], [u8; X25519_SHARE_LEN], Vec<u8>), Error> {
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = *X25519Public::from(&x25519_secret).as_bytes();
    let (shared, mlkem_ct) = client_request_shared_secret(engine, x25519_secret.to_bytes())?;
    let key = derive_content_key(&shared, DIRECTION_REQUEST, &engine.engine_id, kid, envelope_nonce)?;
    Ok((key, x25519_public, mlkem_ct))
}

/// Convenience: response key for client session + server share.
pub fn derive_response_content_key(
    shared: &[u8; 64],
    engine_id: &str,
    kid: &str,
    envelope_nonce: &str,
) -> Result<[u8; 32], Error> {
    derive_content_key(shared, DIRECTION_RESPONSE, engine_id, kid, envelope_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::DEV_ENGINE_SEED;
    use crate::identity::ClientSession;

    #[test]
    fn request_static_roundtrip() {
        let (engine_secret, engine_pub) = crate::mock::mock_engine_from_seed(&DEV_ENGINE_SEED);

        let client_x25519_secret = [0x33u8; 32];
        let (shared, mlkem_ct) =
            client_request_shared_secret(&engine_pub, client_x25519_secret).unwrap();
        let client_x25519_public = x25519_dalek::PublicKey::from(&StaticSecret::from(
            client_x25519_secret,
        ));
        let server_shared = engine_secret
            .request_shared_secret(&mlkem_ct, *client_x25519_public.as_bytes())
            .unwrap();
        assert_eq!(shared, server_shared);
    }

    #[test]
    fn response_ephemeral_roundtrip() {
        let (engine_secret, _) = crate::mock::mock_engine_from_seed(&DEV_ENGINE_SEED);
        let client = ClientSession::generate().unwrap();
        let (server_shared, server) =
            engine_response_shared_secret(&engine_secret, &client.kex).unwrap();
        let client_shared = client_response_shared_secret(&client.kex, &server).unwrap();
        assert_eq!(server_shared, client_shared);
    }
}
