use kem::{Decapsulate, Encapsulate};
use ml_kem::{array::Array, Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::Error;
use crate::sizes::{
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN, MLKEM768_SHARED_SECRET_LEN,
    X25519MLKEM768_CLIENT_SHARE_LEN, X25519MLKEM768_SERVER_SHARE_LEN,
    X25519MLKEM768_SHARED_SECRET_LEN, X25519_SHARE_LEN,
};

type DecapsKey = <MlKem768 as KemCore>::DecapsulationKey;
type EncapsKey = <MlKem768 as KemCore>::EncapsulationKey;
/// Client `key_exchange` share: `ML-KEM encapsulation key || X25519 ephemeral public`.
pub struct ClientKeyExchange {
    pub bytes: Vec<u8>,
    decaps_secret: DecapsKey,
    x25519_private: [u8; X25519_SHARE_LEN],
}

impl ClientKeyExchange {
    /// Generate a fresh client share (ephemeral).
    pub fn generate() -> Result<Self, Error> {
        let (decaps_secret, encap_key) = MlKem768::generate(&mut OsRng);
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let x25519_private = x25519_secret.to_bytes();

        let encap_bytes = encap_key.as_bytes();
        let mut bytes = Vec::with_capacity(X25519MLKEM768_CLIENT_SHARE_LEN);
        bytes.extend_from_slice(encap_bytes.as_slice());
        bytes.extend_from_slice(x25519_public.as_bytes());

        if bytes.len() != X25519MLKEM768_CLIENT_SHARE_LEN {
            return Err(Error::InvalidShareLength {
                expected: X25519MLKEM768_CLIENT_SHARE_LEN,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            bytes,
            decaps_secret,
            x25519_private,
        })
    }
}

/// Server `key_exchange` share: `ML-KEM ciphertext || X25519 ephemeral public`.
pub struct ServerKeyExchange {
    pub bytes: Vec<u8>,
}

impl ServerKeyExchange {
    /// Process client share and produce server share + combined shared secret.
    pub fn respond_to(
        client: &ClientKeyExchange,
    ) -> Result<(Self, [u8; X25519MLKEM768_SHARED_SECRET_LEN]), Error> {
        let encap_key = parse_encapsulation_key(&client.bytes[..MLKEM768_ENCAPSULATION_KEY_LEN])?;
        let client_x25519_bytes: [u8; X25519_SHARE_LEN] = client.bytes
            [MLKEM768_ENCAPSULATION_KEY_LEN..]
            .try_into()
            .map_err(|_| Error::InvalidShareLength {
                expected: X25519_SHARE_LEN,
                actual: client.bytes.len() - MLKEM768_ENCAPSULATION_KEY_LEN,
            })?;

        let (ciphertext, mlkem_ss) = encap_key
            .encapsulate(&mut OsRng)
            .map_err(|e| Error::MlKem(format!("encapsulate: {e:?}")))?;

        let server_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let server_x25519_public = X25519Public::from(&server_x25519_secret);
        let client_x25519_public = X25519Public::from(client_x25519_bytes);
        let x25519_ss = server_x25519_secret.diffie_hellman(&client_x25519_public);

        let mut bytes = Vec::with_capacity(X25519MLKEM768_SERVER_SHARE_LEN);
        bytes.extend_from_slice(ciphertext.as_slice());
        bytes.extend_from_slice(server_x25519_public.as_bytes());

        let shared = combine_shared_secrets(mlkem_ss.as_slice(), x25519_ss.as_bytes());
        Ok((Self { bytes }, shared))
    }
}

/// Client-side shared secret from server share.
pub fn client_shared_secret(
    client: &ClientKeyExchange,
    server: &ServerKeyExchange,
) -> Result<[u8; X25519MLKEM768_SHARED_SECRET_LEN], Error> {
    if server.bytes.len() != X25519MLKEM768_SERVER_SHARE_LEN {
        return Err(Error::InvalidShareLength {
            expected: X25519MLKEM768_SERVER_SHARE_LEN,
            actual: server.bytes.len(),
        });
    }

    let ciphertext = parse_ciphertext(&server.bytes[..MLKEM768_CIPHERTEXT_LEN])?;
    let server_x25519_bytes: [u8; X25519_SHARE_LEN] = server.bytes[MLKEM768_CIPHERTEXT_LEN..]
        .try_into()
        .map_err(|_| Error::InvalidShareLength {
            expected: X25519_SHARE_LEN,
            actual: server.bytes.len() - MLKEM768_CIPHERTEXT_LEN,
        })?;

    let mlkem_ss = client
        .decaps_secret
        .decapsulate(&ciphertext)
        .map_err(|e| Error::MlKem(format!("decapsulate: {e:?}")))?;

    let server_x25519_public = X25519Public::from(server_x25519_bytes);
    let x25519_ss =
        StaticSecret::from(client.x25519_private).diffie_hellman(&server_x25519_public);

    Ok(combine_shared_secrets(
        mlkem_ss.as_slice(),
        x25519_ss.as_bytes(),
    ))
}

fn parse_encapsulation_key(bytes: &[u8]) -> Result<EncapsKey, Error> {
    if bytes.len() != MLKEM768_ENCAPSULATION_KEY_LEN {
        return Err(Error::InvalidShareLength {
            expected: MLKEM768_ENCAPSULATION_KEY_LEN,
            actual: bytes.len(),
        });
    }
    let encoded: Encoded<EncapsKey> = Array::clone_from_slice(bytes);
    Ok(EncapsKey::from_bytes(&encoded))
}

/// Parse a BoringSSL / NIST-encoded ML-KEM-768 decapsulation key (2400 bytes).
pub fn parse_decapsulation_key(bytes: &[u8]) -> Result<DecapsKey, Error> {
    const DECAPS_LEN: usize = 2400;
    if bytes.len() != DECAPS_LEN {
        return Err(Error::InvalidShareLength {
            expected: DECAPS_LEN,
            actual: bytes.len(),
        });
    }
    let encoded: Encoded<DecapsKey> = Array::clone_from_slice(bytes);
    Ok(DecapsKey::from_bytes(&encoded))
}

/// Decapsulate ML-KEM-768 ciphertext with a decapsulation key (BoringSSL ACVP vectors).
pub fn mlkem_decapsulate(
    decaps_secret: &DecapsKey,
    ciphertext: &[u8],
) -> Result<[u8; MLKEM768_SHARED_SECRET_LEN], Error> {
    let ct = parse_ciphertext(ciphertext)?;
    let ss = decaps_secret
        .decapsulate(&ct)
        .map_err(|e| Error::MlKem(format!("decapsulate: {e:?}")))?;
    let mut out = [0u8; MLKEM768_SHARED_SECRET_LEN];
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

/// RFC 7748-style X25519 DH: `X25519(private, peer_public)`.
pub fn x25519_shared_secret(
    private: [u8; X25519_SHARE_LEN],
    peer_public: [u8; X25519_SHARE_LEN],
) -> [u8; X25519_SHARE_LEN] {
    let secret = StaticSecret::from(private);
    let peer = X25519Public::from(peer_public);
    *secret.diffie_hellman(&peer).as_bytes()
}

/// Build client state from official test vector material (hybrid / negative tests).
pub fn client_from_test_material(
    decapsulation_key: &[u8],
    client_share: &[u8],
    x25519_private: [u8; X25519_SHARE_LEN],
) -> Result<ClientKeyExchange, Error> {
    if client_share.len() != X25519MLKEM768_CLIENT_SHARE_LEN {
        return Err(Error::InvalidShareLength {
            expected: X25519MLKEM768_CLIENT_SHARE_LEN,
            actual: client_share.len(),
        });
    }
    Ok(ClientKeyExchange {
        bytes: client_share.to_vec(),
        decaps_secret: parse_decapsulation_key(decapsulation_key)?,
        x25519_private,
    })
}

impl ServerKeyExchange {
    /// Parse server `key_exchange` bytes from the wire (1120 bytes for X25519MLKEM768).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != X25519MLKEM768_SERVER_SHARE_LEN {
            return Err(Error::InvalidShareLength {
                expected: X25519MLKEM768_SERVER_SHARE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

fn parse_ciphertext(bytes: &[u8]) -> Result<Ciphertext<MlKem768>, Error> {
    if bytes.len() != MLKEM768_CIPHERTEXT_LEN {
        return Err(Error::InvalidShareLength {
            expected: MLKEM768_CIPHERTEXT_LEN,
            actual: bytes.len(),
        });
    }
    Ok(Array::clone_from_slice(bytes))
}

/// Concatenate per draft-ietf-tls-ecdhe-mlkem: `ML-KEM_ss || X25519_ss`.
pub fn combine_shared_secrets(
    mlkem_ss: &[u8],
    x25519_ss: &[u8],
) -> [u8; X25519MLKEM768_SHARED_SECRET_LEN] {
    let mut out = [0u8; X25519MLKEM768_SHARED_SECRET_LEN];
    out[..MLKEM768_SHARED_SECRET_LEN].copy_from_slice(&mlkem_ss[..MLKEM768_SHARED_SECRET_LEN]);
    out[MLKEM768_SHARED_SECRET_LEN..].copy_from_slice(&x25519_ss[..X25519_SHARE_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kex_roundtrip() {
        let client = ClientKeyExchange::generate().unwrap();
        let (server, server_ss) = ServerKeyExchange::respond_to(&client).unwrap();
        let client_ss = client_shared_secret(&client, &server).unwrap();
        assert_eq!(client_ss, server_ss);
        assert_eq!(client_ss.len(), X25519MLKEM768_SHARED_SECRET_LEN);
    }
}
