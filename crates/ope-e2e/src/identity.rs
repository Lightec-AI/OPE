//! Engine and client hybrid identity material.

use kem::{Decapsulate, Kem, KeyExport};
use ml_kem::{
    array::Array,
    ml_kem_768::{Ciphertext, EncapsulationKey},
    ExpandedDecapsulationKey, ExpandedKeyEncoding, MlKem768,
};
use ope_crypto::{encode, PublicKey};
use rand::rngs::OsRng;
use ope_transport::{
    parse_decapsulation_key, ClientKeyExchange, MLKEM768_ENCAPSULATION_KEY_LEN, X25519_SHARE_LEN,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Published engine identity (gateway + clients).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineIdentity {
    pub engine_id: String,
    pub kex: String,
    pub mlkem_encapsulation_key: String,
    pub x25519_public: String,
    pub ed25519_public: String,
}

impl EngineIdentity {
    pub const KEX_X25519_MLKEM768: &'static str = "X25519MLKEM768";

    pub fn mlkem_encap_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        let b = ope_crypto::decode(&self.mlkem_encapsulation_key)
            .map_err(|_| crate::Error::E2e("invalid mlkem_encapsulation_key".into()))?;
        if b.len() != MLKEM768_ENCAPSULATION_KEY_LEN {
            return Err(crate::Error::E2e(format!(
                "mlkem encap len {} expected {}",
                b.len(),
                MLKEM768_ENCAPSULATION_KEY_LEN
            )));
        }
        Ok(b)
    }

    pub fn x25519_public_bytes(&self) -> Result<[u8; X25519_SHARE_LEN], crate::Error> {
        let b = ope_crypto::decode(&self.x25519_public)
            .map_err(|_| crate::Error::E2e("invalid x25519_public".into()))?;
        b.try_into()
            .map_err(|_| crate::Error::E2e("x25519_public length".into()))
    }
}

/// Static engine secrets (TEE-only in production).
pub struct EngineStaticSecret {
    pub engine_id: String,
    mlkem_decaps_bytes: Vec<u8>,
    x25519_secret: StaticSecret,
    pub ed25519_public: PublicKey,
}

impl EngineStaticSecret {
    /// Build from ML-KEM decapsulation key bytes (2400) + X25519 secret + Ed25519 public.
    pub fn from_bytes(
        engine_id: impl Into<String>,
        mlkem_decaps: &[u8],
        x25519_secret: [u8; X25519_SHARE_LEN],
        ed25519_public: PublicKey,
    ) -> Result<Self, crate::Error> {
        parse_decapsulation_key(mlkem_decaps)?;
        Ok(Self {
            engine_id: engine_id.into(),
            mlkem_decaps_bytes: mlkem_decaps.to_vec(),
            x25519_secret: StaticSecret::from(x25519_secret),
            ed25519_public,
        })
    }

    /// Generate a fresh production engine epoch secret (real ML-KEM-768 + X25519 keypairs)
    /// using the operating-system CSPRNG. Returns the secret (held in RAM, TEE-only in
    /// production) and the publishable [`EngineIdentity`].
    ///
    /// The `ed25519_public` is the engine's long-term signing key (used for usage-report and
    /// ephemeral-identity signatures); it is carried in the identity for client binding.
    pub fn generate(
        engine_id: impl Into<String>,
        ed25519_public: PublicKey,
    ) -> Result<(Self, EngineIdentity), crate::Error> {
        let (decaps, _encaps) = MlKem768::generate_keypair();
        #[allow(deprecated)]
        let expanded: ExpandedDecapsulationKey<MlKem768> = decaps.to_expanded_bytes();
        let mlkem_decaps: Vec<u8> = expanded.iter().copied().collect();

        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_bytes = x25519_secret.to_bytes();

        let secret = Self::from_bytes(engine_id, &mlkem_decaps, x25519_bytes, ed25519_public)?;
        let identity = secret.public_identity()?;
        Ok((secret, identity))
    }

    pub fn public_identity(&self) -> Result<EngineIdentity, crate::Error> {
        let decaps = parse_decapsulation_key(&self.mlkem_decaps_bytes)?;
        let encap = decaps.encapsulation_key();
        let encap_bytes = encap.to_bytes();
        let x25519_public = X25519Public::from(&self.x25519_secret);
        Ok(EngineIdentity {
            engine_id: self.engine_id.clone(),
            kex: EngineIdentity::KEX_X25519_MLKEM768.into(),
            mlkem_encapsulation_key: encode(encap_bytes.as_ref()),
            x25519_public: encode(x25519_public.as_bytes()),
            ed25519_public: encode(self.ed25519_public.as_bytes()),
        })
    }

    /// Decrypt a request encrypted with [`crate::kex::client_request_shared_secret`].
    pub fn request_shared_secret(
        &self,
        mlkem_ciphertext: &[u8],
        client_x25519_public: [u8; X25519_SHARE_LEN],
    ) -> Result<[u8; 64], crate::Error> {
        use ope_transport::combine_shared_secrets;
        use ope_transport::MLKEM768_CIPHERTEXT_LEN;

        if mlkem_ciphertext.len() != MLKEM768_CIPHERTEXT_LEN {
            return Err(crate::Error::E2e("mlkem ciphertext length".into()));
        }
        let decaps = parse_decapsulation_key(&self.mlkem_decaps_bytes)?;
        let ct: Ciphertext = Array::clone_from_slice(mlkem_ciphertext);
        let mlkem_ss = decaps.decapsulate(&ct);
        let peer = X25519Public::from(client_x25519_public);
        let x25519_ss = self.x25519_secret.diffie_hellman(&peer);
        Ok(combine_shared_secrets(mlkem_ss.as_ref(), x25519_ss.as_bytes()))
    }

    /// Hybrid server step for streaming **response** to client ephemeral session.
    pub fn respond_to_client(
        &self,
        client: &ClientKeyExchange,
    ) -> Result<([u8; 64], ope_transport::ServerKeyExchange), crate::Error> {
        let (server, shared) = ope_transport::ServerKeyExchange::respond_to(client)?;
        Ok((shared, server))
    }
}

/// Client ephemeral session (retain for response decryption).
pub struct ClientSession {
    pub kex: ClientKeyExchange,
    pub x25519_public: [u8; X25519_SHARE_LEN],
}

impl ClientSession {
    pub fn generate() -> Result<Self, crate::Error> {
        let kex = ClientKeyExchange::generate()?;
        let x25519_public: [u8; X25519_SHARE_LEN] = kex.bytes[MLKEM768_ENCAPSULATION_KEY_LEN..]
            .try_into()
            .map_err(|_| crate::Error::E2e("client share x25519".into()))?;
        Ok(Self { kex, x25519_public })
    }
}

/// Encapsulation key parse for client → static engine request path.
pub fn parse_mlkem_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey, crate::Error> {
    ope_transport::parse_encapsulation_key(bytes).map_err(crate::Error::Transport)
}
