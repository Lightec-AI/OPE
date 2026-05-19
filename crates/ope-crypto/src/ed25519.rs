use ed25519_dalek::{Signer, Verifier};
use thiserror::Error;

pub type SecretKey = ed25519_dalek::SigningKey;
pub type PublicKey = ed25519_dalek::VerifyingKey;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("signature verification failed")]
    VerifyFailed(#[from] ed25519_dalek::SignatureError),
    #[error("invalid signature encoding")]
    InvalidSignature,
}

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.verifying_key();
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

pub fn sign(secret: &SecretKey, message: &[u8]) -> [u8; 64] {
    secret.sign(message).to_bytes()
}

pub fn verify(public: &PublicKey, message: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    public.verify(message, &sig)?;
    Ok(())
}

pub fn public_key_from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, Error> {
    PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)
}

pub fn secret_key_from_bytes(bytes: &[u8; 32]) -> SecretKey {
    SecretKey::from_bytes(bytes)
}
