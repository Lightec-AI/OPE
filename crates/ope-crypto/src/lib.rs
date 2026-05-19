//! OPE L0: cryptographic primitives.

mod base64url;
mod ed25519;
mod hash;
mod mock;

pub use base64url::{decode, encode};
pub use ed25519::{
    public_key_from_bytes, secret_key_from_bytes, sign, verify, Keypair, PublicKey, SecretKey,
};
pub use hash::sha256;
pub use mock::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};

pub type Error = ed25519::Error;
