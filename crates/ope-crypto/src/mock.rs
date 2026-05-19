//! Deterministic development key material. Never use in production.

use crate::ed25519::{Keypair, SecretKey};

/// 32-byte seed for vector `001-valid-plaintext` (repeated byte pattern for visibility).
pub const DEV_VECTOR_001_SEED: [u8; 32] = [0x01; 32];

/// Mock attester signing key (vector / CI only).
pub const DEV_ATTESTER_SEED: [u8; 32] = [0x03; 32];

/// Build a mock Ed25519 keypair from a 32-byte seed (development / CI only).
pub fn mock_keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::{sign, verify};

    #[test]
    fn deterministic_mock_sign_verify() {
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let msg = b"ope-dev";
        let sig = sign(&kp.secret, msg);
        verify(&kp.public, msg, &sig).unwrap();
    }
}
