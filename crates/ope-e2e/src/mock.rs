//! Deterministic dev engine keys (CI only).

use kem::FromSeed;
use ml_kem::{array::Array, ExpandedDecapsulationKey, ExpandedKeyEncoding, MlKem768, Seed};
use ope_crypto::mock_keypair_from_seed;

use crate::identity::{EngineIdentity, EngineStaticSecret};

/// Dev-only seed for mock engine (`0xEE` repeated).
pub const DEV_ENGINE_SEED: [u8; 32] = [0xEE; 32];

/// Generate deterministic engine static secret + public identity for tests.
pub fn mock_engine_from_seed(seed: &[u8; 32]) -> (EngineStaticSecret, EngineIdentity) {
    let mut seed_arr = [0u8; 64];
    seed_arr[..32].copy_from_slice(seed);
    seed_arr[32..].copy_from_slice(seed);
    let kem_seed: Seed = Array::clone_from_slice(&seed_arr);
    let (decaps, _encaps) = MlKem768::from_seed(&kem_seed);
    #[allow(deprecated)]
    let expanded: ExpandedDecapsulationKey<MlKem768> = decaps.to_expanded_bytes();
    let decaps_bytes: Vec<u8> = expanded.iter().copied().collect();
    let x25519_secret = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed[i % 32] ^ 0xA5;
        }
        s
    };
    let ed = mock_keypair_from_seed(seed);
    let secret = EngineStaticSecret::from_bytes(
        "engine-dev",
        &decaps_bytes,
        x25519_secret,
        ed.public,
    )
    .expect("mock engine");
    let identity = secret.public_identity().expect("mock identity");
    (secret, identity)
}
