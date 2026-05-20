//! Deterministic dev engine keys (CI only).

use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use ope_crypto::mock_keypair_from_seed;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::identity::{EngineIdentity, EngineStaticSecret};

/// Dev-only seed for mock engine (`0xEE` repeated).
pub const DEV_ENGINE_SEED: [u8; 32] = [0xEE; 32];

/// Generate deterministic engine static secret + public identity for tests.
pub fn mock_engine_from_seed(seed: &[u8; 32]) -> (EngineStaticSecret, EngineIdentity) {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let (decaps, _encaps) = MlKem768::generate(&mut rng);
    let decaps_bytes = decaps.as_bytes().to_vec();
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
