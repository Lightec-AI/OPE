use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{verify_envelope, VerifyOptions};
use serde::Deserialize;

/// Spec vectors carry a fixed `ts` for reproducible signatures; allow a wide skew in tests only.
const DEV_VECTOR_MAX_SKEW: Duration = Duration::from_secs(60 * 60 * 24 * 365);

#[derive(Deserialize)]
struct VectorFile {
    envelope: ope_envelope::Envelope,
}

#[test]
fn vector_001_valid_plaintext() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/001-valid-plaintext.json");
    let text = fs::read_to_string(&path).expect("read vector file");
    let vector: VectorFile = serde_json::from_str(&text).expect("parse vector");

    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    verify_envelope(
        &vector.envelope,
        &kp.public,
        &VerifyOptions {
            max_skew: DEV_VECTOR_MAX_SKEW,
            ..VerifyOptions::with_defaults()
        },
    )
    .expect("vector 001 should verify");
}
