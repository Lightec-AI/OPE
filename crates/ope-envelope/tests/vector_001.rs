use std::fs;
use std::path::PathBuf;

use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{verify_envelope, VerifyOptions};
use serde::Deserialize;

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
    verify_envelope(&vector.envelope, &kp.public, &VerifyOptions::with_defaults())
        .expect("vector 001 should verify");
}
