use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use ope_crypto::{mock_keypair_from_seed, DEV_CONTENT_KEY, DEV_VECTOR_001_SEED};
use ope_envelope::{verify_envelope, VerifyOptions};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vector_id: String,
    signing_key_seed_hex: String,
    expect_verify: String,
    expect_error_substr: Option<String>,
    envelope: ope_envelope::Envelope,
}

fn load_vectors() -> Vec<VectorFile> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let mut out: Vec<VectorFile> = Vec::new();
    for entry in fs::read_dir(&dir).expect("read vectors dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read vector");
        out.push(serde_json::from_str(&text).expect("parse vector"));
    }
    out.sort_by(|a, b| a.vector_id.cmp(&b.vector_id));
    out
}

#[test]
fn all_spec_vectors() {
    for vector in load_vectors() {
        let seed = hex::decode(vector.signing_key_seed_hex.trim()).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let kp = mock_keypair_from_seed(&seed_arr);

        let content_key = if vector.envelope.enc != "none" {
            Some(DEV_CONTENT_KEY)
        } else {
            None
        };

        let require_model = vector.vector_id == "008-invalid-model-id";
        let expected_recipient = if vector.vector_id == "006-wrong-recipient" {
            Some("gateway-dev".into())
        } else {
            None
        };

        let result = verify_envelope(
            &vector.envelope,
            &kp.public,
            &VerifyOptions {
                max_skew: std::time::Duration::from_secs(300),
                seen_nonces: None,
                expected_recipient,
                content_key,
                require_routed_model: require_model,
                opaque_e2e: false,
            },
        );

        match vector.expect_verify.as_str() {
            "pass" => result.unwrap_or_else(|e| panic!("{} should pass: {e}", vector.vector_id)),
            "fail" => {
                let err = result.expect_err(&vector.vector_id);
                if let Some(sub) = &vector.expect_error_substr {
                    assert!(
                        err.to_string().to_lowercase().contains(&sub.to_lowercase()),
                        "{}: expected substring {sub} in {err}",
                        vector.vector_id
                    );
                }
            }
            other => panic!("unknown expect_verify: {other}"),
        }
    }
}

#[test]
fn vector_003_replay_detected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/003-replayed-nonce.json");
    let text = fs::read_to_string(&path).unwrap();
    let vector: VectorFile = serde_json::from_str(&text).unwrap();
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let mut cache = HashSet::new();
    let opts = VerifyOptions {
        seen_nonces: Some(cache.clone()),
        ..VerifyOptions::with_defaults()
    };
    verify_envelope(&vector.envelope, &kp.public, &opts).unwrap();
    cache.insert((vector.envelope.kid.clone(), vector.envelope.nonce.clone()));
    let opts2 = VerifyOptions {
        seen_nonces: Some(cache),
        ..VerifyOptions::with_defaults()
    };
    let err = verify_envelope(&vector.envelope, &kp.public, &opts2).unwrap_err();
    assert!(err.to_string().contains("replay"));
}
