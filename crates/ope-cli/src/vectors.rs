use std::fs;
use std::path::Path;

use chrono::Utc;
use ope_crypto::{encode, mock_keypair_from_seed, DEV_CONTENT_KEY, DEV_VECTOR_001_SEED};
use ope_envelope::{encrypt_envelope, sign_envelope, Envelope};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
pub struct VectorFile {
    pub vector_id: String,
    pub description: String,
    pub dev_only: bool,
    pub signing_key_seed_hex: String,
    pub verifying_key_hex: String,
    pub expect_verify: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_error_substr: Option<String>,
    pub envelope: Envelope,
}

pub fn write_all_vectors(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let vectors = build_vectors()?;
    for v in vectors {
        let path = dir.join(format!("{}.json", v.vector_id));
        fs::write(path, serde_json::to_string_pretty(&v)?)?;
    }
    Ok(())
}

fn build_vectors() -> Result<Vec<VectorFile>, Box<dyn std::error::Error>> {
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let seed_hex = hex::encode(DEV_VECTOR_001_SEED);
    let pk_hex = hex::encode(kp.public_key_bytes());

    let mut pass = sample_envelope();
    sign_envelope(&mut pass, &kp.secret)?;

    let mut bad_sig = pass.clone();
    let sig = bad_sig.sig.as_mut().unwrap();
    sig.pop();
    sig.push('X');

    let mut stale = pass.clone();
    stale.ts = "2020-01-01T00:00:00Z".into();
    sign_envelope(&mut stale, &kp.secret)?;

    let mut wrong_recipient = pass.clone();
    wrong_recipient.recipient = "wrong-gateway".into();
    sign_envelope(&mut wrong_recipient, &kp.secret)?;

    let mut bad_hash = pass.clone();
    sign_envelope(&mut bad_hash, &kp.secret)?;
    if let Some(p) = bad_hash.payload.as_mut() {
        p["messages"] = json!([{"role": "user", "content": "tampered"}]);
    }

    let mut bad_model = pass.clone();
    if let Some(p) = bad_model.payload.as_mut() {
        p["model"] = json!("gpt-4.1");
    }
    sign_envelope(&mut bad_model, &kp.secret)?;

    let mut encrypted = pass.clone();
    encrypted.enc = "xchacha20poly1305".into();
    encrypted.payload = pass.payload.clone();
    encrypted.ciphertext = None;
    encrypted.iv = None;
    encrypt_envelope(&mut encrypted, &DEV_CONTENT_KEY)?;
    sign_envelope(&mut encrypted, &kp.secret)?;

    Ok(vec![
        VectorFile {
            vector_id: "001-valid-plaintext".into(),
            description: "Valid signed plaintext envelope (enc=none)".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "pass".into(),
            expect_error_substr: None,
            envelope: pass,
        },
        VectorFile {
            vector_id: "002-invalid-signature".into(),
            description: "Tampered signature".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "fail".into(),
            expect_error_substr: Some("signature".into()),
            envelope: bad_sig,
        },
        VectorFile {
            vector_id: "003-replayed-nonce".into(),
            description: "Valid envelope used with replay cache (see tests)".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "pass".into(),
            expect_error_substr: None,
            envelope: {
                let mut e = sample_envelope();
                sign_envelope(&mut e, &kp.secret)?;
                e
            },
        },
        VectorFile {
            vector_id: "004-stale-timestamp".into(),
            description: "Timestamp outside skew window".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "fail".into(),
            expect_error_substr: Some("timestamp".into()),
            envelope: stale,
        },
        VectorFile {
            vector_id: "005-encrypted-roundtrip".into(),
            description: "xchacha20poly1305 encrypted payload".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "pass".into(),
            expect_error_substr: None,
            envelope: encrypted,
        },
        VectorFile {
            vector_id: "006-wrong-recipient".into(),
            description: "Recipient mismatch at gateway".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "fail".into(),
            expect_error_substr: Some("recipient".into()),
            envelope: wrong_recipient,
        },
        VectorFile {
            vector_id: "007-malformed-canonical".into(),
            description: "payload_hash does not match payload".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex.clone(),
            verifying_key_hex: pk_hex.clone(),
            expect_verify: "fail".into(),
            expect_error_substr: Some("payload hash".into()),
            envelope: bad_hash,
        },
        VectorFile {
            vector_id: "008-invalid-model-id".into(),
            description: "Missing @provider in payload.model".into(),
            dev_only: true,
            signing_key_seed_hex: seed_hex,
            verifying_key_hex: pk_hex,
            expect_verify: "fail".into(),
            expect_error_substr: Some("model".into()),
            envelope: bad_model,
        },
    ])
}

fn sample_envelope() -> Envelope {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    Envelope {
        ope_version: Envelope::VERSION.into(),
        alg: Envelope::ALG_EDDSA.into(),
        enc: Envelope::ENC_NONE.into(),
        kid: "mock-sender-001".into(),
        recipient: "gateway-dev".into(),
        engine_id: None,
        ts: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        nonce: encode(&nonce),
        payload_hash: String::new(),
        payload: Some(json!({
            "model": "gpt-4.1@openai",
            "messages": [{"role": "user", "content": "hello"}]
        })),
        ciphertext: None,
        iv: None,
        aad: None,
        meta: None,
        e2e: None,
        sig: None,
    }
}
