use std::collections::HashSet;

use ope_attest::VerifyEnvelopeRequest;
use ope_gateway::{normalize_payload_for_provider, strip_provider_suffix, verify_envelope_request, GatewayConfig};
use serde_json::json;

#[test]
fn strip_model_suffix() {
    let (base, provider) = strip_provider_suffix("gpt-4.1@openai").unwrap();
    assert_eq!(base, "gpt-4.1");
    assert_eq!(provider, "openai");
}

#[test]
fn verify_allow_and_normalize() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/001-valid-plaintext.json");
    let text = std::fs::read_to_string(path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut cache = HashSet::new();
    let req = VerifyEnvelopeRequest {
        envelope: v["envelope"].clone(),
        attestation: None,
        policy_context: None,
    };
    let verdict = verify_envelope_request(&req, &GatewayConfig::default(), &mut cache).unwrap();
    assert!(verdict.verified);
    let payload = v["envelope"]["payload"].clone();
    let normalized = normalize_payload_for_provider(&payload).unwrap();
    assert_eq!(normalized["model"], "gpt-4.1");
}
