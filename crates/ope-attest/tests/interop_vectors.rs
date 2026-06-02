//! E2E interop vectors (O-3): policy + quote fixtures.

use ope_attest::{AttestationPolicySchema, CpuQuoteInput, CpuQuoteVerifier, FixtureQuoteVerifier};

#[test]
fn policy_allowlist_accepts_known_measurement() {
    let mut policy = AttestationPolicySchema::default();
    policy.allowlists.vllm_binary_sha256 = Some(vec!["abc".into()]);
    let m = serde_json::json!({ "vllm_binary_sha256": "abc" });
    assert!(policy.validate_measurements(&m));
}

#[test]
fn fixture_quote_verifier_matches_report_data() {
    let v = FixtureQuoteVerifier {
        expect_report_data_hex: Some("deadbeef".into()),
    };
    let out = v
        .verify_cpu_quote(&CpuQuoteInput {
            quote_b64: "AA==".into(),
            report_data: serde_json::json!({ "hex": "deadbeef" }),
        })
        .expect("verify");
    assert!(out.ok);
}
