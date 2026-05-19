use ope_attest::{CreateAttestationRequest, MockAttester};
use serde_json::json;

#[test]
fn mock_attester_issues_and_verifies() {
    let attester = MockAttester::default();
    let resp = attester
        .create(CreateAttestationRequest {
            ope_version: "1.0".into(),
            kid: "mock-sender-001".into(),
            subject: "workload://tenant-dev/ci".into(),
            recipient: Some("gateway-dev".into()),
            nonce: "nonce-attest-001".into(),
            evidence: json!({"type": "mock_tee", "claim": "dev"}),
            requested_ttl_sec: 600,
        })
        .unwrap();
    attester.verify_attestation_object(&resp.attestation).unwrap();
}
