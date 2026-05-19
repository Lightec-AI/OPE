//! OPE gateway: verify envelopes, optional attestation, strip `model@provider` for upstream APIs.

use std::collections::HashSet;

use ope_attest::{
    allow_verdict, checks_from_results, deny_verdict, verify_attestation, Attestation,
    MockAttester, VerificationVerdict, VerifyEnvelopeRequest,
};
use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{parse_routed_model, verify_envelope, Envelope, VerifyOptions};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("envelope: {0}")]
    Envelope(#[from] ope_envelope::Error),
    #[error("attestation: {0}")]
    Attestation(#[from] ope_attest::Error),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub gateway_id: String,
    pub content_key: Option<[u8; 32]>,
    pub require_attestation: bool,
    pub require_routed_model: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            gateway_id: "gateway-dev".into(),
            content_key: Some(ope_crypto::DEV_CONTENT_KEY),
            require_attestation: false,
            require_routed_model: true,
        }
    }
}

/// Strip `@provider` suffix for provider-native APIs (`ope.md` §8.1).
pub fn strip_provider_suffix(model: &str) -> Result<(String, String), ope_envelope::Error> {
    let routed = parse_routed_model(model)?;
    Ok((routed.base, routed.provider))
}

/// Build provider-ready payload JSON (OpenAI-compatible body with base model only).
pub fn normalize_payload_for_provider(payload: &Value) -> Result<Value, GatewayError> {
    let mut out = payload.clone();
    if let Some(model) = out.get("model").and_then(|m| m.as_str()) {
        let (base, _provider) = strip_provider_suffix(model)?;
        out["model"] = serde_json::json!(base);
    }
    Ok(out)
}

/// Gateway verification per `POST /v1/ope/verifications:verifyEnvelope`.
pub fn verify_envelope_request(
    req: &VerifyEnvelopeRequest,
    config: &GatewayConfig,
    seen_nonces: &mut HashSet<(String, String)>,
) -> Result<VerificationVerdict, GatewayError> {
    let envelope: Envelope = serde_json::from_value(req.envelope.clone())
        .map_err(|e| GatewayError::InvalidRequest(e.to_string()))?;

    let sender_kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    let verify_result = verify_envelope(
        &envelope,
        &sender_kp.public,
        &VerifyOptions {
            max_skew: std::time::Duration::from_secs(300),
            seen_nonces: Some(seen_nonces.clone()),
            expected_recipient: Some(config.gateway_id.clone()),
            content_key: config.content_key,
            require_routed_model: config.require_routed_model,
        },
    );

    let sig_ok = verify_result.is_ok();
    let checks = checks_from_results(&[
        ("signature", sig_ok),
        ("timestamp_freshness", sig_ok),
        ("nonce_replay", sig_ok),
        ("recipient_match", sig_ok),
    ]);

    if !sig_ok {
        let code = match verify_result {
            Err(ope_envelope::Error::InvalidTimestamp(_)) => "ope_invalid_timestamp",
            Err(ope_envelope::Error::ReplayDetected { .. }) => "ope_replay_detected",
            Err(ope_envelope::Error::InvalidRecipient { .. }) => "ope_invalid_recipient",
            Err(ope_envelope::Error::InvalidModelId(_)) => "ope_invalid_model_id",
            _ => "ope_verification_failed",
        };
        return Ok(deny_verdict(
            code,
            "envelope verification failed",
            checks,
        ));
    }

    seen_nonces.insert((envelope.kid.clone(), envelope.nonce.clone()));

    let mut att_ok = true;
    if config.require_attestation || req.attestation.is_some() {
        let att_val = req
            .attestation
            .as_ref()
            .ok_or_else(|| GatewayError::InvalidRequest("attestation required".into()))?;
        let att: Attestation =
            serde_json::from_value(att_val.clone()).map_err(|e| GatewayError::InvalidRequest(e.to_string()))?;
        att_ok = verify_attestation(&att, &MockAttester::keypair().public).is_ok()
            && att.kid == envelope.kid;
        if att.recipient.is_some() && att.recipient.as_deref() != Some(&config.gateway_id) {
            att_ok = false;
        }
    }
    let mut final_checks = checks;
    final_checks.extend(checks_from_results(&[
        ("attestation", att_ok),
        ("policy", att_ok),
    ]));

    if !att_ok {
        return Ok(deny_verdict(
            "ope_attestation_invalid",
            "attestation verification failed",
            final_checks,
        ));
    }

    Ok(allow_verdict(
        final_checks,
        serde_json::json!({
            "kid": envelope.kid,
            "recipient": envelope.recipient,
        }),
    ))
}
