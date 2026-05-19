use std::collections::HashSet;
use std::sync::Mutex;

use ope_crypto::{mock_keypair_from_seed, DEV_ATTESTER_SEED};
use uuid::Uuid;

use crate::sign::issue_attestation;
use crate::types::{
    Attestation, CreateAttestationRequest, CreateAttestationResponse, VerificationCheck,
    VerificationVerdict,
};
use crate::verify::verify_attestation;
use crate::Error;

/// In-process mock attester for CI (`dev_only`).
pub struct MockAttester {
    attester_id: String,
    seen_nonces: Mutex<HashSet<String>>,
}

impl Default for MockAttester {
    fn default() -> Self {
        Self::new("attester-dev.mock")
    }
}

impl MockAttester {
    pub fn new(attester_id: &str) -> Self {
        Self {
            attester_id: attester_id.into(),
            seen_nonces: Mutex::new(HashSet::new()),
        }
    }

    pub fn keypair() -> ope_crypto::Keypair {
        mock_keypair_from_seed(&DEV_ATTESTER_SEED)
    }

    pub fn create(&self, req: CreateAttestationRequest) -> Result<CreateAttestationResponse, Error> {
        {
            let mut cache = self.seen_nonces.lock().unwrap();
            if !cache.insert(req.nonce.clone()) {
                return Err(Error::ReplayDetected);
            }
        }

        let ttl = req.requested_ttl_sec.min(3600);
        let kp = Self::keypair();
        let claims = serde_json::json!({
            "tenant": "tenant-dev",
            "env": "ci",
            "allowed_models": ["gpt-4.1@openai", "gpt-4.1-mini@openai"]
        });

        let att = issue_attestation(
            &self.attester_id,
            &req.kid,
            &req.subject,
            req.recipient.clone(),
            claims,
            &req.nonce,
            ttl,
            &kp.secret,
        )?;

        let issued_at = att.ts.clone();
        let expires_at = att.exp.clone();
        Ok(CreateAttestationResponse {
            attestation_id: format!("att_{}", Uuid::new_v4().simple()),
            issued_at,
            expires_at,
            attestation: att,
        })
    }

    pub fn verify_attestation_object(&self, att: &Attestation) -> Result<(), Error> {
        let kp = Self::keypair();
        verify_attestation(att, &kp.public)?;
        Ok(())
    }
}

pub fn checks_from_results(results: &[(&str, bool)]) -> Vec<VerificationCheck> {
    results
        .iter()
        .map(|(name, ok)| VerificationCheck {
            name: (*name).into(),
            ok: *ok,
        })
        .collect()
}

pub fn deny_verdict(code: &str, message: &str, checks: Vec<VerificationCheck>) -> VerificationVerdict {
    VerificationVerdict {
        verified: false,
        decision: "deny".into(),
        checks: Some(checks),
        error: Some(crate::types::VerificationError {
            code: code.into(),
            message: message.into(),
        }),
        normalized: None,
    }
}

pub fn allow_verdict(checks: Vec<VerificationCheck>, normalized: serde_json::Value) -> VerificationVerdict {
    VerificationVerdict {
        verified: true,
        decision: "allow".into(),
        checks: Some(checks),
        error: None,
        normalized: Some(normalized),
    }
}
