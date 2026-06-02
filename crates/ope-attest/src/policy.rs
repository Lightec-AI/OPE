//! Attestation policy schema (O-4): allowlists, freshness, replay windows.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementAllowlist {
    pub mrtd: Option<Vec<String>>,
    pub rtmr: Option<Vec<String>>,
    pub vllm_binary_sha256: Option<Vec<String>>,
    pub engine_binary_sha256: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicySchema {
    pub ope_version: String,
    pub max_quote_age_secs: u64,
    pub max_attestation_ttl_secs: u64,
    pub allowlists: MeasurementAllowlist,
    #[serde(default)]
    pub extra: Value,
}

impl Default for AttestationPolicySchema {
    fn default() -> Self {
        Self {
            ope_version: "1.0".into(),
            max_quote_age_secs: 3600,
            max_attestation_ttl_secs: 86400,
            allowlists: MeasurementAllowlist {
                mrtd: None,
                rtmr: None,
                vllm_binary_sha256: None,
                engine_binary_sha256: None,
            },
            extra: Value::Null,
        }
    }
}

impl AttestationPolicySchema {
    pub fn validate_measurements(&self, measurements: &Value) -> bool {
        let obj = measurements.as_object();
        let Some(obj) = obj else {
            return false;
        };
        if let Some(allowed) = &self.allowlists.vllm_binary_sha256 {
            let v = obj.get("vllm_binary_sha256").and_then(|x| x.as_str());
            if v.is_none() || !allowed.iter().any(|a| a == v.unwrap()) {
                return false;
            }
        }
        if let Some(allowed) = &self.allowlists.engine_binary_sha256 {
            let v = obj.get("engine_binary_sha256").and_then(|x| x.as_str());
            if v.is_none() || !allowed.iter().any(|a| a == v.unwrap()) {
                return false;
            }
        }
        true
    }
}
