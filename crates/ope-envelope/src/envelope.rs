use serde::{Deserialize, Serialize};
use serde_json::Value;

/// OPE envelope (wire object). Extra JSON fields are preserved for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub ope_version: String,
    pub alg: String,
    pub enc: String,
    pub kid: String,
    pub recipient: String,
    /// Target inference engine (`enc=e2e-hybrid-pq`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    pub ts: String,
    pub nonce: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    /// Hybrid E2E session descriptor ([`spec/ope-confidential-ai.md`](../../spec/ope-confidential-ai.md)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e2e: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Envelope {
    pub const VERSION: &'static str = "1.0";
    pub const ALG_EDDSA: &'static str = "EdDSA";
    pub const ENC_NONE: &'static str = "none";
    /// Confidential AI: PQ hybrid encrypt to inference engine TEE.
    pub const ENC_E2E_HYBRID_PQ: &'static str = "e2e-hybrid-pq";

    pub fn validate_structure(&self) -> Result<(), crate::Error> {
        if self.ope_version != Self::VERSION {
            return Err(crate::Error::UnsupportedVersion(self.ope_version.clone()));
        }
        if self.alg != Self::ALG_EDDSA {
            return Err(crate::Error::UnsupportedAlg(self.alg.clone()));
        }
        match self.enc.as_str() {
            Self::ENC_NONE => {
                if self.payload.is_none() {
                    return Err(crate::Error::InvalidEnvelope(
                        "enc=none requires payload".into(),
                    ));
                }
                if self.ciphertext.is_some() || self.iv.is_some() {
                    return Err(crate::Error::InvalidEnvelope(
                        "enc=none must not include ciphertext/iv".into(),
                    ));
                }
            }
            "xchacha20poly1305" | "A256GCM" | Self::ENC_E2E_HYBRID_PQ => {
                if self.payload.is_some() {
                    return Err(crate::Error::InvalidEnvelope(
                        "encrypted enc must omit payload".into(),
                    ));
                }
                if self.ciphertext.is_none() || self.iv.is_none() {
                    return Err(crate::Error::InvalidEnvelope(
                        "encrypted enc requires ciphertext and iv".into(),
                    ));
                }
                if self.enc == Self::ENC_E2E_HYBRID_PQ {
                    if self.engine_id.is_none() {
                        return Err(crate::Error::InvalidEnvelope(
                            "e2e-hybrid-pq requires engine_id".into(),
                        ));
                    }
                    if self.e2e.is_none() {
                        return Err(crate::Error::InvalidEnvelope(
                            "e2e-hybrid-pq requires e2e".into(),
                        ));
                    }
                }
            }
            other => return Err(crate::Error::UnsupportedEnc(other.to_string())),
        }
        if self.sig.is_none() {
            return Err(crate::Error::InvalidEnvelope("missing sig".into()));
        }
        Ok(())
    }
}
