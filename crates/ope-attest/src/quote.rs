//! CPU/GPU quote verification trait (O-1, O-2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuQuoteInput {
    pub quote_b64: String,
    pub report_data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerifyResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub normalized: Option<Value>,
}

pub trait CpuQuoteVerifier: Send + Sync {
    fn verify_cpu_quote(&self, input: &CpuQuoteInput) -> Result<QuoteVerifyResult, Error>;
}

/// Stub for unit tests and CI without TDX hardware (O-1).
pub struct FixtureQuoteVerifier {
    pub expect_report_data_hex: Option<String>,
}

impl CpuQuoteVerifier for FixtureQuoteVerifier {
    fn verify_cpu_quote(&self, input: &CpuQuoteInput) -> Result<QuoteVerifyResult, Error> {
        if let Some(hex) = &self.expect_report_data_hex {
            let rd = input.report_data.get("hex").and_then(|v| v.as_str()).unwrap_or("");
            if rd != hex {
                return Ok(QuoteVerifyResult {
                    ok: false,
                    reason: Some("report_data_mismatch".into()),
                    normalized: None,
                });
            }
        }
        Ok(QuoteVerifyResult {
            ok: true,
            reason: None,
            normalized: Some(input.report_data.clone()),
        })
    }
}
