//! OPE HTTP framing (`spec/ope-transport.md` §4).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// JSON API base type per `ope.md` §14.
pub const CONTENT_TYPE_JSON: &str = "application/json";

/// OPE envelope wire type.
pub const CONTENT_TYPE_OPE_JSON: &str = "application/ope+json";

/// Inline envelope + attestation transport wrapper (`ope.md` §14.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineEnvelopeTransport {
    pub envelope: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Value>,
}

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("missing Content-Type header")]
    MissingContentType,
    #[error("unsupported Content-Type: {0}")]
    UnsupportedContentType(String),
}

/// Parse `Content-Type` for OPE-over-HTTP requests.
pub fn parse_content_type(header: Option<&str>) -> Result<&'static str, FramingError> {
    let value = header.ok_or(FramingError::MissingContentType)?;
    let mime = value.split(';').next().unwrap_or(value).trim().to_ascii_lowercase();
    match mime.as_str() {
        "application/ope+json" => Ok(CONTENT_TYPE_OPE_JSON),
        "application/json" => Ok(CONTENT_TYPE_JSON),
        other => Err(FramingError::UnsupportedContentType(other.to_string())),
    }
}

/// Build response headers for an OPE envelope body.
pub fn ope_response_headers() -> Vec<(&'static str, &'static str)> {
    vec![("Content-Type", CONTENT_TYPE_OPE_JSON)]
}
