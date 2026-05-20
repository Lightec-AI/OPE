//! Wire `e2e` JSON object on envelopes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eFields {
    pub kex: String,
    /// Full ephemeral share (1216 B) when client retains session for response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_share: Option<String>,
    /// ML-KEM ciphertext to static engine (request path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mlkem_ciphertext: Option<String>,
    /// Client X25519 ephemeral public (request path).
    pub client_x25519: String,
    pub content_alg: String,
    pub engine_mlkem_encap: String,
    pub engine_x25519: String,
    /// Present on streaming responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_share: Option<String>,
}

impl E2eFields {
    pub const ALG_CHACHA: &'static str = "chacha20poly1305";
    pub const ALG_STREAM: &'static str = "chacha20poly1305-stream";
    pub const KEX: &'static str = "X25519MLKEM768";
}
