//! Official transport test vector types (JSON under `spec/vectors/transport/`).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BoringSslMlkem768Vector {
    pub vector_id: String,
    pub provider: String,
    #[serde(default)]
    pub aws_lineage: Option<String>,
    pub sources: serde_json::Value,
    pub official_test_index: u32,
    pub seed: String,
    pub entropy_hex: String,
    pub encapsulation_key_hex: String,
    pub decapsulation_key_hex: String,
    pub ciphertext_hex: String,
    pub mlkem_shared_secret_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rfc7748X25519Vector {
    pub vector_id: String,
    pub provider: String,
    pub sources: serde_json::Value,
    pub alice_private_hex: String,
    pub alice_public_hex: String,
    pub bob_private_hex: String,
    pub bob_public_hex: String,
    pub x25519_shared_secret_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HybridX25519Mlkem768Vector {
    pub vector_id: String,
    pub provider: String,
    pub sources: serde_json::Value,
    pub tls_group: String,
    pub tls_group_id: u16,
    pub client_share_hex: String,
    pub server_share_hex: String,
    pub decapsulation_key_hex: String,
    pub mlkem_shared_secret_hex: String,
    pub x25519_shared_secret_hex: String,
    pub hybrid_shared_secret_hex: String,
}

pub fn decode_hex(field: &str, hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str.trim()).map_err(|e| format!("{field}: invalid hex: {e}"))
}
