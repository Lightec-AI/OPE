//! Browser / Capacitor WebView bindings for OPE client encrypt + response decrypt.
//!
//! Mirrors the client subset of `ope-ffi` `e2e.rs` (handle registries + JSON in/out).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ope_crypto::encode;
use ope_e2e::{decrypt_response_chunk, encrypt_request, ClientSession, EngineIdentity};
use ope_envelope::Envelope;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

static REG: OnceLock<Mutex<ClientRegistries>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct ClientRegistries {
    clients: HashMap<u64, Arc<ClientSession>>,
}

fn registries() -> &'static Mutex<ClientRegistries> {
    REG.get_or_init(|| Mutex::new(ClientRegistries::default()))
}

fn lock_registries() -> std::sync::MutexGuard<'static, ClientRegistries> {
    registries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn next_handle() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn js_err(msg: impl AsRef<str>) -> JsValue {
    JsValue::from_str(msg.as_ref())
}

#[wasm_bindgen]
pub fn ope_wasm_version() -> String {
    "0.1.0".into()
}

/// Client encrypt. Returns JSON `{ "envelope", "client_session" }`.
#[wasm_bindgen]
pub fn ope_wasm_client_encrypt_request(
    engine_identity_json: &str,
    payload_json: &str,
    base_envelope_json: &str,
    want_response_session: bool,
) -> Result<String, JsValue> {
    let engine: EngineIdentity = serde_json::from_str(engine_identity_json)
        .map_err(|e| js_err(format!("engine_identity: {e}")))?;
    let payload: Value =
        serde_json::from_str(payload_json).map_err(|e| js_err(format!("payload: {e}")))?;
    let mut envelope: Envelope = serde_json::from_str(base_envelope_json)
        .map_err(|e| js_err(format!("base_envelope: {e}")))?;

    let session = if want_response_session {
        Some(
            ClientSession::generate().map_err(|e| js_err(format!("client session: {e}")))?,
        )
    } else {
        None
    };

    encrypt_request(&mut envelope, &engine, &payload, session.as_ref())
        .map_err(|e| js_err(format!("encrypt_request: {e}")))?;

    let envelope_json = serde_json::to_value(&envelope)
        .map_err(|e| js_err(format!("envelope serialize: {e}")))?;

    let session_handle = session.map(|s| {
        let h = next_handle();
        lock_registries().clients.insert(h, Arc::new(s));
        h
    });

    serde_json::to_string(&json!({
        "envelope": envelope_json,
        "client_session": session_handle,
    }))
    .map_err(|e| js_err(format!("output json: {e}")))
}

/// Decrypt one response chunk. Returns JSON `{ "plaintext_b64" }`.
#[wasm_bindgen]
pub fn ope_wasm_client_decrypt_response_chunk(
    client_session: u64,
    request_envelope_json: &str,
    server_share_b64: &str,
    seq: u32,
    ciphertext_b64: &str,
) -> Result<String, JsValue> {
    let request: Envelope = serde_json::from_str(request_envelope_json)
        .map_err(|e| js_err(format!("request_envelope: {e}")))?;
    let session = lock_registries()
        .clients
        .get(&client_session)
        .cloned()
        .ok_or_else(|| js_err("unknown client session"))?;
    let pt = decrypt_response_chunk(&request, &session, server_share_b64, seq, ciphertext_b64)
        .map_err(|e| js_err(format!("decrypt_response_chunk: {e}")))?;
    serde_json::to_string(&json!({ "plaintext_b64": encode(&pt) }))
        .map_err(|e| js_err(format!("output json: {e}")))
}

#[wasm_bindgen]
pub fn ope_wasm_client_session_free(client_session: u64) {
    lock_registries().clients.remove(&client_session);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_e2e::{mock_engine_from_seed, DEV_ENGINE_SEED};

    #[test]
    fn wasm_client_roundtrip_in_wasm_host() {
        let _ = registries();
        let (_secret, engine) = mock_engine_from_seed(&DEV_ENGINE_SEED);
        let identity = serde_json::to_string(&engine).unwrap();
        let payload = json!({ "model": "m", "messages": [] });
        let base = json!({
            "ope_version": "1.0",
            "alg": "EdDSA",
            "enc": "none",
            "kid": "k",
            "recipient": "r",
            "ts": "2026-05-29T12:00:00Z",
            "nonce": "n1",
            "payload_hash": "",
        });
        let out = ope_wasm_client_encrypt_request(
            &identity,
            &payload.to_string(),
            &base.to_string(),
            true,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["client_session"].as_u64().is_some());
        assert_eq!(v["envelope"]["enc"], "e2e-hybrid-pq");
    }
}
