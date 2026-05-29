//! C ABI for the OPE Confidential AI hybrid E2E path (X25519MLKEM768 + ChaCha20-Poly1305).
//!
//! Secrets (engine epoch keys, client sessions, response sessions) never cross the ABI as
//! bytes. They live in process-local registries keyed by an opaque `u64` handle; the caller
//! holds the handle for the lifetime of the epoch/session and frees it explicitly.
//!
//! All fallible functions return a newly-allocated JSON C string (free with `ope_string_free`)
//! or `null` on error; on `null`, retrieve the reason with `ope_last_error_alloc`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use ope_crypto::{decode, encode, public_key_from_bytes};
use ope_e2e::{
    begin_response_session_from_share, decrypt_request, decrypt_response_chunk, encrypt_request,
    encrypt_response_chunk, ClientSession, E2eFields, EngineIdentity, EngineStaticSecret,
};
use ope_envelope::Envelope;
use serde_json::{json, Value};

use crate::error::{set_last_error_code, OPE_ERR_CRYPTO, OPE_ERR_INVALID_ARG, OPE_ERR_JSON, OPE_OK};

struct ResponseSession {
    key: [u8; 32],
    iv: [u8; 12],
}

#[derive(Default)]
struct Registries {
    engines: HashMap<u64, EngineStaticSecret>,
    clients: HashMap<u64, ClientSession>,
    responses: HashMap<u64, ResponseSession>,
}

static REG: OnceLock<Mutex<Registries>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn registries() -> &'static Mutex<Registries> {
    REG.get_or_init(|| Mutex::new(Registries::default()))
}

fn next_handle() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn err_null(code: i32, msg: impl Into<String>) -> *mut c_char {
    set_last_error_code(code, msg);
    std::ptr::null_mut()
}

fn json_out(value: Value) -> *mut c_char {
    match CString::new(value.to_string()) {
        Ok(c) => c.into_raw(),
        Err(_) => err_null(crate::error::OPE_ERR_INTERNAL, "nul byte in json output"),
    }
}

fn read_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, *mut c_char> {
    if ptr.is_null() {
        return Err(err_null(OPE_ERR_INVALID_ARG, format!("null {name}")));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| err_null(crate::error::OPE_ERR_UTF8, format!("invalid utf-8 {name}: {e}")))
}

fn read_json<T: serde::de::DeserializeOwned>(
    ptr: *const c_char,
    name: &str,
) -> Result<T, *mut c_char> {
    let text = read_str(ptr, name)?;
    serde_json::from_str(text)
        .map_err(|e| err_null(OPE_ERR_JSON, format!("invalid json {name}: {e}")))
}

// ---------------------------------------------------------------------------
// Engine: epoch keypair lifecycle + request decryption + response sessions.
// ---------------------------------------------------------------------------

/// Generate a fresh engine epoch keypair (real ML-KEM-768 + X25519). Returns
/// `{ "handle": <u64>, "identity": { engine_id, kex, mlkem_encapsulation_key, x25519_public, ed25519_public } }`.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_generate(
    engine_id: *const c_char,
    ed25519_public_b64: *const c_char,
) -> *mut c_char {
    let engine_id = match read_str(engine_id, "engine_id") {
        Ok(s) => s.to_string(),
        Err(p) => return p,
    };
    let ed_b64 = match read_str(ed25519_public_b64, "ed25519_public_b64") {
        Ok(s) => s,
        Err(p) => return p,
    };
    let ed_bytes = match decode(ed_b64) {
        Ok(b) => b,
        Err(_) => return err_null(OPE_ERR_INVALID_ARG, "ed25519_public_b64 not base64url"),
    };
    let ed_arr: [u8; 32] = match ed_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return err_null(OPE_ERR_INVALID_ARG, "ed25519_public must be 32 bytes"),
    };
    let ed_public = match public_key_from_bytes(&ed_arr) {
        Ok(p) => p,
        Err(_) => return err_null(OPE_ERR_CRYPTO, "invalid ed25519 public key"),
    };
    let (secret, identity) = match EngineStaticSecret::generate(engine_id, ed_public) {
        Ok(v) => v,
        Err(e) => return err_null(OPE_ERR_CRYPTO, format!("engine generate: {e}")),
    };
    let handle = next_handle();
    registries().lock().unwrap().engines.insert(handle, secret);
    let identity_json = match serde_json::to_value(&identity) {
        Ok(v) => v,
        Err(e) => return err_null(OPE_ERR_JSON, format!("identity serialize: {e}")),
    };
    json_out(json!({ "handle": handle, "identity": identity_json }))
}

/// Free an engine epoch handle. Returns `OPE_OK` even if the handle was unknown.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_free(handle: u64) -> i32 {
    registries().lock().unwrap().engines.remove(&handle);
    OPE_OK
}

/// Engine: decrypt a request envelope. Returns the plaintext payload JSON.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_decrypt_request(
    handle: u64,
    envelope_json: *const c_char,
) -> *mut c_char {
    let envelope: Envelope = match read_json(envelope_json, "envelope") {
        Ok(v) => v,
        Err(p) => return p,
    };
    let guard = registries().lock().unwrap();
    let engine = match guard.engines.get(&handle) {
        Some(e) => e,
        None => return err_null(OPE_ERR_INVALID_ARG, "unknown engine handle"),
    };
    match decrypt_request(&envelope, engine) {
        Ok(payload) => json_out(payload),
        Err(e) => err_null(OPE_ERR_CRYPTO, format!("decrypt_request: {e}")),
    }
}

/// Engine: begin a streaming response session bound to the request's client share.
/// Returns `{ "session": <u64>, "server_share": <base64url> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_begin_response(
    handle: u64,
    request_envelope_json: *const c_char,
) -> *mut c_char {
    let envelope: Envelope = match read_json(request_envelope_json, "request_envelope") {
        Ok(v) => v,
        Err(p) => return p,
    };
    let e2e_val = match envelope.e2e.clone() {
        Some(v) => v,
        None => return err_null(OPE_ERR_INVALID_ARG, "request envelope missing e2e"),
    };
    let e2e: E2eFields = match serde_json::from_value(e2e_val) {
        Ok(v) => v,
        Err(e) => return err_null(OPE_ERR_JSON, format!("e2e parse: {e}")),
    };
    let client_share = match e2e.client_share.as_deref() {
        Some(s) => s,
        None => {
            return err_null(
                OPE_ERR_INVALID_ARG,
                "request e2e.client_share required for response session",
            )
        }
    };
    let mut guard = registries().lock().unwrap();
    let engine = match guard.engines.get(&handle) {
        Some(e) => e,
        None => return err_null(OPE_ERR_INVALID_ARG, "unknown engine handle"),
    };
    let (key, iv, server) =
        match begin_response_session_from_share(engine, &envelope, client_share) {
            Ok(v) => v,
            Err(e) => return err_null(OPE_ERR_CRYPTO, format!("begin_response: {e}")),
        };
    let server_share = encode(&server.bytes);
    let session = next_handle();
    guard.responses.insert(session, ResponseSession { key, iv });
    json_out(json!({ "session": session, "server_share": server_share }))
}

/// Engine: encrypt one response stream chunk. `plaintext_b64` is base64url of raw bytes.
/// Returns `{ "ciphertext": <base64url> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_response_encrypt_chunk(
    session: u64,
    seq: u32,
    plaintext_b64: *const c_char,
) -> *mut c_char {
    let pt_b64 = match read_str(plaintext_b64, "plaintext_b64") {
        Ok(s) => s,
        Err(p) => return p,
    };
    let plaintext = match decode(pt_b64) {
        Ok(b) => b,
        Err(_) => return err_null(OPE_ERR_INVALID_ARG, "plaintext_b64 not base64url"),
    };
    let guard = registries().lock().unwrap();
    let sess = match guard.responses.get(&session) {
        Some(s) => s,
        None => return err_null(OPE_ERR_INVALID_ARG, "unknown response session"),
    };
    match encrypt_response_chunk(&sess.key, &sess.iv, seq, &plaintext) {
        Ok(ct) => json_out(json!({ "ciphertext": ct })),
        Err(e) => err_null(OPE_ERR_CRYPTO, format!("encrypt_chunk: {e}")),
    }
}

/// Free a response session handle.
#[no_mangle]
pub extern "C" fn ope_e2e_response_free(session: u64) -> i32 {
    registries().lock().unwrap().responses.remove(&session);
    OPE_OK
}

// ---------------------------------------------------------------------------
// Client: encrypt request + decrypt response stream.
// ---------------------------------------------------------------------------

/// Client: encrypt a request payload to the engine identity and build the `e2e` envelope.
///
/// `base_envelope_json` provides envelope metadata (ope_version, alg, kid, recipient, ts,
/// nonce, meta, ...). When `want_response_session != 0`, a client session is retained for
/// response decryption and its handle is returned.
///
/// Returns `{ "envelope": <envelope-json>, "client_session": <u64 | null> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_client_encrypt_request(
    engine_identity_json: *const c_char,
    payload_json: *const c_char,
    base_envelope_json: *const c_char,
    want_response_session: i32,
) -> *mut c_char {
    let engine: EngineIdentity = match read_json(engine_identity_json, "engine_identity") {
        Ok(v) => v,
        Err(p) => return p,
    };
    let payload: Value = match read_json(payload_json, "payload") {
        Ok(v) => v,
        Err(p) => return p,
    };
    let mut envelope: Envelope = match read_json(base_envelope_json, "base_envelope") {
        Ok(v) => v,
        Err(p) => return p,
    };

    let session = if want_response_session != 0 {
        match ClientSession::generate() {
            Ok(s) => Some(s),
            Err(e) => return err_null(OPE_ERR_CRYPTO, format!("client session: {e}")),
        }
    } else {
        None
    };

    if let Err(e) = encrypt_request(&mut envelope, &engine, &payload, session.as_ref()) {
        return err_null(OPE_ERR_CRYPTO, format!("encrypt_request: {e}"));
    }

    let envelope_json = match serde_json::to_value(&envelope) {
        Ok(v) => v,
        Err(e) => return err_null(OPE_ERR_JSON, format!("envelope serialize: {e}")),
    };

    let session_handle = session.map(|s| {
        let h = next_handle();
        registries().lock().unwrap().clients.insert(h, s);
        h
    });

    json_out(json!({
        "envelope": envelope_json,
        "client_session": session_handle,
    }))
}

/// Client: decrypt one response stream chunk. Returns `{ "plaintext_b64": <base64url> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_client_decrypt_response_chunk(
    client_session: u64,
    request_envelope_json: *const c_char,
    server_share_b64: *const c_char,
    seq: u32,
    ciphertext_b64: *const c_char,
) -> *mut c_char {
    let request: Envelope = match read_json(request_envelope_json, "request_envelope") {
        Ok(v) => v,
        Err(p) => return p,
    };
    let server_share = match read_str(server_share_b64, "server_share_b64") {
        Ok(s) => s.to_string(),
        Err(p) => return p,
    };
    let ciphertext = match read_str(ciphertext_b64, "ciphertext_b64") {
        Ok(s) => s.to_string(),
        Err(p) => return p,
    };
    let guard = registries().lock().unwrap();
    let session = match guard.clients.get(&client_session) {
        Some(s) => s,
        None => return err_null(OPE_ERR_INVALID_ARG, "unknown client session"),
    };
    match decrypt_response_chunk(&request, session, &server_share, seq, &ciphertext) {
        Ok(pt) => json_out(json!({ "plaintext_b64": encode(&pt) })),
        Err(e) => err_null(OPE_ERR_CRYPTO, format!("decrypt_response_chunk: {e}")),
    }
}

/// Free a client session handle.
#[no_mangle]
pub extern "C" fn ope_e2e_client_session_free(client_session: u64) -> i32 {
    registries().lock().unwrap().clients.remove(&client_session);
    OPE_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
    use std::ffi::CString;

    unsafe fn take_json(ptr: *mut c_char) -> Value {
        assert!(!ptr.is_null(), "ffi returned null (error path)");
        let s = CStr::from_ptr(ptr).to_str().unwrap().to_string();
        crate::error::ope_string_free(ptr);
        serde_json::from_str(&s).unwrap()
    }

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn hybrid_request_response_roundtrip_via_ffi() {
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let ed_b64 = encode(kp.public.as_bytes());

        // Engine generates an epoch keypair.
        let engine_id = cstr("engine-ffi");
        let gen = unsafe {
            take_json(ope_e2e_engine_generate(engine_id.as_ptr(), cstr(&ed_b64).as_ptr()))
        };
        let engine_handle = gen["handle"].as_u64().unwrap();
        let identity = gen["identity"].clone();

        // Client encrypts a request (retaining a response session).
        let payload = json!({ "model": "llama3@teechat", "messages": [{ "role": "user", "content": "hi" }] });
        let base = json!({
            "ope_version": "1.0",
            "alg": "EdDSA",
            "enc": "none",
            "kid": "user-1",
            "recipient": "teechat-gateway",
            "ts": "2026-05-29T09:00:00Z",
            "nonce": "nonce-1",
            "payload_hash": "",
        });
        let enc = unsafe {
            take_json(ope_e2e_client_encrypt_request(
                cstr(&identity.to_string()).as_ptr(),
                cstr(&payload.to_string()).as_ptr(),
                cstr(&base.to_string()).as_ptr(),
                1,
            ))
        };
        let envelope = enc["envelope"].clone();
        let client_session = enc["client_session"].as_u64().unwrap();
        assert_eq!(envelope["enc"], "e2e-hybrid-pq");

        // Engine decrypts the request.
        let decrypted = unsafe {
            take_json(ope_e2e_engine_decrypt_request(
                engine_handle,
                cstr(&envelope.to_string()).as_ptr(),
            ))
        };
        assert_eq!(decrypted, payload);

        // Engine begins a response session and encrypts a chunk.
        let resp = unsafe {
            take_json(ope_e2e_engine_begin_response(
                engine_handle,
                cstr(&envelope.to_string()).as_ptr(),
            ))
        };
        let session = resp["session"].as_u64().unwrap();
        let server_share = resp["server_share"].as_str().unwrap().to_string();
        let chunk_pt = encode(b"hello from engine");
        let chunk = unsafe {
            take_json(ope_e2e_response_encrypt_chunk(
                session,
                0,
                cstr(&chunk_pt).as_ptr(),
            ))
        };
        let ciphertext = chunk["ciphertext"].as_str().unwrap().to_string();

        // Client decrypts the response chunk.
        let dec = unsafe {
            take_json(ope_e2e_client_decrypt_response_chunk(
                client_session,
                cstr(&envelope.to_string()).as_ptr(),
                cstr(&server_share).as_ptr(),
                0,
                cstr(&ciphertext).as_ptr(),
            ))
        };
        let pt = decode(dec["plaintext_b64"].as_str().unwrap()).unwrap();
        assert_eq!(pt, b"hello from engine");

        assert_eq!(ope_e2e_response_free(session), OPE_OK);
        assert_eq!(ope_e2e_client_session_free(client_session), OPE_OK);
        assert_eq!(ope_e2e_engine_free(engine_handle), OPE_OK);
    }

    #[test]
    fn unknown_engine_handle_errors() {
        let env = json!({
            "ope_version": "1.0", "alg": "EdDSA", "enc": "e2e-hybrid-pq",
            "kid": "k", "recipient": "r", "ts": "2026-05-29T09:00:00Z",
            "nonce": "n", "payload_hash": "",
        });
        let out = ope_e2e_engine_decrypt_request(987654, cstr(&env.to_string()).as_ptr());
        assert!(out.is_null());
    }
}
