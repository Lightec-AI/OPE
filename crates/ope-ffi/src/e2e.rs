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
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use ope_crypto::{decode, encode, public_key_from_bytes};
use ope_e2e::{
    begin_response_session_from_share, decrypt_request, decrypt_response_chunk, encrypt_request,
    encrypt_response_chunk, ClientSession, E2eFields, EngineIdentity, EngineStaticSecret,
};
use ope_envelope::Envelope;
use serde_json::{json, Value};
use zeroize::ZeroizeOnDrop;

use crate::error::{
    set_last_error_code, OPE_ERR_CRYPTO, OPE_ERR_INTERNAL, OPE_ERR_INVALID_ARG, OPE_ERR_JSON, OPE_OK,
};

/// Derived response-stream key + IV. The key is zeroized on drop (SEC-028); the IV is not
/// secret but is small enough to clear alongside it.
#[derive(ZeroizeOnDrop)]
struct ResponseSession {
    key: [u8; 32],
    iv: [u8; 12],
}

/// Secrets are held behind `Arc` so a caller can clone the handle out under a short critical
/// section and run the (potentially slow, attacker-influenced) crypto **without** holding the
/// global registry lock. This avoids serializing all crypto on one mutex and, combined with the
/// `catch_unwind` guards below, prevents a panic from poisoning the lock and wedging the process
/// (SEC-020).
#[derive(Default)]
struct Registries {
    engines: HashMap<u64, Arc<EngineStaticSecret>>,
    clients: HashMap<u64, Arc<ClientSession>>,
    responses: HashMap<u64, Arc<ResponseSession>>,
}

static REG: OnceLock<Mutex<Registries>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn registries() -> &'static Mutex<Registries> {
    REG.get_or_init(|| Mutex::new(Registries::default()))
}

/// Acquire the registry lock, recovering from a poisoned mutex instead of panicking. The data
/// behind the lock is plain handle maps (no broken invariant), so recovery is safe.
fn lock_registries() -> MutexGuard<'static, Registries> {
    registries().lock().unwrap_or_else(|e| e.into_inner())
}

fn next_handle() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn err_null(code: i32, msg: impl Into<String>) -> *mut c_char {
    set_last_error_code(code, msg);
    std::ptr::null_mut()
}

/// Run a pointer-returning FFI body with panic isolation. A panic must never unwind across the
/// C ABI (UB / process abort); convert it to a null + last-error instead (SEC-020).
fn guard_ptr(op: &str, f: impl FnOnce() -> *mut c_char) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => err_null(OPE_ERR_INTERNAL, format!("panic in {op}")),
    }
}

/// Run a status-returning FFI body with panic isolation.
fn guard_status(f: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(c) => c,
        Err(_) => OPE_ERR_INTERNAL,
    }
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
    guard_ptr("ope_e2e_engine_generate", || {
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
        let identity_json = match serde_json::to_value(&identity) {
            Ok(v) => v,
            Err(e) => return err_null(OPE_ERR_JSON, format!("identity serialize: {e}")),
        };
        let handle = next_handle();
        lock_registries().engines.insert(handle, Arc::new(secret));
        json_out(json!({ "handle": handle, "identity": identity_json }))
    })
}

/// Free an engine epoch handle. Returns `OPE_OK` even if the handle was unknown.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_free(handle: u64) -> i32 {
    guard_status(|| {
        lock_registries().engines.remove(&handle);
        OPE_OK
    })
}

/// Engine: decrypt a request envelope. Returns the plaintext payload JSON.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_decrypt_request(
    handle: u64,
    envelope_json: *const c_char,
) -> *mut c_char {
    guard_ptr("ope_e2e_engine_decrypt_request", || {
        let envelope: Envelope = match read_json(envelope_json, "envelope") {
            Ok(v) => v,
            Err(p) => return p,
        };
        // Clone the Arc under a short lock, then decrypt without holding the registry mutex.
        let engine = match lock_registries().engines.get(&handle).cloned() {
            Some(e) => e,
            None => return err_null(OPE_ERR_INVALID_ARG, "unknown engine handle"),
        };
        match decrypt_request(&envelope, &engine) {
            Ok(payload) => json_out(payload),
            Err(e) => err_null(OPE_ERR_CRYPTO, format!("decrypt_request: {e}")),
        }
    })
}

/// Engine: begin a streaming response session bound to the request's client share.
/// Returns `{ "session": <u64>, "server_share": <base64url> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_engine_begin_response(
    handle: u64,
    request_envelope_json: *const c_char,
) -> *mut c_char {
    guard_ptr("ope_e2e_engine_begin_response", || {
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
        let engine = match lock_registries().engines.get(&handle).cloned() {
            Some(e) => e,
            None => return err_null(OPE_ERR_INVALID_ARG, "unknown engine handle"),
        };
        let (key, iv, server) =
            match begin_response_session_from_share(&engine, &envelope, client_share) {
                Ok(v) => v,
                Err(e) => return err_null(OPE_ERR_CRYPTO, format!("begin_response: {e}")),
            };
        let server_share = encode(&server.bytes);
        let session = next_handle();
        lock_registries()
            .responses
            .insert(session, Arc::new(ResponseSession { key, iv }));
        json_out(json!({ "session": session, "server_share": server_share }))
    })
}

/// Engine: encrypt one response stream chunk. `plaintext_b64` is base64url of raw bytes.
/// Returns `{ "ciphertext": <base64url> }`.
#[no_mangle]
pub extern "C" fn ope_e2e_response_encrypt_chunk(
    session: u64,
    seq: u32,
    plaintext_b64: *const c_char,
) -> *mut c_char {
    guard_ptr("ope_e2e_response_encrypt_chunk", || {
        let pt_b64 = match read_str(plaintext_b64, "plaintext_b64") {
            Ok(s) => s,
            Err(p) => return p,
        };
        let plaintext = match decode(pt_b64) {
            Ok(b) => b,
            Err(_) => return err_null(OPE_ERR_INVALID_ARG, "plaintext_b64 not base64url"),
        };
        let sess = match lock_registries().responses.get(&session).cloned() {
            Some(s) => s,
            None => return err_null(OPE_ERR_INVALID_ARG, "unknown response session"),
        };
        match encrypt_response_chunk(&sess.key, &sess.iv, seq, &plaintext) {
            Ok(ct) => json_out(json!({ "ciphertext": ct })),
            Err(e) => err_null(OPE_ERR_CRYPTO, format!("encrypt_chunk: {e}")),
        }
    })
}

/// Free a response session handle.
#[no_mangle]
pub extern "C" fn ope_e2e_response_free(session: u64) -> i32 {
    guard_status(|| {
        lock_registries().responses.remove(&session);
        OPE_OK
    })
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
    guard_ptr("ope_e2e_client_encrypt_request", || {
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
            lock_registries().clients.insert(h, Arc::new(s));
            h
        });

        json_out(json!({
            "envelope": envelope_json,
            "client_session": session_handle,
        }))
    })
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
    guard_ptr("ope_e2e_client_decrypt_response_chunk", || {
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
        let session = match lock_registries().clients.get(&client_session).cloned() {
            Some(s) => s,
            None => return err_null(OPE_ERR_INVALID_ARG, "unknown client session"),
        };
        match decrypt_response_chunk(&request, &session, &server_share, seq, &ciphertext) {
            Ok(pt) => json_out(json!({ "plaintext_b64": encode(&pt) })),
            Err(e) => err_null(OPE_ERR_CRYPTO, format!("decrypt_response_chunk: {e}")),
        }
    })
}

/// Free a client session handle.
#[no_mangle]
pub extern "C" fn ope_e2e_client_session_free(client_session: u64) -> i32 {
    guard_status(|| {
        lock_registries().clients.remove(&client_session);
        OPE_OK
    })
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

    #[test]
    fn null_and_invalid_inputs_error_without_panic() {
        // Null pointers must not deref-panic.
        assert!(ope_e2e_engine_generate(std::ptr::null(), std::ptr::null()).is_null());
        assert!(
            ope_e2e_engine_decrypt_request(1, std::ptr::null()).is_null(),
            "null envelope"
        );
        // Malformed JSON envelope.
        let bad = cstr("{not json");
        assert!(ope_e2e_engine_decrypt_request(1, bad.as_ptr()).is_null());
        // Unknown sessions on every handle-based call.
        let env = cstr(&json!({"ope_version":"1.0","alg":"EdDSA","enc":"none","kid":"k","recipient":"r","ts":"2026-05-29T09:00:00Z","nonce":"n","payload_hash":""}).to_string());
        assert!(ope_e2e_engine_begin_response(424242, env.as_ptr()).is_null());
        assert!(ope_e2e_response_encrypt_chunk(424242, 0, cstr(&encode(b"x")).as_ptr()).is_null());
        assert!(ope_e2e_client_decrypt_response_chunk(
            424242,
            env.as_ptr(),
            cstr("AAAA").as_ptr(),
            0,
            cstr("AAAA").as_ptr(),
        )
        .is_null());
    }

    #[test]
    fn free_is_idempotent_and_unknown_safe() {
        // Free on never-seen handles returns OK (no panic / no poison).
        assert_eq!(ope_e2e_engine_free(111111), OPE_OK);
        assert_eq!(ope_e2e_response_free(111111), OPE_OK);
        assert_eq!(ope_e2e_client_session_free(111111), OPE_OK);
        // Double free is safe.
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let gen = unsafe {
            take_json(ope_e2e_engine_generate(
                cstr("dbl").as_ptr(),
                cstr(&encode(kp.public.as_bytes())).as_ptr(),
            ))
        };
        let h = gen["handle"].as_u64().unwrap();
        assert_eq!(ope_e2e_engine_free(h), OPE_OK);
        assert_eq!(ope_e2e_engine_free(h), OPE_OK);
    }

    #[test]
    fn lock_recovers_from_poison() {
        // Poison the registry mutex deliberately, then confirm FFI calls still work
        // (poison recovery via `lock_registries`), proving a panic-while-locked elsewhere
        // cannot wedge the whole process.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _g = registries().lock().unwrap();
            panic!("force poison");
        }));
        assert!(registries().is_poisoned());

        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let gen = unsafe {
            take_json(ope_e2e_engine_generate(
                cstr("after-poison").as_ptr(),
                cstr(&encode(kp.public.as_bytes())).as_ptr(),
            ))
        };
        let h = gen["handle"].as_u64().unwrap();
        assert_eq!(ope_e2e_engine_free(h), OPE_OK);
    }

    #[test]
    fn concurrent_engine_generate_is_thread_safe() {
        use std::thread;
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        let ed = encode(kp.public.as_bytes());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let ed = ed.clone();
                thread::spawn(move || {
                    let gen = unsafe {
                        take_json(ope_e2e_engine_generate(
                            cstr(&format!("eng-{i}")).as_ptr(),
                            cstr(&ed).as_ptr(),
                        ))
                    };
                    gen["handle"].as_u64().unwrap()
                })
            })
            .collect();
        let ids: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // All handles unique and freeable.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "handles must be unique");
        for h in ids {
            assert_eq!(ope_e2e_engine_free(h), OPE_OK);
        }
    }
}
