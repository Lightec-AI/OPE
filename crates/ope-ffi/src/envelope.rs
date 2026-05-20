use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;

use ope_crypto::{public_key_from_bytes, secret_key_from_bytes};
use ope_envelope::{sign_envelope, verify_envelope, Envelope, VerifyOptions};

use crate::error::{
    ope_string_free, set_last_error_code, OPE_ERR_CRYPTO, OPE_ERR_INVALID_ARG, OPE_ERR_JSON,
    OPE_ERR_INTERNAL, OPE_ERR_UTF8, OPE_ERR_VERIFY, OPE_OK,
};

fn parse_envelope_json(json: *const c_char) -> Result<Envelope, i32> {
    if json.is_null() {
        return Err(set_last_error_code(
            OPE_ERR_INVALID_ARG,
            "null json pointer",
        ));
    }
    let c_str = unsafe { CStr::from_ptr(json) };
    let text = c_str
        .to_str()
        .map_err(|e| set_last_error_code(OPE_ERR_UTF8, format!("invalid utf-8: {e}")))?;
    serde_json::from_str(text)
        .map_err(|e| set_last_error_code(OPE_ERR_JSON, format!("invalid json: {e}")))
}

fn key32(ptr: *const u8, name: &str) -> Result<[u8; 32], i32> {
    if ptr.is_null() {
        return Err(set_last_error_code(
            OPE_ERR_INVALID_ARG,
            format!("null {name}"),
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, 32) };
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Sign an envelope JSON object. Writes a newly allocated JSON string to `*out_json`.
#[no_mangle]
pub unsafe extern "C" fn ope_envelope_sign(
    secret_key: *const u8,
    json_in: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    if out_json.is_null() {
        return set_last_error_code(OPE_ERR_INVALID_ARG, "null out_json");
    }
    let seed = match key32(secret_key, "secret_key") {
        Ok(s) => s,
        Err(c) => return c,
    };
    let mut envelope = match parse_envelope_json(json_in) {
        Ok(e) => e,
        Err(c) => return c,
    };
    let secret = secret_key_from_bytes(&seed);
    if let Err(e) = sign_envelope(&mut envelope, &secret) {
        return set_last_error_code(OPE_ERR_CRYPTO, format!("sign failed: {e}"));
    }
    let text = match serde_json::to_string(&envelope) {
        Ok(t) => t,
        Err(e) => return set_last_error_code(OPE_ERR_JSON, format!("serialize failed: {e}")),
    };
    match CString::new(text) {
        Ok(c) => {
            unsafe { *out_json = c.into_raw() };
            OPE_OK
        }
        Err(e) => set_last_error_code(OPE_ERR_INTERNAL, format!("cstring failed: {e}")),
    }
}

/// Sign and return allocated JSON (`ope_string_free`). Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn ope_envelope_sign_alloc(
    secret_key: *const u8,
    json_in: *const c_char,
) -> *mut c_char {
    let mut out: *mut c_char = std::ptr::null_mut();
    let rc = ope_envelope_sign(secret_key, json_in, &mut out);
    if rc == OPE_OK {
        out
    } else {
        if !out.is_null() {
            ope_string_free(out);
        }
        std::ptr::null_mut()
    }
}

/// Verify an envelope JSON object with a 32-byte Ed25519 public key.
/// `max_skew_secs`: 0 uses default (300).
#[no_mangle]
pub unsafe extern "C" fn ope_envelope_verify(
    public_key: *const u8,
    json: *const c_char,
    max_skew_secs: u32,
) -> i32 {
    let pk_bytes = match key32(public_key, "public_key") {
        Ok(b) => b,
        Err(c) => return c,
    };
    let envelope = match parse_envelope_json(json) {
        Ok(e) => e,
        Err(c) => return c,
    };
    let public = match public_key_from_bytes(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return set_last_error_code(OPE_ERR_CRYPTO, "invalid public key"),
    };
    let max_skew = if max_skew_secs == 0 {
        300
    } else {
        max_skew_secs
    };
    let options = VerifyOptions {
        max_skew: Duration::from_secs(max_skew as u64),
        seen_nonces: None,
        expected_recipient: None,
        content_key: None,
        require_routed_model: false,
        opaque_e2e: false,
    };
    match verify_envelope(&envelope, &public, &options) {
        Ok(()) => OPE_OK,
        Err(e) => set_last_error_code(OPE_ERR_VERIFY, format!("verify failed: {e}")),
    }
}

/// Verify using the dev vector-001 mock public key (CI/dev only).
#[no_mangle]
pub unsafe extern "C" fn ope_envelope_verify_dev_json(json: *const c_char) -> i32 {
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
    let envelope = match parse_envelope_json(json) {
        Ok(e) => e,
        Err(c) => return c,
    };
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    match verify_envelope(&envelope, &kp.public, &VerifyOptions::with_defaults()) {
        Ok(()) => OPE_OK,
        Err(e) => set_last_error_code(OPE_ERR_VERIFY, format!("verify failed: {e}")),
    }
}
