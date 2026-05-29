//! Stable C ABI for OPE language bindings.

mod e2e;
mod envelope;
mod error;

pub use error::{
    ope_last_error_alloc, ope_last_error_message, ope_string_free, OPE_ERR_CRYPTO,
    OPE_ERR_INTERNAL, OPE_ERR_INVALID_ARG, OPE_ERR_JSON, OPE_ERR_UTF8, OPE_ERR_VERIFY, OPE_OK,
};

pub use envelope::{
    ope_envelope_sign, ope_envelope_sign_alloc, ope_envelope_verify,
    ope_envelope_verify_dev_json,
};

pub use e2e::{
    ope_e2e_client_decrypt_response_chunk, ope_e2e_client_encrypt_request,
    ope_e2e_client_session_free, ope_e2e_engine_begin_response, ope_e2e_engine_decrypt_request,
    ope_e2e_engine_free, ope_e2e_engine_generate, ope_e2e_response_encrypt_chunk,
    ope_e2e_response_free,
};

use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn ope_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Backward-compatible alias.
#[no_mangle]
pub unsafe extern "C" fn ope_verify_envelope_dev_json(json: *const c_char) -> i32 {
    ope_envelope_verify_dev_json(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
    use std::ffi::CString;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
        // Use a current timestamp so the verifier's freshness window is satisfied
        // regardless of when the suite runs (avoids hardcoded-date time bombs).
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let input = CString::new(format!(
            r#"{{"ope_version":"1.0","alg":"EdDSA","enc":"none","kid":"k","recipient":"r","ts":"{ts}","nonce":"abc","payload_hash":"","payload":{{"model":"gpt-4.1@openai","messages":[]}}}}"#,
        ))
        .unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let rc = unsafe {
            ope_envelope_sign(kp.secret.to_bytes().as_ptr(), input.as_ptr(), &mut out)
        };
        assert_eq!(rc, OPE_OK);
        assert!(!out.is_null());
        let rc2 = unsafe { ope_envelope_verify(kp.public.to_bytes().as_ptr(), out, 86_400) };
        assert_eq!(rc2, OPE_OK);
        unsafe { ope_string_free(out) };
    }
}
