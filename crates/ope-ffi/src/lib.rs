//! C ABI for OPE (minimal surface for bindings).

use std::ffi::CStr;
use std::os::raw::c_char;

use ope_crypto::{mock_keypair_from_seed, DEV_VECTOR_001_SEED};
use ope_envelope::{verify_envelope, Envelope, VerifyOptions};

/// Verify a JSON envelope using the dev vector-001 mock public key.
/// Returns 0 on success, non-zero on failure.
#[no_mangle]
pub unsafe extern "C" fn ope_verify_envelope_dev_json(json: *const c_char) -> i32 {
    if json.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(json) };
    let Ok(text) = c_str.to_str() else {
        return -2;
    };
    let Ok(envelope) = serde_json::from_str::<Envelope>(text) else {
        return -3;
    };
    let kp = mock_keypair_from_seed(&DEV_VECTOR_001_SEED);
    match verify_envelope(&envelope, &kp.public, &VerifyOptions::with_defaults()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ope_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}
