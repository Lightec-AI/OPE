use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;

thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

pub const OPE_OK: i32 = 0;
pub const OPE_ERR_INVALID_ARG: i32 = -1;
pub const OPE_ERR_UTF8: i32 = -2;
pub const OPE_ERR_JSON: i32 = -3;
pub const OPE_ERR_CRYPTO: i32 = -4;
pub const OPE_ERR_VERIFY: i32 = -5;
pub const OPE_ERR_INTERNAL: i32 = -99;

#[allow(dead_code)]
pub fn set_last_error(msg: impl Into<String>) -> i32 {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
    OPE_ERR_INTERNAL
}

pub fn set_last_error_code(code: i32, msg: impl Into<String>) -> i32 {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
    code
}

#[no_mangle]
pub extern "C" fn ope_last_error_message(buf: *mut c_char, buflen: usize) -> i32 {
    if buf.is_null() || buflen == 0 {
        return OPE_ERR_INVALID_ARG;
    }
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    let bytes = msg.as_bytes();
    let copy_len = (buflen - 1).min(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy_len);
        *buf.add(copy_len) = 0;
    }
    bytes.len() as i32
}

/// Allocate and return the last error message as a NUL-terminated C string.
/// Returns null when there is no message. Free with [`ope_string_free`].
#[no_mangle]
pub extern "C" fn ope_last_error_alloc() -> *mut c_char {
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    if msg.is_empty() {
        return std::ptr::null_mut();
    }
    match CString::new(msg) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ope_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
