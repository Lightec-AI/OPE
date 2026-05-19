"""OPE Python bindings (ctypes → libope_ffi)."""

from ope._native import (
    OpeError,
    VerifyError,
    envelope_sign,
    envelope_verify,
    envelope_verify_dev,
    last_error,
    lib_path,
    version,
)

__all__ = [
    "OpeError",
    "VerifyError",
    "envelope_sign",
    "envelope_verify",
    "envelope_verify_dev",
    "last_error",
    "lib_path",
    "version",
]

__version__ = "0.1.0"
