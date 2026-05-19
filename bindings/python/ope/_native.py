"""Load libope_ffi and expose envelope sign/verify."""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Union

OPE_OK = 0
OPE_ERR_VERIFY = -5

KeyBytes = bytes  # 32 bytes


class OpeError(RuntimeError):
  pass


class VerifyError(OpeError):
  pass


def _repo_root() -> Path:
  return Path(__file__).resolve().parents[3]


def lib_path() -> Path:
  env = os.environ.get("OPE_LIB_PATH")
  if env:
    return Path(env)
  root = _repo_root()
  target = root / "target" / "release"
  name = {
    "Darwin": "libope_ffi.dylib",
    "Linux": "libope_ffi.so",
    "Windows": "ope_ffi.dll",
  }.get(platform.system())
  if name is None:
    raise OpeError(f"unsupported platform: {platform.system()}")
  path = target / name
  if not path.exists():
    debug = root / "target" / "debug" / name
    if debug.exists():
      return debug
    raise OpeError(
      f"native library not found at {path}; run: cargo build -p ope-ffi --release"
    )
  return path


def _load_lib() -> ctypes.CDLL:
  lib = ctypes.CDLL(str(lib_path()))
  lib.ope_version.restype = ctypes.c_char_p
  lib.ope_last_error_message.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
  lib.ope_last_error_message.restype = ctypes.c_int
  lib.ope_string_free.argtypes = [ctypes.c_char_p]
  lib.ope_envelope_sign.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p),
  ]
  lib.ope_envelope_sign.restype = ctypes.c_int
  lib.ope_envelope_verify.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_char_p,
    ctypes.c_uint32,
  ]
  lib.ope_envelope_verify.restype = ctypes.c_int
  lib.ope_envelope_verify_dev_json.argtypes = [ctypes.c_char_p]
  lib.ope_envelope_verify_dev_json.restype = ctypes.c_int
  return lib


_LIB = None


def _lib() -> ctypes.CDLL:
  global _LIB
  if _LIB is None:
    _LIB = _load_lib()
  return _LIB


def version() -> str:
  raw = _lib().ope_version()
  return raw.decode("utf-8")


def last_error() -> str:
  buf = ctypes.create_string_buffer(512)
  _lib().ope_last_error_message(buf, len(buf))
  return buf.value.decode("utf-8")


def _key_array(key: KeyBytes) -> ctypes.Array:
  if len(key) != 32:
    raise ValueError("key must be 32 bytes")
  return (ctypes.c_uint8 * 32).from_buffer_copy(key)


def envelope_sign(secret_key: KeyBytes, envelope: Union[dict[str, Any], str]) -> str:
  json_in = envelope if isinstance(envelope, str) else json.dumps(envelope, separators=(",", ":"))
  out = ctypes.c_char_p()
  rc = _lib().ope_envelope_sign(_key_array(secret_key), json_in.encode("utf-8"), ctypes.byref(out))
  try:
    if rc != OPE_OK:
      raise OpeError(f"ope_envelope_sign failed ({rc}): {last_error()}")
    return out.value.decode("utf-8")
  finally:
    if out:
      _lib().ope_string_free(out)


def envelope_verify(
  public_key: KeyBytes,
  envelope: Union[dict[str, Any], str],
  *,
  max_skew_secs: int = 300,
) -> None:
  json_text = envelope if isinstance(envelope, str) else json.dumps(envelope, separators=(",", ":"))
  rc = _lib().ope_envelope_verify(
    _key_array(public_key),
    json_text.encode("utf-8"),
    ctypes.c_uint32(max_skew_secs),
  )
  if rc == OPE_ERR_VERIFY:
    raise VerifyError(last_error())
  if rc != OPE_OK:
    raise OpeError(f"ope_envelope_verify failed ({rc}): {last_error()}")


def envelope_verify_dev(envelope: Union[dict[str, Any], str]) -> None:
  json_text = envelope if isinstance(envelope, str) else json.dumps(envelope, separators=(",", ":"))
  rc = _lib().ope_envelope_verify_dev_json(json_text.encode("utf-8"))
  if rc == OPE_ERR_VERIFY:
    raise VerifyError(last_error())
  if rc != OPE_OK:
    raise OpeError(f"ope_envelope_verify_dev_json failed ({rc}): {last_error()}")
