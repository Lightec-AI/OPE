/**
 * OPE C API — envelope sign/verify (implemented in Rust `ope-ffi`).
 *
 * Build: `cargo build -p ope-ffi --release`
 * Link:  `-L target/release -lope_ffi`
 */
#ifndef OPE_H
#define OPE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPE_KEY_BYTES 32

#define OPE_OK 0
#define OPE_ERR_INVALID_ARG -1
#define OPE_ERR_UTF8 -2
#define OPE_ERR_JSON -3
#define OPE_ERR_CRYPTO -4
#define OPE_ERR_VERIFY -5
#define OPE_ERR_INTERNAL -99

const char *ope_version(void);

/** Copy last error message into `buf` (NUL-terminated). Returns message length. */
int ope_last_error_message(char *buf, size_t buflen);

void ope_string_free(char *s);

/**
 * Sign envelope JSON. `secret_key` is 32-byte Ed25519 seed/key.
 * On success, sets `*out_json` (free with `ope_string_free`).
 */
int ope_envelope_sign(const uint8_t secret_key[OPE_KEY_BYTES],
                      const char *json_in,
                      char **out_json);

/** Sign; returns allocated JSON or NULL on error (free with `ope_string_free`). */
char *ope_envelope_sign_alloc(const uint8_t secret_key[OPE_KEY_BYTES],
                              const char *json_in);

/**
 * Verify envelope JSON with 32-byte Ed25519 public key.
 * `max_skew_secs`: 0 → default 300s.
 */
int ope_envelope_verify(const uint8_t public_key[OPE_KEY_BYTES],
                        const char *json,
                        uint32_t max_skew_secs);

/** Verify with dev vector-001 mock key (development only). */
int ope_envelope_verify_dev_json(const char *json);

/** @deprecated use ope_envelope_verify_dev_json */
int ope_verify_envelope_dev_json(const char *json);

#ifdef __cplusplus
}
#endif

#endif /* OPE_H */
