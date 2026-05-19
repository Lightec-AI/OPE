# OPE roadmap

Last updated to match the Rust reference workspace in this repository.

## P0 — Reference core ✅

| Item | Status |
|------|--------|
| Monorepo + `rust-toolchain.toml` (stable) | Done |
| `ope-envelope` sign/verify (JCS, Ed25519) | Done |
| `enc=none`, `payload_hash`, timestamp skew | Done |
| OPE-OpenAI `model@provider` parse | Done |
| Mock keys + vector `001-valid-plaintext.json` | Done |
| `ope-cli` (`sign`, `verify`, `transport-test`, `keygen`) | Done |
| `spec/ope-transport.md` | Done |
| `X25519MLKEM768` KEX round-trip (`ope-transport`) | Done |
| Official transport vectors (BoringSSL + RFC 7748 + hybrid) | Done |
| CI: vectors + `cargo test --all` | Done |

## P1 — Transport & wire framing ✅

| Item | Status |
|------|--------|
| TLS 1.3 integration guide (s2n-tls / BoringSSL policies) | Done — [`docs/tls-integration.md`](tls-integration.md) |
| HKDF bridge from 64-byte hybrid secret → record keys | Done — `ope_transport::derive_record_keys` |
| HTTP framing: `Content-Type: application/ope+json` | Done — `ope-http` |
| Envelope `enc=A256GCM` / `xchacha20poly1305` | Done — `ope-envelope` encrypt/decrypt |
| Vectors `002`–`008` | Done — `ope gen-vectors` |

## P2 — Language bindings (partial)

| Item | Status |
|------|--------|
| Stable `ope.h` C ABI (sign + verify + error strings) | Done |
| Python / Go / TypeScript (Node koffi) / C++ wrappers | Done (envelope P0) |
| Transport + attestation in FFI | Not started |
| Browser WASM | Not started |
| Published packages / crates.io | Not started |

## P3 — Gateway + attestation ✅ (mock / dev)

| Item | Status |
|------|--------|
| `ope-attest`: attestation sign/verify + `MockAttester` | Done |
| `ope-server`: `POST /v1/ope/attestations` | Done |
| `ope-server`: `POST /v1/ope/verifications:verifyEnvelope` | Done |
| `ope-gateway`: verify + strip `model@provider` | Done |
| Production attester evidence (OIDC, real TEE) | Not started |

## P4 — Application SDK (stub)

| Item | Status |
|------|--------|
| `sdks/conversation`: manifest + layout docs | Done (stub) |
| File manifest (`file_id`, `sha256`) | Done |
| Desktop / mobile storage adapters | Not started |

## P5 — TEE profiles (stub)

| Item | Status |
|------|--------|
| Mock TEE evidence type in `MockAttester` (`mock_tee`) | Done |
| Manual lab: AMD SEV / TDX / nvtrust | Not started |

## How to contribute

1. **Production TLS:** Wire `ope-transport` KEX into s2n-tls/BoringSSL per [`docs/tls-integration.md`](tls-integration.md).
2. **FFI:** Expose encrypt/verify and attestation in `ope-ffi` + bindings.
3. **Attestation:** Replace `MockAttester` with OIDC / real TEE evidence validators.
