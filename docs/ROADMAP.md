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
| CI: sign vector + `cargo test --all` | Done |
| `ope-ffi` minimal C hook | Done (dev verify only) |

## P1 — Transport & wire framing

| Item | Status |
|------|--------|
| TLS 1.3 integration guide (s2n-tls / BoringSSL policies) | Not started |
| HKDF bridge from 64-byte hybrid secret → record keys | Not started |
| HTTP framing: `Content-Type: application/ope+json` | Not started |
| Envelope `enc=A256GCM` / `xchacha20poly1305` in `ope-envelope` | Not started |
| Vectors `002`–`008` | Not started |

## P2 — Language bindings

| Item | Status |
|------|--------|
| Stable `ope.h` C ABI (sign + verify + error strings) | Not started |
| Python / Go / TypeScript (WASM) thin wrappers | Not started |
| Published packages / crates.io | Not started |

## P3 — Gateway + attestation

| Item | Status |
|------|--------|
| `ope-attest`: `POST /v1/ope/attestations` | Not started |
| `ope-attest`: `POST /v1/ope/verifications:verifyEnvelope` | Not started |
| Mock attester for CI | Not started |
| Gateway: verify + strip `model@provider` + route | Not started |

## P4 — Application SDK

| Item | Status |
|------|--------|
| `conversations/<id>/` local layout | Not started |
| File manifest (`file_id`, `sha256`) | Not started |
| Desktop / mobile storage adapters | Not started |

## P5 — TEE profiles

| Item | Status |
|------|--------|
| Mock TDX / SEV-SNP / GPU attestation claims in CI | Not started |
| Manual lab: [AMDESE/AMDSEV](https://github.com/AMDESE/AMDSEV), [canonical/tdx](https://github.com/canonical/tdx), [nvtrust](https://github.com/NVIDIA/nvtrust) | Not started |

## How to contribute to the next phase

1. **P1:** Add `docs/tls-integration.md` and wire `ope-transport` output into a TLS 1.3 stack or document s2n-tls policy names (`AWS-CRT-SDK-TLSv1.3-2025-PQ`).
2. **P2:** Expand `ope-ffi` + `bindings/` using vector `001` as the conformance gate.
3. **P3:** Implement `ope.md` §14 against `ope-attest` with mock keys first.
