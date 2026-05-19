# OPE — Open Privacy Envelope

Vendor-neutral protocol for privacy-preserving API calls (including OpenAI-compatible payloads).

| Document | Purpose |
|----------|---------|
| [`ope.md`](ope.md) | Core envelope, attestation APIs, OPE-OpenAI profile |
| [`spec/ope-transport.md`](spec/ope-transport.md) | Hybrid PQ transport (`X25519MLKEM768`, TLS-aligned) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, crates, design rules |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phased delivery status |

## Implementation status (P0)

| Component | Status |
|-----------|--------|
| Envelope sign/verify (Ed25519, JCS) | Done |
| `enc=none` + `payload_hash` | Done |
| `model@provider` routing parse | Done |
| Hybrid KEX `X25519MLKEM768` | Done (`ope-transport` + [official vectors](spec/vectors/transport/)) |
| Test vector `001` | Done |
| Attestation HTTP APIs (§14) | Spec only; `ope-attest` stub |
| TLS / HTTP record framing | Planned (P1) |
| Language bindings (C, Go, Python, TS) | Planned (P2) |

## Quick start

Requires **Rust stable** (see [`rust-toolchain.toml`](rust-toolchain.toml)).

```bash
cargo test --all

# Sign / verify interoperability vector (mock dev keys)
cargo run -p ope-cli -- sign --vector spec/vectors/001-valid-plaintext.json
cargo run -p ope-cli -- verify --vector spec/vectors/001-valid-plaintext.json

# Hybrid post-quantum KEX self-test (ML-KEM-768 + X25519)
cargo run -p ope-cli -- transport-test

# Print mock vector-001 key material
cargo run -p ope-cli -- keygen
```

CI (`.github/workflows/ci.yml`) signs vector `001` then runs `cargo test --all`.

## Repository layout

```text
ope.md                 # Protocol spec
spec/
  ope-transport.md     # Transport profile
  vectors/             # JSON test vectors
crates/
  ope-crypto/          # L0 primitives
  ope-envelope/        # L1 envelope
  ope-transport/       # L2 hybrid KEX
  ope-attest/          # L3 stub
  ope-ffi/             # C ABI (minimal)
  ope-cli/             # `ope` CLI
docs/
bindings/              # planned: Go, Python, TypeScript, C++
```

## Crates

| Crate | Description |
|-------|-------------|
| `ope-crypto` | Ed25519, SHA-256, base64url; deterministic mock keys for dev |
| `ope-envelope` | JCS canonicalization; `sign_envelope` / `verify_envelope` |
| `ope-transport` | `X25519MLKEM768` per [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) |
| `ope-attest` | Attestation / verification API (stub) |
| `ope-ffi` | `ope_verify_envelope_dev_json()` for bindings work |
| `ope-cli` | Vector tooling and transport self-test |

## Development keys

Vector [`001-valid-plaintext.json`](spec/vectors/001-valid-plaintext.json) uses seed `0x01` repeated 32 bytes. **Development and CI only.** See [`spec/vectors/README.md`](spec/vectors/README.md).

## Standards alignment

- **Envelope:** Ed25519 (`alg=EdDSA`), SHA-256 `payload_hash`, JCS signed fields.
- **Transport:** Same hybrid profile as Google Chrome / AWS KMS PQ TLS — TLS 1.3 + **X25519** + **ML-KEM-768** ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)), combined shared secret `ML-KEM_ss || X25519_ss`.
