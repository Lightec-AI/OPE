# OPE — Open Privacy Envelope

Privacy layer for **Confidential AI**: signed envelopes on **standard TLS**, with post-quantum **application-layer E2E** encryption so TDX/SEV gateways can authenticate and meter traffic without reading prompts, and only the target inference TEE (TDX/SEV + GPU) decrypts requests.

| Document | Purpose |
|----------|---------|
| [`ope.md`](ope.md) | Core envelope + attestation APIs |
| [`spec/ope-confidential-ai.md`](spec/ope-confidential-ai.md) | **Confidential AI E2E profile** |
| [`docs/confidential-ai.md`](docs/confidential-ai.md) | Client / gateway / engine architecture |
| [`spec/ope-transport.md`](spec/ope-transport.md) | Optional TLS PQ KEX alignment |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Crates and layers |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phased delivery |

## Architecture (summary)

```text
Client ──HTTPS (TLS unchanged)──► Gateway (TDX/SEV) ──► Inference engine (TDX/SEV + GPU TEE)
         OPE enc=e2e-hybrid-pq          meta + sig only        decrypt / infer / stream-encrypt
```

- **Request:** Hybrid **ML-KEM-768 + X25519** to engine static keys; ChaCha20-Poly1305 ciphertext.
- **Response:** Encrypted to client **ephemeral** hybrid session; **streaming** via `chacha20poly1305-stream`.
- **Third parties:** Light SDK (`ope-e2e` + sign) — no custom TLS.

## Quick start

Requires **Rust stable** ([`rust-toolchain.toml`](rust-toolchain.toml)).

```bash
cargo test --all

# Confidential AI E2E round-trip (mock engine)
cargo run -p ope-cli -- e2e-test

# Legacy envelope vectors
cargo run -p ope-cli -- verify --vector spec/vectors/001-valid-plaintext.json

# Optional TLS PQ KEX self-test (not application E2E)
cargo run -p ope-cli -- transport-test

cargo run -p ope-cli -- gen-vectors --dir spec/vectors
cargo run -p ope-cli -- serve --addr 127.0.0.1:8080
```

## Crates

| Crate | Role |
|-------|------|
| `ope-crypto` | Ed25519, SHA-256, AEAD helpers |
| `ope-envelope` | Signed envelope, `meta`, `enc=e2e-hybrid-pq` fields |
| **`ope-e2e`** | **Confidential AI** hybrid PQ encrypt/decrypt + stream |
| `ope-transport` | X25519MLKEM768 KEX (TLS vector alignment) |
| `ope-gateway` | Opaque gateway verify + routing |
| `ope-attest` / `ope-server` | Attestation APIs (mock) |
| `ope-ffi` / `bindings/` | Thin client libraries (envelope today) |

## Standards

- Envelope: Ed25519, JCS, `payload_hash`.
- E2E: ML-KEM-768 + X25519 ([draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)) with OPE HKDF domain `OPE-E2E-v1`.
- TLS: External stack, unchanged integration ([`docs/tls-integration.md`](docs/tls-integration.md)).
