# OPE TLS 1.3 integration guide (P1)

OPE-Transport uses **TLS 1.3** with hybrid **`X25519MLKEM768`** (`0x11EC`) per [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/). Envelope signing (Ed25519) remains separate from TLS credentials.

## Recommended production stacks

| Stack | Policy / notes |
|-------|----------------|
| [AWS s2n-tls](https://github.com/aws/s2n-tls) | Security policies `AWS-CRT-SDK-TLSv1.3-2025-PQ`, `AWS-LC-TLSv1.3-2025-PQ` |
| [Google BoringSSL / Chromium](https://chromium.googlesource.com/chromium/src/+/main/net/socket/) | Group `X25519MLKEM768` (`4588` / `0x11EC`) |
| [AWS KMS PQ TLS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html) | Same hybrid group for KMS endpoints |

Configure the client and server to negotiate **`X25519MLKEM768`** (and optionally classical fallbacks per your threat model). Record protection stays **AES-256-GCM** (TLS 1.3 default).

## Mapping `ope-transport` → TLS

1. **KEX (in-repo):** `ope_transport::ClientKeyExchange` / `ServerKeyExchange` produce the 64-byte combined secret `ML-KEM_ss || X25519_ss` (see `spec/ope-transport.md` §3).
2. **HKDF (in-repo harness):** `ope_transport::derive_record_keys` expands that secret into client/server write keys and IVs for tests. Production MUST use the TLS 1.3 key schedule in your TLS library instead of calling this directly on the wire.
3. **Application data:** After TLS is up, send OPE envelopes with `Content-Type: application/ope+json` (`ope-http` constants).

```rust
use ope_transport::{ClientKeyExchange, ServerKeyExchange, client_shared_secret, derive_record_keys};

let client = ClientKeyExchange::generate()?;
let (server_share, _) = ServerKeyExchange::respond_to(&client)?;
let secret = client_shared_secret(&client, &server_share)?;
let keys = derive_record_keys(&secret, &client_random, &server_random)?;
```

## HTTP framing

| Header | Value |
|--------|--------|
| `Content-Type` | `application/ope+json` (envelope body) |
| Attestation / verification APIs | `application/json` per `ope.md` §14 |

See `ope-http` and `ope-server` (`cargo run -p ope-cli -- serve`).

## Defense in depth

| Layer | Protects |
|-------|----------|
| TLS 1.3 + hybrid KEX | Wire confidentiality / PQ-forward secrecy on channel |
| OPE envelope signature | Sender authenticity + integrity of signed fields |
| `enc=xchacha20poly1305` / `enc=A256GCM` | Payload confidentiality to gateway even if TLS terminates early |

## Development / CI

- Run primitive KEX tests: `cargo run -p ope-cli -- transport-test`
- Official vectors: `cargo test -p ope-transport --test official_vectors`
- Self-signed TLS certs are acceptable locally; **never** use `dev_only` envelope or attester keys in production.
