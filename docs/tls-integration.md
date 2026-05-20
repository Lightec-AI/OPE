# TLS integration (unchanged third-party TLS)

OPE **does not** define a custom TLS record layer. Integrators use **normal TLS 1.3** (OpenSSL, BoringSSL, s2n-tls, platform stacks) and carry OPE bodies as `application/ope+json`.

## Confidential AI placement

| Layer | What it protects | Required? |
|-------|------------------|-----------|
| **TLS 1.3** | Bytes on the wire to gateway | Yes (standard HTTPS) |
| **OPE envelope `sig`** | Sender auth + envelope integrity | Yes |
| **`enc=e2e-hybrid-pq`** | Prompt/context to **inference engine only** | Yes (Confidential AI profile) |

The gateway may terminate TLS inside a TEE but still MUST treat `ciphertext` as opaque (see [`confidential-ai.md`](confidential-ai.md)).

## Optional PQ TLS

For channel-level post-quantum hybrid KEX, configure your TLS stack with **`X25519MLKEM768`** per [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/). This is **independent** of OPE-E2E content keys (`ope-e2e` HKDF label `OPE-E2E-v1`).

| Stack | Notes |
|-------|--------|
| AWS s2n-tls | Policies `AWS-CRT-SDK-TLSv1.3-2025-PQ` |
| Google BoringSSL / Chromium | Group `0x11EC` |
| AWS KMS PQ TLS | Same hybrid group |

Reference KEX tests: `cargo run -p ope-cli -- transport-test` (`ope-transport` only).

## HTTP framing

| Header | Value |
|--------|--------|
| `Content-Type` | `application/ope+json` |
| Streaming response chunks | `application/ope+json` lines or SSE `data:` with `ope_stream` objects |

## Development / CI

- Envelope vectors: `cargo test -p ope-envelope`
- E2E round-trip: `cargo run -p ope-cli -- e2e-test`
- Transport vectors: `cargo test -p ope-transport --test official_vectors`

Do not use `dev_only` envelope or mock engine seeds (`DEV_ENGINE_SEED`) in production.
