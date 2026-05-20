# OPE Transport Profile v1.0 (Draft)

Status: Draft  
Normative references:

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3)
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) (preferred: `-04`)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM)

Related: [`ope.md`](../ope.md) (envelope layer), [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md).

## 1. Scope

OPE-Transport defines how OPE peers establish confidential channels before carrying `application/ope+json` envelopes. The default profile aligns with industry practice (Google Chrome / AWS s2n-tls): **TLS 1.3** with hybrid **ECDHE + ML-KEM** key exchange and **AES-256-GCM** record protection.

OPE-Transport is independent of envelope signing keys (`kid` / Ed25519).

## 2. Default hybrid group: X25519MLKEM768

| Field | Value |
|-------|--------|
| TLS group name | `X25519MLKEM768` |
| IANA code point | `4588` (`0x11EC`) |
| Classical KEX | X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)) |
| Post-quantum KEM | ML-KEM-768 ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) |
| Combined shared secret | `ML-KEM_ss \|\| X25519_ss` (64 bytes) |
| Key derivation | TLS 1.3 HKDF over transcript + combined secret ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) |
| Record encryption | AES-256-GCM (TLS default AEAD) |

Alternate groups (optional, same draft):

- `SecP256r1MLKEM768` — FIPS P-256 + ML-KEM-768
- `SecP384r1MLKEM1024` — P-384 + ML-KEM-1024

## 3. Share sizes (X25519MLKEM768)

Per [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/):

| Direction | Composition | Size (bytes) |
|-----------|-------------|--------------|
| Client `key_exchange` | `ML-KEM-768 encapsulation key \|\| X25519 ephemeral` | 1216 |
| Server `key_exchange` | `ML-KEM ciphertext \|\| X25519 ephemeral` | 1120 |
| Shared secret | `ML-KEM_ss \|\| X25519_ss` | 64 |

Note: share order for `X25519MLKEM768` is historically ML-KEM first, then X25519 (differs from generic hybrid-design naming).

## 4. OPE usage profile

**Confidential AI (primary):** Use **standard TLS 1.3** for HTTPS and **`enc=e2e-hybrid-pq`** for application E2E per [`ope-confidential-ai.md`](ope-confidential-ai.md). OPE-Transport KEX math is shared with TLS PQ groups but **application keys come from `ope-e2e`**, not TLS exporters.

**Optional channel PQ:**

1. Establish TLS 1.3 with `X25519MLKEM768` negotiated when desired.
2. Send OPE envelopes as `application/ope+json`.
3. Envelope Ed25519 signature is always required.

Legacy gateway-local encryption (`enc=xchacha20poly1305`, `enc=A256GCM`) encrypts to the gateway content key; Confidential AI deployments MUST NOT rely on this for user prompts.

## 5. Development mode (mock keys)

For local development and CI:

| Layer | Dev practice |
|-------|----------------|
| Envelope | Deterministic Ed25519 mock seeds in [`spec/vectors/`](../spec/vectors/) (`dev_only: true`) |
| Transport | `ope-transport` in-process KEX **or** TLS with self-signed certs |

Production MUST use properly provisioned keys and certificate validation. Mock envelope keys MUST NOT be used outside test environments.

## 6. Reference implementation (`ope-transport`)

| API | Status | Notes |
|-----|--------|-------|
| `ClientKeyExchange::generate()` | Implemented | Produces 1216-byte client share |
| `ServerKeyExchange::respond_to()` | Implemented | Produces 1120-byte server share + 64-byte secret |
| `client_shared_secret()` | Implemented | Client-side secret verification |
| TLS 1.3 / HKDF / AES-GCM records | Not implemented | Use external TLS stack (P1) |
| `SecP256r1MLKEM768` / `SecP384r1MLKEM1024` | Not implemented | Optional future |

Constants exported from `ope_transport::sizes` (e.g. `GROUP_X25519_MLKEM768 = 0x11EC`).

CLI check:

```bash
cargo run -p ope-cli -- transport-test
```

## 7. External implementation mapping

| Component | Implementation |
|-----------|----------------|
| Hybrid KEX + TLS | [aws/s2n-tls](https://github.com/aws/s2n-tls) policies `*-2025-PQ` |
| AWS KMS PQ TLS docs | [Hybrid PQ TLS with KMS](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html) |
| Browser interop | Chromium / BoringSSL `X25519MLKEM768` (`0x11EC`) |
| OPE reference KEX | `crates/ope-transport` in this repository |

## 8. Conformance

An OPE-Transport v1 conformant stack MUST:

1. Implement `X25519MLKEM768` shared-secret concatenation exactly as in draft-ietf-tls-ecdhe-mlkem.
2. Derive record keys via TLS 1.3 HKDF when using TLS on the wire.
3. Not reuse envelope Ed25519 keys as TLS authentication credentials.

The in-repo `ope-transport` crate satisfies (1) for test harnesses; full wire conformance requires (2) via a TLS implementation.
