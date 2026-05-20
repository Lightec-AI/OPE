# Open Privacy Envelope (OPE) v1.0 Draft

Status: Draft  
Audience: Protocol implementers, SDK authors, API gateway maintainers  
Goal: Define a vendor-neutral envelope for **Confidential AI** — privacy-preserving API calls where gateways (TDX/SEV) authenticate and meter traffic without seeing prompts, and inference engines (TDX/SEV + GPU TEE) alone decrypt payloads (including OpenAI-compatible bodies).

## 1. Scope

OPE defines:

- a signed envelope wrapper for API payloads,
- optional end-to-end encrypted content transport,
- replay protection and timestamp rules,
- attestation and verification APIs for identity and policy checks,
- interoperability and conformance requirements.

OPE does **not** mandate a specific identity provider, key escrow model, or transport protocol.

### 1.1 Related specifications

| Document | Scope |
|----------|--------|
| [`spec/ope-transport.md`](spec/ope-transport.md) | Hybrid post-quantum transport (TLS 1.3 + `X25519MLKEM768`) |
| [`spec/vectors/`](spec/vectors/) | Interoperability test vectors |
| [`spec/ope-confidential-ai.md`](spec/ope-confidential-ai.md) | **Confidential AI E2E profile** (`enc=e2e-hybrid-pq`) |
| [`docs/confidential-ai.md`](docs/confidential-ai.md) | Architecture: client / gateway / inference engine |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Repository layout and layer model |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Implementation phases |

## 2. Terminology

- **Envelope**: Outer OPE object transmitted over the wire.
- **Payload**: Inner API request object (for example, OpenAI-compatible JSON).
- **Sender**: Client creating an envelope.
- **Gateway**: Server component that verifies/decrypts OPE and forwards internally.
- **Recipient**: Logical service identity for key selection and policy checks.
- **Attester**: Service that issues signed attestation statements for a sender key or workload identity.
- **Verifier**: Service endpoint that validates envelopes and/or attestation chains and returns machine-readable verdicts.
- **Provider slug**: Short identifier for the upstream inference stack (for example `ollama`, `teechat`, `openai`). Used as the suffix in routed model IDs.

## 3. Media Type and Versioning

- Media type: `application/ope+json`
- Required envelope field: `ope_version`
- Initial version: `"1.0"`
- Non-breaking additions: new optional fields only
- Breaking changes: increment major version (`2.0`)

## 4. Envelope Format (JSON)

```json
{
  "ope_version": "1.0",
  "alg": "EdDSA",
  "enc": "none",
  "kid": "sender-key-id",
  "recipient": "gateway-id",
  "ts": "2026-04-24T18:00:00Z",
  "nonce": "base64url-random-96bit+",
  "payload_hash": "base64url-sha256",
  "payload": { "model": "gpt-4.1@openai", "messages": [] },
  "sig": "base64url-signature"
}
```

### 4.1 Required Fields

- `ope_version` (string)
- `alg` (string) - signature algorithm
- `enc` (string) - payload protection mode (`none` or encrypted mode)
- `kid` (string) - sender key identifier
- `recipient` (string) - intended gateway/service identifier
- `ts` (RFC3339 UTC timestamp)
- `nonce` (base64url, >= 96-bit entropy)
- `payload_hash` (base64url SHA-256 over canonical payload bytes)
- `sig` (base64url signature over canonical signed fields)

### 4.2 Optional Fields

- `payload` (object) - present when `enc=none`
- `ciphertext` (string, base64url) - present when encrypted mode is used
- `iv` (string, base64url) - required for AEAD encrypted mode
- `aad` (object) - optional associated authenticated data
- `meta` (object) - non-sensitive routing metadata

## 5. Canonicalization and Signature

Implementations MUST:

1. Canonicalize signed fields using deterministic JSON canonicalization ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JCS-style: UTF-8, lexicographically sorted object keys, minimal number encoding).
2. Compute `payload_hash` over canonical payload bytes before signing.
3. Sign canonical representation of:
   - `ope_version, alg, enc, kid, recipient, ts, nonce, payload_hash` and encryption fields if present.
4. Reject envelopes with missing/extra conflicting cryptographic fields.

Recommended baseline:

- Signature: `Ed25519` (`alg=EdDSA`)
- Hash: `SHA-256`

## 6. Encryption Modes

### 6.1 `enc=none`

- Payload is plaintext in `payload`.
- Signature is still mandatory.

### 6.2 `enc=xchacha20poly1305` (recommended encrypted profile)

- `payload` omitted.
- `ciphertext` and `iv` required.
- `payload_hash` is computed over plaintext payload before encryption.
- Gateway decrypts, re-hashes payload, verifies `payload_hash`, then routes.

Alternative AEAD (`A256GCM`) MAY be supported via profile declaration.

### 6.3 `enc=e2e-hybrid-pq` (Confidential AI — normative profile)

Production Confidential AI deployments MUST use this mode for user prompts and context.

- `payload` omitted; `ciphertext` + `iv` required.
- `engine_id` (string) names the target inference engine.
- `e2e` (object) carries hybrid `X25519MLKEM768` material per [`spec/ope-confidential-ai.md`](spec/ope-confidential-ai.md).
- `meta` (object) SHOULD expose gateway-visible fields (`tenant`, `model`, `metering`) without plaintext payload.
- **Gateway** MUST verify signature and policy but MUST NOT decrypt `ciphertext` (opaque forward).
- **Inference engine** MUST verify `payload_hash` after decrypt.

Request content key: HKDF over `ML-KEM_ss || X25519_ss` with `info = "OPE-E2E-v1" || "request" || engine_id || kid || nonce`.

Response streaming SHOULD use `chacha20poly1305-stream` in the `e2e` object with per-chunk nonces (see confidential-ai spec §7).

## 7. Replay and Freshness Rules

Gateway MUST enforce:

- `ts` within allowed clock skew window (recommended: ±300s).
- `nonce` uniqueness per `kid` within replay cache window (recommended: 10 minutes).
- reject duplicate (`kid`, `nonce`) pairs in active window.

## 8. OpenAI-Compatible Profile (OPE-OpenAI)

OPE-OpenAI constrains payload schema to OpenAI-compatible request bodies.

- Envelope transport is OPE.
- Inner `payload` remains provider-compatible JSON.
- Gateway forwards unwrapped payload to internal OpenAI adapter/function chain.

### 8.1 Routed model ID (`payload.model`)

To disambiguate same-named models across vendors, **`payload.model` MUST include the provider as a postfix**, using a single `@` separator:

- Syntax: `\<base-model>@\<provider-slug>`
- `base-model` is the model name as understood by that provider’s API (for example `gpt-4.1`, `llama3.2`).
- `provider-slug` is a lowercase registry identifier (ASCII letters, digits, hyphen; no `@` in either segment). Examples: `ollama`, `teechat`, `openai`.

Examples:

- `gpt-4.1@openai`
- `llama3.2@ollama`
- `custom-v1@teechat`

Gateways that implement OPE-OpenAI MUST parse this form for routing and policy (including `allowed_models` in attestations). Before calling a provider whose native API does not accept the suffix, the gateway SHOULD strip `\@\<provider-slug>` and route using `base-model` only to that provider.

Implementations MAY maintain a registry mapping `provider-slug` to connection endpoints; the spec does not mandate registry mechanics.

## 9. Error Model

Gateways return structured errors:

- `ope_invalid_signature`
- `ope_invalid_timestamp`
- `ope_replay_detected`
- `ope_invalid_recipient`
- `ope_decryption_failed`
- `ope_unsupported_version`
- `ope_unsupported_alg`
- `ope_attestation_required`
- `ope_attestation_invalid`
- `ope_attestation_expired`
- `ope_verification_failed`
- `ope_invalid_model_id` (OPE-OpenAI: `payload.model` missing or malformed `\@\<provider-slug>`)

Errors MUST avoid leaking key material or plaintext payload fragments.

## 10. Security Considerations

- OPE does not eliminate endpoint XSS risk on sender devices.
- Signature verification MUST occur before trust-sensitive routing.
- Encrypted modes protect transport/storage confidentiality; metadata may still leak.
- Key rotation MUST support overlapping active key windows.
- Logging systems MUST redact envelope crypto fields and payload by policy.

## 11. Conformance Requirements

An implementation is OPE v1.0 conformant if it:

1. Produces and validates required fields exactly as specified.
2. Implements canonicalization + signature verification deterministically.
3. Enforces timestamp and nonce replay rules.
4. Emits standardized error codes.
5. Passes public OPE v1 test vectors.

## 12. Test Vectors

Vectors live under [`spec/vectors/`](spec/vectors/) as JSON. Each file includes metadata (`vector_id`, `dev_only`, optional `signing_key_seed_hex`) and an `envelope` object.

| Vector | Status | Description |
|--------|--------|-------------|
| `001-valid-plaintext.json` | **Published** | `enc=none`, Ed25519 signature, `model@provider` payload |
| `002-invalid-signature.json` | **Published** | Tampered `sig` |
| `003-replayed-nonce.json` | **Published** | Duplicate `(kid, nonce)` |
| `004-stale-timestamp.json` | **Published** | `ts` outside skew window |
| `005-encrypted-roundtrip.json` | **Published** | `enc=xchacha20poly1305` |
| `006-wrong-recipient.json` | **Published** | Recipient mismatch at gateway |
| `007-malformed-canonical.json` | **Published** | Payload / `payload_hash` mismatch |
| `008-invalid-model-id.json` | **Published** | Missing or invalid `\@\<provider-slug>` |

Transport hybrid KEX vectors: [`spec/vectors/transport/`](spec/vectors/transport/) (BoringSSL ML-KEM-768, RFC 7748 X25519, composed `X25519MLKEM768`). Run `cargo test -p ope-transport --test official_vectors`.

Verify with:

```bash
cargo run -p ope-cli -- verify --vector spec/vectors/001-valid-plaintext.json
```

Development vectors marked `"dev_only": true` use deterministic mock keys documented in the vector file. **Never use those keys in production.**

## 13. Governance and Evolution

- Spec repository: open, public RFC process.
- Versioning: semantic (`major.minor`).
- Required artifacts for each release:
  - reference vectors,
  - changelog,
  - migration notes,
  - interop matrix.

---

Suggested naming:

- User-facing feature: **Privacy Shield**
- Standards-facing protocol: **Open Privacy Envelope (OPE)**
- Wire object: **OPE Envelope**

## 14. Attestation and Verification APIs

This section defines interoperable HTTP APIs that complement envelope signing/encryption.

- Base media type for API requests/responses: `application/json`
- Nested envelope objects remain `application/ope+json`
- All timestamps MUST be RFC3339 UTC (`Z`)
- All signatures are base64url over canonicalized JSON bytes

### 14.1 Attestation API

Attestation binds a sender key (`kid`) to an identity context and policy claims.

#### 14.1.1 `POST /v1/ope/attestations`

Creates an attestation statement signed by the attester.

Request:

```json
{
  "ope_version": "1.0",
  "kid": "sender-key-id",
  "subject": "workload://tenant-a/service-x",
  "recipient": "gateway-id",
  "nonce": "base64url-random-96bit+",
  "evidence": {
    "type": "oidc_jwt",
    "token": "eyJ..."
  },
  "requested_ttl_sec": 600
}
```

Successful response (`201 Created`):

```json
{
  "attestation_id": "att_01HV...",
  "issued_at": "2026-04-24T18:00:00Z",
  "expires_at": "2026-04-24T18:10:00Z",
  "attestation": {
    "ope_version": "1.0",
    "attester": "attester.example",
    "kid": "sender-key-id",
    "subject": "workload://tenant-a/service-x",
    "recipient": "gateway-id",
    "claims": {
      "tenant": "tenant-a",
      "env": "prod",
      "allowed_models": ["gpt-4.1@openai", "gpt-4.1-mini@openai"]
    },
    "ts": "2026-04-24T18:00:00Z",
    "exp": "2026-04-24T18:10:00Z",
    "nonce": "base64url-random-96bit+",
    "sig": "base64url-signature"
  }
}
```

Behavioral requirements:

1. Attester MUST validate `evidence` before issuing.
2. Attester MUST cap TTL to server policy max.
3. `attestation.kid` MUST match requested `kid`.
4. `attestation.recipient` SHOULD be set when recipient-bound tokens are required.
5. Attester MUST reject replayed request `nonce` values within its replay window.

### 14.2 Envelope Verification API

Verification provides a deterministic gateway-style verdict for an envelope, optionally including attestation checks.

#### 14.2.1 `POST /v1/ope/verifications:verifyEnvelope`

Request:

```json
{
  "envelope": {
    "ope_version": "1.0",
    "alg": "EdDSA",
    "enc": "none",
    "kid": "sender-key-id",
    "recipient": "gateway-id",
    "ts": "2026-04-24T18:00:00Z",
    "nonce": "base64url-random-96bit+",
    "payload_hash": "base64url-sha256",
    "payload": { "model": "gpt-4.1@openai", "messages": [] },
    "sig": "base64url-signature"
  },
  "attestation": {
    "attestation_id": "att_01HV..."
  },
  "policy_context": {
    "route": "/v1/chat/completions",
    "method": "POST"
  }
}
```

Successful response (`200 OK`):

```json
{
  "verified": true,
  "decision": "allow",
  "checks": [
    { "name": "signature", "ok": true },
    { "name": "timestamp_freshness", "ok": true },
    { "name": "nonce_replay", "ok": true },
    { "name": "recipient_match", "ok": true },
    { "name": "attestation", "ok": true },
    { "name": "policy", "ok": true }
  ],
  "normalized": {
    "kid": "sender-key-id",
    "subject": "workload://tenant-a/service-x",
    "recipient": "gateway-id"
  }
}
```

Failure response (`200 OK`, deterministic negative verdict):

```json
{
  "verified": false,
  "decision": "deny",
  "error": {
    "code": "ope_attestation_expired",
    "message": "attestation is expired"
  },
  "checks": [
    { "name": "signature", "ok": true },
    { "name": "attestation", "ok": false }
  ]
}
```

### 14.3 Inline Attestation on Envelope Transport

Senders MAY include attestation evidence directly with envelope transport when out-of-band lookup is unavailable:

```json
{
  "envelope": { "...": "OPE envelope object" },
  "attestation": { "...": "signed attestation object" }
}
```

Gateway requirements:

1. MUST verify envelope first (signature, freshness, replay).
2. MUST verify attestation signature, validity window, and recipient binding.
3. MUST confirm `envelope.kid == attestation.kid`.
4. MUST enforce local policy claims before forwarding payload.

### 14.4 HTTP Status Guidance

- `201`: attestation created
- `200`: verification completed (`allow` or `deny`)
- `400`: malformed request
- `401`: caller not authenticated to attestation service
- `403`: caller authenticated but not authorized for requested subject/recipient
- `409`: nonce replay detected on attestation issuance
- `422`: semantically valid JSON but invalid cryptographic material
- `429`: rate-limited
- `500`: internal verifier/attester fault

### 14.5 Conformance Additions for APIs

An implementation claiming OPE Attestation/Verification profile conformance MUST:

1. Implement `POST /v1/ope/attestations` and `POST /v1/ope/verifications:verifyEnvelope`.
2. Return machine-readable verdicts with stable `decision` values (`allow|deny`).
3. Emit OPE error codes from Section 9 for attestation/verification failures.
4. Provide test vectors covering positive and negative attestation verification.

## 15. Reference Implementation (Rust)

This repository ships a reference workspace (see [`README.md`](README.md)):

| Crate | Spec alignment | Status |
|-------|----------------|--------|
| `ope-crypto` | §5 primitives | Ed25519, SHA-256, base64url; dev mock keys |
| `ope-envelope` | §4–8, §11 | Sign/verify, encrypt/decrypt, JCS, vectors `001`–`008` |
| `ope-e2e` | [`spec/ope-confidential-ai.md`](spec/ope-confidential-ai.md) | Hybrid PQ E2E encrypt/decrypt + stream chunks |
| `ope-transport` | [`spec/ope-transport.md`](spec/ope-transport.md) | `X25519MLKEM768` KEX (TLS-aligned tests; not app E2E) |
| `ope-http` | Transport §4 | `application/ope+json` framing |
| `ope-attest` | §14 | Mock attester + attestation sign/verify |
| `ope-gateway` | §8, §14 | Gateway verify + `model@provider` strip |
| `ope-server` | §14 | HTTP APIs (`ope serve`) |
| `ope-ffi` | Bindings | C ABI envelope sign/verify |
| `ope-cli` | §12 vectors | `gen-vectors`, `serve`, `hkdf-test`, `transport-test` |

**Key separation:**

| Keys | Use |
|------|-----|
| Ed25519 `kid` | Envelope signatures only |
| Engine ML-KEM + X25519 (static) | Decrypt requests inside inference TEE |
| Client ephemeral hybrid | Decrypt streaming responses |
| TLS session keys | Standard HTTPS — optional PQ per [`docs/tls-integration.md`](docs/tls-integration.md) |

**TLS:** Use ordinary TLS 1.3; OPE does not ship a custom TLS implementation. **E2E** uses `ope-e2e` HKDF labels, not TLS exporter secrets.
