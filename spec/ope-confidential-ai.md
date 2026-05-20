# OPE Confidential AI Profile v1.0 (Draft)

Status: Draft  
Related: [`ope.md`](../ope.md), [`docs/confidential-ai.md`](../docs/confidential-ai.md), [`spec/ope-transport.md`](ope-transport.md).

## 1. Scope

This profile defines **application-layer end-to-end encryption** for Confidential AI:

| Role | TEE | Sees plaintext prompt/context? |
|------|-----|--------------------------------|
| **Client** | User device / app | Yes (before encrypt) |
| **Gateway** | Intel TDX or AMD SEV | **No** — metadata + signed envelope only |
| **Inference engine** | TDX/SEV + GPU TEE | Yes (after decrypt) |

TLS 1.3 remains a **standard, third-party** channel (any CA, any stack). OPE does **not** require custom TLS record formats.

## 2. Trust boundaries

```text
Client ──TLS 1.3 (unchanged)──► Gateway (TDX/SEV) ──TLS/mTLS──► Inference engine (TDX/SEV + GPU TEE)
         │                              │                              │
         │  OPE envelope (signed)       │  Opaque `ciphertext`         │  Decrypt request
         │  enc=e2e-hybrid-pq           │  `meta` for auth/metering    │  Encrypt streaming response
         └──────────────────────────────┴──────────────────────────────┘
```

1. **Request:** Client encrypts inner API payload to the **target engine’s** hybrid public material (`ML-KEM-768` + `X25519`). Only that engine can derive the content key.
2. **Gateway:** Verifies envelope signature, freshness, replay, attestation; reads **`meta`** (and routing fields); forwards **opaque** `ciphertext` + `e2e` to the engine. MUST NOT hold engine decapsulation secrets in production.
3. **Response:** Engine encrypts token stream to the client’s **ephemeral** hybrid session from the request (`e2e.client_share`). Client decrypts with the matching ephemeral secret.

## 3. Engine identity (long-lived)

Published out-of-band (registry, attestation quote, `GET /v1/ope/engines/{engine_id}`):

```json
{
  "engine_id": "engine-prod-7",
  "kex": "X25519MLKEM768",
  "mlkem_encapsulation_key": "base64url-1184-bytes",
  "x25519_public": "base64url-32-bytes",
  "ed25519_public": "base64url-32-bytes",
  "attestation": { "...": "TEE evidence binding this key material" }
}
```

| Field | Use |
|-------|-----|
| `mlkem_encapsulation_key` | Client includes in `e2e` for routing verification; engine uses matching **decapsulation** key inside TEE |
| `x25519_public` | Static engine X25519 for hybrid shared secret |
| `ed25519_public` | Identity binding in attestation quotes (not used for ECDH) |

**Rule:** Engine decapsulation / X25519 private keys MUST live only inside the inference TEE.

## 4. Envelope extensions

### 4.1 `enc=e2e-hybrid-pq` (Confidential AI request)

| Field | Required | Notes |
|-------|----------|-------|
| `engine_id` | Yes | Target inference engine |
| `e2e` | Yes | Hybrid session descriptor (see §5) |
| `ciphertext` | Yes | AEAD over canonical plaintext payload bytes |
| `iv` | Yes | 12-byte nonce base (see §6) |
| `payload` | No | Omitted |
| `meta` | Recommended | Gateway-visible: `tenant`, `model`, `metering`, `route` — **not** in `payload_hash` |

`payload_hash` is still SHA-256 over **canonical JCS plaintext payload** before encryption (engine verifies after decrypt).

Signed fields (§5 of `ope.md`) **add** when present: `engine_id`, `e2e` (canonical JCS object).

### 4.2 Gateway-visible vs engine-only

| Data | Gateway | Engine |
|------|---------|--------|
| `kid`, `recipient`, `ts`, `nonce`, `sig` | Verify | Verify |
| `meta`, `engine_id`, `payload.model` in meta | Policy / metering | Optional |
| `ciphertext`, `e2e`, `iv` | Forward opaque | Decrypt |
| Plaintext `payload` | MUST NOT access | Decrypt + verify `payload_hash` |

## 5. `e2e` object (request)

```json
{
  "kex": "X25519MLKEM768",
  "client_share": "base64url-1216-bytes",
  "content_alg": "chacha20poly1305",
  "engine_mlkem_encap": "base64url-1184-bytes",
  "engine_x25519": "base64url-32-bytes"
}
```

- `client_share`: Ephemeral client hybrid share per [`spec/ope-transport.md`](ope-transport.md) §3 (ML-KEM encaps key ‖ X25519 ephemeral public).
- `engine_*`: Copy of published engine public material for bind-before-encrypt (gateway may check `engine_id` maps to these bytes).
- `content_alg`: `chacha20poly1305` (single-shot request) or `chacha20poly1305-stream` (responses, §7).

## 6. Content key derivation

From 64-byte hybrid secret `S = ML-KEM_ss || X25519_ss` ([draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)):

```text
HKDF-SHA256(
  salt = empty,
  ikm  = S,
  info = "OPE-E2E-v1" || direction || engine_id || kid || nonce
)
→ 32-byte content_key
```

| `direction` | Who runs KEX | Who encrypts |
|-------------|--------------|--------------|
| `request` | Client ephemeral → engine static | Client |
| `response` | Engine ephemeral → client ephemeral from request | Engine |

Request path: engine performs server-side hybrid step using **static** ML-KEM decaps + X25519 secret against `client_share` (same mathematics as TLS server `respond_to`, but static server keys).

Response path: engine generates fresh server hybrid share; client uses `client_shared_secret` from request material + response `e2e.server_share`.

## 7. Streaming responses

Inference APIs often stream tokens (SSE/chunked JSON). Profile:

| `content_alg` | Use |
|---------------|-----|
| `chacha20poly1305` | Single-shot bodies |
| `chacha20poly1305-stream` | **Recommended** for streaming |

### 7.1 Stream framing

Each chunk is a JSON line or SSE `data:` frame containing:

```json
{
  "ope_stream": "1.0",
  "seq": 0,
  "ciphertext": "base64url",
  "final": false
}
```

- Nonce for chunk `seq`: `iv_base XOR (seq as uint32 BE in first 4 bytes of 12-byte nonce)`.
- Poly1305 tag appended per chunk (standard ChaCha20-Poly1305).
- `final: true` on last chunk; optional `stream_mac` over all chunk tags in envelope footer.

AES-256-GCM (`A256GCM`) MAY be used for non-streaming responses; streaming SHOULD use `chacha20poly1305-stream`.

## 8. TLS integration (unchanged)

1. Client ↔ Gateway: ordinary TLS 1.3 (PQ groups optional, not mandated by OPE).
2. Body: `Content-Type: application/ope+json` with `enc=e2e-hybrid-pq`.
3. Gateway ↔ Engine: TLS or mTLS inside DC; OPE ciphertext stays opaque to gateway.

OPE-Transport (`X25519MLKEM768` in TLS) and OPE-E2E (application hybrid) share the **same KEX math** but **different key schedules and labels**. Do not mix TLS record keys with envelope content keys.

## 9. Lightweight third-party SDK

Integrators need only:

1. Generate ephemeral hybrid share + encrypt payload to engine pubkey (`enc=e2e-hybrid-pq`).
2. Sign envelope with user `kid` (Ed25519).
3. On streaming response, decrypt chunks with request ephemeral secret + `e2e.server_share` from response headers.

Reference: `ope-e2e` crate + `ope-ffi` (planned) — no TLS fork required.

## 10. Errors (additions)

| Code | Meaning |
|------|---------|
| `ope_e2e_engine_mismatch` | `e2e.engine_*` does not match registry for `engine_id` |
| `ope_e2e_decrypt_failed` | Engine cannot derive key or AEAD fails |
| `ope_gateway_opaque_required` | Gateway attempted to decrypt `enc=e2e-hybrid-pq` |

## 11. Conformance

Confidential AI conformant implementations MUST:

1. Support `enc=e2e-hybrid-pq` request encryption to a static engine hybrid pubkey.
2. Keep gateway from decrypting request ciphertext in production configuration.
3. Support `chacha20poly1305-stream` response decryption on the client.
4. Bind `engine_id` in attestation / registry to `ed25519_public` + ML-KEM encap key.
5. Pass vectors under `spec/vectors/confidential-ai/` when published.
