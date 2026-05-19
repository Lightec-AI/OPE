# OPE test vectors

JSON files used for cross-language interoperability and CI.

## Vector file schema

```json
{
  "vector_id": "001-valid-plaintext",
  "description": "human-readable summary",
  "dev_only": true,
  "signing_key_seed_hex": "64 hex chars (32 bytes)",
  "verifying_key_hex": "64 hex chars (32-byte Ed25519 public key)",
  "expect_verify": "pass",
  "expect_error_substr": null,
  "envelope": { }
}
```

- **`expect_verify`:** `pass` or `fail` for `ope-envelope` verification tests.
- **`expect_error_substr`:** optional substring matched against error text when `fail`.

## Published vectors

| File | Covers |
|------|--------|
| `001-valid-plaintext.json` | `enc=none`, valid signature |
| `002-invalid-signature.json` | Tampered `sig` |
| `003-replayed-nonce.json` | Replay cache (see envelope tests) |
| `004-stale-timestamp.json` | Stale `ts` |
| `005-encrypted-roundtrip.json` | `enc=xchacha20poly1305` |
| `006-wrong-recipient.json` | Recipient binding |
| `007-malformed-canonical.json` | Payload tamper / hash mismatch |
| `008-invalid-model-id.json` | Malformed `payload.model` |

## Commands

```bash
cargo run -p ope-cli -- gen-vectors --dir spec/vectors
cargo run -p ope-cli -- verify --vector spec/vectors/001-valid-plaintext.json
cargo test -p ope-envelope --test vectors
```

Mock content key for vector `005`: `ope_crypto::DEV_CONTENT_KEY` (32 × `0x02`).
