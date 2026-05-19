# OPE test vectors

JSON files used for cross-language interoperability and CI. Consumed by:

- `cargo test` (`ope-envelope/tests/vector_001.rs`)
- `ope-cli verify` / `ope-cli sign`
- GitHub Actions (`.github/workflows/ci.yml`)

## Vector file schema

```json
{
  "vector_id": "001-valid-plaintext",
  "description": "human-readable summary",
  "dev_only": true,
  "signing_key_seed_hex": "64 hex chars (32 bytes)",
  "verifying_key_hex": "64 hex chars (32-byte Ed25519 public key)",
  "envelope": { }
}
```

- **`dev_only`:** when `true`, `signing_key_seed_hex` is a deterministic mock key (see `ope-crypto::DEV_VECTOR_001_SEED`). Never deploy these keys.
- **`envelope`:** full OPE envelope per [`ope.md`](../../ope.md) §4, including `sig` after signing.

## Published vectors

| File | `vector_id` | Covers |
|------|-------------|--------|
| [`001-valid-plaintext.json`](001-valid-plaintext.json) | `001-valid-plaintext` | `enc=none`, valid signature, `gpt-4.1@openai` payload |

## Planned vectors

See [`ope.md`](../../ope.md) §12 (`002`–`008`): invalid signature, replay, stale timestamp, encrypted round-trip, wrong recipient, malformed canonicalization, invalid model id.

## Commands

```bash
# Regenerate signature and timestamp on vector 001
cargo run -p ope-cli -- sign --vector spec/vectors/001-valid-plaintext.json

# Verify
cargo run -p ope-cli -- verify --vector spec/vectors/001-valid-plaintext.json

# Show mock key material for vector 001 seed
cargo run -p ope-cli -- keygen
```

## Mock development keys (vector 001)

| Field | Value |
|-------|--------|
| Seed | 32 × `0x01` (`0101…0101` hex) |
| `kid` in envelope | `mock-sender-001` |
| Rust constant | `ope_crypto::DEV_VECTOR_001_SEED` |

After changing canonicalization or signed-field rules, re-run `ope sign` on all vectors and commit updated JSON.

## Transport vectors

Official hybrid KEX vectors (BoringSSL ML-KEM-768, RFC 7748 X25519, composed `X25519MLKEM768`) live under [`transport/`](transport/).

```bash
cargo test -p ope-transport --test official_vectors
cargo run -p ope-cli -- transport-test
```

See [`transport/README.md`](transport/README.md) and [`spec/ope-transport.md`](../ope-transport.md) §6.
