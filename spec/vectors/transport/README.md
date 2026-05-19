# Transport / hybrid KEX test vectors

Official and composed vectors for **`X25519MLKEM768`** ([draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)), used by Google Chrome (BoringSSL) and AWS KMS / s2n-tls PQ TLS.

## Sources

| File | Provider | Origin |
|------|----------|--------|
| `boringssl-mlkem768-*.json` | **Google BoringSSL** | [mlkem768_keygen_tests.txt](https://github.com/google/boringssl/blob/main/crypto/mlkem/mlkem768_keygen_tests.txt), [mlkem768_encap_tests.txt](https://github.com/google/boringssl/blob/main/crypto/mlkem/mlkem768_encap_tests.txt) (NIST ACVP-derived) |
| `rfc7748-x25519-001.json` | **IETF** | [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1) X25519 test vector |
| `hybrid-x25519mlkem768-000.json` | **Composed** | TLS share layout from draft + ML-KEM vector `000` + RFC 7748 vector `001` |

**AWS:** There is no separate published wire-format hybrid vector file. AWS [s2n-tls](https://github.com/aws/s2n-tls) and [AWS-LC](https://github.com/aws/aws-lc) implement the same **ML-KEM-768** primitives and negotiate group **`0x11EC`** (`X25519MLKEM768`) per the IETF draft and [KMS PQ TLS documentation](https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html). ML-KEM bytes in this directory are therefore valid for AWS interop at the primitive layer.

## Wire layout (`X25519MLKEM768`)

| Party | Field order | Length (bytes) |
|-------|-------------|----------------|
| Client `key_exchange` | ML-KEM-768 encapsulation key ∥ X25519 public | 1216 |
| Server `key_exchange` | ML-KEM-768 ciphertext ∥ X25519 public | 1120 |
| Shared secret | ML-KEM shared secret ∥ X25519 shared secret | 64 |

## Regenerate JSON from upstream

```bash
python3 tools/import_transport_vectors.py
```

Downloads BoringSSL `.txt` fixtures into `source/` (if missing), then rewrites `*.json`.

## Tests

```bash
cargo test -p ope-transport --test official_vectors
cargo test -p ope-transport
```

Tests live in `crates/ope-transport/tests/official_vectors.rs`.
