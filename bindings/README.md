# OPE language bindings

All bindings call the stable C ABI in [`crates/ope-ffi`](../crates/ope-ffi/) (`libope_ffi`). Crypto and canonicalization stay in Rust; bindings must pass [`spec/vectors/`](../spec/vectors/) interop tests.

## Build native library

```bash
./bindings/build-native.sh
# or: cargo build -p ope-ffi --release
```

Override library path with `OPE_LIB_PATH` (Python, TypeScript, optional for Go).

| Language | Path | Mechanism |
|----------|------|-----------|
| C | [`c/include/ope.h`](c/include/ope.h) | Direct link |
| C++ | [`cpp/include/ope/ope.hpp`](cpp/include/ope/ope.hpp) | Thin RAII wrapper |
| Python | [`python/`](python/) | ctypes |
| Go | [`go/ope`](go/ope/) | cgo |
| TypeScript / Node | [`ts/`](ts/) | koffi FFI |

## Quick test (after build)

```bash
cargo test -p ope-ffi
cargo run -p ope-cli -- sign --vector spec/vectors/001-valid-plaintext.json

pip install -e bindings/python[dev] && pytest bindings/python/tests -q
cd bindings/go/ope && CGO_ENABLED=1 go test -v .
cd bindings/ts && npm install && npm test
```

C example: [`c/example/verify_vector.c`](c/example/verify_vector.c).

## API (envelope P0)

- `ope_envelope_sign(secret_key[32], json_in, &out_json)` → signed JSON (`ope_string_free`)
- `ope_envelope_verify(public_key[32], json, max_skew_secs)`
- `ope_envelope_verify_dev_json(json)` — dev vector-001 mock key only

Transport (`X25519MLKEM768`) and attestation APIs are not exposed in FFI yet; use Rust crates `ope-transport` / `ope-attest` or wait for P2.

## Publishing

Packages are source-first: consumers build `ope-ffi` locally or via CI artifacts. npm/PyPI/crates.io publishing is tracked on [`docs/ROADMAP.md`](../docs/ROADMAP.md).
