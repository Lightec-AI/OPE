# OPE language bindings (planned)

Bindings will wrap the stable C ABI from [`crates/ope-ffi`](../crates/ope-ffi/) and must pass all files under [`spec/vectors/`](../spec/vectors/).

| Language | Status | Notes |
|----------|--------|-------|
| C / C++ | Minimal | `ope_verify_envelope_dev_json()` (dev keys only) |
| Python | Planned | PyO3 or ctypes |
| Go | Planned | cgo |
| TypeScript | Planned | WASM build of `ope-core` or Node native addon |

Until the C ABI stabilizes (P2), implementers may embed the Rust crates directly or verify vectors in their language.

See [`docs/ROADMAP.md`](../docs/ROADMAP.md).
