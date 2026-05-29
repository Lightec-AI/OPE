# OPE TypeScript / Node bindings

[koffi](https://github.com/Koromix/koffi) FFI over `libope_ffi` (Rust).

## Build

```bash
cargo build -p ope-ffi --release
cd bindings/ts && npm install && npm test
```

Set `OPE_LIB_PATH` to point at `libope_ffi` if not using `target/release/`.

The C ABI also exposes the hybrid E2E functions (`ope_e2e_*`, see [`../README.md`](../README.md)). A consumer-side koffi wrapper for the full hybrid request/response flow lives in the TeaChat inference engine (`vendor/inference-engine/src/native/ope-ffi.ts`); the envelope helpers here cover sign/verify.

Browser WASM bindings are not included yet; use Node or embed Rust/WASM in a future release.
