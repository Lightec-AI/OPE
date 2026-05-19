# OPE TypeScript / Node bindings

[koffi](https://github.com/Koromix/koffi) FFI over `libope_ffi` (Rust).

## Build

```bash
cargo build -p ope-ffi --release
cd bindings/ts && npm install && npm test
```

Set `OPE_LIB_PATH` to point at `libope_ffi` if not using `target/release/`.

Browser WASM bindings are not included yet; use Node or embed Rust/WASM in a future release.
