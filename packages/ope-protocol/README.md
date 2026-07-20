# `@teechat/ope-protocol`

Shared **wire types** and **NDJSON stream codec** for Confidential AI (client ↔ gateway ↔ inference engine).

This package does **not** include crypto. Use:

- npm `@teechat/ope-wasm` / crates.io `ope-e2e` for hybrid encrypt/decrypt
- GitHub `libope_ffi.so` for measured engine FFI

## Install

```bash
pnpm add @teechat/ope-protocol
# or local: "file:vendor/ope/packages/ope-protocol"
```

## Exports

| Path | Contents |
|------|----------|
| `@teechat/ope-protocol` | Envelope, trust/epoch, traffic class, engine-plane paths/headers |
| `@teechat/ope-protocol/stream` | `application/ope+json-stream` NDJSON frames |

Source of truth: [Lightec-AI/OPE](https://github.com/Lightec-AI/OPE) `packages/ope-protocol`.
