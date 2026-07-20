# `@teechat/ope-protocol`

TypeScript **binding** for the OPE Confidential AI wire protocol.

| Layer | Location |
|-------|----------|
| **Source of truth** | Rust crate [`crates/ope-protocol`](../../../crates/ope-protocol) |
| **This package** | Hand-maintained TS types + NDJSON helpers mirroring the Rust API |

Does **not** include crypto. Use `@teechat/ope-wasm` / `ope-e2e` / `libope_ffi` for encrypt/decrypt.

## Install

```bash
pnpm add @teechat/ope-protocol
# TeeChat / IE: pin the published version (same train as ope-wasm)
# "@teechat/ope-protocol": "0.1.0"
```

## Exports

| Path | Contents |
|------|----------|
| `@teechat/ope-protocol` | Envelope, trust/epoch, traffic class, engine-plane paths/headers |
| `@teechat/ope-protocol/stream` | `application/ope+json-stream` NDJSON frames |

When changing wire shapes, update **`crates/ope-protocol` first**, then this binding and its tests.
