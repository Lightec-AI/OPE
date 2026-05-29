# OPE roadmap

Aligned with **Confidential AI** (client → TDX/SEV gateway → TDX/SEV+GPU inference engine).

## P0 — Envelope core ✅

| Item | Status |
|------|--------|
| Ed25519 sign/verify, JCS, `payload_hash` | Done |
| Vectors `001`–`008` | Done |
| `model@provider` routing | Done |

## P1 — Confidential AI E2E (new primary) 🚧

| Item | Status |
|------|--------|
| [`spec/ope-confidential-ai.md`](../spec/ope-confidential-ai.md) | Done (draft) |
| [`docs/confidential-ai.md`](confidential-ai.md) | Done |
| `ope-e2e` crate (request static hybrid, response stream) | Done (reference) |
| `enc=e2e-hybrid-pq`, `engine_id`, `e2e` on envelope | Done |
| Gateway opaque verify (`opaque_e2e`) | Done |
| `ope e2e-test` CLI | Done |
| E2E FFI (`ope_e2e_*` hybrid request/response C ABI) | Done |
| E2E interop vectors | Not started |
| Real TEE engine key provisioning | Not started |
| GPU TEE attestation binding | Not started |

## P1b — TLS (optional channel PQ) ✅

| Item | Status |
|------|--------|
| `ope-transport` X25519MLKEM768 + official vectors | Done |
| [`docs/tls-integration.md`](tls-integration.md) — use external TLS, not OPE wire format | Done |

## P2 — Language bindings (partial)

| Item | Status |
|------|--------|
| C / Python / Go / TS envelope sign/verify | Done |
| E2E encrypt/stream decrypt in FFI (`ope_e2e_*`, handle-based) | Done |
| Published packages | Not started |
| Browser/WASM binding | Not started |

## P3 — Gateway + attestation ✅ (mock)

| Item | Status |
|------|--------|
| Opaque forward for `e2e-hybrid-pq` | Done |
| `meta` metering hooks | Spec + struct fields |
| Production OIDC / TEE attestation | Not started |

## P4 — Application SDK (stub)

| Item | Status |
|------|--------|
| `sdks/conversation` manifest stub | Done |

## How to contribute

1. **E2E vectors:** Add `spec/vectors/confidential-ai/009-*.json` + `gen-vectors` support.
2. **FFI:** ✅ hybrid E2E exposed via `ope_e2e_*` (handle-based; see [`bindings/README.md`](../bindings/README.md)). Next: WASM binding for browsers.
3. **TEE:** Wire `EngineIdentity` to real attestation quotes (TDX/SEV/nvtrust).
