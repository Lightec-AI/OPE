# OPE Python bindings

ctypes wrapper over `libope_ffi` (Rust).

## Build native library

```bash
cargo build -p ope-ffi --release
```

## Use

```python
import json
from ope import envelope_sign, envelope_verify, envelope_verify_dev

# Dev vector-001 (mock keys)
with open("../../spec/vectors/001-valid-plaintext.json") as f:
    vector = json.load(f)

envelope_verify_dev(vector["envelope"])

# Or with explicit keys (32-byte Ed25519)
secret = bytes.fromhex(vector["signing_key_seed_hex"])
public = bytes.fromhex(vector["verifying_key_hex"])
signed = envelope_sign(secret, vector["envelope"])
envelope_verify(public, signed)
```

Set `OPE_LIB_PATH` to override library location.

## Test

```bash
pip install -e ".[dev]"
pytest tests -q
```
