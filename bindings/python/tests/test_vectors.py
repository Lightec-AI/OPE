import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ope import OpeError, envelope_sign, envelope_verify, envelope_verify_dev, version

ROOT = Path(__file__).resolve().parents[3]
VECTOR = ROOT / "spec" / "vectors" / "001-valid-plaintext.json"


@pytest.fixture(scope="module")
def vector():
  with VECTOR.open() as f:
    return json.load(f)


def test_version():
  assert version() == "0.1.0"


def test_vector_001_dev_verify(vector):
  envelope_verify_dev(vector["envelope"])


def test_sign_verify_roundtrip(vector):
  secret = bytes.fromhex(vector["signing_key_seed_hex"])
  public = bytes.fromhex(vector["verifying_key_hex"])
  unsigned = dict(vector["envelope"])
  unsigned.pop("sig", None)
  unsigned["payload_hash"] = ""
  unsigned["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  signed_json = envelope_sign(secret, unsigned)
  envelope_verify(public, signed_json, max_skew_secs=600)
