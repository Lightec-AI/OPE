#!/usr/bin/env python3
"""Regenerate spec/vectors/transport/*.json from official BoringSSL + RFC 7748 sources."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "spec" / "vectors" / "transport"
SOURCE = OUT / "source"
BORINGSSL_BASE = (
    "https://raw.githubusercontent.com/google/boringssl/main/crypto/mlkem"
)


def parse_plain_boringssl(text: str, idx: int) -> dict:
    pattern = rf"# Official test vector {idx}, seed: \"([^\"]+)\""
    m = re.search(pattern, text)
    if not m:
        raise SystemExit(f"vector {idx} not found")
    start = m.start()
    m2 = re.search(rf"# Official test vector {idx + 1},", text)
    block = text[start : m2.start() if m2 else len(text)]

    def field(name: str) -> str:
        for pat in (rf"^{name}: ([0-9a-f]+)\s*$", rf"^{name} = ([0-9a-f]+)\s*$"):
            mm = re.search(pat, block, re.M)
            if mm:
                return mm.group(1)
        raise SystemExit(f"missing {name} in vector {idx}")

    return {
        "seed": m.group(1),
        "entropy_hex": field("entropy"),
        "encapsulation_key_hex": field("public_key"),
        "ciphertext_hex": field("ciphertext"),
        "mlkem_shared_secret_hex": field("shared_secret"),
    }


def parse_md_keygen(text: str, idx: int) -> dict:
    pattern = rf"# Official test vector {idx}, seed: \"([^\"]+)\""
    m = re.search(pattern, text)
    start = m.start()
    m2 = re.search(rf"# Official test vector {idx + 1},", text)
    block = text[start : m2.start() if m2 else len(text)]

    def field(name: str) -> str:
        mm = re.search(rf"\| {name}: ([0-9a-f]+) \|", block)
        if not mm:
            raise SystemExit(f"missing {name} in keygen vector {idx}")
        return mm.group(1)

    return {
        "seed": m.group(1),
        "encapsulation_key_hex": field("public_key"),
        "decapsulation_key_hex": field("private_key"),
    }


def fetch(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print("fetch", url)
    subprocess.run(
        ["curl", "-fsSL", "--max-time", "180", "-o", str(dest), url],
        check=True,
    )


def main() -> None:
    SOURCE.mkdir(parents=True, exist_ok=True)
    keygen_path = SOURCE / "mlkem768_keygen_tests.txt"
    encap_path = SOURCE / "mlkem768_encap_tests.txt"
    if not keygen_path.exists():
        fetch(f"{BORINGSSL_BASE}/mlkem768_keygen_tests.txt", keygen_path)
    if not encap_path.exists():
        fetch(f"{BORINGSSL_BASE}/mlkem768_encap_tests.txt", encap_path)

    keygen_text = keygen_path.read_text()
    encap_text = encap_path.read_text()

    for i in range(3):
        kg = parse_md_keygen(keygen_text, i) if "| public_key:" in keygen_text else {}
        if not kg:
            kg = parse_plain_boringssl(keygen_text, i)
            kg["decapsulation_key_hex"] = kg.pop("private_key", "")
        ec = parse_plain_boringssl(encap_text, i)
        if kg["encapsulation_key_hex"] != ec["encapsulation_key_hex"]:
            raise SystemExit(f"public key mismatch at index {i}")
        doc = {
            "vector_id": f"boringssl-mlkem768-{i:03d}",
            "provider": "google-boringssl",
            "aws_lineage": "AWS-LC and s2n-tls use the same NIST ACVP / BoringSSL ML-KEM vectors",
            "sources": {
                "keygen": f"{BORINGSSL_BASE}/mlkem768_keygen_tests.txt",
                "encap": f"{BORINGSSL_BASE}/mlkem768_encap_tests.txt",
            },
            "official_test_index": i,
            "seed": kg["seed"],
            **ec,
            "decapsulation_key_hex": kg["decapsulation_key_hex"],
        }
        (OUT / f"boringssl-mlkem768-{i:03d}.json").write_text(
            json.dumps(doc, indent=2) + "\n"
        )

    rfc = {
        "vector_id": "rfc7748-x25519-001",
        "provider": "ietf-rfc7748",
        "sources": {"rfc": "https://www.rfc-editor.org/rfc/rfc7748#section-6.1"},
        "alice_private_hex": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "alice_public_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "bob_private_hex": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "bob_public_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "x25519_shared_secret_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    }
    (OUT / "rfc7748-x25519-001.json").write_text(json.dumps(rfc, indent=2) + "\n")

    ml = json.loads((OUT / "boringssl-mlkem768-000.json").read_text())
    hybrid = {
        "vector_id": "hybrid-x25519mlkem768-000",
        "provider": "ietf-draft-ecdhe-mlkem",
        "sources": {
            "ml_kem": "boringssl-mlkem768-000.json",
            "x25519": "rfc7748-x25519-001.json",
            "spec": "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/",
            "google_chrome": "https://blog.google/chromium/advancing-our-amazing-bet-on-asymmetric/",
            "aws_s2n": "https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html",
        },
        "tls_group": "X25519MLKEM768",
        "tls_group_id": 4588,
        "client_share_hex": ml["encapsulation_key_hex"] + rfc["alice_public_hex"],
        "server_share_hex": ml["ciphertext_hex"] + rfc["bob_public_hex"],
        "decapsulation_key_hex": ml["decapsulation_key_hex"],
        "mlkem_shared_secret_hex": ml["mlkem_shared_secret_hex"],
        "x25519_shared_secret_hex": rfc["x25519_shared_secret_hex"],
        "hybrid_shared_secret_hex": ml["mlkem_shared_secret_hex"]
        + rfc["x25519_shared_secret_hex"],
    }
    (OUT / "hybrid-x25519mlkem768-000.json").write_text(json.dumps(hybrid, indent=2) + "\n")
    print("wrote vectors to", OUT)


if __name__ == "__main__":
    main()
