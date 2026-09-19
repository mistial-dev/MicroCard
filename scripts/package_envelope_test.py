#!/usr/bin/env python3
"""Verify the MP05 envelope vector with independent OpenSSL-backed cryptography."""
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from package_envelope import verify


def signature(key, message, signature):
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key).verify(
            encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


vector = json.loads((Path(__file__).resolve().parents[1] / "format/package-envelope-v5.json").read_text())
raw = bytes.fromhex(vector["package"])
assert verify(raw, signature) == tuple(bytes.fromhex(vector[name]) for name in ("manifest", "image", "key"))
for i in range(len(raw)):
    changed = bytearray(raw)
    changed[i] ^= 1
    try:
        verify(bytes(changed), signature)
    except ValueError:
        continue
    raise AssertionError(f"accepted changed byte {i}")
print("PASS: MP05 independent vector and every-byte authentication coverage")
