#!/usr/bin/env python3
"""Compare the Python device encoder with shared wire vectors."""
import json
from pathlib import Path
from device_cbor import management_names, manifest, decode_manifest

for vector in json.loads((Path(__file__).resolve().parents[1] / "format/management-names-v1.json").read_text()):
    assert management_names(vector["first"], vector["second"]).hex() == vector["hex"]
for invalid in ("", "x" * 65, "bad/name", "é", None):
    try:
        management_names(invalid, "Counter")
    except ValueError:
        continue
    raise AssertionError(f"accepted invalid identifier: {invalid!r}")
print("PASS: management CBOR shared vectors and identifier bounds")

for vector in json.loads((Path(__file__).resolve().parents[1] / "format/manifest-cbor-v1.json").read_text()):
    assert manifest(vector["manifest"]).hex() == vector["hex"]
    assert decode_manifest(bytes.fromhex(vector["hex"])) == vector["manifest"]
print("PASS: manifest CBOR shared vectors")
