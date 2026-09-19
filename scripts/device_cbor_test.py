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

from device_cbor import encode, decode
policy = [bytes([*range(2, 14), 20, *range(22, 53)]), 8, 8, 512, 64, 8192, 8, 16384]
domain = [bytes([1] * 16), bytes.fromhex("a000000151000000"), bytes([2] * 32), policy,
          [["mscorlib", [7, 123, bytes([3] * 32)]]], [], [], [], [], [], [], [], [], []]
state = [2, 0, 0, domain, []]
vector = json.loads((Path(__file__).resolve().parents[1] / "format/snapshot-cbor-v2.json").read_text())
assert encode(state).hex() == vector["hex"]
assert decode(bytes.fromhex(vector["hex"])) == state
print("PASS: internal snapshot CBOR Rust/Python golden vector")
