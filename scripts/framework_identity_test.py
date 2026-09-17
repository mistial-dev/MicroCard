#!/usr/bin/env python3
"""Verify stable platform ABI identities in deterministic MC04 output."""
import hashlib
import pathlib
import subprocess
import tempfile

import mcinspect

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFIXES = [
    "mscorlib", "core-consumer", "counter", "keys", "kdf108", "kdf108-consumer",
    "signing-acceptance", "iso7816", "iso7816-consumer", "encoding",
    "encoding-consumer", "cryptography", "cryptography-consumer", "security",
    "security-consumer", "credential",
]
SYSTEM_RUNTIME_TOKEN = "b03f5f7f11d50a3a"
FRAMEWORK_ABI_IDENTITY = "e9b276dc4459e6ffb37f9119874b5053b14cd0b3484a01c70316dd80fb08365a"


def value(column):
    return column.get("value", column.get("hex"))


def assembly_refs(parsed):
    return next(table["rows"] for table in parsed["tables"] if table["name"] == "AssemblyRef")


def main():
    framework = ROOT / "managed/MicroCard.Framework/bin/Release/net10.0/MicroCard.Framework.dll"
    for prefix in PREFIXES:
        parsed = mcinspect.inspect((ROOT / f"work/{prefix}.mca").read_bytes())
        for row in assembly_refs(parsed):
            columns = row["columns"]
            name = value(columns["Name"])
            token = value(columns["PublicKeyOrToken"])
            culture = value(columns["Culture"])
            digest = value(columns["HashValue"])
            if name == "System.Runtime":
                assert token == SYSTEM_RUNTIME_TOKEN and culture == "" and digest == ""
            elif name == "MicroCard.Framework":
                assert token == "" and culture == "" and digest == FRAMEWORK_ABI_IDENTITY
            else:
                assert token == "" and culture == "" and digest == ""

    simulator = ROOT / "target/debug/microcard-sim"
    raw = bytearray((ROOT / "work/counter.mca").read_bytes())
    parsed = mcinspect.inspect(raw)
    rows = assembly_refs(parsed)
    blob_start = int.from_bytes(raw[38:42], "little")
    for name, column in [
        ("System.Runtime", "PublicKeyOrToken"),
        ("MicroCard.Framework", "HashValue"),
    ]:
        forged = bytearray(raw)
        row = next(item for item in rows if value(item["columns"]["Name"]) == name)
        blob_offset = row["columns"][column]["offset"]
        forged[blob_start + blob_offset + 1] ^= 1
        with tempfile.NamedTemporaryFile(suffix=".mca") as output:
            output.write(forged)
            output.flush()
            rejected = subprocess.run(
                [str(simulator), "verify-assembly", output.name],
                capture_output=True, text=True,
            )
        assert rejected.returncode != 0
        assert "Unauthorized" in rejected.stdout + rejected.stderr

    print("PASS: stable framework ABI identity, System.Runtime token and neutral dependency identities")


if __name__ == "__main__":
    main()
