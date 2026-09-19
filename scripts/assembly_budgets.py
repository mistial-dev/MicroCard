#!/usr/bin/env python3
"""Generate deterministic MC04 corpus size budgets and enforce regression ceilings."""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
# 40 byte header, a 65 byte uncompressed SEC1 signer key and a 64 byte signature.
PACKAGE_FIXED_BYTES = 169
sys.path.insert(0, str(ROOT / "scripts"))
import mcinspect

CORPUS = [
    ("mscorlib", "mscorlib", "samples/CoreLib/bin/Release/net10.0/MicroCard.Core.dll", 3072, 4096),
    ("CoreConsumer", "core-consumer", "samples/CoreConsumer/bin/Release/net10.0/CoreConsumer.dll", 2048, 3072),
    ("Counter", "counter", "samples/Counter/bin/Release/net10.0/Counter.dll", 3072, 4096),
    ("KeyOperations", "keys", "samples/KeyOperations/bin/Release/net10.0/KeyOperations.dll", 3072, 4096),
    ("Kdf108", "kdf108", "samples/Kdf108/bin/Release/net10.0/Kdf108.dll", 1024, 2048),
    ("Kdf108Consumer", "kdf108-consumer", "samples/Kdf108Consumer/bin/Release/net10.0/Kdf108Consumer.dll", 2048, 3072),
    ("SigningAcceptance", "signing-acceptance", "samples/SigningAcceptance/bin/Release/net10.0/SigningAcceptance.dll", 512, 1280),
    ("MicroCard.Iso7816", "iso7816", "managed/MicroCard.Iso7816/bin/Release/net10.0/MicroCard.Iso7816.dll", 3072, 4096),
    ("Iso7816Consumer", "iso7816-consumer", "samples/Iso7816Consumer/bin/Release/net10.0/Iso7816Consumer.dll", 2048, 3072),
    ("MicroCard.Encoding", "encoding", "managed/MicroCard.Encoding/bin/Release/net10.0/MicroCard.Encoding.dll", 4096, 5120),
    ("EncodingConsumer", "encoding-consumer", "samples/EncodingConsumer/bin/Release/net10.0/EncodingConsumer.dll", 2048, 3072),
    ("MicroCard.Cryptography", "cryptography", "managed/MicroCard.Cryptography/bin/Release/net10.0/MicroCard.Cryptography.dll", 3072, 4096),
    ("CryptographyConsumer", "cryptography-consumer", "samples/CryptographyConsumer/bin/Release/net10.0/CryptographyConsumer.dll", 3072, 4096),
    ("MicroCard.Security", "security", "managed/MicroCard.Security/bin/Release/net10.0/MicroCard.Security.dll", 2048, 3072),
    ("SecurityConsumer", "security-consumer", "samples/SecurityConsumer/bin/Release/net10.0/SecurityConsumer.dll", 3072, 4096),
    ("Credential", "credential", "samples/Credential/bin/Release/net10.0/Credential.dll", 3072, 5120),
]
SECTION_NAMES = {1: "tables", 2: "strings", 3: "blob", 4: "code"}

def sections(raw):
    assert raw[:4] == b"MC04" and raw[8] == 4
    result = {}
    for index in range(4):
        offset = 16 + index * 10
        kind = raw[offset]
        start = int.from_bytes(raw[offset + 2:offset + 6], "little")
        length = int.from_bytes(raw[offset + 6:offset + 10], "little")
        assert start + length <= len(raw)
        result[SECTION_NAMES[kind]] = length
    assert sum(result.values()) + int.from_bytes(raw[10:12], "little") == len(raw)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    records = []
    for expected_name, prefix, pe_name, assembly_ceiling, package_ceiling in CORPUS:
        assembly_path = ROOT / "work" / f"{prefix}.mca"
        metadata_path = ROOT / "work" / f"{prefix}.json"
        map_path = ROOT / "work" / f"{prefix}.map.json"
        raw = assembly_path.read_bytes()
        metadata = json.loads(metadata_path.read_text())
        assert metadata["assembly"] == expected_name
        parsed = mcinspect.inspect(raw)
        tables = {table["name"]: len(table["rows"]) for table in parsed["tables"]}
        manifest = {
            "domain": "budget",
            "incarnation": [0] * 16,
            **metadata,
            "version": 1,
            "limits": {"arena": 16384, "stack": 256, "frames": 32, "instructions": 100000},
        }
        manifest_bytes = len(json.dumps(manifest, separators=(",", ":")).encode())
        package_bytes = PACKAGE_FIXED_BYTES + manifest_bytes + len(raw)
        assert len(raw) <= assembly_ceiling, f"{expected_name} exceeds MC04 ceiling"
        assert package_bytes <= package_ceiling, f"{expected_name} exceeds package ceiling"
        records.append({
            "assembly": expected_name,
            "source_pe_bytes": (ROOT / pe_name).stat().st_size,
            "mc04_bytes": len(raw),
            "sections": {"header": int.from_bytes(raw[10:12], "little"), **sections(raw)},
            "table_rows": tables,
            "method_defs": tables.get("MethodDef", 0),
            "member_refs": tables.get("MemberRef", 0),
            "build_metadata_bytes": metadata_path.stat().st_size,
            "debug_map_bytes": map_path.stat().st_size,
            "representative_manifest_bytes": manifest_bytes,
            "package_fixed_bytes": PACKAGE_FIXED_BYTES,
            "representative_package_bytes": package_bytes,
            "ceilings": {"mc04_bytes": assembly_ceiling, "package_bytes": package_ceiling},
        })
    by_name = {record["assembly"]: record for record in records}
    bundle_specs = [
        ("default_isd", ["mscorlib", "MicroCard.Iso7816", "MicroCard.Encoding",
                         "MicroCard.Cryptography", "MicroCard.Security"], 12288, 14336),
        ("credential_profile", ["mscorlib", "MicroCard.Cryptography",
                                "MicroCard.Security", "Credential"], 7168, 10240),
    ]
    bundles = []
    for name, assembly_names, assembly_ceiling, package_ceiling in bundle_specs:
        assembly_bytes = sum(by_name[item]["mc04_bytes"] for item in assembly_names)
        package_bytes = sum(by_name[item]["representative_package_bytes"] for item in assembly_names)
        assert assembly_bytes <= assembly_ceiling, f"{name} exceeds aggregate MC04 ceiling"
        assert package_bytes <= package_ceiling, f"{name} exceeds aggregate package ceiling"
        bundles.append({
            "name": name,
            "assemblies": assembly_names,
            "aggregate_mc04_bytes": assembly_bytes,
            "aggregate_representative_package_bytes": package_bytes,
            "ceilings": {
                "aggregate_mc04_bytes": assembly_ceiling,
                "aggregate_representative_package_bytes": package_ceiling,
            },
        })
    output = json.dumps({"format": 2, "assemblies": records, "bundles": bundles}, indent=2) + "\n"
    destination = ROOT / "docs/ASSEMBLY_BUDGETS.json"
    if args.stdout:
        print(output, end="")
        return
    if args.check:
        assert destination.read_text() == output, "docs/ASSEMBLY_BUDGETS.json is stale"
    else:
        destination.write_text(output)
    print(f"PASS: {len(records)} MC04 assembly and signed-package size budgets")

if __name__ == "__main__":
    main()
