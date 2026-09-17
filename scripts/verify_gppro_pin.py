#!/usr/bin/env python3
"""Verify a local GlobalPlatformPro release artifact against the project pin."""

import argparse
import hashlib
import json
import pathlib
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / "docs/GLOBALPLATFORMPRO_PIN.json"


def manifest_fields(raw):
    fields = {}
    current = None
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.startswith(" ") and current is not None:
            fields[current] += line[1:]
            continue
        if ": " in line:
            current, value = line.split(": ", 1)
            fields[current] = value
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jar", type=pathlib.Path)
    parser.add_argument("--pin", type=pathlib.Path, default=DEFAULT_PIN)
    args = parser.parse_args()

    pin = json.loads(args.pin.read_text())
    artifact = args.jar.read_bytes()
    expected = pin["asset"]
    if len(artifact) != expected["size"]:
        raise SystemExit("GlobalPlatformPro jar size mismatch")
    if hashlib.sha256(artifact).hexdigest() != expected["sha256"]:
        raise SystemExit("GlobalPlatformPro jar digest mismatch")

    with zipfile.ZipFile(args.jar) as jar:
        manifest = manifest_fields(jar.read("META-INF/MANIFEST.MF").decode("utf-8"))
    expected_manifest = pin["jar_manifest"]
    checks = {
        "Last-Commit-Id": expected_manifest["last_commit_id"],
        "Last-Commit-Time": expected_manifest["last_commit_time"],
        "Reproducible-Build": str(expected_manifest["reproducible_build"]).lower(),
        "Main-Class": expected_manifest["main_class"],
    }
    for name, value in checks.items():
        if manifest.get(name) != value:
            raise SystemExit(f"GlobalPlatformPro manifest {name} mismatch")

    print(f"PASS: GlobalPlatformPro {pin['release']} artifact matches the project pin")


if __name__ == "__main__":
    main()
