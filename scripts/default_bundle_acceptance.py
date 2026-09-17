#!/usr/bin/env python3
"""Create and independently inspect the signed default-bundle manifest."""
import hashlib
import pathlib
import struct
import subprocess
import tempfile

from scp03_acceptance import ensure_assembly

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
BUNDLE = ROOT / "managed/MicroCard.Bundle/bin/Release/net10.0/MicroCard.Bundle.dll"
ASSEMBLIES = ["mscorlib", "iso7816", "encoding", "cryptography", "security"]
PROJECTS = [
    "samples/CoreLib",
    "managed/MicroCard.Iso7816",
    "managed/MicroCard.Encoding",
    "managed/MicroCard.Cryptography",
    "managed/MicroCard.Security",
]
EXPECTED = ["mscorlib", "MicroCard.Cryptography", "MicroCard.Encoding", "MicroCard.Iso7816", "MicroCard.Security"]
CONTEXT = b"MicroCard default bundle v1\0"


def run(*args, ok=True):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if ok and result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def inspect(path):
    raw = path.read_bytes()
    assert raw[:4] == b"MDB1" and raw[4:4 + len(CONTEXT)] == CONTEXT
    offset = 4 + len(CONTEXT)
    count = raw[offset]
    offset += 1
    incarnation = raw[offset:offset + 16]
    offset += 16
    signer = raw[offset:offset + 32]
    offset += 32
    entries = []
    for _ in range(count):
        length = raw[offset]
        offset += 1
        name = raw[offset:offset + length].decode()
        offset += length
        version = struct.unpack_from("<4H", raw, offset)
        offset += 8
        package_version, = struct.unpack_from("<I", raw, offset)
        offset += 4
        image_digest = raw[offset:offset + 32]
        package_digest = raw[offset + 32:offset + 64]
        offset += 64
        entries.append((name, version, package_version, image_digest, package_digest))
    assert offset + 64 == len(raw)
    return incarnation, signer, entries


with tempfile.TemporaryDirectory() as temporary:
    directory = pathlib.Path(temporary)
    seed = directory / "owner.seed"
    seed.write_bytes(bytes(range(32)))
    incarnation = "42" * 16
    inputs = {
        name: ensure_assembly(project, name)
        for name, project in zip(ASSEMBLIES, PROJECTS, strict=True)
    }
    packages = []
    for name in ASSEMBLIES:
        package = directory / f"{name}.mcp"
        image, metadata = inputs[name]
        run("dotnet", PACK, image, metadata,
            "ISD", incarnation, "1", seed, package, "--explicit-sign")
        packages.append(package)

    first = directory / "default-one.mdb"
    second = directory / "default-two.mdb"
    run("dotnet", BUNDLE, "create", first, seed, *packages, "--explicit-sign")
    run("dotnet", BUNDLE, "create", second, seed, *reversed(packages), "--explicit-sign")
    assert first.read_bytes() == second.read_bytes(), "bundle depends on input order"
    run("dotnet", BUNDLE, "verify", first, *reversed(packages))

    bundle_incarnation, signer, entries = inspect(first)
    assert bundle_incarnation == bytes.fromhex(incarnation)
    assert [entry[0] for entry in entries] == EXPECTED
    assert all(entry[2] == 1 for entry in entries)
    by_name = {
        "mscorlib": packages[0],
        "MicroCard.Iso7816": packages[1],
        "MicroCard.Encoding": packages[2],
        "MicroCard.Cryptography": packages[3],
        "MicroCard.Security": packages[4],
    }
    for name, _, _, _, package_digest in entries:
        assert package_digest == hashlib.sha256(by_name[name].read_bytes()).digest()
    assert len(signer) == 32 and signer != bytes(32)

    changed = directory / "changed.mdb"
    damaged = bytearray(first.read_bytes())
    damaged[-1] ^= 1
    changed.write_bytes(damaged)
    assert run("dotnet", BUNDLE, "verify", changed, *packages, ok=False).returncode != 0
    assert run("dotnet", BUNDLE, "verify", first, *packages[:-1], ok=False).returncode != 0

    other_seed = directory / "other.seed"
    other_seed.write_bytes(bytes(range(31, -1, -1)))
    other_core = directory / "other-mscorlib.mcp"
    run("dotnet", PACK, *inputs["mscorlib"],
        "ISD", incarnation, "1", other_seed, other_core, "--explicit-sign")
    mixed = [other_core, *packages[1:]]
    assert run("dotnet", BUNDLE, "create", directory / "mixed.mdb", seed, *mixed,
               "--explicit-sign", ok=False).returncode != 0

print("PASS: deterministic signed default-bundle manifest")
