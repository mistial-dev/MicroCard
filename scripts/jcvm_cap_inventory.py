#!/usr/bin/env python3
"""Report what a Java Card CAP file actually contains.

The profile in docs/JCVM_PROFILE.md rests on numbers measured from real CAP files. This
reads those numbers back out so the profile can be checked against its sources, and so the
Rust loader has expected values to be tested against.

CAP files are third-party build outputs and are not committed here, so this refuses to run
without an explicit path in the manner of the other hardware and interop scripts.
"""
import argparse
import hashlib
import json
import pathlib
import sys
import zipfile

# JCVM 3.x section 6.3 gives the order of a Load File Data Block. Debug and Descriptor are
# excluded from it, which is why the block is far smaller than the archive that carries it.
LOAD_FILE_ORDER = (
    "Header",
    "Directory",
    "Applet",
    "Import",
    "ConstantPool",
    "Class",
    "Method",
    "StaticField",
    "RefLocation",
    "Export",
)
ALL_COMPONENTS = LOAD_FILE_ORDER + ("Descriptor", "Debug")
TAGS = {
    1: "Header",
    2: "Directory",
    3: "Applet",
    4: "Import",
    5: "ConstantPool",
    6: "Class",
    7: "Method",
    8: "StaticField",
    9: "RefLocation",
    10: "Export",
    11: "Descriptor",
    12: "Debug",
}
MAGIC = bytes.fromhex("DECAFFED")


def components(archive: zipfile.ZipFile) -> dict[str, bytes]:
    """Every component in the archive, keyed by its specification name."""
    found = {}
    for entry in archive.namelist():
        name = entry.rsplit("/", 1)[-1]
        if not name.endswith(".cap"):
            continue
        stem = name[: -len(".cap")]
        if stem in ALL_COMPONENTS:
            found[stem] = archive.read(entry)
    return found


def aid(raw: bytes, offset: int) -> tuple[str, int]:
    """A length-prefixed AID, returned as hex with the offset that follows it."""
    length = raw[offset]
    return raw[offset + 1: offset + 1 + length].hex().upper(), offset + 1 + length


def header(raw: bytes) -> dict[str, object]:
    """The Header component, JCVM section 6.4."""
    if raw[0] != 1:
        raise ValueError(f"header tag is {raw[0]}")
    size = int.from_bytes(raw[1:3], "big")
    if size != len(raw) - 3:
        raise ValueError(f"header size {size} disagrees with {len(raw) - 3} bytes of info")
    if raw[3:7] != MAGIC:
        raise ValueError(f"magic is {raw[3:7].hex()}")
    package_aid, end = aid(raw, 12)
    if end != len(raw):
        raise ValueError(f"header has {len(raw) - end} trailing bytes")
    return {
        "cap_version": f"{raw[8]}.{raw[7]}",
        "flags": raw[9],
        "package_version": f"{raw[11]}.{raw[10]}",
        "package_aid": package_aid,
    }


def imports(raw: bytes) -> list[dict[str, str]]:
    """The Import component, JCVM section 6.7."""
    count = raw[3]
    offset = 4
    entries = []
    for _ in range(count):
        minor, major = raw[offset], raw[offset + 1]
        package_aid, offset = aid(raw, offset + 2)
        entries.append({"aid": package_aid, "version": f"{major}.{minor}"})
    return entries


def directory(raw: bytes) -> list[int]:
    """The component sizes the Directory claims, JCVM section 6.5.

    Each entry counts the info bytes alone, so a present component is three bytes longer
    than its entry once its own tag and size are included. An absent one claims zero.
    """
    return [int.from_bytes(raw[3 + i * 2: 5 + i * 2], "big") for i in range(11)]


def inventory(path: pathlib.Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        found = components(archive)
    missing = [name for name in ("Header", "Directory", "Method") if name not in found]
    if missing:
        raise ValueError(f"{path.name} has no {', '.join(missing)} component")
    block = b"".join(found[name] for name in LOAD_FILE_ORDER if name in found)
    record = {
        "file": path.name,
        "archive_bytes": path.stat().st_size,
        "load_file_bytes": len(block),
        "load_file_sha256": hashlib.sha256(block).hexdigest(),
        "components": {name: len(found[name]) for name in ALL_COMPONENTS if name in found},
        "imports": imports(found["Import"]) if "Import" in found else [],
    }
    record.update(header(found["Header"]))
    # Each component declares its own size, and the Directory declares them all. Disagreement
    # means the archive was assembled from parts that never belonged together.
    for name, value in found.items():
        declared = int.from_bytes(value[1:3], "big")
        if declared != len(value) - 3:
            raise ValueError(f"{path.name} {name} declares {declared} against {len(value) - 3}")
        if TAGS.get(value[0]) != name:
            raise ValueError(f"{path.name} {name} carries tag {value[0]}")
    claimed = directory(found["Directory"])
    for index, name in enumerate(ALL_COMPONENTS[:11]):
        actual = len(found[name]) - 3 if name in found else 0
        if claimed[index] != actual:
            raise ValueError(f"{path.name} directory claims {claimed[index]} for {name}, found {actual}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=pathlib.Path,
                        help="CAP files, or directories searched for them")
    parser.add_argument("--json", action="store_true", help="emit the records as JSON")
    arguments = parser.parse_args()
    files = []
    for path in arguments.paths:
        files.extend(sorted(path.rglob("*.cap")) if path.is_dir() else [path])
    if not files:
        raise SystemExit("No CAP file found at the given paths")
    records = [inventory(path) for path in files]
    if arguments.json:
        json.dump(records, sys.stdout, indent=2)
        print()
        return
    for record in records:
        print(f"{record['file']}")
        print(f"  CAP {record['cap_version']} flags {record['flags']:#04x} "
              f"package {record['package_aid']} version {record['package_version']}")
        print(f"  load file {record['load_file_bytes']} bytes, archive {record['archive_bytes']}")
        print("  " + "  ".join(f"{name}={size}" for name, size in record["components"].items()))
        print("  imports " + ", ".join(f"{e['aid']}@{e['version']}" for e in record["imports"]))
    print(f"PASS: {len(records)} CAP files parsed with self-consistent component tables")


if __name__ == "__main__":
    main()
