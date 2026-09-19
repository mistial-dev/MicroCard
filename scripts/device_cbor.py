"""Versioned deterministic CBOR device records. Host reports may still use JSON."""
import re


def management_names(first, second):
    values = []
    for value in (first, second):
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is None:
            raise ValueError("invalid management identifier")
        encoded = value.encode("ascii")
        length = len(encoded)
        values.append((bytes([0x60 + length]) if length < 24 else bytes([0x78, length])) + encoded)
    return b"\x83\x01" + b"".join(values)


def _argument(major, value):
    if not 0 <= value <= 0xffffffffffffffff:
        raise ValueError("CBOR argument outside uint64")
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise ValueError("CBOR integer overflow")


def encode(value):
    """Encode the restricted device subset; no maps, tags, or floating point."""
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _argument(0, value) if value >= 0 else _argument(1, -1 - value)
    if isinstance(value, bytes):
        return _argument(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _argument(3, len(data)) + data
    if isinstance(value, (tuple, list)):
        return _argument(4, len(value)) + b"".join(encode(item) for item in value)
    raise ValueError("unsupported CBOR value")


def manifest(value):
    """Encode the version-1 manifest record from host authoring data."""
    def binary(value):
        return None if value is None else bytes(value)
    entries = []
    for entry in value["entry_points"]:
        aid = entry["aid"]
        if re.fullmatch(r"(?:[0-9A-F]{2}){5,16}", aid) is None:
            raise ValueError("invalid AID")
        entries.append([bytes.fromhex(aid)] + [entry[name] for name in ("process", "install", "uninstall", "select", "deselect")])
    dependencies = []
    for dependency in value["dependencies"]:
        ranges = [[r["min"], r["min_inclusive"], r["max"], r["max_inclusive"]] for r in dependency["ranges"]]
        dependencies.append([dependency["assembly"], ranges, dependency["package_version"],
                             binary(dependency["signer"]), binary(dependency["digest"]), dependency["scope"]])
    return encode([1, value["domain"], bytes(value["incarnation"]), value["assembly"], value["assembly_version"],
                   value["version"], [value["export"]["access"], binary(value["export"]["key"])], entries,
                   dependencies, bytes(value["capabilities"]),
                   [[s["key"], s["kind"], s["max_bytes"]] for s in value["storage"]],
                   [value["limits"][name] for name in ("arena", "stack", "frames", "instructions")]])
