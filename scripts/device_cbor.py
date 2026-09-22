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


def decode(data):
    """Decode the bounded device subset and require preferred encodings."""
    offset = 0
    def take(length):
        nonlocal offset
        if length > len(data) - offset:
            raise ValueError("truncated CBOR")
        value = data[offset:offset + length]
        offset += length
        return value
    def item(depth=0):
        if depth > 16:
            raise ValueError("CBOR nesting exceeded")
        initial = take(1)[0]
        if initial in (0xf4, 0xf5, 0xf6):
            return {0xf4: False, 0xf5: True, 0xf6: None}[initial]
        major, additional = initial >> 5, initial & 31
        if major not in (0, 1, 2, 3, 4) or additional > 27:
            raise ValueError("unsupported CBOR type")
        if additional < 24:
            argument = additional
        else:
            width = 1 << (additional - 24)
            argument = int.from_bytes(take(width), "big")
            if argument < (24 if width == 1 else 1 << (width * 4)):
                raise ValueError("noncanonical CBOR argument")
        if major == 0: return argument
        if major == 1: return -1 - argument
        if argument > len(data) - offset:
            raise ValueError("CBOR length exceeds input")
        if major == 2: return bytes(take(argument))
        if major == 3: return take(argument).decode("utf-8")
        return [item(depth + 1) for _ in range(argument)]
    if len(data) > 16384:
        raise ValueError("CBOR input quota exceeded")
    value = item()
    if offset != len(data): raise ValueError("trailing CBOR data")
    return value


def decode_manifest(data):
    r = decode(data)
    if not isinstance(r, list) or len(r) != 12 or r[0] != 1:
        raise ValueError("unsupported manifest version")
    def binary(value): return None if value is None else list(value)
    result = dict(domain=r[1], incarnation=binary(r[2]), assembly=r[3], assembly_version=r[4], version=r[5],
                  export=dict(access=r[6][0], key=binary(r[6][1])),
                  entry_points=[dict(zip(("aid", "process", "install", "uninstall", "select", "deselect"), [e[0].hex().upper(), *e[1:]])) for e in r[7]],
                  dependencies=[dict(assembly=d[0], ranges=[dict(zip(("min", "min_inclusive", "max", "max_inclusive"), v)) for v in d[1]],
                                     package_version=d[2], signer=binary(d[3]), digest=binary(d[4]), scope=d[5]) for d in r[8]],
                  capabilities=binary(r[9]), storage=[dict(zip(("key", "kind", "max_bytes"), v)) for v in r[10]],
                  limits=dict(zip(("arena", "stack", "frames", "instructions"), r[11])))
    if manifest(result) != data:
        raise ValueError("manifest record shape mismatch")
    return result
