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
