#!/usr/bin/env python3
"""Verify that a UF2 bootloader readback contains an expected application image."""
import argparse
import hashlib
import pathlib
import struct

START0 = 0x0A324655
START1 = 0x9E5D5157
END = 0x0AB16F30


def blocks(path):
    image = pathlib.Path(path).read_bytes()
    if not image or len(image) % 512:
        raise ValueError(f"{path}: length is not a nonzero multiple of 512")
    result = {}
    declared = None
    for offset in range(0, len(image), 512):
        block = image[offset:offset + 512]
        start0, start1, _flags, address, size, index, count, _family = struct.unpack_from("<8I", block)
        if (start0, start1) != (START0, START1) or struct.unpack_from("<I", block, 508)[0] != END:
            raise ValueError(f"{path}: invalid UF2 magic in block {offset // 512}")
        if not 0 < size <= 476 or address + size > 0x1_00000:
            raise ValueError(f"{path}: invalid payload range in block {offset // 512}")
        if declared is None:
            declared = count
        if count != declared or index >= count or index in result:
            raise ValueError(f"{path}: inconsistent block numbering at block {offset // 512}")
        result[index] = (address, block[32:32 + size])
    if len(result) != declared:
        raise ValueError(f"{path}: has {len(result)} of {declared} blocks")
    return [result[index] for index in range(declared)]


def addressed(path):
    result = {}
    for address, payload in blocks(path):
        for offset, byte in enumerate(payload):
            location = address + offset
            if location in result and result[location] != byte:
                raise ValueError(f"{path}: conflicting payload at 0x{location:05X}")
            result[location] = byte
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True, help="UF2 image that was copied to the board")
    parser.add_argument("--current", required=True, help="CURRENT.UF2 read back from the bootloader")
    args = parser.parse_args()
    expected = addressed(args.expected)
    current = addressed(args.current)
    for address in sorted(expected):
        if address not in current:
            raise SystemExit(f"FAIL: readback omits expected address 0x{address:05X}")
        if current[address] != expected[address]:
            raise SystemExit(
                f"FAIL: readback mismatch at 0x{address:05X}: "
                f"expected {expected[address]:02X}, got {current[address]:02X}"
            )
    digest = hashlib.sha256(bytes(expected[address] for address in sorted(expected))).hexdigest()
    first, last = min(expected), max(expected) + 1
    print(f"PASS: {len(expected)} application bytes match at 0x{first:05X}..0x{last:05X} ({digest})")


if __name__ == "__main__":
    main()
