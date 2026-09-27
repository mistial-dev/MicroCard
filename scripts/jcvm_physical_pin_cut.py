#!/usr/bin/env python3
"""Check one OwnerPIN retry checkpoint across a controlled power interruption."""

import argparse
import pathlib
import tempfile

from jcvm_physical_persistence import connect, select


STATUS = bytes.fromhex("00200080")
WRONG_PIN = bytes.fromhex("0020008008303030303030FFFF")


def retries(client) -> int:
    select(client)
    response = client.raw(STATUS)
    if response == b"\x90\x00":
        # A previous successful VERIFY can leave transient validation active.
        reset = client.raw(bytes.fromhex("0020FF80"))
        if reset != b"\x90\x00":
            raise RuntimeError(f"PIV PIN validation reset failed: {reset.hex()}")
        response = client.raw(STATUS)
    if len(response) != 2 or response[0] != 0x63 or response[1] & 0xF0 != 0xC0:
        raise RuntimeError(f"PIV PIN retry status unavailable: {response.hex()}")
    return response[1] & 0x0F


def baseline(client, record: pathlib.Path) -> None:
    count = retries(client)
    if count < 2:
        raise RuntimeError(f"need at least two retries for a safe cut test, got {count}")
    record.write_text(f"{count}\n")
    print(f"READY: saved public retry count {count} in {record}")


def send(client, expected: int, pause: bool) -> None:
    current = retries(client)
    if current != expected:
        raise RuntimeError(f"retry count changed: expected {expected}, got {current}")
    if pause:
        input("READY: arm the flash breakpoint, then press Enter for one failed VERIFY: ")
    response = client.raw(WRONG_PIN)
    expected_status = bytes([0x63, 0xC0 | (expected - 1)])
    if response != expected_status:
        raise RuntimeError(f"failed VERIFY returned {response.hex()}, expected {expected_status.hex()}")
    print(f"PASS: failed VERIFY returned {response.hex()} after durable checkpoint")


def verify(client, expected: int, result: str) -> None:
    current = retries(client)
    allowed = {"old": (expected,), "new": (expected - 1,),
               "either": (expected, expected - 1)}[result]
    if current not in allowed:
        raise RuntimeError(f"recovered {current} retries, expected {result}: {allowed}")
    print(f"PASS: recovered {current} retries ({'old' if current == expected else 'new'} checkpoint)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("baseline", "send", "verify"))
    parser.add_argument("--reader", required=True)
    parser.add_argument("--management-key", required=True, type=pathlib.Path)
    parser.add_argument("--record", required=True, type=pathlib.Path)
    parser.add_argument("--pause", action="store_true")
    parser.add_argument("--result", choices=("old", "new", "either"), default="either")
    args = parser.parse_args()
    if len(args.management_key.read_bytes()) != 32:
        parser.error("management key must contain exactly 32 bytes")
    if args.phase == "baseline" and args.record.exists():
        parser.error("baseline record already exists")
    if args.phase != "baseline" and not args.record.is_file():
        parser.error("baseline record is missing")
    if args.pause and args.phase != "send":
        parser.error("--pause applies only to send")
    with tempfile.TemporaryDirectory(prefix="microcard-pin-cut-") as temporary:
        client = connect(args.reader, args.management_key, pathlib.Path(temporary))
        try:
            if args.phase == "baseline":
                baseline(client, args.record)
            elif args.phase == "send":
                send(client, int(args.record.read_text().strip()), args.pause)
            else:
                verify(client, int(args.record.read_text().strip()), args.result)
        finally:
            client.close()


if __name__ == "__main__":
    main()
