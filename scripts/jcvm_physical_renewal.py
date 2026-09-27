#!/usr/bin/env python3
"""Drive one development-card heap counter to an authenticated epoch renewal."""

import argparse
import pathlib
import tempfile
import time

from jcvm_diagnostic import COMMAND as DIAGNOSTIC, decode
from jcvm_physical_p256 import PIN
from jcvm_physical_persistence import connect, select
from jcvm_physical_pin_cut import retries


VERIFY = bytes([0, 0x20, 0, 0x80, len(PIN)]) + PIN
COUNTER_WORDS = 1024


def generation(client) -> tuple[int, int]:
    state = decode(client.raw(bytes.fromhex(DIAGNOSTIC)))
    return state["generation_hi"], state["generation_lo"]


def drive(client, record: pathlib.Path) -> None:
    select(client)
    if retries(client) != 6:
        raise RuntimeError("development PIN must have all six retries before renewal stress")
    high, low = generation(client)
    if high >= COUNTER_WORDS - 2:
        raise RuntimeError(f"counter already near renewal: {high}/{COUNTER_WORDS}")
    target = COUNTER_WORDS - 2
    if (target - high) & 1:
        target -= 1
    start = time.monotonic()
    while high < target:
        response = client.raw(VERIFY)
        if response != b"\x90\x00":
            raise RuntimeError(f"PIN verification failed at anchor {high}: {response.hex()}")
        next_high, next_low = generation(client)
        if next_high != high + 2:
            raise RuntimeError(f"unexpected anchor advance {high} -> {next_high}")
        high, low = next_high, next_low
        if (target - high) % 100 == 0 or high == target:
            print(f"anchor {high}/{COUNTER_WORDS}, append {low}, {time.monotonic() - start:.1f}s", flush=True)
    record.write_text(f"{high} {low}\n")
    print(f"READY: {COUNTER_WORDS - high} anchor words remain; saved {record}")


def trigger(client, record: pathlib.Path, pause: bool) -> None:
    select(client)
    expected_high = int(record.read_text().split()[0])
    high, _ = generation(client)
    if high != expected_high or COUNTER_WORDS - high < 2:
        raise RuntimeError(f"anchor moved or lacks room for PIN checkpoint: {high}")
    if pause:
        input("READY: arm the renewal breakpoint, then press Enter for final VERIFY: ")
    response = client.raw(VERIFY)
    if response != b"\x90\x00":
        raise RuntimeError(f"final PIN verification failed: {response.hex()}")
    print("PASS: final PIN VERIFY returned 9000; awaiting automatic idle renewal", flush=True)
    time.sleep(5)


def verify(client) -> None:
    count = retries(client)
    if count != 6:
        raise RuntimeError(f"PIN state changed across renewal cut: {count} retries")
    high, low = generation(client)
    print(f"PASS: six retries recovered; journal generation high={high}, low={low}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("drive", "trigger", "verify"))
    parser.add_argument("--reader", required=True)
    parser.add_argument("--management-key", required=True, type=pathlib.Path)
    parser.add_argument("--record", required=True, type=pathlib.Path)
    parser.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    if len(args.management_key.read_bytes()) != 32:
        parser.error("management key must contain exactly 32 bytes")
    if args.phase == "drive" and args.record.exists():
        parser.error("record already exists")
    if args.phase == "trigger" and not args.record.is_file():
        parser.error("drive record missing")
    if args.pause and args.phase != "trigger":
        parser.error("--pause applies only to trigger")
    with tempfile.TemporaryDirectory(prefix="microcard-renewal-") as temporary:
        client = connect(args.reader, args.management_key, pathlib.Path(temporary))
        try:
            if args.phase == "drive":
                drive(client, args.record)
            elif args.phase == "trigger":
                trigger(client, args.record, args.pause)
            else:
                verify(client)
        finally:
            client.close()


if __name__ == "__main__":
    main()
