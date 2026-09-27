#!/usr/bin/env python3
"""Check old-or-new PIV object recovery after a controlled flash interruption.

Prepare a public candidate, send it through the normal SCP03/PIV path, and
compare the recovered object with the saved old and candidate values. The
optional pause lets a debugger arm a breakpoint before the final mutating APDU.
"""

import argparse
import hashlib
import pathlib
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec

from jcvm_physical_persistence import connect, select
from jcvm_transport_acceptance import certificate_for, read_certificate, tlv, write_certificate


def prepare(old: pathlib.Path, candidate: pathlib.Path) -> None:
    previous = old.read_bytes()
    serial = int.from_bytes(hashlib.sha256(previous).digest()[:16], "big") or 1
    certificate = certificate_for(ec.derive_private_key(13, ec.SECP256R1()).public_key(), serial)
    replacement = tlv(0x53, tlv(0x70, certificate) + bytes.fromhex("710100FE00"))
    if replacement == previous:
        raise RuntimeError("candidate must differ from the saved old value")
    candidate.write_bytes(replacement)
    print(f"Prepared {len(replacement)} public bytes; old {len(previous)} bytes")


def send(client, candidate: pathlib.Path, pause: bool) -> None:
    select(client)
    client.connect(select_isd=False)
    replacement = candidate.read_bytes()
    def wait_for_debugger() -> None:
        input("READY: arm the debugger, then press Enter for the final APDU: ")
    write_certificate(client, replacement, before_final=wait_for_debugger if pause else None)
    read_certificate(client, replacement)
    print("PASS: candidate published and read back")


def verify(client, old: pathlib.Path, candidate: pathlib.Path) -> None:
    previous = old.read_bytes()
    replacement = candidate.read_bytes()
    if previous == replacement:
        raise RuntimeError("old and candidate records are identical")
    for label, expected in (("old", previous), ("new", replacement)):
        select(client)
        try:
            read_certificate(client, expected)
        except AssertionError:
            continue
        print(f"PASS: recovered the exact {label} authenticated PIV value")
        return
    raise RuntimeError("recovered PIV value matches neither saved version")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "send", "verify"))
    parser.add_argument("--old", required=True, type=pathlib.Path)
    parser.add_argument("--candidate", required=True, type=pathlib.Path)
    parser.add_argument("--reader")
    parser.add_argument("--management-key", type=pathlib.Path)
    parser.add_argument("--pause", action="store_true", help="wait before the mutating APDUs")
    args = parser.parse_args()
    if not args.old.is_file():
        parser.error("--old must name a saved public object")
    if args.phase == "prepare":
        if args.candidate.exists():
            parser.error("candidate already exists; choose a fresh path")
        prepare(args.old, args.candidate)
        return
    if not args.candidate.is_file():
        parser.error("--candidate must name a prepared public object")
    if not args.reader or not args.management_key:
        parser.error("--reader and --management-key are required for card access")
    if len(args.management_key.read_bytes()) != 32:
        parser.error("management key must contain exactly 32 bytes")
    if args.pause and args.phase != "send":
        parser.error("--pause applies only to send")
    with tempfile.TemporaryDirectory(prefix="microcard-publication-") as temporary:
        client = connect(args.reader, args.management_key, pathlib.Path(temporary))
        try:
            if args.phase == "send":
                send(client, args.candidate, args.pause)
            else:
                verify(client, args.old, args.candidate)
        finally:
            client.close()


if __name__ == "__main__":
    main()
