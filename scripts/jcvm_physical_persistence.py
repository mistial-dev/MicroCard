#!/usr/bin/env python3
"""Check one applet-visible persistent object across a physical DK reboot.

Run write with --install on an unprovisioned card, power-cycle the target,
then run verify with the same record file. Later writes omit --install. The
record contains only a public test certificate.
"""

import argparse
import pathlib
import secrets
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec

from device_cbor import decode
from jcvm_transport_acceptance import (
    certificate_for,
    install_openfips,
    read_certificate,
    tlv,
    write_certificate,
)
from scp03_acceptance import Client, ROOT


APPLET = bytes.fromhex("A000000308000010000100")
OBJECT_DEFINITION = bytes.fromhex("64128B035FC10A8C017F8D017F91019B92020400")


def connect(reader: str, key: pathlib.Path, classes: pathlib.Path) -> Client:
    subprocess.run(
        ["javac", "--release", "21", "-d", str(classes),
         str(ROOT / "scripts/PcscRelay.java")],
        check=True,
    )
    return Client(key, None, transport=["java", "-cp", str(classes), "PcscRelay", reader])


def select(client: Client) -> None:
    command = bytes([0, 0xA4, 4, 0, len(APPLET)]) + APPLET
    response = client.raw(command)
    if response[-2:] != b"\x90\x00":
        raise RuntimeError(f"OpenFIPS201 selection failed: {response.hex()}")


def write(client: Client, record: pathlib.Path, install: bool) -> None:
    if install:
        client.connect()
        discovery = decode(client.command(0xE2, b"\0"))
        install_openfips(client, discovery)
    else:
        select(client)
    client.connect(select_isd=False)
    if install:
        client.command(0xDB, OBJECT_DEFINITION, p1=0xFF, p2=0xFF)
    serial = secrets.randbits(128) or 1
    certificate = certificate_for(ec.derive_private_key(13, ec.SECP256R1()).public_key(), serial)
    expected = tlv(0x53, tlv(0x70, certificate) + bytes.fromhex("710100FE00"))
    write_certificate(client, expected)
    read_certificate(client, expected)
    record.write_bytes(expected)
    print(f"PASS: wrote and read {len(expected)} public certificate bytes; record {record}")


def verify(client: Client, record: pathlib.Path) -> None:
    expected = record.read_bytes()
    select(client)
    read_certificate(client, expected)
    print(f"PASS: recovered the same {len(expected)} applet-visible bytes after reboot")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("write", "verify"))
    parser.add_argument("--reader", required=True)
    parser.add_argument("--management-key", type=pathlib.Path, required=True)
    parser.add_argument("--record", type=pathlib.Path, required=True)
    parser.add_argument("--install", action="store_true",
                        help="load OpenFIPS201 and define the object on a fresh card")
    args = parser.parse_args()
    if len(args.management_key.read_bytes()) != 32:
        parser.error("management key must contain exactly 32 bytes")
    if args.phase == "write" and args.record.exists():
        parser.error("record already exists; use a fresh path for a new physical run")
    if args.phase == "verify" and not args.record.is_file():
        parser.error("record does not exist")
    if args.phase == "verify" and args.install:
        parser.error("--install applies only to the write phase")
    with tempfile.TemporaryDirectory(prefix="microcard-persistence-") as temporary:
        client = connect(args.reader, args.management_key, pathlib.Path(temporary))
        try:
            if args.phase == "write":
                write(client, args.record, args.install)
            else:
                verify(client, args.record)
        finally:
            client.close()


if __name__ == "__main__":
    main()
