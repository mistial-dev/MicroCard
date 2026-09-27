#!/usr/bin/env python3
"""Generate a PIV P-256 key on the DK and verify its signatures off-card.

Run setup once, then verify with the saved public point after reset or a power
cycle. The fixed PIN and management key are development credentials only.
"""

import argparse
import pathlib
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from jcvm_physical_persistence import connect, select
from jcvm_transport_acceptance import generate_key, sign_with_pin


PIN = bytes.fromhex("363534333231FFFF")
PIV_MANAGEMENT_KEY = bytes(range(0x30, 0x40))
MANAGEMENT_POLICY = bytes.fromhex("66128B019B8C017F8D01008E01088F0101900114")
KEY_POLICY = bytes.fromhex("66128B019C8C01028D010A8E01118F0104900110")


def setup(client, record: pathlib.Path, define_management: bool) -> None:
    client.connect()
    client.command(0xA4, bytes.fromhex("A000000308000010000100"), p1=4, cla=0x04)
    client.connect(select_isd=False)
    if define_management:
        client.command(0xDB, MANAGEMENT_POLICY, p1=0xFF, p2=0xFF)
    client.command(0x25, bytes.fromhex("80010830128010") + PIV_MANAGEMENT_KEY,
                   p1=1, p2=0x9B)
    client.command(0x24, PIN, p1=1, p2=0x80)
    client.command(0xDB, KEY_POLICY, p1=0xFF, p2=0xFF)
    public_key = generate_key(client, 0x9C)
    sign_with_pin(client, public_key, PIN)
    record.write_bytes(public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    print(f"PASS: DK P-256 key generated, signed, and verified off-card; public point {record}")


def verify(client, record: pathlib.Path) -> None:
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), record.read_bytes())
    select(client)
    sign_with_pin(client, public_key, PIN)
    print("PASS: persisted DK P-256 key signed and verified off-card after restart")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("setup", "verify"))
    parser.add_argument("--reader", required=True)
    parser.add_argument("--management-key", type=pathlib.Path, required=True)
    parser.add_argument("--record", type=pathlib.Path, required=True)
    parser.add_argument("--define-management", action="store_true",
                        help="define PIV key 9B on a fresh applet before provisioning")
    args = parser.parse_args()
    management_key = args.management_key.read_bytes()
    if len(management_key) != 32:
        parser.error("management key must contain exactly 32 bytes")
    if args.phase == "setup" and args.record.exists():
        parser.error("record already exists; use a fresh path for a new physical run")
    if args.phase == "verify" and not args.record.is_file():
        parser.error("record does not exist")
    if args.phase == "verify" and args.define_management:
        parser.error("--define-management applies only to setup")
    with tempfile.TemporaryDirectory(prefix="microcard-p256-") as temporary:
        client = connect(args.reader, args.management_key, pathlib.Path(temporary))
        try:
            if args.phase == "setup":
                setup(client, args.record, args.define_management)
            else:
                verify(client, args.record)
        finally:
            client.close()


if __name__ == "__main__":
    main()
