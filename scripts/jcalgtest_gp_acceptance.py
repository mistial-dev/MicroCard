#!/usr/bin/env python3
"""Load the independent JCAlgTest CAP through SCP03 on host or a PC/SC board."""
import argparse
import pathlib
import subprocess
import tempfile

from device_cbor import decode
from jcvm_transport_acceptance import load_cap, lv
from scp03_acceptance import Client, ROOT


IMAGE = ROOT / "crates/microcard-engine-jcvm/tests/vectors/jcalgtest-v1.8.2-jc305.lfdb"
PACKAGE = bytes.fromhex("4A43416C6754657374")
APPLET = bytes.fromhex("4A43416C675465737431")


def probe(client):
    selected = client.raw(bytes([0, 0xA4, 4, 0, len(APPLET)]) + APPLET)
    assert selected[-2:] == b"\x90\x00", selected.hex()
    version = client.raw(bytes.fromhex("B0E100000100"))
    assert version == b"1.8.2_jc305\x90\x00", version.hex()
    digest = client.raw(bytes.fromhex("B075150003040000"))
    assert digest[:2] == bytes.fromhex("1500") and digest[-2:] == b"\x90\x00", digest.hex()
    for pin_type in (2, 3):
        result = client.raw(bytes.fromhex("B075240003") + bytes([pin_type, 0, 0, 0]))
        assert result[:2] == bytes.fromhex("2400") and result[-2:] == b"\x90\x00", result.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", help="Exact PC/SC reader name; omit for host JCVM")
    parser.add_argument("--management-key", type=pathlib.Path,
                        help="32-byte board management key")
    parser.add_argument("--select-only", action="store_true",
                        help="Check the applet already installed on a board")
    args = parser.parse_args()
    if args.reader and args.management_key is None:
        parser.error("--management-key is required with --reader")
    if args.management_key and len(args.management_key.read_bytes()) != 32:
        parser.error("--management-key must contain exactly 32 bytes")
    with tempfile.TemporaryDirectory(prefix="microcard-jcalgtest-gp-") as temporary:
        root = pathlib.Path(temporary)
        keys, state = root / "keys", root / "state"
        if args.reader:
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(["javac", "--release", "21", "-d", classes,
                            ROOT / "scripts/PcscRelay.java"], check=True)
            keys = args.management_key
            state = None
            transport = ["java", "-cp", str(classes), "PcscRelay", args.reader]
        else:
            keys.write_bytes(bytes(range(32)))
            transport = "serve-jcvm-managed"
        client = (Client(keys, state, transport=transport) if args.reader
                  else Client(keys, state, transport))
        try:
            client.connect()
            if not args.select_only:
                discovery = decode(client.command(0xE2, b"\0"))
                assert discovery[:4] == [2, 2, 1, 0]
                load_cap(client, discovery[4], PACKAGE, IMAGE.read_bytes())
                client.command(0xE6, lv(PACKAGE, APPLET, APPLET, b"\0", b"\xc9\0", b""), p1=0x0C)
            probe(client)
        finally:
            client.close()
        if args.reader:
            print("PASS: physical unsigned JCAlgTest load, install and probe" if not args.select_only
                  else "PASS: physical JCAlgTest selection after reset")
            return
        client = Client(keys, state, "serve-jcvm-managed")
        try:
            client.connect()
            probe(client)
        finally:
            client.close()
    print("PASS: unsigned JCAlgTest CAP loads through SCP03 and survives reboot")


if __name__ == "__main__":
    main()
