#!/usr/bin/env python3
"""Load the independent JCAlgTest CAP through SCP03 and run an applet probe."""
import pathlib
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


def main():
    with tempfile.TemporaryDirectory(prefix="microcard-jcalgtest-gp-") as temporary:
        root = pathlib.Path(temporary)
        keys, state = root / "keys", root / "state"
        keys.write_bytes(bytes(range(32)))
        client = Client(keys, state, "serve-jcvm-managed")
        try:
            client.connect()
            discovery = decode(client.command(0xE2, b"\0"))
            assert discovery[:4] == [2, 2, 1, 0]
            load_cap(client, discovery[4], PACKAGE, IMAGE.read_bytes())
            client.command(0xE6, lv(PACKAGE, APPLET, APPLET, b"\0", b"\xc9\0", b""), p1=0x0C)
            probe(client)
        finally:
            client.close()
        client = Client(keys, state, "serve-jcvm-managed")
        try:
            client.connect()
            probe(client)
        finally:
            client.close()
    print("PASS: unsigned JCAlgTest CAP loads through SCP03 and survives reboot")


if __name__ == "__main__":
    main()
