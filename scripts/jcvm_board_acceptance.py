#!/usr/bin/env python3
"""Load the committed OpenFIPS201 fixture through a physical PC/SC MicroCard."""
import argparse
import pathlib
import subprocess
import tempfile

from device_cbor import decode
from jcvm_transport_acceptance import install_openfips, piv
from scp03_acceptance import Client, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True, help="Exact PC/SC reader name")
    parser.add_argument("--management-key", type=pathlib.Path,
                        help="32-byte management key; defaults to the documented development key")
    parser.add_argument("--version", type=int,
                        help="Monotonic signed package version to load (default: 1)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--select-only", action="store_true",
                        help="Select an OpenFIPS201 instance that is already installed")
    action.add_argument("--replace", action="store_true",
                        help="Delete an existing OpenFIPS201 package before loading it")
    action.add_argument("--enter-uf2", action="store_true",
                        help="Authenticate and ask the development firmware to enter UF2")
    args = parser.parse_args()
    if args.replace and args.version is None:
        parser.error("--replace requires a higher --version than the installed package")
    version = args.version if args.version is not None else 1

    with tempfile.TemporaryDirectory(prefix="microcard-board-") as temporary:
        temporary = pathlib.Path(temporary)
        classes = temporary / "classes"
        classes.mkdir()
        subprocess.run(["javac", "--release", "21", "-d", classes,
                        ROOT / "scripts/PcscRelay.java"], check=True)
        keys = args.management_key
        if keys is None:
            keys = temporary / "management.key"
            keys.write_bytes(bytes(range(0x40, 0x50)) * 2)
        elif len(keys.read_bytes()) != 32:
            parser.error("--management-key must contain exactly 32 bytes")

        client = Client(keys, None, transport=["java", "-cp", str(classes),
            "PcscRelay", args.reader])
        try:
            client.connect()
            if args.enter_uf2:
                client.command(0xfe, p1=0x55, p2=0xaa)
                print("PASS: authenticated UF2 request accepted")
                return
            discovery = decode(client.command(0xe2, b"\0"))
            if discovery[:4] != [2, 1, 1, 0]:
                raise RuntimeError(f"unexpected JCVM discovery record: {discovery!r}")
            instance = bytes.fromhex("A000000308000010000100")
            if args.replace:
                package = bytes.fromhex("A00000030800001000")
                for aid in (instance, package):
                    client.command(0xe4, bytes([0x4f, len(aid)]) + aid)
            if args.select_only:
                selected = piv(client, 0xa4, instance, p1=4, le=256)
                if selected[:3] != bytes.fromhex("618192") or len(selected) != 149:
                    raise RuntimeError("unexpected OpenFIPS201 selection response")
                print("PASS: physical SCP03 and existing OpenFIPS201 PIV selection")
            else:
                instance, _, selected = install_openfips(client, discovery, version)
                if piv(client, 0xa4, instance, p1=4, le=256) != selected:
                    raise RuntimeError("OpenFIPS201 re-selection changed its response")
                print("PASS: physical SCP03, signed OpenFIPS201 load, install and PIV selection")
        finally:
            if client.p.poll() is None:
                client.close()


if __name__ == "__main__":
    main()
