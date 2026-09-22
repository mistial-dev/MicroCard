#!/usr/bin/env python3
"""Load one converted MC04 assembly through the signed host path and invoke it."""

import argparse
import os
import pathlib
import subprocess
import tempfile

from device_cbor import management_names
from scp03_acceptance import Client, bootstrap_isd

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
SIMULATOR = ROOT / "target/debug/microcard-sim"
ISD_SEED = bytes([0x11]) * 32
ASSEMBLY_SEED = bytes([0x33]) * 32


def build_host_tools() -> None:
    subprocess.run(
        ["dotnet", "build", "managed/MicroCard.Pack", "-c", "Release", "--nologo",
         "--verbosity", "quiet", "-p:NuGetAudit=false"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(["cargo", "build", "--locked", "--quiet", "-p", "microcard-sim"], cwd=ROOT, check=True)


def upload(client: Client, package: bytes) -> None:
    client.command(0xE6)
    for offset in range(0, len(package), 200):
        client.command(0xE8, offset.to_bytes(4, "little") + package[offset:offset + 200])
    client.command(0xEA)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("aid", help="application AID in hexadecimal")
    parser.add_argument("command", nargs="?", default="", help="Process payload in hexadecimal")
    args = parser.parse_args()
    aid = bytes.fromhex(args.aid)
    command = bytes.fromhex(args.command)
    if not 5 <= len(aid) <= 16:
        parser.error("AID must contain 5 through 16 bytes")

    build_host_tools()
    with tempfile.TemporaryDirectory(prefix="microcard-assembly-") as temporary:
        directory = pathlib.Path(temporary)
        management = directory / "management.key"
        management.write_bytes(os.urandom(32))
        management.chmod(0o600)
        isd_seed = directory / "isd.seed"
        assembly_seed = directory / "assembly.seed"
        isd_seed.write_bytes(ISD_SEED)
        assembly_seed.write_bytes(ASSEMBLY_SEED)

        client = Client(management, directory / "state", simulator=SIMULATOR)
        try:
            client.connect()
            bootstrap_isd(client, ISD_SEED)
            incarnation = client.command(0xE0, b"template")
            package = directory / "assembly.mcp"
            subprocess.run(
                [
                    "dotnet", str(PACK), str(args.image), str(args.manifest), "template",
                    incarnation.hex(), "1", str(assembly_seed), str(package), "--explicit-sign",
                ],
                cwd=ROOT,
                check=True,
            )
            upload(client, package.read_bytes())
            client.command(0xEC, management_names("template", args.aid.upper()))
            client.command(0xA4, aid)
            response = client.command(0x10, command)
            print((response + bytes.fromhex("9000")).hex().upper())
        finally:
            client.close()


if __name__ == "__main__":
    main()
