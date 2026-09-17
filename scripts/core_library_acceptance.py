#!/usr/bin/env python3
"""Signed execution acceptance for the compact core library and its reference-name rewrite."""
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from domain_inventory import inventory
from scp03_acceptance import Client, bootstrap_isd, ensure_assembly

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
ISD_SEED = bytes([0x11]) * 32
SSD_SEED = bytes([0x44]) * 32
ISD_PUBLIC = Ed25519PrivateKey.from_private_bytes(ISD_SEED).public_key().public_bytes(
    Encoding.Raw, PublicFormat.Raw)


def package(image, metadata, domain, incarnation, seed, output):
    subprocess.run(["dotnet", str(PACK), str(image), str(metadata), domain, incarnation.hex(),
                    "1", str(seed), str(output), "--explicit-sign"], check=True)


def upload(client, raw, status=0x9000):
    client.command(0xE6)
    for offset in range(0, len(raw), 200):
        client.command(0xE8, offset.to_bytes(4, "little") + raw[offset:offset + 200])
    client.command(0xEA, status=status)


def main():
    consumer_image, consumer_metadata = ensure_assembly("samples/CoreConsumer", "core-consumer")
    metadata = json.loads(consumer_metadata.read_text())
    dependency = metadata["dependencies"][0]
    assert dependency["assembly"] == "mscorlib"
    assert dependency["scope"] == 1 and dependency["package_version"] == 1
    assert bytes(dependency["signer"]) == ISD_PUBLIC

    with tempfile.TemporaryDirectory() as directory_name:
        directory = pathlib.Path(directory_name)
        isd_seed = directory / "isd.seed"
        ssd_seed = directory / "ssd.seed"
        isd_seed.write_bytes(ISD_SEED)
        ssd_seed.write_bytes(SSD_SEED)
        management = directory / "management.key"
        management.write_bytes(os.urandom(32))
        management.chmod(0o600)
        state = directory / "state"
        client = Client(management, state)
        client.connect()
        bootstrap_isd(client, ISD_SEED)
        incarnation = client.command(0xE0, b"core-test")

        consumer_package = directory / "core-consumer.mcp"
        package(consumer_image, consumer_metadata, "core-test", incarnation, ssd_seed,
                consumer_package)
        upload(client, consumer_package.read_bytes())
        client.command(0xEC, b'["core-test","F04D4309C0"]')
        client.command(0xA4, bytes.fromhex("F04D4309C0"))

        assert client.command(0x10, bytes([0])) == bytes([1, 1, 2, 3, 4])
        assert client.command(0x10, bytes.fromhex("01AABBCC")) == bytes.fromhex("AABBCC")
        assert client.command(0x10, bytes.fromhex("0289ABCDEF")) == bytes.fromhex("EFCDAB89")
        assert client.command(0x10, bytes.fromhex("0301020102")) == bytes([1])
        assert client.command(0x10, bytes.fromhex("040102")) == bytes([0])
        assert client.command(0x10, bytes.fromhex("0501")) == bytes([10])
        assert client.command(0x10, bytes.fromhex("0519")) == bytes([20])
        client.command(0xF0, b'["ISD","mscorlib"]', status=0x6985)

        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, bytes.fromhex("F04D4309C0"))
        assert client.command(0x10, bytes.fromhex("0201020304")) == bytes.fromhex("04030201")
        domains = {item["identifier"]: item for item in inventory(client)}
        assert domains["ISD"]["assemblies"] == 1
        assert domains["core-test"]["assemblies"] == 1
        assert domains["core-test"]["instances"] == 1
        client.close()
    print("PASS: signed mscorlib identity rewrite, verified dependency link, execution and reboot")


if __name__ == "__main__":
    main()
