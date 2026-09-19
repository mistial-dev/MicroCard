#!/usr/bin/env python3
"""Signed default-security dependency and durable retry acceptance."""
from device_cbor import management_names
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from domain_inventory import inventory
from scp03_acceptance import Client, bootstrap_isd, ensure_assembly, signer_identity

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
ISD_SEED = bytes([0x11]) * 32
SSD_SEED = bytes([0x45]) * 32
ISD_PUBLIC = signer_identity(ISD_SEED)
SSD_PUBLIC = signer_identity(SSD_SEED)
AID = bytes.fromhex("F04D4307C0")


def package(image, metadata, domain, incarnation, seed, output):
    subprocess.run([
        "dotnet", str(PACK), str(image), str(metadata), domain, incarnation.hex(), "1",
        str(seed), str(output), "--explicit-sign"
    ], check=True)


def upload(client, raw, status=0x9000):
    client.command(0xE6)
    for offset in range(0, len(raw), 200):
        client.command(0xE8, offset.to_bytes(4, "little") + raw[offset:offset + 200])
    client.command(0xEA, status=status)


def main():
    provider_image, provider_metadata = ensure_assembly(
        "managed/MicroCard.Security", "security")
    consumer_image, consumer_metadata = ensure_assembly(
        "samples/SecurityConsumer", "security-consumer")
    provider = json.loads(provider_metadata.read_text())
    consumer = json.loads(consumer_metadata.read_text())
    assert provider["assembly"] == "MicroCard.Security"
    assert provider["entry_points"] == []
    assert provider["capabilities"] == [40, 41, 42, 43, 44, 45]
    dependency = consumer["dependencies"][0]
    assert dependency["assembly"] == "MicroCard.Security"
    assert dependency["scope"] == 1 and bytes(dependency["signer"]) == ISD_PUBLIC
    assert consumer["capabilities"] == [2, 11, 12, 13, 23]
    assert ISD_PUBLIC != SSD_PUBLIC

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
        isd_incarnation = bootstrap_isd(client, ISD_SEED)

        provider_package = directory / "security.mcp"
        package(provider_image, provider_metadata, "ISD", isd_incarnation, isd_seed,
                provider_package)
        upload(client, provider_package.read_bytes())
        ssd_incarnation = client.command(0xE0, b"security-test")

        bad = json.loads(json.dumps(consumer))
        bad["dependencies"][0]["signer"] = list(SSD_PUBLIC)
        bad_metadata = directory / "wrong-signer.json"
        bad_metadata.write_text(json.dumps(bad, separators=(",", ":")))
        bad_package = directory / "wrong-signer.mcp"
        package(consumer_image, bad_metadata, "security-test", ssd_incarnation,
                ssd_seed, bad_package)
        upload(client, bad_package.read_bytes(), 0x6985)
        unbound = {item["identifier"]: item for item in inventory(client)}["security-test"]
        assert unbound["assemblies"] == 0 and unbound["signing_public_key"] is None

        consumer_package = directory / "consumer.mcp"
        package(consumer_image, consumer_metadata, "security-test", ssd_incarnation,
                ssd_seed, consumer_package)
        upload(client, consumer_package.read_bytes())
        client.command(0xEC, management_names("security-test", "F04D4307C0"))
        client.command(0xA4, AID)

        client.command(0x10, b"\x00" + b"1234" + b"12345678")
        assert client.command(0x10, b"\x07") == b"\x00"
        assert client.command(0x10, b"\x01" + b"9999") == b"\x00"
        assert client.command(0x10, b"\x02") == b"\x02"

        # The missing key faults after the failed comparison. The retry must still commit.
        client.command(0x10, b"\x03" + b"9999", status=0x6982)
        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, AID)
        assert client.command(0x10, b"\x02") == b"\x01"
        assert client.command(0x10, b"\x01" + b"9999") == b"\x00"
        assert client.command(0x10, b"\x01" + b"1234") == b"\x00"
        client.command(0x10, b"\x08" + b"00000000" + b"5678", status=0x6982)
        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, AID)
        assert client.command(0x10, b"\x05") == b"\x01"
        assert client.command(0x10, b"\x04" + b"12345678" + b"5678") == b"\x01"
        assert client.command(0x10, b"\x01" + b"5678") == b"\x01"
        assert client.command(0x10, b"\x07") == b"\x00"
        assert client.command(0x10, b"\x06" + b"5678" + b"2468") == b"\x01"
        assert client.command(0x10, b"\x01" + b"2468") == b"\x01"
        client.command(0xF0, management_names("ISD", "MicroCard.Security"), status=0x6985)

        # The same managed assembly in another SSD cannot see the first SSD's verifier.
        client.command(0xEE, management_names("security-test", "F04D4307C0"))
        other_incarnation = client.command(0xE0, b"security-other")
        other_package = directory / "other-consumer.mcp"
        package(consumer_image, consumer_metadata, "security-other", other_incarnation,
                ssd_seed, other_package)
        upload(client, other_package.read_bytes())
        client.command(0xEC, management_names("security-other", "F04D4307C0"))
        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, AID)
        client.command(0x10, b"\x01" + b"2468", status=0x6982)
        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xE4, b"security-other")
        client.command(0xEC, management_names("security-test", "F04D4307C0"))
        client.command(0xA4, AID)

        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, AID)
        assert client.command(0x10, b"\x07") == b"\x00"
        assert client.command(0x10, b"\x01" + b"2468") == b"\x01"
        domains = {item["identifier"]: item for item in inventory(client)}
        assert domains["security-test"]["assemblies"] == 1
        assert bytes.fromhex(domains["security-test"]["signing_public_key"]) == SSD_PUBLIC
        client.close()
    print("PASS: signed MicroCard.Security facade, durable retries and reboot")


if __name__ == "__main__":
    main()
