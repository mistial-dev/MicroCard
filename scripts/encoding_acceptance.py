#!/usr/bin/env python3
"""Signed ISD dependency acceptance for MicroCard.Encoding."""
from device_cbor import management_names
import json, os, pathlib, subprocess, tempfile
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from domain_inventory import inventory
from scp03_acceptance import Client, bootstrap_isd, ensure_assembly, signer_identity

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
ISD_SEED = bytes([0x11]) * 32
SSD_SEED = bytes([0x44]) * 32
ISD_PUBLIC = signer_identity(ISD_SEED)
SSD_PUBLIC = signer_identity(SSD_SEED)

def package(image, metadata, domain, incarnation, seed, output):
    subprocess.run(["dotnet", str(PACK), str(image), str(metadata), domain, incarnation.hex(),
        "1", str(seed), str(output), "--explicit-sign"], check=True)

def upload(client, raw, status=0x9000):
    client.command(0xE6)
    for offset in range(0, len(raw), 200):
        client.command(0xE8, offset.to_bytes(4, "little") + raw[offset:offset + 200])
    client.command(0xEA, status=status)

def main():
    provider_image, provider_metadata = ensure_assembly(
        "managed/MicroCard.Encoding", "encoding")
    consumer_image, consumer_metadata = ensure_assembly(
        "samples/EncodingConsumer", "encoding-consumer")
    provider = json.loads(provider_metadata.read_text())
    consumer = json.loads(consumer_metadata.read_text())
    assert provider["assembly"] == "MicroCard.Encoding"
    assert provider["capabilities"] == [53, 54] and provider["entry_points"] == []
    dependency = consumer["dependencies"][0]
    assert dependency["assembly"] == "MicroCard.Encoding"
    assert dependency["scope"] == 1 and bytes(dependency["signer"]) == ISD_PUBLIC
    assert consumer["capabilities"] == [2, 11, 12, 13] and ISD_PUBLIC != SSD_PUBLIC

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

        provider_package = directory / "encoding.mcp"
        package(provider_image, provider_metadata, "ISD", isd_incarnation, isd_seed, provider_package)
        upload(client, provider_package.read_bytes())
        isd = {item["identifier"]: item for item in inventory(client)}["ISD"]
        assert isd["assemblies"] == 2
        assert bytes.fromhex(isd["signing_public_key"]) == ISD_PUBLIC

        ssd_incarnation = client.command(0xE0, b"encoding-test")
        bad = json.loads(json.dumps(consumer))
        bad["dependencies"][0]["signer"] = list(SSD_PUBLIC)
        bad_metadata = directory / "bad.json"
        bad_metadata.write_text(json.dumps(bad, separators=(",", ":")))
        bad_package = directory / "bad.mcp"
        package(consumer_image, bad_metadata, "encoding-test", ssd_incarnation, ssd_seed, bad_package)
        upload(client, bad_package.read_bytes(), 0x6985)
        unbound = {item["identifier"]: item for item in inventory(client)}["encoding-test"]
        assert unbound["assemblies"] == 0 and unbound["signing_public_key"] is None

        consumer_package = directory / "consumer.mcp"
        package(consumer_image, consumer_metadata, "encoding-test", ssd_incarnation, ssd_seed,
            consumer_package)
        upload(client, consumer_package.read_bytes())
        client.command(0xEC, management_names("encoding-test", "F04D430690"))
        client.command(0xA4, bytes.fromhex("F04D430690"))

        assert client.command(0x10, bytes.fromhex("0002020080")) == bytes.fromhex("000002020002")
        client.command(0x10, bytes.fromhex("000202007F"), status=0x6A80)
        high_tag = client.command(0x10, bytes.fromhex("009F1F0100"))
        assert high_tag == bytes.fromhex("009F1F030001"), high_tag.hex()
        assert client.command(0x10, bytes.fromhex("0100000080")) == bytes.fromhex("02020080")
        assert client.command(0x10, bytes.fromhex("01FFFFFF7F")) == bytes.fromhex("0202FF7F")
        assert client.command(0x10, bytes.fromhex("03010203")) == bytes.fromhex("0403010203")
        assert client.command(0x10, bytes([4])) == bytes.fromhex("040401020304")
        assert client.command(0x10, bytes.fromhex("020201010500")) == bytes.fromhex("30050201010500")
        client.command(0x10, bytes.fromhex("023000"), status=0x6A80)
        assert client.command(0x10, bytes.fromhex("0530053003020101")) == bytes([1])
        client.command(0x10, bytes.fromhex("053003020201"), status=0x6A80)
        assert client.command(0x10, bytes.fromhex("060102")) == bytes.fromhex("9F1F020102")
        assert client.command(0x10, bytes.fromhex("07020101020102")) == bytes.fromhex(
            "3106020101020102")
        client.command(0x10, bytes.fromhex("07020102020101"), status=0x6A80)
        client.command(0x10, bytes([8]), status=0x6A86)
        client.command(0xF0, management_names("ISD", "MicroCard.Encoding"), status=0x6985)

        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, bytes.fromhex("F04D430690"))
        assert client.command(0x10, bytes.fromhex("0006032A8648")) == bytes.fromhex(
            "000006020003")
        domains = {item["identifier"]: item for item in inventory(client)}
        assert domains["encoding-test"]["assemblies"] == 1
        assert domains["encoding-test"]["instances"] == 1
        assert bytes.fromhex(domains["encoding-test"]["signing_public_key"]) == SSD_PUBLIC
        client.close()
    print("PASS: signed MicroCard.Encoding ISD dependency, exact signer pin, SSD execution and reboot")

if __name__ == "__main__": main()
