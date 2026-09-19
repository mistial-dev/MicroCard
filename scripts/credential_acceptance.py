#!/usr/bin/env python3
"""Signed credential assembly acceptance using default ISD dependencies."""
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from domain_inventory import inventory
from scp03_acceptance import Client, bootstrap_isd, ensure_assembly, signer_identity

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
ISD_SEED = bytes([0x11]) * 32
SSD_SEED = bytes([0x45]) * 32
ISD_PUBLIC = signer_identity(ISD_SEED)
SSD_PUBLIC = signer_identity(SSD_SEED)
AID = bytes.fromhex("F04D4308C0")
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


def verify_p256(public_key, message, signature):
    assert len(signature) == 64
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key).verify(
        utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


def main():
    credential_image, credential_metadata = ensure_assembly("samples/Credential", "credential")
    providers = {
        "cryptography": ensure_assembly("managed/MicroCard.Cryptography", "cryptography"),
        "security": ensure_assembly("managed/MicroCard.Security", "security"),
    }
    metadata = json.loads(credential_metadata.read_text())
    assert metadata["assembly"] == "Credential"
    assert metadata["capabilities"] == [2, 11, 12, 13, 31, 52]
    assert [dependency["assembly"] for dependency in metadata["dependencies"]] == [
        "MicroCard.Cryptography", "MicroCard.Security"]
    for dependency in metadata["dependencies"]:
        assert dependency["scope"] == 1
        assert dependency["package_version"] == 1
        assert bytes(dependency["signer"]) == ISD_PUBLIC
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

        for name in ("cryptography", "security"):
            output = directory / f"{name}.mcp"
            package(*providers[name], "ISD",
                    isd_incarnation, isd_seed, output)
            upload(client, output.read_bytes())
        assert {item["identifier"]: item for item in inventory(client)}["ISD"]["assemblies"] == 3

        ssd_incarnation = client.command(0xE0, b"credential-test")
        bad = json.loads(json.dumps(metadata))
        bad["dependencies"][1]["signer"] = list(SSD_PUBLIC)
        bad_metadata = directory / "wrong-signer.json"
        bad_metadata.write_text(json.dumps(bad, separators=(",", ":")))
        bad_package = directory / "wrong-signer.mcp"
        package(credential_image, bad_metadata, "credential-test",
                ssd_incarnation, ssd_seed, bad_package)
        upload(client, bad_package.read_bytes(), 0x6985)
        unbound = {item["identifier"]: item for item in inventory(client)}["credential-test"]
        assert unbound["assemblies"] == 0 and unbound["signing_public_key"] is None

        credential_package = directory / "credential.mcp"
        package(credential_image, credential_metadata,
                "credential-test", ssd_incarnation, ssd_seed, credential_package)
        upload(client, credential_package.read_bytes())
        client.command(0xEC, b'["credential-test","F04D4308C0"]')
        client.command(0xA4, AID)

        assert client.command(0x10, b"\x01") == b""
        public_data = b"credential-public-data"
        client.command(0x10, b"\x00" + b"1234" + b"12345678" + public_data)
        assert client.command(0x10, b"\x01") == public_data
        public_key = client.command(0x10, b"\x02")
        assert len(public_key) == 65 and public_key[0] == 4

        message = b"signed credential challenge"
        client.command(0x10, b"\x03" + b"9999" + message, status=0x6982)
        assert client.command(0x10, b"\x04") == b"\x02"
        signature = client.command(0x10, b"\x03" + b"1234" + message)
        verify_p256(public_key, message, signature)
        client.command(0x10, b"\x03" + b"1234", status=0x6700)
        client.command(0xF0, b'["ISD","MicroCard.Cryptography"]', status=0x6985)
        client.command(0xF0, b'["ISD","MicroCard.Security"]', status=0x6985)

        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, AID)
        assert client.command(0x10, b"\x01") == public_data
        assert client.command(0x10, b"\x02") == public_key
        assert client.command(0x10, b"\x04") == b"\x03"
        verify_p256(public_key, message,
                    client.command(0x10, b"\x03" + b"1234" + message))

        client.command(0x10, b"\x03" + b"0000" + message, status=0x6982)
        client.command(0x10, b"\x03" + b"0000" + message, status=0x6982)
        client.command(0x10, b"\x03" + b"0000" + message, status=0x6982)
        assert client.command(0x10, b"\x04") == b"\x00"
        client.command(0x10, b"\x03" + b"1234" + message, status=0x6982)
        assert client.command(0x10, b"\x05" + b"12345678" + b"2468") == b"\x01"
        verify_p256(public_key, message,
                    client.command(0x10, b"\x03" + b"2468" + message))

        client.command(0xE4, b"credential-test")
        recreated = client.command(0xE0, b"credential-test")
        assert recreated != ssd_incarnation
        upload(client, credential_package.read_bytes(), 0x6985)
        recreated_package = directory / "credential-recreated.mcp"
        package(credential_image, credential_metadata,
                "credential-test", recreated, ssd_seed, recreated_package)
        upload(client, recreated_package.read_bytes())
        client.command(0xEC, b'["credential-test","F04D4308C0"]')
        client.command(0xA4, AID)
        assert client.command(0x10, b"\x01") == b""
        assert client.command(0x10, b"\x02") != public_key
        domains = {item["identifier"]: item for item in inventory(client)}
        assert bytes.fromhex(domains["credential-test"]["signing_public_key"]) == SSD_PUBLIC
        client.close()
    print("PASS: signed credential data, opaque P-256 key, PIN retries and revocation")


if __name__ == "__main__":
    main()
