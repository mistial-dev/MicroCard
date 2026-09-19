#!/usr/bin/env python3
"""Signed default-cryptography dependency acceptance."""
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from domain_inventory import inventory
from scp03_acceptance import sign_package, signer_public_key, Client, bootstrap_isd, ensure_assembly, signer_identity

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
ISD_SEED = bytes([0x11]) * 32
SSD_SEED = bytes([0x45]) * 32
ISD_PUBLIC = signer_identity(ISD_SEED)
SSD_PUBLIC = signer_identity(SSD_SEED)


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
        "managed/MicroCard.Cryptography", "cryptography")
    consumer_image, consumer_metadata = ensure_assembly(
        "samples/CryptographyConsumer", "cryptography-consumer")
    provider = json.loads(provider_metadata.read_text())
    consumer = json.loads(consumer_metadata.read_text())
    assert provider["assembly"] == "MicroCard.Cryptography"
    assert provider["entry_points"] == []
    assert provider["capabilities"] == [
        20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38, 39, 49, 50, 51]
    dependency = consumer["dependencies"][0]
    assert dependency["assembly"] == "MicroCard.Cryptography"
    assert dependency["scope"] == 1 and bytes(dependency["signer"]) == ISD_PUBLIC
    assert consumer["capabilities"] == [2, 11, 12, 13, 20, 50]
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

        provider_package = directory / "cryptography.mcp"
        package(provider_image, provider_metadata, "ISD", isd_incarnation, isd_seed,
            provider_package)
        upload(client, provider_package.read_bytes())
        isd = {item["identifier"]: item for item in inventory(client)}["ISD"]
        assert isd["assemblies"] == 2
        assert bytes.fromhex(isd["signing_public_key"]) == ISD_PUBLIC

        ssd_incarnation = client.command(0xE0, b"crypto-test")
        bad = json.loads(json.dumps(consumer))
        bad["dependencies"][0]["signer"] = list(SSD_PUBLIC)
        bad_metadata = directory / "wrong-signer.json"
        bad_metadata.write_text(json.dumps(bad, separators=(",", ":")))
        bad_package = directory / "wrong-signer.mcp"
        package(consumer_image, bad_metadata, "crypto-test", ssd_incarnation, ssd_seed,
            bad_package)
        upload(client, bad_package.read_bytes(), 0x6985)
        unbound = {item["identifier"]: item for item in inventory(client)}["crypto-test"]
        assert unbound["assemblies"] == 0 and unbound["signing_public_key"] is None

        consumer_package = directory / "consumer.mcp"
        package(consumer_image, consumer_metadata, "crypto-test", ssd_incarnation, ssd_seed,
            consumer_package)
        upload(client, consumer_package.read_bytes())
        client.command(0xEC, b'["crypto-test","F04D4306C0"]')
        client.command(0xA4, bytes.fromhex("F04D4306C0"))

        message = b"MicroCard cryptography facade"
        assert client.command(0x10, b"\x00" + message) == hashlib.sha256(message).digest()
        alias_message = bytes(range(40))
        assert client.command(0x10, b"\x0e" + alias_message) == hashlib.sha256(alias_message).digest()
        projected_message = b"standard System.Security.Cryptography projection"
        assert client.command(0x10, b"\x0f" + projected_message) == hashlib.sha256(projected_message).digest()
        projected_random = client.command(0x10, b"\x10")
        assert len(projected_random) == 32 and projected_random != bytes(32)
        comparison = bytes(range(32))
        assert client.command(0x10, b"\x12" + comparison + comparison) == b"\x01"
        different = bytearray(comparison)
        different[-1] ^= 1
        assert client.command(0x10, b"\x12" + comparison + different) == b"\x00"
        signing_seed = bytes([0x72]) * 32
        public_key = signer_public_key(signing_seed)
        signature = sign_package(signing_seed, message)
        verify = b"\x01" + public_key + signature + message
        assert client.command(0x10, verify) == b"\x01"
        invalid = bytearray(verify)
        # Inside the public key, so the point no longer matches the signature.
        invalid[40] ^= 1
        assert client.command(0x10, bytes(invalid)) == b"\x00"
        assert client.command(0x10, b"\x06") == b"\x00"

        first_hmac = client.command(0x10, b"\x02" + message)
        second_hmac = client.command(0x10, b"\x02" + message)
        assert len(first_hmac) == 32 and first_hmac == second_hmac
        first_cmac = client.command(0x10, b"\x03" + message)
        second_cmac = client.command(0x10, b"\x03" + message)
        assert len(first_cmac) == 16 and first_cmac == second_cmac
        assert client.command(0x10, b"\x04" + message) == message
        assert client.command(0x10, b"\x05" + message) == message
        device_public = client.command(0x10, b"\x07")
        assert len(device_public) == 65 and device_public[0] == 4
        p256_signature = client.command(0x10, b"\x08" + message)
        assert len(p256_signature) == 64
        r = int.from_bytes(p256_signature[:32], "big")
        s = int.from_bytes(p256_signature[32:], "big")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_public).verify(
            utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        verify_p256 = b"\x09" + device_public + p256_signature + message
        assert client.command(0x10, verify_p256) == b"\x01"
        invalid_p256 = bytearray(verify_p256)
        invalid_p256[70] ^= 1
        assert client.command(0x10, bytes(invalid_p256)) == b"\x00"
        malformed_verify = b"\x09" + bytes(65 + 64)
        assert client.command(0x10, malformed_verify) == b"\x00"
        peer_private = ec.generate_private_key(ec.SECP256R1())
        peer_public = peer_private.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        peer_der_signature = peer_private.sign(message, ec.ECDSA(hashes.SHA256()))
        peer_r, peer_s = utils.decode_dss_signature(peer_der_signature)
        peer_signature = peer_r.to_bytes(32, "big") + peer_s.to_bytes(32, "big")
        assert client.command(
            0x10, b"\x09" + peer_public + peer_signature + message) == b"\x01"
        expected_shared = peer_private.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_public))
        assert client.command(0x10, b"\x0a" + peer_public) == expected_shared
        random_one = client.command(0x10, b"\x0b")
        random_two = client.command(0x10, b"\x0b")
        assert len(random_one) == 32 and len(random_two) == 32 and random_one != random_two
        client.command(0x10, b"\x01", status=0x6700)
        client.command(0xF0, b'["ISD","MicroCard.Cryptography"]', status=0x6985)
        client.command(0x10, b"\x0a" + bytes(65), status=0x6982)

        client.close()
        client = Client(management, state)
        client.connect()
        client.command(0xA4, bytes.fromhex("F04D4306C0"))
        assert client.command(0x10, b"\x00" + message) == hashlib.sha256(message).digest()
        assert client.command(0x10, b"\x07") == device_public
        assert len(client.command(0x10, b"\x0b")) == 32
        domains = {item["identifier"]: item for item in inventory(client)}
        assert domains["crypto-test"]["assemblies"] == 1
        assert domains["crypto-test"]["instances"] == 1
        assert bytes.fromhex(domains["crypto-test"]["signing_public_key"]) == SSD_PUBLIC
        client.command(0x10, b"\x13", status=0x6982)
        client.close()
    print("PASS: signed MicroCard.Cryptography facade, native primitives, signer pin and reboot")


if __name__ == "__main__":
    main()
