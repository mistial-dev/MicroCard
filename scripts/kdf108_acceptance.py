#!/usr/bin/env python3
"""Host acceptance for the signed Kdf108 ISD/SSD assembly pair."""
import json, os, pathlib, subprocess, tempfile
from domain_inventory import inventory
from scp03_acceptance import (Client, bootstrap_isd, ensure_assembly, sign_package,
                              signer_identity, signer_public_key)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "managed/MicroCard.Pack/bin/Release/net10.0/MicroCard.Pack.dll"
# The identity a domain binds to, which is the digest of the signer's uncompressed key.
KDF_PUBLIC = bytes.fromhex("2bad0fd610d99eae443e932a26142bca1e5fa995b4518452827e78ef1f317ff0")
SSD_PUBLIC = bytes.fromhex("6fc66a90486171ca69b512be185d66a763a68ff2d34cda639e78cff9e98caeab")
CONTEXT = b"MicroCard signed package v4\0"
HEADER = 12 + len(CONTEXT)

def verify_package(path, expected_identity):
    """Parse and verify a package independently of the tool that produced it."""
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives import hashes
    raw = path.read_bytes()
    assert raw[:4] == b"MP04" and raw[4:4 + len(CONTEXT)] == CONTEXT
    manifest_length = int.from_bytes(raw[4 + len(CONTEXT):8 + len(CONTEXT)], "little")
    image_length = int.from_bytes(raw[8 + len(CONTEXT):HEADER], "little")
    signed_end = HEADER + manifest_length + image_length + 65
    assert signed_end + 64 == len(raw)
    key = raw[signed_end - 65:signed_end]
    assert key[0] == 0x04, "a package carries an uncompressed point"
    assert hashlib.sha256(key).digest() == expected_identity
    signature = raw[signed_end:]
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert 0 < s <= order // 2, "a package carries the low signature"
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key).verify(
        encode_dss_signature(r, s), raw[:signed_end], ec.ECDSA(hashes.SHA256()))
    manifest = json.loads(raw[HEADER:HEADER + manifest_length])
    image = raw[HEADER + manifest_length:HEADER + manifest_length + image_length]
    return raw, manifest, image

def signed_type_confusion_package(incarnation, seed):
    valid = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 32)
    tables = bytearray([2, 0, 0, 0]) + valid.to_bytes(8, "little")
    tables += (1).to_bytes(2, "little") * 4
    tables += bytes([1])
    tables += bytes([0, 0, 0, 0, 3, 0, 0, 0, 1, 1])
    tables += bytes([0, 0, 0, 0, 0, 0, 0, 0, 5, 1])
    tables += bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9])
    body = bytes([0x14, 0x16, 0x58, 0x26, 0x2A]) # ldnull + int is height-valid, type-invalid.
    code = bytes([0, 0]) + (2).to_bytes(2, "little") + len(body).to_bytes(4, "little") + bytes(4) + body
    sections = [tables, b"\0M\0T\0Run\0A\0", bytes([0, 3, 0, 0, 1]), code]
    header_size = 56
    image = bytearray(b"MC04" + bytes([4, 0, 0, 0, 4, 2]))
    image += header_size.to_bytes(2, "little")
    image += (header_size + sum(map(len, sections))).to_bytes(4, "little")
    offset = header_size
    for index, section in enumerate(sections, 1):
        image += bytes([index, 0]) + offset.to_bytes(4, "little") + len(section).to_bytes(4, "little")
        offset += len(section)
    image += b"".join(sections)
    manifest = dict(domain="ISD", incarnation=list(incarnation), assembly="TypeConfusion",
        assembly_version=[0, 1, 0, 0], version=1, export=dict(access=1, key=None),
        entry_points=[], dependencies=[], capabilities=[],
        limits=dict(arena=16384, stack=256, frames=32, instructions=100000))
    meta = json.dumps(manifest, separators=(",", ":")).encode()
    raw = b"MP04" + CONTEXT + len(meta).to_bytes(4, "little") + len(image).to_bytes(4, "little") + meta + image
    raw += signer_public_key(seed)
    return raw + sign_package(seed, raw)

def main():
    subprocess.run(["dotnet", "build", str(ROOT / "tests/Kdf108Reference"), "-c", "Release",
                    "--nologo", "--verbosity", "quiet"], check=True)
    subprocess.run(["dotnet", str(ROOT / "tests/Kdf108Reference/bin/Release/net10.0/Kdf108Reference.dll")], check=True)
    kdf_image, kdf_metadata_path = ensure_assembly("samples/Kdf108", "kdf108")
    consumer_image, consumer_metadata_path = ensure_assembly(
        "samples/Kdf108Consumer", "kdf108-consumer")
    assert kdf_image.read_bytes()[:4] == b"MC04" and consumer_image.read_bytes()[:4] == b"MC04"
    kdf_metadata = json.loads(kdf_metadata_path.read_text())
    assert kdf_metadata["assembly"] == "Kdf108" and kdf_metadata["export"] == {"access": 1, "key": None}
    assert kdf_metadata["capabilities"] == [26]

    consumer_metadata = json.loads(consumer_metadata_path.read_text())
    assert consumer_metadata["assembly"] == "Kdf108Consumer"
    assert consumer_metadata["capabilities"] == [2, 11, 12, 13, 22, 23, 24]
    assert consumer_metadata["entry_points"][0]["uninstall"] == 1
    assert consumer_metadata["dependencies"][0]["signer"] == list(KDF_PUBLIC)
    with tempfile.TemporaryDirectory() as directory:
        directory = pathlib.Path(directory)
        kdf_seed, ssd_seed = directory / "kdf.seed", directory / "ssd.seed"
        kdf_seed.write_bytes(bytes([0x11]) * 32); ssd_seed.write_bytes(bytes([0x22]) * 32)
        assert signer_identity(kdf_seed.read_bytes()) == KDF_PUBLIC
        assert signer_identity(ssd_seed.read_bytes()) == SSD_PUBLIC
        consumer_json = directory / "entry.json"; consumer_json.write_text(json.dumps(consumer_metadata, separators=(",", ":")))
        kdf_package, consumer_package = directory / "kdf.mcp", directory / "entry.mcp"
        incarnation = "00112233445566778899aabbccddeeff"
        subprocess.run(["dotnet", str(PACK), str(kdf_image), str(kdf_metadata_path),
            "ISD", incarnation, "1", str(kdf_seed), str(kdf_package), "--explicit-sign"], check=True)
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(consumer_json),
            "kdf-test", incarnation, "1", str(ssd_seed), str(consumer_package), "--explicit-sign"], check=True)
        kdf_raw, kdf_manifest, signed_kdf_image = verify_package(kdf_package, KDF_PUBLIC)
        consumer_raw, consumer_manifest, signed_consumer_image = verify_package(consumer_package, SSD_PUBLIC)
        assert signed_kdf_image == kdf_image.read_bytes() and signed_consumer_image == consumer_image.read_bytes()
        assert kdf_manifest["domain"] == "ISD" and consumer_manifest["domain"] == "kdf-test"
        dependency = consumer_manifest["dependencies"][0]
        assert bytes(dependency["signer"]) == KDF_PUBLIC and dependency["scope"] == 1
        import hashlib as _hashlib
        assert KDF_PUBLIC != SSD_PUBLIC
        assert _hashlib.sha256(consumer_raw[-129:-64]).digest() == SSD_PUBLIC
        from cryptography.exceptions import InvalidSignature
        tampered = bytearray(consumer_raw); tampered[-130] ^= 1
        tampered_path = directory / "tampered.mcp"; tampered_path.write_bytes(bytes(tampered))
        try:
            verify_package(tampered_path, SSD_PUBLIC)
        except InvalidSignature:
            pass
        else:
            raise AssertionError("tampered package signature accepted")
        management = directory / "management.key"
        management.write_bytes(os.urandom(32)); management.chmod(0o600)
        state = directory / "state"
        client = Client(management, state); client.connect()
        isd_incarnation = bootstrap_isd(client, kdf_seed.read_bytes())
        active_package = directory / "active-kdf.mcp"
        subprocess.run(["dotnet", str(PACK), str(kdf_image), str(kdf_metadata_path),
            "ISD", isd_incarnation.hex(), "1", str(kdf_seed), str(active_package), "--explicit-sign"], check=True)
        def upload(raw, status=0x9000):
            client.command(0xe6)
            for offset in range(0, len(raw), 200):
                client.command(0xe8, offset.to_bytes(4, "little") + raw[offset:offset + 200])
            client.command(0xea, status=status)
        active = active_package.read_bytes(); upload(active)
        isd = inventory(client)[0]
        assert isd["identifier"] == "ISD" and isd["assemblies"] == 2
        assert bytes.fromhex(isd["signing_public_key"]) == KDF_PUBLIC

        ssd_incarnation = client.command(0xe0, b"kdf-test")
        missing_capability_metadata = dict(consumer_metadata)
        missing_capability_metadata["capabilities"] = [2, 11, 12, 13, 23, 24]
        missing_capability_json = directory / "missing-capability.json"
        missing_capability_json.write_text(json.dumps(missing_capability_metadata, separators=(",", ":")))
        missing_capability_package = directory / "missing-capability.mcp"
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(missing_capability_json),
            "kdf-test", ssd_incarnation.hex(), "1", str(ssd_seed), str(missing_capability_package),
            "--explicit-sign"], check=True)
        before_consumer = {path.name: path.read_bytes() for path in state.glob("slot*.bin")}
        upload(missing_capability_package.read_bytes(), 0x6985)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == before_consumer
        undeclared_metadata = dict(consumer_metadata)
        undeclared_metadata["dependencies"] = []
        undeclared_json = directory / "undeclared.json"
        undeclared_json.write_text(json.dumps(undeclared_metadata, separators=(",", ":")))
        undeclared_package = directory / "undeclared.mcp"
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(undeclared_json),
            "kdf-test", ssd_incarnation.hex(), "1", str(ssd_seed), str(undeclared_package),
            "--explicit-sign"], check=True)
        upload(undeclared_package.read_bytes(), 0x6985)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == before_consumer
        for name, mutate in [
            ("wrong-dependency-signer", lambda metadata: metadata["dependencies"][0].update(signer=list(SSD_PUBLIC))),
            ("wrong-dependency-version", lambda metadata: metadata["dependencies"][0].update(
                ranges=[{"min": [0, 2, 0, 0], "min_inclusive": True,
                         "max": [0, 2, 0, 0], "max_inclusive": True}])),
            ("wrong-dependency-scope", lambda metadata: metadata["dependencies"][0].update(scope=0)),
        ]:
            rejected_metadata = json.loads(json.dumps(consumer_metadata))
            mutate(rejected_metadata)
            rejected_json = directory / f"{name}.json"
            rejected_json.write_text(json.dumps(rejected_metadata, separators=(",", ":")))
            rejected_package = directory / f"{name}.mcp"
            subprocess.run(["dotnet", str(PACK), str(consumer_image), str(rejected_json),
                "kdf-test", ssd_incarnation.hex(), "1", str(ssd_seed), str(rejected_package),
                "--explicit-sign"], check=True)
            upload(rejected_package.read_bytes(), 0x6985)
            assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == before_consumer
        unbound = {domain["identifier"]: domain for domain in inventory(client)}["kdf-test"]
        assert unbound["assemblies"] == 0 and unbound["signing_public_key"] is None

        active_consumer_package = directory / "active-entry.mcp"
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(consumer_json),
            "kdf-test", ssd_incarnation.hex(), "1", str(ssd_seed), str(active_consumer_package),
            "--explicit-sign"], check=True)
        upload(active_consumer_package.read_bytes())
        domains = {domain["identifier"]: domain for domain in inventory(client)}
        ssd = domains["kdf-test"]
        assert ssd["assemblies"] == 1 and ssd["instances"] == 0
        assert bytes.fromhex(ssd["signing_public_key"]) == SSD_PUBLIC

        # Install executes verified MC04 through sealed framework import IDs and
        # creates an SSD-owned AES key without exposing its bytes to managed code.
        client.command(0xec, b'["kdf-test","F04D430108"]')
        installed = {path.name: path.read_bytes() for path in state.glob("slot*.bin")}
        assert {domain["identifier"]: domain for domain in inventory(client)}["kdf-test"]["instances"] == 1
        client.command(0xa4, bytes.fromhex("F04D430108"))
        derived = client.command(0x10, b"\x01\x03abc")
        assert len(derived) == 16
        assert client.command(0x10, b"\x01\x03abc") == derived
        assert len(client.command(0x10, b"\x02\x00")) == 16
        # SCP03 padding and the command MAC bound the context a short APDU can carry, and
        # a 16-byte MAC in S16 mode takes eight bytes more than an 8-byte one.
        context = (255 - client.width) // 16 * 16 - 3
        assert len(client.command(0x10, bytes([3, context]) + bytes(range(context)))) == 16
        client.command(0x10, b"\x04\xf0", status=0x6700)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == installed

        # The exact ISD provider binding prevents removal while the SSD
        # consumer remains active, even though each assembly has its own signer.
        client.command(0xf0, b'["ISD","Kdf108"]', status=0x6985)

        bad_consumer_metadata = dict(consumer_metadata)
        bad_consumer_metadata["entry_points"] = [dict(consumer_metadata["entry_points"][0], process=65535)]
        bad_consumer_json = directory / "bad-entry.json"
        bad_consumer_json.write_text(json.dumps(bad_consumer_metadata, separators=(",", ":")))
        bad_consumer_package = directory / "bad-entry.mcp"
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(bad_consumer_json),
            "kdf-test", ssd_incarnation.hex(), "2", str(ssd_seed), str(bad_consumer_package),
            "--explicit-sign"], check=True)
        upload(bad_consumer_package.read_bytes(), 0x6985)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == installed

        persisted = {path.name: path.read_bytes() for path in state.glob("slot*.bin")}
        tampered = bytearray(active); tampered[20] ^= 1; upload(tampered, 0x6985)
        for name, field, value in [
            ("identity-name-mismatch", "assembly", "KdfAlias"),
            ("identity-version-mismatch", "assembly_version", [0, 2, 0, 0]),
        ]:
            identity_metadata = dict(kdf_metadata)
            identity_metadata[field] = value
            identity_json = directory / f"{name}.json"
            identity_json.write_text(json.dumps(identity_metadata, separators=(",", ":")))
            identity_package = directory / f"{name}.mcp"
            subprocess.run(["dotnet", str(PACK), str(kdf_image), str(identity_json),
                "ISD", isd_incarnation.hex(), "2", str(kdf_seed), str(identity_package),
                "--explicit-sign"], check=True)
            upload(identity_package.read_bytes(), 0x6985)
        type_confusion = signed_type_confusion_package(
            isd_incarnation, kdf_seed.read_bytes())
        upload(type_confusion, 0x6985)
        wrong_signer = directory / "wrong-signer.mcp"
        subprocess.run(["dotnet", str(PACK), str(kdf_image), str(kdf_metadata_path),
            "ISD", isd_incarnation.hex(), "2", str(ssd_seed), str(wrong_signer), "--explicit-sign"], check=True)
        upload(wrong_signer.read_bytes(), 0x6985)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == persisted
        assert inventory(client)[0]["assemblies"] == 2
        client.close()
        client = Client(management, state); client.connect()
        domains = {domain["identifier"]: domain for domain in inventory(client)}
        isd = domains["ISD"]
        assert isd["assemblies"] == 2 and bytes.fromhex(isd["signing_public_key"]) == KDF_PUBLIC
        ssd = domains["kdf-test"]
        assert ssd["assemblies"] == 1 and ssd["instances"] == 1
        assert bytes.fromhex(ssd["signing_public_key"]) == SSD_PUBLIC

        # Deletion revokes the selected instance and its opaque key. The old
        # package cannot cross the new incarnation boundary; a freshly targeted
        # package installs and executes with a newly generated SSD key.
        client.command(0xe4, b"kdf-test")
        client.command(0x10, b"\x01\x00", status=0x6982)
        client.connect()
        recreated_incarnation = client.command(0xe0, b"kdf-test")
        assert recreated_incarnation != ssd_incarnation
        before_replay = {path.name: path.read_bytes() for path in state.glob("slot*.bin")}
        upload(active_consumer_package.read_bytes(), 0x6985)
        assert {path.name: path.read_bytes() for path in state.glob("slot*.bin")} == before_replay
        recreated_package = directory / "recreated-entry.mcp"
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(consumer_json),
            "kdf-test", recreated_incarnation.hex(), "1", str(ssd_seed), str(recreated_package),
            "--explicit-sign"], check=True)
        upload(recreated_package.read_bytes())
        client.command(0xec, b'["kdf-test","F04D430108"]')
        client.command(0xa4, bytes.fromhex("F04D430108"))
        assert len(client.command(0x10, b"\x05\x03xyz")) == 16

        # The same verified call path also supports a private dependency loaded
        # earlier in the consumer's SSD. Both packages use that SSD's pinned key.
        local_incarnation = client.command(0xe0, b"local-kdf")
        local_dependency_metadata = json.loads(json.dumps(consumer_metadata))
        local_dependency_metadata["dependencies"][0]["scope"] = 0
        local_dependency_metadata["dependencies"][0]["signer"] = list(SSD_PUBLIC)
        local_dependency_metadata["entry_points"][0]["aid"] = "F04D430109"
        local_dependency_json = directory / "local-entry.json"
        local_dependency_json.write_text(json.dumps(local_dependency_metadata, separators=(",", ":")))
        local_provider = directory / "local-kdf.mcp"
        local_consumer = directory / "local-entry.mcp"
        subprocess.run(["dotnet", str(PACK), str(kdf_image), str(kdf_metadata_path),
            "local-kdf", local_incarnation.hex(), "1", str(ssd_seed), str(local_provider),
            "--explicit-sign"], check=True)
        subprocess.run(["dotnet", str(PACK), str(consumer_image), str(local_dependency_json),
            "local-kdf", local_incarnation.hex(), "1", str(ssd_seed), str(local_consumer),
            "--explicit-sign"], check=True)
        upload(local_provider.read_bytes())
        upload(local_consumer.read_bytes())
        client.command(0xec, b'["local-kdf","F04D430109"]')
        client.command(0xa4, bytes.fromhex("F04D430109"))
        assert len(client.command(0x10, b"\x06\x05local")) == 16
        local = {domain["identifier"]: domain for domain in inventory(client)}["local-kdf"]
        assert local["assemblies"] == 2 and local["instances"] == 1
        assert bytes.fromhex(local["signing_public_key"]) == SSD_PUBLIC
        client.close()
    print("PASS: signed MC04 Kdf108 linking in ISD and same SSD, protected APDU boundaries, negative pins, reboot, revocation and SSD recreation")

if __name__ == "__main__": main()
