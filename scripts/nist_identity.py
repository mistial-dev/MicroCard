#!/usr/bin/env python3
"""Create a derived P-256 test identity, never a production credential or GSA golden image."""
import argparse
import datetime
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from nist_acceptance import REVISION


def create(upstream, output):
    import subprocess
    revision = subprocess.check_output(["git", "-C", upstream, "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError(f"upstream must be at {REVISION}")
    source = upstream / "test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV"
    config_path = upstream / "tools/piv_test_runner/config/OpenFIPS201-ECC256.xml"
    config = ET.parse(config_path)
    entries = {entry.attrib["name"]: entry for entry in config.iter("entry")}
    output.mkdir(parents=True, exist_ok=False)
    objects = output / "identity"
    objects.mkdir()
    inputs = {str(config_path.relative_to(upstream)): hashlib.sha256(config_path.read_bytes()).hexdigest()}

    def read(path):
        raw = path.read_bytes()
        inputs[str(path.relative_to(upstream))] = hashlib.sha256(raw).hexdigest()
        return raw

    for name in ("1 - Discovery Object", "2 - Security Object", "7 - CCC", "8 - CHUID Object",
                 "9 - Fingerprints", "10 - Face Object", "11 - Printed Information"):
        (objects / name).write_bytes(read(source / name))
    for name in ("LICENSE.txt", "PROVENANCE.md"):
        shutil.copyfile(upstream / "test-vectors/gsa-icam-card-builder" / name, output / name)

    # A public, fixed test-only issuer. Do not use this key outside test fixtures.
    issuer_key = ec.derive_private_key(0x4D6963726F43617264, ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MicroCard TEST ONLY PIV issuer")])
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
          .public_key(issuer_key.public_key()).serial_number(1).not_valid_before(start).not_valid_after(end)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), critical=False)
          .sign(issuer_key, hashes.SHA256()))
    (output / "issuer.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    replaced = {ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ExtensionOID.CRL_DISTRIBUTION_POINTS,
                ExtensionOID.KEY_USAGE, ExtensionOID.BASIC_CONSTRAINTS}
    roles = ("Auth", "Dig_Sig", "Key_Mgmt", "Card_Auth")
    for index, (slot, role) in enumerate(zip(("9A", "9C", "9D", "9E"), roles), 3):
        certificates = sorted(source.glob(f"{index} - *.crt"))
        preferred = [p for p in certificates if "ICAM_Test_Card" in p.name]
        original = x509.load_pem_x509_certificate(read((preferred or certificates)[0]))
        key_name = "11_private.pem" if slot == "9A" else "11.pem"
        key = serialization.load_pem_private_key(read(upstream / f"tools/piv_test_runner/test_keys/{slot}/{key_name}"), None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"Expected a P-256 fixture key in {slot}")
        builder = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(int(slot, 16))
                   .not_valid_before(start).not_valid_after(end))
        # Retain the identity bindings and PIV policies, replacing issuer/key-specific fields.
        for extension in original.extensions:
            if extension.oid not in replaced:
                builder = builder.add_extension(extension.value, extension.critical)
        agreement = slot == "9D"
        builder = (builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.KeyUsage(not agreement, slot == "9C", False, False,
                       agreement, False, False, False if agreement else None, False if agreement else None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
                   .add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
                       AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("https://microcard.invalid/test-issuer.crt"))]), False)
                   .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                       [x509.UniformResourceIdentifier("https://microcard.invalid/test-issuer.crl")], None, None, None)]), False))
        certificate = builder.sign(issuer_key, hashes.SHA256())
        stem = objects / f"{index} - ICAM_PIV_{role}_MicroCard_TEST_ONLY"
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        stem.with_suffix(".crt").write_bytes(pem)
        stem.with_suffix(".p12").write_bytes(pkcs12.serialize_key_and_certificates(
            slot.encode(), key, certificate, [ca], serialization.BestAvailableEncryption(b"microcard-test")))
        entries[f"KEY_{slot}_11"].text = pem.decode()
    entries["GENERAL_AUTH_ALGORITHM_PIV_AUTHENTICATION_KEY"].text = "11"
    entries["KEY_ALGORITHMS_CARD_AUTHENTICATION_SYMMETRIC"].text = ""
    config.write(output / "config.xml", encoding="UTF-8", xml_declaration=True)
    manifest = dict(kind="derived P-256 test identity", production_credential=False,
                    original_gsa_image=False, pkcs12_test_password="microcard-test", upstream_revision=revision, inputs=inputs,
                    outputs={str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(output.rglob("*")) if p.is_file()})
    (output / "identity.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    create(args.upstream.resolve(), args.out.resolve())
