#!/usr/bin/env python3
"""Exercise persistent JCVM delivery with the independent Python SCP03/package client."""
import argparse
import datetime
import hashlib
import pathlib
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from device_cbor import decode, jcvm_manifest
from package_envelope import create
from scp03_acceptance import Client, SIM, ROOT, sign_package, signer_public_key, aes, modes


def lv(*values):
    return b"".join(bytes([len(value)]) + value for value in values)


def files(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).digest()
            for path in directory.rglob("*") if path.is_file() and path.name != ".lock"}


def piv(client, ins, data=b"", *, p1=0, p2=0, status=0x9000, cla=0, le=None):
    command = bytes([cla, ins, p1, p2])
    if data:
        command += bytes([len(data)]) + data
    if le is not None:
        command += bytes([le % 256])
    response = client.raw(command)
    assert response[-2:] == status.to_bytes(2, "big"), (hex(ins), response.hex())
    return response[:-2]


def tlv(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([0x82]) + length.to_bytes(2, "big")
    return bytes([tag]) + encoded + value


def check_lifecycle(client, expected):
    response = client.command(0xcb, bytes.fromhex("5C032F4753"), p1=0xff, p2=0xff, le=256)
    assert len(response) >= 5 and response[0] == 0x53 and response[1] == len(response) - 2
    assert response[2:5] == bytes([0x80, 1, expected]), response.hex()


def certificate_for(public_key, serial=1):
    issuer_key = ec.derive_private_key(9, ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "MicroCard acceptance CA")])
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "OpenFIPS201 signing key")])
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(serial)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
            .sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


def read_certificate(client, expected):
    response = client.raw(bytes.fromhex("00CB3FFF055C035FC10AC0"))
    collected = bytearray()
    for _ in range(8):
        collected.extend(response[:-2])
        assert len(collected) <= len(expected)
        status = int.from_bytes(response[-2:], "big")
        if status == 0x9000:
            assert collected == expected
            return
        assert status >> 8 == 0x61, response.hex()
        response = client.raw(bytes.fromhex("00C00000C0"))
    raise AssertionError("certificate response did not finish")


def write_certificate(client, certificate_object):
    payload = bytes.fromhex("5C035FC10A") + certificate_object
    for offset in range(0, len(payload), 180):
        more = offset + 180 < len(payload)
        client.command(0xdb, payload[offset:offset + 180], p1=0x3f, p2=0xff,
                       cla=0x14 if more else 0x04)


def sign_with_pin(client, public_key, pin):
    digest = hashlib.sha256(b"MicroCard OpenFIPS201 signing acceptance").digest()
    request = bytes.fromhex("7C2482008120") + digest
    piv(client, 0x87, request, p1=0x11, p2=0x9c, status=0x6982)
    piv(client, 0x20, pin, p2=0x80)
    response = piv(client, 0x87, request, p1=0x11, p2=0x9c, le=256)
    assert response[0] == 0x7c and response[1] == len(response) - 2, response.hex()
    assert response[2] == 0x82 and response[3] == len(response) - 4, response.hex()
    public_key.verify(response[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    # Slot 9C requires a fresh PIN verification for every signature.
    piv(client, 0x87, request, p1=0x11, p2=0x9c, status=0x6982)


def generate_key(client, slot):
    generated = client.command(0x47, bytes.fromhex("AC03800111"), p2=slot, le=256)
    assert len(generated) == 70 and generated[:5] == bytes.fromhex("7F49438641"), generated.hex()
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), generated[5:])


def agree_with_pin(client, public_key, pin):
    peer = ec.derive_private_key(13, ec.SECP256R1())
    encoded = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    request = tlv(0x7c, tlv(0x85, encoded) + tlv(0x82, b""))
    piv(client, 0x20, p1=0xff, p2=0x80)
    piv(client, 0x87, request, p1=0x11, p2=0x9d, status=0x6982)
    piv(client, 0x20, pin, p2=0x80)
    response = piv(client, 0x87, request, p1=0x11, p2=0x9d, le=256)
    assert response == tlv(0x7c, tlv(0x82, peer.exchange(ec.ECDH(), public_key)))
    # (0, 0) is correctly encoded but is not on P-256. Rejection must keep selection.
    malformed = tlv(0x7c, tlv(0x85, b"\x04" + bytes(64)) + tlv(0x82, b""))
    piv(client, 0x87, malformed, p1=0x11, p2=0x9d, status=0x6a80)
    piv(client, 0x20, p2=0x80)


def install_openfips(client, discovery):
    """Load the pinned applet through signed management and return its installation data."""
    package = bytes.fromhex("A00000030800001000")
    module = bytes.fromhex("A000000308000010000100")
    instance = module
    image = (ROOT / "crates/microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb").read_bytes()
    manifest = jcvm_manifest(dict(domain=discovery[4].hex(), incarnation=discovery[5].hex(),
        package=package.hex(), package_version=[1, 10], version=1,
        limits=dict(heap_bytes=65536, frame_words=8192, buffer_bytes=261, budget=4000000)))
    seed = bytes([7]) * 32
    raw = create(manifest, image, signer_public_key(seed), lambda value: sign_package(seed, value), 60 * 1024)
    client.command(0xe6, lv(package, discovery[4], hashlib.sha256(raw).digest(), b"", b""), p1=2)
    wire = b"\xc4\x82" + len(raw).to_bytes(2, "big") + raw
    blocks = [wire[offset:offset + 220] for offset in range(0, len(wire), 220)]
    assert len(blocks) <= 256
    for index, block in enumerate(blocks):
        client.command(0xe8, block, p1=0x80 if index + 1 == len(blocks) else 0, p2=index)
    install = lv(package, module, instance, b"\0", b"\xc9\0", b"")
    client.command(0xe6, install, p1=0x0c)
    selected = client.command(0xa4, instance, p1=4, cla=0x04)
    assert selected[:3] == bytes.fromhex("618192") and len(selected) == 149
    # PIV hosts also select the nine-byte application prefix, not only the full AID.
    assert piv(client, 0xa4, package, p1=4, le=256) == selected
    return instance, install, selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate-capacity", type=int, default=4096,
                        help="Fixed certificate-object capacity for allocation qualification (default: 4096)")
    args = parser.parse_args()
    if not 1024 <= args.certificate_capacity <= 32767:
        parser.error("certificate capacity must be between 1024 and 32767 bytes")
    with tempfile.TemporaryDirectory(prefix="microcard-jcvm-") as temporary:
        root = pathlib.Path(temporary)
        keys, state = root / "keys", root / "state"
        keys.write_bytes(bytes(range(32)))
        mode = "serve-jcvm-managed"
        client = Client(keys, state, mode)
        client.connect()
        discovery = decode(client.command(0xe2, b"\0"))
        assert discovery[:4] == [2, 1, 1, 0]
        assert discovery[6:] == [None, 0, 0]
        # Concurrent processes must not share monotonic/nonce reservations.
        blocked = subprocess.run([SIM, mode, keys, state], input="", text=True,
                                 capture_output=True, timeout=10)
        assert blocked.returncode and "already in use" in blocked.stderr
        instance, install, selected = install_openfips(client, discovery)
        # Provision the real applet through its administrative secure-channel API.
        management_key = bytes(range(0x30, 0x40))
        definition = bytes.fromhex("66128B019B8C017F8D01008E01088F0101900114")
        client.connect(level=1)
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0xdb, definition, p1=0xff, p2=0xff, status=0x6982)
        # GP clients may authenticate after selecting PIV. INITIALIZE UPDATE must
        # retain that selection while discarding the prior channel's authority.
        client.connect(select_isd=False)
        client.command(0xdb, definition, p1=0xff, p2=0xff)
        client.command(0x25, bytes.fromhex("80010830128010") + management_key,
                       p1=1, p2=0x9b)
        signing_pin = bytes.fromhex("363534333231FFFF")
        client.command(0x24, signing_pin, p1=1, p2=0x80)
        client.command(0xdb, bytes.fromhex("66128B019C8C01028D010A8E01118F0104900110"),
                       p1=0xff, p2=0xff)
        public_key = generate_key(client, 0x9c)
        client.command(0xdb, bytes.fromhex("66128B019D8C01018D01098E01118F0102900110"),
                       p1=0xff, p2=0xff)
        agreement_key = generate_key(client, 0x9d)
        sign_with_pin(client, public_key, signing_pin)
        certificate = certificate_for(public_key)
        container = tlv(0x70, certificate) + bytes.fromhex("710100FE00")
        certificate_object = tlv(0x53, container)
        client.command(0xdb, bytes.fromhex("64128B035FC10A8C017F8D017F91019B9202") + args.certificate_capacity.to_bytes(2, "big"),
                       p1=0xff, p2=0xff)
        write_certificate(client, certificate_object)
        read_certificate(client, certificate_object)
        check_lifecycle(client, 0x07)
        client.command(0xdb, bytes.fromhex("6900"), p1=0xff, p2=0xff)
        check_lifecycle(client, 0x0f)
        # Stop between encrypted chain fragments, without graceful session cleanup.
        replacement = tlv(0x53, tlv(0x70, certificate_for(public_key, serial=2))
                          + bytes.fromhex("710100FE00"))
        incomplete = bytes.fromhex("5C035FC10A") + replacement
        assert len(incomplete) > 180
        client.command(0xdb, incomplete[:180], p1=0x3f, p2=0xff, cla=0x14)
        client.p.kill()
        assert client.p.wait(timeout=5) != 0
        client.p.stdin.close()
        client.p.stdout.close()
        client = Client(keys, state, mode)
        assert piv(client, 0xa4, instance, p1=4, le=256) == selected
        read_certificate(client, certificate_object)
        # A fresh authenticated upload must replace the object, not resume stale chaining.
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        check_lifecycle(client, 0x0f)
        write_certificate(client, replacement)
        certificate_object = replacement
        read_certificate(client, certificate_object)
        # The interindustry class belongs to the applet, even for a GP instruction number.
        client.command(0xe4, b"\x4f" + bytes([len(instance)]) + instance,
                       cla=0x04, status=0x6d00)
        pin = bytes.fromhex("0020008008313233343536FFFF")
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c5)
        # Keep both heap banks occupied and retain the second applet's reset-scoped
        # arrays while exercising the personalized instance.
        second = instance[:-1] + bytes([instance[-1] + 1])
        client.connect()
        client.command(0xe6, lv(instance[:9], instance, second, b"\0", b"\xc9\0", b""), p1=0x0c)
        client.command(0xa4, second, p1=4, cla=0x04)
        check_lifecycle(client, 0x07)
        piv(client, 0xa4, instance, p1=4, le=256)
        client.connect(select_isd=False)
        check_lifecycle(client, 0x0f)
        client.close()

        # Consume only nonce reservations in the closed host fixture. The committed
        # heap remains intact; selecting it must renew before the next callback.
        nonces = state / "heap0/nonces.bin"
        counter = nonces.read_bytes()
        reserve = len(counter) - 1024 * 4
        assert reserve > 0 and counter[reserve:] == b"\xff" * (1024 * 4)
        nonces.write_bytes(b"\0" * reserve + counter[reserve:])
        registry_before = files(state / "registry")

        client = Client(keys, state, mode)
        # A normal PIV client can select and read after boot without ever opening SCP03.
        piv(client, 0xa4, second, p1=4, le=256)
        assert piv(client, 0xa4, instance, p1=4, le=256) == selected
        assert nonces.read_bytes()[reserve - 4:] == b"\xff" * (len(counter) - reserve + 4)
        assert files(state / "registry") != registry_before, "renewal must publish its new identity"
        read_certificate(client, certificate_object)
        client.connect()
        assert decode(client.command(0xe2, b"\0"))[5] == discovery[5]
        assert client.command(0xa4, instance, p1=4) == selected
        check_lifecycle(client, 0x0f)
        # MAC-only transport supplies no applet administrative grant. Prove that
        # the imported persistent key itself answers the PIV authentication flow.
        client.connect(level=1)
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        for valid in (False, True):
            challenge = client.command(0x87, bytes.fromhex("7C028100"), p1=8, p2=0x9b, cla=0x04, le=256)
            assert len(challenge) == 20 and challenge[:4] == bytes.fromhex("7C128110"), challenge.hex()
            cryptogram = bytearray(aes(management_key, modes.ECB(), challenge[4:]))
            if not valid:
                cryptogram[0] ^= 1
            client.command(0x87, bytes.fromhex("7C128210") + cryptogram, p1=8, p2=0x9b,
                           cla=0x04, status=0x9000 if valid else 0x6982)
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c4)
        # Plain application traffic receives no administrative authority from SCP03.
        assert client.raw(pin) == bytes.fromhex("63c3")
        piv(client, 0xdb, definition, p1=0xff, p2=0xff, cla=0x80, status=0x6982)
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        sign_with_pin(client, public_key, signing_pin)
        agree_with_pin(client, agreement_key, signing_pin)
        # A reselect runs deselect/select callbacks but retains the PIV PIN validation.
        piv(client, 0x20, signing_pin, p2=0x80)
        assert piv(client, 0xa4, instance, p1=4, le=256) == selected
        piv(client, 0x20, p2=0x80)
        # The applet reset its secure channel during reselect; old SCP commands fail.
        client.command(0xe2, b"\0", status=0x6982)
        assert piv(client, 0xa4, instance, p1=4, le=256) == selected
        piv(client, 0x20, signing_pin, p2=0x80)
        client.connect(select_isd=False)
        piv(client, 0x20, p2=0x80, status=0x63c6)
        # A real deselection clears PIN validation, while a missing SELECT preserves it.
        piv(client, 0x20, signing_pin, p2=0x80)
        piv(client, 0xa4, bytes.fromhex("F04D434AFF"), p1=4, status=0x6a82)
        piv(client, 0x20, p2=0x80)
        piv(client, 0xa4, bytes.fromhex("A000000151000000"), p1=4)
        piv(client, 0xa4, instance, p1=4)
        piv(client, 0x20, p2=0x80, status=0x63c6)
        piv(client, 0xa4, bytes.fromhex("A000000151000000"), p1=4)
        client.connect()
        # Reclaiming an explicitly deleted instance must establish a fresh heap identity.
        client.command(0xe4, b"\x4f" + bytes([len(instance)]) + instance)
        client.command(0xe6, install, p1=0x0c)
        client.command(0xa4, instance, p1=4)
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c5)
        client.close()

        damaged = state / "heap0/slot0.bin"
        damaged.unlink()
        before = files(state)
        rejected = subprocess.run([SIM, mode, keys, state], input="", text=True,
                                  capture_output=True, timeout=10)
        assert rejected.returncode and "Storage" in rejected.stderr
        assert files(state) == before, "recovery recreated or changed damaged storage"
        legacy = root / "legacy"
        legacy.mkdir()
        (legacy / "slot0.bin").write_bytes(b"old state")
        before = files(legacy)
        rejected = subprocess.run([SIM, mode, keys, legacy], input="", text=True,
                                  capture_output=True, timeout=10)
        assert rejected.returncode and "IncompatibleState" in rejected.stderr
        assert files(legacy) == before
    print("PASS: JCVM load, durable personalization, management-key authentication and PIN-gated P-256 signing/ECDH, interrupted certificate replacement/reboot, counter renewal, reclaim and fail-closed storage")


if __name__ == "__main__":
    main()
