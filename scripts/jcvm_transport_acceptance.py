#!/usr/bin/env python3
"""Exercise persistent JCVM delivery with the independent Python SCP03/package client."""
import hashlib
import pathlib
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from device_cbor import decode, jcvm_manifest
from package_envelope import create
from scp03_acceptance import Client, SIM, ROOT, sign_package, signer_public_key, aes, modes


def lv(*values):
    return b"".join(bytes([len(value)]) + value for value in values)


def files(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).digest()
            for path in directory.rglob("*") if path.is_file() and path.name != ".lock"}


def sign_with_pin(client, public_key, pin):
    digest = hashlib.sha256(b"MicroCard OpenFIPS201 signing acceptance").digest()
    request = bytes.fromhex("7C2482008120") + digest
    client.command(0x87, request, p1=0x11, p2=0x9c, cla=0x04, status=0x6982)
    client.command(0x20, pin, p2=0x80, cla=0x04)
    response = client.command(0x87, request, p1=0x11, p2=0x9c, cla=0x04, le=256)
    assert response[0] == 0x7c and response[1] == len(response) - 2, response.hex()
    assert response[2] == 0x82 and response[3] == len(response) - 4, response.hex()
    public_key.verify(response[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    # Slot 9C requires a fresh PIN verification for every signature.
    client.command(0x87, request, p1=0x11, p2=0x9c, cla=0x04, status=0x6982)


def main():
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
        package = bytes.fromhex("A00000030800001000")
        module = bytes.fromhex("A000000308000010000100")
        instance = bytes.fromhex("F04D434A01")
        image = (ROOT / "crates/microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb").read_bytes()
        manifest = jcvm_manifest(dict(domain=discovery[4].hex(), incarnation=discovery[5].hex(),
            package=package.hex(), package_version=[1, 10], version=1,
            limits=dict(heap_bytes=65536, frame_words=8192, buffer_bytes=261, budget=1000000)))
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
        # Provision the real applet through its administrative secure-channel API.
        management_key = bytes(range(0x30, 0x40))
        definition = bytes.fromhex("66128B019B8C017F8D01008E01088F0101900114")
        client.connect(level=1)
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0xdb, definition, p1=0xff, p2=0xff, status=0x6982)
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0xdb, definition, p1=0xff, p2=0xff)
        client.command(0x25, bytes.fromhex("80010830128010") + management_key,
                       p1=1, p2=0x9b)
        signing_pin = bytes.fromhex("363534333231FFFF")
        client.command(0x24, signing_pin, p1=1, p2=0x80)
        client.command(0xdb, bytes.fromhex("66128B019C8C01028D010A8E01118F0104900110"),
                       p1=0xff, p2=0xff)
        generated = client.command(0x47, bytes.fromhex("AC03800111"), p2=0x9c, le=256)
        assert len(generated) == 70 and generated[:5] == bytes.fromhex("7F49438641"), generated.hex()
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), generated[5:])
        sign_with_pin(client, public_key, signing_pin)
        # The interindustry class belongs to the applet, even for a GP instruction number.
        client.command(0xe4, b"\x4f" + bytes([len(instance)]) + instance,
                       cla=0x04, status=0x6d00)
        pin = bytes.fromhex("0020008008313233343536FFFF")
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c5)
        client.close()

        client = Client(keys, state, mode)
        client.connect()
        assert decode(client.command(0xe2, b"\0"))[5] == discovery[5]
        assert client.command(0xa4, instance, p1=4) == selected
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
        # Direct command routing must not admit a command without its SCP03 MAC.
        assert client.raw(pin) == bytes.fromhex("6982")
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c3)
        sign_with_pin(client, public_key, signing_pin)
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
    print("PASS: JCVM load, management-key authentication and PIN-gated P-256 signing after reboot, reclaim and fail-closed storage")


if __name__ == "__main__":
    main()
