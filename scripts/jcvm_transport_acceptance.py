#!/usr/bin/env python3
"""Exercise persistent JCVM delivery with the independent Python SCP03/package client."""
import hashlib
import pathlib
import subprocess
import tempfile

from device_cbor import decode, jcvm_manifest
from package_envelope import create
from scp03_acceptance import Client, SIM, ROOT, sign_package, signer_public_key


def lv(*values):
    return b"".join(bytes([len(value)]) + value for value in values)


def files(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).digest()
            for path in directory.rglob("*") if path.is_file() and path.name != ".lock"}


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
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c4)
        # Direct command routing must not admit a command without its SCP03 MAC.
        assert client.raw(pin) == bytes.fromhex("6982")
        client.connect()
        assert client.command(0xa4, instance, p1=4, cla=0x04) == selected
        client.command(0x20, pin[5:], p2=0x80, cla=0x04, status=0x63c3)
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
    print("PASS: authenticated JCVM file-backed load/install/reboot/reclaim and fail-closed storage")


if __name__ == "__main__":
    main()
