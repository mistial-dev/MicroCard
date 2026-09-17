#!/usr/bin/env python3
"""Adversarial signed loading over SCP03; optional DK reset, no firmware writes.
Creates and deletes only a fresh test SSD. Never deletes a pre-existing SSD.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from dk_smoke import SerialClient
from domain_inventory import inventory
from scp03_acceptance import BinaryClient, bootstrap_isd, cmac, domain_policy, ensure_assembly

class StrictReplies:
    def command(self, ins, data=b"", status=0x9000):
        reply = self.raw(self.encode(ins, data))
        assert reply[-2:] == status.to_bytes(2, "big"), (hex(ins), reply.hex())
        if status == 0x9000 or status >> 8 in (0x62, 0x63):
            assert len(reply) >= 10
            assert reply[-10:-2] == cmac(self.rmac, self.chain + reply[:-10] + reply[-2:])[:8]
            return reply[:-10]
        # This SCP03 profile returns bare error status words; state checks are separate.
        assert len(reply) == 2
        return b""

class StrictSerial(StrictReplies, SerialClient):
    pass

class StrictBinary(StrictReplies, BinaryClient):
    pass

CONTEXT = b"MicroCard signed package v3\0"
HEADER = 12 + len(CONTEXT)
AID = "F04D43EE01"

def acceptance_image():
    image, _ = ensure_assembly("samples/SigningAcceptance", "signing-acceptance")
    return image.read_bytes()

def manifest(domain, incarnation, version=2):
    return dict(domain=domain, incarnation=list(incarnation), assembly="SigningAcceptance",
                assembly_version=[1, 0, 0, 0], version=version, export=dict(access=0, key=None),
                entry_points=[dict(aid=AID, process=0, install=None, uninstall=None, select=None, deselect=None)],
                dependencies=[], capabilities=[], storage=[],
                limits=dict(arena=16384, stack=256, frames=32, instructions=100000))

def dependency(assembly):
    return dict(assembly=assembly,
                ranges=[dict(min=[1, 0, 0, 0], min_inclusive=True,
                             max=[1, 0, 0, 0], max_inclusive=True)],
                package_version=0, signer=None, digest=None, scope=0)

def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()

def package(meta, key, image=None, context=CONTEXT):
    if image is None: image = acceptance_image()
    meta = encode(meta) if isinstance(meta, dict) else meta
    raw = b"MP03" + context + len(meta).to_bytes(4, "little") + len(image).to_bytes(4, "little") + meta + image
    raw += key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw + key.sign(raw)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port")
    parser.add_argument("--management-key", type=pathlib.Path)
    parser.add_argument("--probe", help="Optional DK debugger reset between durable checks")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    if bool(args.port) != bool(args.management_key): parser.error("port and management-key must be supplied together")
    if args.probe and not args.port: parser.error("probe requires a DK port")
    results = []
    with tempfile.TemporaryDirectory(prefix="microcard-signing-") as temp:
        temp = pathlib.Path(temp)
        keys = args.management_key or temp / "management.key"
        if not args.port: keys.write_bytes(os.urandom(32)); keys.chmod(0o600)
        state = temp / "state"
        def connect():
            c = StrictSerial(keys, args.port) if args.port else StrictBinary(keys, state)
            c.connect()
            if not args.port: bootstrap_isd(c)
            return c
        c = connect()
        original_inventory = inventory(c) if not args.port else None
        domain = "sigtest-" + os.urandom(8).hex()
        owned = False
        print(f"Dedicated test SSD: {domain}", file=sys.stderr, flush=True)
        def upload(raw, expected=0x9000):
            c.command(0xe6)
            for offset in range(0, len(raw), 200):
                c.command(0xe8, offset.to_bytes(4, "little") + raw[offset:offset+200])
            c.command(0xea, status=expected)
        def disk_fingerprint():
            if args.port: return None
            return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in state.glob("*") if p.is_file()}
        def reject(name, raw):
            nonlocal c
            before_inventory = inventory(c) if not args.port else None
            before = disk_fingerprint()
            upload(raw, 0x6985)
            assert disk_fingerprint() == before, "rejected package modified persisted simulator state"
            if not args.port:
                assert inventory(c) == before_inventory
                c.close()
                c = connect()
                assert disk_fingerprint() == before, "rejected package changed state after restart"
                assert inventory(c) == before_inventory, "rejected package changed inventory after restart"
            results.append(name)
        def reboot():
            nonlocal c
            c.close()
            if args.port:
                if not args.probe:
                    c = connect()
                    return False
                try:
                    subprocess.run(["probe-rs", "reset", "--chip", "nRF52840_xxAA", "--probe", args.probe], check=True)
                    time.sleep(1)
                finally:
                    # Restore the transport even if reset fails, so cleanup remains possible.
                    c = connect()
                return True
            c = connect()
            return True
        try:
            inc = c.command(0xe0, domain.encode()); owned = True
            c.command(0xe1, domain_policy(domain, []))
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(dict(result="IN_PROGRESS", test_domain=domain, checks=results), indent=2)+"\n")
            key = Ed25519PrivateKey.generate(); other = Ed25519PrivateKey.generate()
            meta = manifest(domain, inc); raw = package(meta, key)
            bad = bytearray(raw); bad[-1] ^= 1
            reject("invalid signature", bytes(bad))
            reject("unsigned", raw[:-64])
            for name, offset in [("metadata tamper", HEADER + 8), ("image tamper", len(raw)-97), ("public-key substitution", len(raw)-96)]:
                bad = bytearray(raw); bad[offset] ^= 1; reject(name, bytes(bad))
            reject("wrong context", package(meta, key, context=b"Other protocol"))
            for name, field, value in [("wrong SSD", "domain", "missing-"+domain),
                                       ("wrong incarnation", "incarnation", [255]*16),
                                       ("missing dependency", "dependencies", [dependency("missing")]),
                                       ("invalid capability", "capabilities", [255]),
                                       ("invalid version", "version", 0)]:
                badmeta = dict(meta); badmeta[field] = value; reject(name, package(badmeta, key))
            reject("invalid image", package(meta, key, image=b"bad"))
            reject("noncanonical metadata", package(encode(meta)+b" ", key))
            # Successful first load under another signer demonstrates failures did not pin the first key.
            raw = package(meta, other); upload(raw)
            results.append("failed first loads did not bind signer")
            c.command(0xec, encode([domain, AID])); c.command(0xa4, bytes.fromhex(AID)); assert c.command(0x10) == b""
            c.command(0xee, encode([domain, AID])); c.command(0xf0, encode([domain, meta["assembly"]]))
            did_reboot = reboot()
            reject("wrong key after unload", package(meta, key))
            reject("rollback after unload", package(manifest(domain, inc, 1), other))
            badmeta = dict(meta); badmeta["capabilities"] = [1]
            reject("same version changed content", package(badmeta, other))
            upload(raw); upload(raw); results.append("identical retries accepted")
            c.command(0xe4, domain.encode()); owned = False
            new = c.command(0xe0, domain.encode()); owned = True
            assert new != inc
            reject("old incarnation replay", raw)
            upload(package(manifest(domain, new), key)); results.append("recreated SSD accepts new signer")
            report = dict(result="PASS", transport="DK UART" if args.port else "binary simulator",
                          reboot_performed=did_reboot, checks=results,
                          state_evidence="All rejected loads preserve complete journal-file fingerprints" if not args.port else
                          "Behavioral pin/version/incarnation checks; no raw flash snapshot or exact application-state comparison",
                          firmware_changed=False)
        except BaseException as error:
            if args.report:
                args.report.write_text(json.dumps(dict(result="FAILED", test_domain=domain, checks=results,
                    error=str(error), firmware_changed=False), indent=2)+"\n")
            raise
        finally:
            try:
                if owned:
                    c.connect(); c.command(0xe4, domain.encode())
                    if not args.port: assert inventory(c) == original_inventory
            finally: c.close()
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2)+"\n")
        print(json.dumps(report, indent=2))

if __name__ == "__main__": main()
