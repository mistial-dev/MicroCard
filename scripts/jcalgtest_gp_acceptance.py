#!/usr/bin/env python3
"""Load the independent JCAlgTest CAP through SCP03 on host or a PC/SC board."""
import argparse
import json
import pathlib
import subprocess
import tempfile
import time

from device_cbor import decode
from jcalgtest_acceptance import performance_command
from jcvm_transport_acceptance import load_cap, lv
from jcvm_diagnostic import query as query_diagnostic
from scp03_acceptance import Client, ROOT


IMAGE = ROOT / "crates/microcard-engine-jcvm/tests/vectors/jcalgtest-v1.8.2-jc305.lfdb"
PACKAGE = bytes.fromhex("4A43416C6754657374")
APPLET = bytes.fromhex("4A43416C675465737431")
KEYPAIR_PROFILES = {
    "rsa1024": (2, 1024),
    "rsa2048": (2, 2048),
    "p384": (5, 384),
}


def probe(client, timings=False):
    def raw(label, command):
        start = time.perf_counter_ns()
        result = client.raw(command)
        if timings:
            print(f"{label}: {(time.perf_counter_ns() - start) / 1_000_000:.2f} ms", flush=True)
        return result

    selected = raw("select", bytes([0, 0xA4, 4, 0, len(APPLET)]) + APPLET)
    assert selected[-2:] == b"\x90\x00", selected.hex()
    version = raw("version", bytes.fromhex("B0E100000100"))
    assert version == b"1.8.2_jc305\x90\x00", version.hex()
    digest = raw("digest factory", bytes.fromhex("B075150003040000"))
    assert digest[:2] == bytes.fromhex("1500") and digest[-2:] == b"\x90\x00", digest.hex()
    for algorithm in (5, 6):
        factory = raw(f"digest {algorithm} factory",
                      bytes.fromhex("B075150003") + bytes([algorithm, 0, 0, 0]))
        assert factory[:2] == bytes.fromhex("1500") and factory[-2:] == b"\x90\x00", factory.hex()
        profile = (0x15, algorithm, 0, 0, 0, 16, 0)
        for label, ins, method in (("prepare", 0x34, 2), ("update", 0x41, 2),
                                   ("doFinal", 0x41, 6), ("reset", 0x41, 4)):
            result = raw(f"digest {algorithm} {label}",
                         bytes.fromhex(performance_command(ins, profile, method)))
            assert result == b"\xaa\x90\x00", result.hex()
    for pin_type in (2, 3):
        result = raw(f"OwnerPIN type {pin_type}", bytes.fromhex("B075240003") + bytes([pin_type, 0, 0, 0]))
        assert result[:2] == bytes.fromhex("2400") and result[-2:] == b"\x90\x00", result.hex()
    # The software AES schedule reads a byte static at the last image offset.
    software_aes = raw("software AES prepare", bytes.fromhex(
        "B0C00000160016FFFFFFFFFFFFFFFF00020010FFFFFFFF0032000100"))
    assert software_aes == b"\xaa\x90\x00", software_aes.hex()


def probe_keypair_generation(client, name):
    key_class, key_bits = KEYPAIR_PROFILES[name]
    # AlgPerformanceTest reads keyClass and keyLength, then invokes genKeyPair.
    profile = (0x19, 0, key_class, 0, key_bits, 0, 0)
    for label, ins in (("prepare", 0x36), ("generate", 0x45)):
        command = bytes.fromhex(performance_command(ins, profile, 1))
        start = time.perf_counter_ns()
        result = client.raw(command)
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        print(f"{name} {label}: {elapsed:.2f} ms, response {result.hex()}", flush=True)
        assert result == b"\xaa\x90\x00", f"{name} {label}: {result.hex()}"


def probe_cmac_factory(client):
    start = time.perf_counter_ns()
    result = client.raw(bytes.fromhex("B075120003310000"))
    elapsed = (time.perf_counter_ns() - start) / 1_000_000
    print(f"AES-CMAC factory: {elapsed:.2f} ms, response {result.hex()}", flush=True)
    assert result[:2] == b"\x12\x00" and result[-2:] == b"\x90\x00", result.hex()


def deletion_timings(client, repeats):
    for _ in range(repeats):
        reset = client.raw(bytes.fromhex("B0E2000000"))
        assert reset == b"\x90\x00", reset.hex()
        start = time.perf_counter_ns()
        result = client.raw(bytes.fromhex("B075150003040000"))
        elapsed = (time.perf_counter_ns() - start) / 1_000_000
        assert result[:2] == bytes.fromhex("1500") and result[-2:] == b"\x90\x00", result.hex()
        print(f"digest factory after deletion request: {elapsed:.2f} ms", flush=True)


def deletion_noop_probes(client, repeats):
    # The upstream extended scan requests deletion before unsupported factory
    # probes. Neither command changes durable applet state when there is no garbage.
    for _ in range(repeats):
        assert client.raw(bytes.fromhex("B0E2000000")) == b"\x90\x00"
        result = client.raw(bytes.fromhex("B075150003FF0000"))
        assert result[0] == 0x15 and result[1] != 0 and result[-2:] == b"\x90\x00", result.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", help="Exact PC/SC reader name; omit for host JCVM")
    parser.add_argument("--management-key", type=pathlib.Path,
                        help="32-byte board management key")
    parser.add_argument("--select-only", action="store_true",
                        help="Check the applet already installed on a board")
    parser.add_argument("--timings", action="store_true", help="Print host-observed latency for each probe APDU")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Repeat the probe sequence within one card session")
    parser.add_argument("--deletion-probes", type=int, default=0,
                        help="Time factory calls after the applet requests object deletion")
    parser.add_argument("--deletion-noop-probes", type=int, default=0,
                        help="Repeat deletion requests followed by unsupported factories")
    parser.add_argument("--keypair-generation", action="append", choices=KEYPAIR_PROFILES,
                        default=[], help="Opt-in JCAlgTest key-pair generation APDU; repeat per size")
    parser.add_argument("--keypair-repeat", type=int, default=1,
                        help="Repeat each opt-in key-pair generation; stop on first failure")
    parser.add_argument("--cmac-factory", action="store_true",
                        help="Probe the selected AES-CMAC Signature factory")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    if args.keypair_repeat < 1:
        parser.error("--keypair-repeat must be positive")
    if args.deletion_probes < 0:
        parser.error("--deletion-probes must be nonnegative")
    if args.deletion_noop_probes < 0:
        parser.error("--deletion-noop-probes must be nonnegative")
    if args.reader and args.management_key is None:
        parser.error("--management-key is required with --reader")
    if args.management_key and len(args.management_key.read_bytes()) != 32:
        parser.error("--management-key must contain exactly 32 bytes")
    with tempfile.TemporaryDirectory(prefix="microcard-jcalgtest-gp-") as temporary:
        root = pathlib.Path(temporary)
        keys, state = root / "keys", root / "state"
        if args.reader:
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(["javac", "--release", "21", "-d", classes,
                            ROOT / "scripts/PcscRelay.java"], check=True)
            keys = args.management_key
            state = None
            transport = ["java", "-cp", str(classes), "PcscRelay", args.reader]
        else:
            keys.write_bytes(bytes(range(32)))
            transport = "serve-jcvm-managed"
        client = (Client(keys, state, transport=transport) if args.reader
                  else Client(keys, state, transport))
        try:
            client.connect()
            if not args.select_only:
                discovery = decode(client.command(0xE2, b"\0"))
                assert discovery[:4] == [2, 2, 1, 0]
                load_cap(client, discovery[4], PACKAGE, IMAGE.read_bytes())
                client.command(0xE6, lv(PACKAGE, APPLET, APPLET, b"\0", b"\xc9\0", b""), p1=0x0C)
            for _ in range(args.repeat):
                probe(client, args.timings)
            for name in args.keypair_generation:
                for _ in range(args.keypair_repeat):
                    probe_keypair_generation(client, name)
            if args.cmac_factory:
                probe_cmac_factory(client)
            deletion_timings(client, args.deletion_probes)
            deletion_noop_probes(client, args.deletion_noop_probes)
        except Exception:
            client.close()
            if args.reader:
                try:
                    print("JCVM diagnostic after failure:",
                          json.dumps(query_diagnostic(args.reader, classes), sort_keys=True),
                          flush=True)
                except Exception as diagnostic_error:
                    print(f"JCVM diagnostic unavailable: {diagnostic_error}", flush=True)
            raise
        finally:
            if client.p.poll() is None:
                client.close()
        if args.reader:
            print("PASS: physical unsigned JCAlgTest load, install and probe" if not args.select_only
                  else "PASS: physical JCAlgTest selection after reset")
            return
        client = Client(keys, state, "serve-jcvm-managed")
        try:
            client.connect()
            for _ in range(args.repeat):
                probe(client, args.timings)
            for name in args.keypair_generation:
                for _ in range(args.keypair_repeat):
                    probe_keypair_generation(client, name)
            if args.cmac_factory:
                probe_cmac_factory(client)
        finally:
            client.close()
    print("PASS: unsigned JCAlgTest CAP loads through SCP03 and survives reboot")


if __name__ == "__main__":
    main()
