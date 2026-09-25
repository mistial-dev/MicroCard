#!/usr/bin/env python3
"""Erase and reprovision an nRF52840 DK from a verified MicroCard bundle."""

import argparse
import hashlib
import json
import pathlib
import re
import shlex
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]


def checked_bundle(bundle: pathlib.Path, management_key: pathlib.Path) -> tuple[pathlib.Path, int]:
    manifest = json.loads((bundle / "manifest.json").read_text())
    expected_layouts = {"jcvm": "memory-dk-jcvm.x", "mc04": "memory-dk.x"}
    if manifest.get("layout") != expected_layouts.get(manifest.get("engine")):
        raise ValueError("factory reset requires a DK firmware bundle")
    layout = ROOT / "board/nrf52840" / manifest["layout"]
    if hashlib.sha256(layout.read_bytes()).hexdigest() != manifest["layout_sha256"]:
        raise ValueError("the bundle's flash layout has changed")
    firmware = bundle / "microcard.elf"
    expected = manifest.get("sha256", {}).get("microcard.elf")
    if not expected or hashlib.sha256(firmware.read_bytes()).hexdigest() != expected:
        raise ValueError("the firmware does not match its manifest")
    if len(management_key.read_bytes()) != 32:
        raise ValueError("management key must contain exactly 32 bytes")
    match = re.search(r"^\s*KEYS\s*:\s*ORIGIN\s*=\s*(0x[0-9a-fA-F]+)", layout.read_text(), re.M)
    if match is None:
        raise ValueError("the layout has no key page")
    return firmware, int(match.group(1), 16)


def commands(probe: str, firmware: pathlib.Path, management_key: pathlib.Path,
             keys_at: int) -> list[list[str]]:
    target = ["--chip", "nRF52840_xxAA", "--probe", probe, "--protocol", "swd", "--speed", "1000"]
    return [
        ["probe-rs", "erase", *target, "--allow-erase-all"],
        ["probe-rs", "download", *target, "--verify", "--binary-format", "bin",
         "--base-address", hex(keys_at), str(management_key)],
        ["probe-rs", "download", *target, "--verify", str(firmware)],
        ["probe-rs", "reset", *target],
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=pathlib.Path, default=ROOT /
                        "artifacts/development-firmware/jcvm/dk")
    parser.add_argument("--management-key", type=pathlib.Path, required=True)
    parser.add_argument("--probe", required=True, help="probe-rs VID:PID:serial selector")
    parser.add_argument("--execute", action="store_true", help="perform the chip erase and flash")
    args = parser.parse_args()
    firmware, keys_at = checked_bundle(args.bundle, args.management_key)
    steps = commands(args.probe, firmware, args.management_key, keys_at)
    if not args.execute:
        print("Dry run. --execute erases all target flash, applets, and prior keys.")
        for step in steps:
            print(shlex.join(step))
        return
    for step in steps:
        subprocess.run(step, check=True)
    print("DK factory reset complete; previous applets and persistent state are erased.")


if __name__ == "__main__":
    main()
