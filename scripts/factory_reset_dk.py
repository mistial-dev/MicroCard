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
DEBUG_UICR_ADDRESS = 0x10001208
DEBUG_UICR_BYTES = bytes((0x5A, 0, 0, 0))


def checked_bundle(bundle: pathlib.Path, management_key: pathlib.Path) -> tuple[pathlib.Path, int]:
    manifest = json.loads((bundle / "manifest.json").read_text())
    expected_layouts = {"jcvm": "memory-dk-jcvm.x", "mc04": "memory-dk.x"}
    if manifest.get("layout") != expected_layouts.get(manifest.get("engine")):
        raise ValueError("factory reset requires a DK firmware bundle")
    if manifest["engine"] == "jcvm" and "usb-ccid" not in manifest.get("board_features", []):
        raise ValueError("JCVM DK firmware must include usb-ccid")
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


def checked_debug_image(bundle: pathlib.Path) -> pathlib.Path:
    manifest = json.loads((bundle / "manifest.json").read_text())
    if not manifest.get("development_only"):
        raise ValueError("keeping SWD open requires a development-only bundle")
    image = bundle / "uicr-debug-open.bin"
    expected = manifest.get("sha256", {}).get(image.name)
    contents = image.read_bytes() if image.is_file() else b""
    if (not expected or contents != DEBUG_UICR_BYTES
            or hashlib.sha256(contents).hexdigest() != expected):
        raise ValueError("development debug UICR image is missing or unverified")
    return image


def commands(probe: str, firmware: pathlib.Path, management_key: pathlib.Path,
             keys_at: int, debug_image: pathlib.Path | None = None) -> list[list[str]]:
    target = ["--chip", "nRF52840_xxAA", "--probe", probe, "--protocol", "swd", "--speed", "1000"]
    steps = [
        ["probe-rs", "erase", *target, "--allow-erase-all"],
        ["probe-rs", "download", *target, "--verify", "--binary-format", "bin",
         "--base-address", hex(keys_at), str(management_key)],
        ["probe-rs", "download", *target, "--verify", str(firmware)],
    ]
    if debug_image is not None:
        steps.append(["probe-rs", "download", *target, "--verify", "--binary-format",
                      "bin", "--base-address", hex(DEBUG_UICR_ADDRESS), str(debug_image)])
    steps.append(["probe-rs", "reset", *target])
    return steps


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=pathlib.Path, default=ROOT /
                        "artifacts/development-firmware/jcvm/dk")
    parser.add_argument("--management-key", type=pathlib.Path, required=True)
    parser.add_argument("--probe", required=True, help="probe-rs VID:PID:serial selector")
    parser.add_argument("--keep-debug-open", action="store_true",
                        help="provision development-only UICR.APPROTECT=HwDisabled")
    parser.add_argument("--execute", action="store_true", help="perform the chip erase and flash")
    args = parser.parse_args()
    firmware, keys_at = checked_bundle(args.bundle, args.management_key)
    debug_image = checked_debug_image(args.bundle) if args.keep_debug_open else None
    steps = commands(args.probe, firmware, args.management_key, keys_at, debug_image)
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
