#!/usr/bin/env python3
"""Build the nRF52840 variants with the board linker config and enforce size budgets."""
import argparse
import json
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOARD = ROOT / "board" / "nrf52840"
BINARY = BOARD / "target" / "thumbv7em-none-eabihf" / "release" / "microcard-nrf52840"
DESTINATION = ROOT / "docs" / "BOARD_BUDGETS.json"
CEILINGS = {"text_bytes": 350_000, "data_bytes": 0, "bss_bytes": 200_000}


def measure(extra_arguments):
    subprocess.run(
        ["cargo", "build", "--release", "--locked", *extra_arguments],
        cwd=BOARD,
        check=True,
    )
    size = shutil.which("arm-none-eabi-size")
    if size is None:
        raise SystemExit("arm-none-eabi-size is required for the board budget gate")
    output = subprocess.run([size, str(BINARY)], check=True, capture_output=True, text=True).stdout
    values = output.strip().splitlines()[-1].split()
    return {
        "text_bytes": int(values[0]),
        "data_bytes": int(values[1]),
        "bss_bytes": int(values[2]),
        "ceilings": CEILINGS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    variants = {
        "production": measure(["--no-default-features", "--features", "software-crypto"]),
        "development_debug": measure([]),
        "usb_ccid": measure(["--features", "usb-ccid"]),
 "dongle": measure(["--features", "dongle"]),
    }
    for name, result in variants.items():
        for field, ceiling in CEILINGS.items():
            if result[field] > ceiling:
                raise SystemExit(f"{name} {field} {result[field]} exceeds {ceiling}")
    output = json.dumps(
        {"format": 1, "target": "thumbv7em-none-eabihf", "variants": variants},
        indent=2,
    ) + "\n"
    if args.check:
        if DESTINATION.read_text() != output:
            raise SystemExit("docs/BOARD_BUDGETS.json is stale")
    else:
        DESTINATION.write_text(output)
    print(
        "PASS: nRF52840 production, development-debug, USB CCID and dongle flash/RAM budgets "
        f"({variants['development_debug']['text_bytes']} text bytes development, "
        f"{variants['usb_ccid']['text_bytes']} with USB CCID, "
 f"{variants['dongle']['text_bytes']} on the dongle)"
    )


if __name__ == "__main__":
    main()
