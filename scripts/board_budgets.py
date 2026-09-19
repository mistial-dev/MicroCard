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


def measure(extra_arguments, engine="mc04"):
    arguments = ["--features", f"engine-{engine}", *extra_arguments]
    link_map = BOARD / "target" / f"microcard-{engine}.map"
    subprocess.run(
        ["cargo", "rustc", "--release", "--locked", *arguments, "--", "-C", f"link-arg=-Map={link_map}"],
        cwd=BOARD,
        check=True,
    )
    symbols = subprocess.run(["arm-none-eabi-nm", "-C", str(BINARY)],
        check=True, capture_output=True, text=True).stdout
    required = "microcard_core::mc04_vm::" if engine == "mc04" else "microcard_engine_jcvm::"
    forbidden = ["microcard_engine_jcvm", "microcard_core::jcvm_"] if engine == "mc04" else ["microcard_core::mc04_vm::", "microcard_core::domains::"]
    if required not in symbols or any(name in symbols for name in forbidden):
        raise SystemExit(f"{engine}: linked interpreter selection is incorrect")
    other_map_symbols = ["microcard_engine_jcvm", "microcard_core9jcvm_card"] if engine == "mc04" else ["microcard_core7mc04_vm", "microcard_core7domains"]
    if any(name in link_map.read_text() for name in other_map_symbols):
        raise SystemExit(f"{engine}: link map includes the other interpreter")
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


def artifact(name, arguments, engine="mc04"):
    result = measure(arguments, engine)
    destination = ROOT / "artifacts" / "firmware" / name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BINARY, destination / f"microcard-{engine}.elf")
    shutil.copy2(BOARD / "target" / f"microcard-{engine}.map", destination / f"microcard-{engine}.map")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    # These failures enforce a public configuration contract, not a duplicate VM test.
    for features in ["software-crypto", "software-crypto,engine-mc04,engine-jcvm"]:
        result = subprocess.run(["cargo", "check", "--locked", "--no-default-features", "--features", features],
            cwd=BOARD, capture_output=True, text=True)
        if result.returncode == 0 or "select exactly one firmware engine" not in result.stderr:
            raise SystemExit("board accepted an invalid engine selection or failed for an unrelated reason")
    variants = {
        "production": artifact("mc04-reference", ["--no-default-features", "--features", "software-crypto"]),
        "development_debug": artifact("mc04-dk", []),
        "usb_ccid": artifact("mc04-dk-usb", ["--features", "usb-ccid"]),
        "dongle": artifact("mc04-dongle", ["--features", "dongle"]),
        "jcvm_development_debug": artifact("jcvm-dk", [], "jcvm"),
        "jcvm_dongle": artifact("jcvm-dongle", ["--features", "dongle"], "jcvm"),
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
        "PASS: MC04 and JCVM engine isolation, configuration, and flash/RAM budgets "
        f"({variants['development_debug']['text_bytes']} text bytes development, "
        f"{variants['usb_ccid']['text_bytes']} with USB CCID, "
        f"{variants['dongle']['text_bytes']} on the dongle)"
    )


if __name__ == "__main__":
    main()
