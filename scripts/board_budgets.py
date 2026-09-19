#!/usr/bin/env python3
"""Build the nRF52840 variants with the board linker config and enforce size budgets."""
import argparse
import json
import pathlib
import shutil
import subprocess
import tempfile
from firmware_link import SOFTWARE, inspect_link

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOARD = ROOT / "board" / "nrf52840"
DESTINATION = ROOT / "docs" / "BOARD_BUDGETS.json"


def measure(extra_arguments, engine, target):
    arguments = ["--features", f"engine-{engine}", *extra_arguments]
    target.mkdir(parents=True, exist_ok=True)
    binary = target / "thumbv7em-none-eabihf" / "release" / "microcard-nrf52840"
    link_map = target / f"microcard-{engine}.map"
    subprocess.run(
        ["cargo", "rustc", "--release", "--locked", "--target-dir", str(target), *arguments, "--", "-C", f"link-arg=-Map={link_map}"],
        cwd=BOARD,
        check=True,
    )
    symbols = subprocess.run(["arm-none-eabi-nm", "-C", str(binary)],
        check=True, capture_output=True, text=True).stdout
    required = "microcard_core::mc04_vm::" if engine == "mc04" else "microcard_engine_jcvm::"
    forbidden = ["microcard_engine_jcvm", "microcard_core::jcvm_"] if engine == "mc04" else ["microcard_core::mc04_vm::", "microcard_core::domains::"]
    if required not in symbols or any(name in symbols for name in forbidden):
        raise SystemExit(f"{engine}: linked interpreter selection is incorrect")
    other_map_symbols = ["microcard_engine_jcvm", "microcard_core9jcvm_card"] if engine == "mc04" else ["microcard_core7mc04_vm", "microcard_core7domains"]
    if any(name in link_map.read_text() for name in other_map_symbols):
        raise SystemExit(f"{engine}: link map includes the other interpreter")
    if engine == "jcvm":
        # Inspect loadable bytes, not ELF debug strings or symbol names.
        with tempfile.TemporaryDirectory(prefix="microcard-api-names-") as temporary:
            image = pathlib.Path(temporary) / "firmware.bin"
            subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", str(binary), str(image)], check=True)
            flashed = image.read_bytes()
        api = json.loads((ROOT / "format/jcvm-api.json").read_text())
        names = [klass["name"] for package in api["packages"] for klass in package["classes"]]
        if any(name.encode() in flashed for name in names):
            raise SystemExit("jcvm: diagnostic API names leaked into firmware")
    size = shutil.which("arm-none-eabi-size")
    if size is None:
        raise SystemExit("arm-none-eabi-size is required for the board budget gate")
    output = subprocess.run([size, str(binary)], check=True, capture_output=True, text=True).stdout
    values = output.strip().splitlines()[-1].split()
    return binary, link_map, {
        "text_bytes": int(values[0]),
        "data_bytes": int(values[1]),
        "bss_bytes": int(values[2]),
    }


def artifact(name, arguments, engine="mc04", hardware=True):
    # Different profiles must never overwrite the ELF between linking and inspection.
    binary, link_map, result = measure(arguments, engine, BOARD / "target" / "profiles" / name)
    inspect_link(binary, link_map, hardware)
    if hardware:
        tree = subprocess.run(["cargo", "tree", "--locked", "--edges", "normal", "--prefix", "none",
            "--features", f"engine-{engine}", *arguments], cwd=BOARD,
            check=True, capture_output=True, text=True).stdout
        software = {line.split()[0] for line in tree.splitlines()} & SOFTWARE
        if software:
            raise SystemExit(f"{name}: hardware firmware includes software crypto: {sorted(software)}")
    destination = ROOT / "artifacts" / "firmware" / name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, destination / f"microcard-{engine}.elf")
    shutil.copy2(link_map, destination / f"microcard-{engine}.map")
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
    result = subprocess.run(["cargo", "check", "--locked", "--features", "engine-mc04,software-crypto"],
        cwd=BOARD, capture_output=True, text=True)
    if result.returncode == 0 or "cc310 excludes software providers" not in result.stderr:
        raise SystemExit("board failed to reject mixed hardware/reference providers")
    variants = {
        "software_reference": artifact("mc04-reference", ["--no-default-features", "--features", "software-crypto"], hardware=False),
        "hardware_release": artifact("mc04-release", ["--no-default-features", "--features", "cc310"]),
        "development_debug": artifact("mc04-dk", []),
        "usb_ccid": artifact("mc04-dk-usb", ["--features", "usb-ccid"]),
        "dongle": artifact("mc04-dongle", ["--features", "dongle"]),
        "jcvm_development_debug": artifact("jcvm-dk", [], "jcvm"),
        "jcvm_dongle": artifact("jcvm-dongle", ["--features", "dongle"], "jcvm"),
    }
    # Small profile-specific headroom above measured links, not a shared 350 KiB cap.
    text_limits = {
        "software_reference": 186_000, "hardware_release": 212_000,
        "development_debug": 212_000, "usb_ccid": 224_000,
        "dongle": 224_000, "jcvm_development_debug": 165_000,
        "jcvm_dongle": 175_000,
    }
    for name, result in variants.items():
        result["ceilings"] = {"text_bytes": text_limits[name],
            "data_bytes": 0 if name == "software_reference" else 160,
            "bss_bytes": 199_000}
        for field, ceiling in result["ceilings"].items():
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
