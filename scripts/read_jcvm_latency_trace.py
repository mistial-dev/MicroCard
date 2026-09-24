#!/usr/bin/env python3
"""Read the opt-in JCVM latency counters from a running DK over SWD."""
import argparse
import pathlib
import shutil
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
APDU_FIELDS = (
    "apdu_count", "apdu_start_us", "apdu_us", "cancel_polls",
    "wait_extensions", "erase_calls", "erase_us", "program_words",
    "program_us", "maintenance_calls", "maintenance_us",
    "maintenance_error", "erase_base", "erase_size",
)
PATCH_FIELDS = (
    "reason", "heap_start", "heap_end", "static_start", "static_end",
    "snapshot_required", "patch_bytes",
)
PATCH_REASONS = {
    0: "no commit recorded", 1: "first snapshot", 2: "no append frame",
    3: "patch exceeds frame", 4: "append patch",
}


def symbols(elf):
    nm = shutil.which("llvm-nm") or shutil.which("arm-none-eabi-nm")
    if nm is None:
        raise RuntimeError("llvm-nm or arm-none-eabi-nm is required")
    result = subprocess.run([nm, "-n", str(elf)], check=True, text=True, capture_output=True)
    addresses = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ("MICROCARD_LATENCY_TRACE", "MICROCARD_JCVM_PATCH_TRACE"):
            addresses[parts[2]] = int(parts[0], 16)
    if len(addresses) != 2:
        raise RuntimeError("ELF lacks both trace symbols; build with --features usb-ccid,latency-trace")
    return addresses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=pathlib.Path,
                        default=ROOT / "artifacts/development-firmware/jcvm/dk/microcard.elf")
    parser.add_argument("--probe", required=True, help="probe-rs selector, such as VID:PID:serial")
    args = parser.parse_args()
    addresses = symbols(args.elf)
    apdu = addresses["MICROCARD_LATENCY_TRACE"]
    patch = addresses["MICROCARD_JCVM_PATCH_TRACE"]
    base = min(apdu, patch)
    end = max(apdu + 4 * len(APDU_FIELDS), patch + 4 * len(PATCH_FIELDS))
    if (end - base) % 4:
        raise RuntimeError("unaligned trace symbols")
    count = (end - base) // 4
    result = subprocess.run([
        "probe-rs", "read", "b32", hex(base), str(count),
        "--chip", "nRF52840_xxAA", "--probe", args.probe, "--protocol", "swd",
    ], check=True, text=True, capture_output=True)
    values = [int(word, 16) for word in result.stdout.split()]
    if len(values) != count:
        raise RuntimeError(f"expected {count} words, received {len(values)}")
    apdu_at = (apdu - base) // 4
    patch_at = (patch - base) // 4
    apdu_values = dict(zip(APDU_FIELDS, values[apdu_at:apdu_at + len(APDU_FIELDS)]))
    patch_values = dict(zip(PATCH_FIELDS, values[patch_at:patch_at + len(PATCH_FIELDS)]))
    if apdu_values["apdu_count"] == 0:
        print("No APDU recorded since target reset; run a probe before reading counters.")
    print("Last APDU:")
    for name, value in apdu_values.items():
        print(f"  {name}: {value:#x}" if name == "erase_base" else f"  {name}: {value}")
    print("Last persistence decision:")
    for name, value in patch_values.items():
        label = f" ({PATCH_REASONS.get(value, 'unknown')})" if name == "reason" else ""
        print(f"  {name}: {value}{label}")


if __name__ == "__main__":
    main()
