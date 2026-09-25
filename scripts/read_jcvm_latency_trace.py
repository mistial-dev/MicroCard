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
    "snapshot_bytes", "maximum_bytes", "heap_bytes",
    "append_commits", "snapshot_commits",
)
MAXIMUM_FIELDS = (
    "max_apdu_us", "erase_calls", "erase_us", "program_words",
    "program_us", "wait_extensions", "total_erase_calls", "total_program_words",
)
PATCH_REASONS = {
    0: "no commit recorded", 1: "first snapshot", 2: "no append frame",
    3: "patch exceeds frame", 4: "append patch",
}
EVENT_NAMES = (
    "BOOT", "USB_READY", "REQUEST", "EXECUTION_DONE", "RESPONSE_QUEUED",
    "MAINTENANCE_START", "MAINTENANCE_DONE", "ERASE_PAGE_START",
    "ERASE_PAGE_DONE", "PROGRAM_START", "PROGRAM_DONE", "WAIT_EXTENSION",
    "USB_POWER_LOST", "PANIC", "HARD_FAULT", "RENEW_PHASE", "PANIC_FILE",
)
RETAINED_HEADER_WORDS = 9
RETAINED_EVENTS = 128
RETAINED_EVENT_WORDS = 4


def symbols(elf):
    nm = shutil.which("llvm-nm") or shutil.which("arm-none-eabi-nm")
    if nm is None:
        raise RuntimeError("llvm-nm or arm-none-eabi-nm is required")
    result = subprocess.run([nm, "-n", str(elf)], check=True, text=True, capture_output=True)
    addresses = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in (
            "MICROCARD_LATENCY_TRACE", "MICROCARD_JCVM_PATCH_TRACE",
            "MICROCARD_RETAINED_TRACE", "MICROCARD_JCVM_ENGINE_ERROR",
            "MICROCARD_JCVM_CORE_ERROR",
            "MICROCARD_JCVM_CHECKPOINT_ERROR",
            "MICROCARD_MAX_APDU_TRACE",
        ):
            addresses[parts[2]] = int(parts[0], 16)
    if len(addresses) < 6:
        raise RuntimeError("ELF lacks trace symbols; build with --features usb-ccid,latency-trace")
    return addresses


def read_words(address, count, probe):
    result = subprocess.run([
        "probe-rs", "read", "b32", hex(address), str(count),
        "--chip", "nRF52840_xxAA", "--probe", probe, "--protocol", "swd",
    ], check=True, text=True, capture_output=True)
    values = [int(word, 16) for word in result.stdout.split()]
    if len(values) != count:
        raise RuntimeError(f"expected {count} words, received {len(values)}")
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=pathlib.Path,
                        default=ROOT / "artifacts/development-firmware/jcvm/dk/microcard.elf")
    parser.add_argument("--probe", required=True, help="probe-rs selector, such as VID:PID:serial")
    parser.add_argument("--events", type=int, default=24,
                        help="number of latest retained events to print (default: 24)")
    parser.add_argument("--legacy-patch", action="store_true",
                        help="decode the ten-field patch trace from earlier diagnostic images")
    args = parser.parse_args()
    if args.events < 0:
        parser.error("--events must be nonnegative")
    patch_fields = PATCH_FIELDS[:10] if args.legacy_patch else PATCH_FIELDS
    addresses = symbols(args.elf)
    apdu = addresses["MICROCARD_LATENCY_TRACE"]
    patch = addresses["MICROCARD_JCVM_PATCH_TRACE"]
    base = min(apdu, patch)
    end = max(apdu + 4 * len(APDU_FIELDS), patch + 4 * len(patch_fields))
    if (end - base) % 4:
        raise RuntimeError("unaligned trace symbols")
    count = (end - base) // 4
    values = read_words(base, count, args.probe)
    apdu_at = (apdu - base) // 4
    patch_at = (patch - base) // 4
    apdu_values = dict(zip(APDU_FIELDS, values[apdu_at:apdu_at + len(APDU_FIELDS)]))
    patch_values = dict(zip(patch_fields, values[patch_at:patch_at + len(patch_fields)]))
    if apdu_values["apdu_count"] == 0:
        print("No APDU recorded since target reset; run a probe before reading counters.")
    print("Last APDU:")
    for name, value in apdu_values.items():
        print(f"  {name}: {value:#x}" if name == "erase_base" else f"  {name}: {value}")
    print("Last persistence decision:")
    for name, value in patch_values.items():
        label = f" ({PATCH_REASONS.get(value, 'unknown')})" if name == "reason" else ""
        print(f"  {name}: {value}{label}")
    engine_error = read_words(addresses["MICROCARD_JCVM_ENGINE_ERROR"], 1, args.probe)[0]
    core_error = read_words(addresses["MICROCARD_JCVM_CORE_ERROR"], 1, args.probe)[0]
    checkpoint_error = read_words(addresses["MICROCARD_JCVM_CHECKPOINT_ERROR"], 1, args.probe)[0]
    print(f"Last JCVM session error: engine={engine_error} core={core_error} "
          f"checkpoint_stage={checkpoint_error >> 16} checkpoint_error={checkpoint_error & 0xffff}")
    if "MICROCARD_MAX_APDU_TRACE" in addresses:
        maximum = read_words(addresses["MICROCARD_MAX_APDU_TRACE"], len(MAXIMUM_FIELDS), args.probe)
        print("Slowest APDU and run totals:")
        for name, value in zip(MAXIMUM_FIELDS, maximum):
            print(f"  {name}: {value}")
    retained = read_words(
        addresses["MICROCARD_RETAINED_TRACE"],
        RETAINED_HEADER_WORDS + RETAINED_EVENTS * RETAINED_EVENT_WORDS,
        args.probe,
    )
    (magic, version, next_seq, boot_count, reset_reason, last_poll, max_gap,
     previous_last_poll, previous_max_gap) = retained[:9]
    if (magic, version) != (0x4D435452, 2):
        print("Retained event ring is uninitialized.")
        return
    print(f"Retained trace: boots={boot_count} reset_reason={reset_reason:#x} "
          f"max_usb_poll_gap_us={max_gap} last_poll_us={last_poll} "
          f"previous_max_gap_us={previous_max_gap} "
          f"previous_last_poll_us={previous_last_poll}")
    entries = []
    for offset in range(RETAINED_HEADER_WORDS, len(retained), RETAINED_EVENT_WORDS):
        sequence, time_us, kind, detail = retained[offset:offset + RETAINED_EVENT_WORDS]
        if sequence and ((next_seq - sequence) & 0xffffffff) < RETAINED_EVENTS:
            entries.append((sequence, time_us, kind, detail))
    entries.sort(key=lambda entry: (next_seq - entry[0]) & 0xffffffff, reverse=True)
    for sequence, time_us, kind, detail in (entries[-args.events:] if args.events else []):
        name = EVENT_NAMES[kind - 1] if 1 <= kind <= len(EVENT_NAMES) else f"UNKNOWN_{kind}"
        print(f"  {sequence:>8} {time_us:>10} us {name:<19} {detail:#010x}")


if __name__ == "__main__":
    main()
