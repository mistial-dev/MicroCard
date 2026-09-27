#!/usr/bin/env python3
"""Read the opt-in JCVM diagnostic APDU through the existing PC/SC relay."""
import argparse
import json
import pathlib
import struct
import subprocess
import tempfile
import time

from scp03_acceptance import ROOT

COMMAND = "80f3000000"
WORDS = 101
FIELDS = (
    "version", "attempt", "scope", "phase", "decision", "generation_hi",
    "generation_lo", "erased_pages", "programmed_words", "elapsed_us",
    "reset_reason", "error", "last_failure_attempt", "last_failure_phase",
    "last_failure_error",
)
SUMMARY = ("attempt", "elapsed_us", "erased_pages", "programmed_words",
           "decision", "error", "generation_hi", "generation_lo")
PHASES = ("prepare", "execute", "publish", "respond", "maintenance", "drained")
ERROR_NAMES = {
    0: "none", 1: "storage", 2: "incompatible-state", 3: "quota",
    4: "authentication", 5: "unauthorized", 6: "cancelled",
    7: "native", 8: "format", 9: "other",
}


def decode(response: bytes) -> dict:
    if response == bytes.fromhex("6d00") or response == bytes.fromhex("6982"):
        raise ValueError("firmware does not expose the opt-in diagnostic APDU")
    if len(response) != WORDS * 4 + 2 or response[-2:] != b"\x90\x00":
        raise ValueError(f"unexpected diagnostic response: {response.hex()}")
    words = struct.unpack(f">{WORDS}I", response[:-2])
    if words[0] != 2:
        raise ValueError(f"unsupported diagnostic version {words[0]}")
    data = dict(zip(FIELDS, words[:15]))
    data["maintenance_recovered"] = data["error"] == 10
    data["last_failure_category"] = ERROR_NAMES.get(data["last_failure_error"], "unknown")
    data["generation"] = (data["generation_hi"] << 32) | data["generation_lo"]
    data["phase_us"] = dict(zip(PHASES, words[15:21]))
    for name, start in (("last_apdu", 21), ("last_maintenance", 29)):
        summary = dict(zip(SUMMARY, words[start:start + 8]))
        summary["generation"] = (summary["generation_hi"] << 32) | summary["generation_lo"]
        phase_start = 37 if name == "last_apdu" else 43
        summary["phase_us"] = dict(zip(PHASES, words[phase_start:phase_start + 6]))
        publications_at = 49 if name == "last_apdu" else 74
        count = words[publications_at]
        slots = [words[publications_at + 1 + index * 6:
                       publications_at + 7 + index * 6] for index in range(4)]
        summary["publication_count"] = count
        summary["publications"] = [
            {
                "decision": slots[index % 4][0] & 0x7fffffff,
                "incomplete": bool(slots[index % 4][0] & 0x80000000),
                "generation": (slots[index % 4][1] << 32) | slots[index % 4][2],
                "erased_pages": slots[index % 4][3],
                "programmed_words": slots[index % 4][4],
                "elapsed_us": slots[index % 4][5],
            }
            for index in range(max(0, count - 4), count)
        ]
        data[name] = summary
    data["retained_from_previous_boot"] = bool(words[99])
    data["last_rsa_generate_us"] = words[100]
    return data


def query(reader: str, classes: pathlib.Path, wait_seconds: float = 10) -> dict:
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            result = subprocess.run(
                ["java", "-cp", str(classes), "PcscRelay", reader],
                input=COMMAND + "\n", text=True, capture_output=True, timeout=5,
                check=True,
            )
            response = bytes.fromhex(result.stdout.strip().splitlines()[-1])
        except (subprocess.SubprocessError, IndexError) as error:
            if time.monotonic() >= deadline:
                if isinstance(error, subprocess.CalledProcessError):
                    raise RuntimeError(error.stderr.strip() or "PC/SC diagnostic query failed") from error
                raise
            time.sleep(0.5)
            continue
        return decode(response)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--wait", type=float, default=10,
                        help="seconds to wait for the reader to reappear after a reset")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="microcard-diagnostic-") as temporary:
        classes = pathlib.Path(temporary)
        subprocess.run(["javac", "--release", "21", "-d", classes,
                        ROOT / "scripts/PcscRelay.java"], check=True)
        print(json.dumps(query(args.reader, classes, args.wait), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
