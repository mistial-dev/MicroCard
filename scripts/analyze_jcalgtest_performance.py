#!/usr/bin/env python3
"""Classify a pinned upstream JCAlgTest DK performance run without changing its CSV."""
import argparse
import json
import math
import pathlib
import re
import subprocess

from analyze_jcalgtest_dk import LOCK, digest
from jcalgtest_gp_acceptance import IMAGE

STATUSES = {"NO_SUCH_ALGORITHM", "CANT_BE_MEASURED", "ILLEGAL_VALUE"}
TRANSPORT = ("SCARD_E_", "CARD_HAS_RETURN_VALUE_", "TIMEOUT", "CRASH",
             "EXCEPTION IN THREAD", "UNKONWN_ERROR", "UNKNOWN_ERROR")
SESSION_FAILURES = {"6982", "6A82"}


def inspect_csv(text):
    entries = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("method name:;"):
            if current is not None:
                entries.append(current)
            current = {"name": line.split(";", 1)[1].strip(), "outcome": None}
        elif current is not None and line in STATUSES:
            current["outcome"] = line
        elif current is not None and line.startswith("operation stats (ms/op):;"):
            fields = line.split(";")
            if len(fields) >= 3 and fields[1] == "avg op:":
                value = float(fields[2])
                current["outcome"] = "measured" if math.isfinite(value) and value >= 0 else "invalid_measurement"
                current["mean_ms_per_op"] = value
    if current is not None:
        entries.append(current)
    counts = {}
    for entry in entries:
        outcome = entry["outcome"] or "incomplete"
        counts[outcome] = counts.get(outcome, 0) + 1
    return entries, counts


def inspect_log(text):
    """Find lost authority or applet selection hidden by an unmeasured CSV row."""
    return [line.strip() for line in text.splitlines()
            if (match := re.search(r"\bSW=([0-9A-Fa-f]{4})\b", line))
            and match.group(1).upper() in SESSION_FAILURES]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("--elf", required=True, type=pathlib.Path)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    args = parser.parse_args()
    csvs = sorted([*args.result.glob("*PERFORMANCE*.csv"),
                   *args.result.glob("*ECCPERF*.csv"),
                   *args.result.glob("*FINGERPRINT*.csv")])
    if len(csvs) != 1:
        parser.error(f"expected one performance CSV, found {len(csvs)}")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip()
    if revision != json.loads(LOCK.read_text())["reference_client_commit"]:
        parser.error("client checkout differs from the pinned revision")
    raw = csvs[0].read_text(errors="replace")
    entries, counts = inspect_csv(raw)
    console = args.result / "console.log"
    transcript = console.read_text(errors="replace") if console.exists() else ""
    exit_file = args.result / "client-exit-code.txt"
    exit_code = exit_file.read_text().strip() if exit_file.exists() else None
    errors = [line for line in transcript.splitlines()
              if any(word in line.upper() for word in TRANSPORT)]
    logs = sorted(args.result.glob("ALGTEST_log_*.log"))
    session_failures = inspect_log(logs[0].read_text(errors="replace")) if len(logs) == 1 else ["missing or ambiguous APDU log"]
    finished = bool(re.search(r"Total test time:;\s*\d+ seconds\.", raw))
    complete = (exit_code == "0" and finished and bool(entries)
                and counts.get("incomplete", 0) == 0 and not errors)
    valid = complete and counts.get("invalid_measurement", 0) == 0 and not session_failures
    report = {
        "completed_run": complete,
        "valid_performance_result": valid,
        "fully_measured": valid and counts.get("CANT_BE_MEASURED", 0) == 0,
        "client_exit_code": exit_code,
        "firmware_sha256": digest(args.elf),
        "client_commit": revision,
        "applet_sha256": digest(IMAGE),
        "csv_sha256": digest(csvs[0]),
        "method_rows": len(entries),
        "outcomes": counts,
        "unmeasured": [entry["name"] for entry in entries if entry["outcome"] == "CANT_BE_MEASURED"],
        "invalid_measurements": [entry for entry in entries if entry["outcome"] == "invalid_measurement"],
        "transport_error_rows": errors,
        "session_failure_rows": session_failures,
    }
    destination = args.result / "analysis.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{'PASS' if valid else 'INVALID'}: {len(entries)} method rows; "
          f"{counts.get('measured', 0)} measured; "
          f"{counts.get('CANT_BE_MEASURED', 0)} unmeasured; "
          f"{counts.get('invalid_measurement', 0)} invalid measurements; "
          f"{len(errors)} transport errors; {len(session_failures)} session failures")
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
