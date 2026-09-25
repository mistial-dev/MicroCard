#!/usr/bin/env python3
"""Classify an untouched DK JCAlgTest extended scan and pin its provenance."""
import argparse
import hashlib
import json
import pathlib
import statistics
import subprocess

from jcalgtest_gp_acceptance import IMAGE
from jcalgtest_profile import pinned_result


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = ROOT / "vendor/jcalgtest/client.lock.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values, numerator):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) * numerator // 100]


def inspect_csv(path, expected):
    observed = {}
    section = None
    metadata = {}
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith(("Used reader;", "Card ATR;", "AlgTestJClient version;",
                            "AlgTest applet version;")):
            name, value, *_ = line.split(";")
            metadata[name] = value.strip()
        if line.startswith(("javacard.", "javacardx.")) and ";" not in line:
            section = line
            continue
        if section is None or ";" not in line:
            continue
        name, status, *_ = line.split(";")
        key = (section, name.strip())
        if key in observed:
            raise ValueError(f"duplicate probe: {key}")
        observed[key] = status.strip()
    missing = sorted(expected.keys() - observed.keys())
    extra = sorted(observed.keys() - expected.keys())
    errors = sorted((section, name, status) for (section, name), status in observed.items()
                    if status not in {"yes", "no", "SystemException_ILLEGAL_USE"})
    supported = {key for key, status in observed.items() if status == "yes"}
    return metadata, {
        "expected_probes": len(expected),
        "observed_probes": len(observed),
        "supported": len(supported),
        "missing_probes": missing,
        "extra_probes": extra,
        "error_rows": errors,
        "missing_p71d321_support": sorted(key for key, yes in expected.items()
                                          if yes and key not in supported),
        "outside_p71d321_support": sorted(key for key in supported if not expected.get(key)),
    }


def client_completed(text, exit_code):
    return "Traceback" not in text and (exit_code == "0" if exit_code is not None else "KIND REQUEST:" in text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("--elf", required=True, type=pathlib.Path,
                        help="exact ELF flashed for this run")
    parser.add_argument("--source", required=True, type=pathlib.Path,
                        help="pinned upstream JCAlgTest desktop checkout")
    args = parser.parse_args()
    csvs = sorted(args.result.glob("*_ALGSUPPORT__*.csv"))
    if len(csvs) != 1:
        parser.error(f"expected one extended-support CSV, found {len(csvs)}")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip()
    expected_revision = json.loads(LOCK.read_text())["reference_client_commit"]
    if revision != expected_revision:
        parser.error("client checkout differs from the pinned revision")
    reference = {(section, name): supported
                 for section, probes in pinned_result()[1].items()
                 for name, supported in probes.items()}
    metadata, comparison = inspect_csv(csvs[0], reference)
    console = args.result / "console.log"
    upstream_logs = sorted(args.result.glob("ALGTEST_log_*.log"))
    transcript = console if console.exists() else (upstream_logs[-1] if upstream_logs else None)
    text = transcript.read_text(errors="replace") if transcript else ""
    exit_file = args.result / "client-exit-code.txt"
    exit_code = exit_file.read_text().strip() if exit_file.exists() else None
    times = [int(part.split(" ms", 1)[0]) for line in text.splitlines()
             if "elapsed=" in line
             for part in [line.split("elapsed=", 1)[1]]
             if " ms" in part and part.split(" ms", 1)[0].isdigit()]
    complete = (not comparison["missing_probes"] and not comparison["extra_probes"]
                and not comparison["error_rows"] and client_completed(text, exit_code))
    report = {
        "valid_extended_result": complete,
        "client_exit_code": exit_code,
        "firmware_sha256": digest(args.elf),
        "client_commit": revision,
        "applet_sha256": digest(IMAGE),
        "csv_sha256": digest(csvs[0]),
        "reader": metadata.get("Used reader"),
        "atr": metadata.get("Card ATR"),
        "client_version": metadata.get("AlgTestJClient version"),
        "applet_version": metadata.get("AlgTest applet version"),
        "host_pcsc_ms": {
            "count": len(times),
            "median": statistics.median(times) if times else None,
            "p95": percentile(times, 95),
            "maximum": max(times) if times else None,
        },
        "profile": comparison,
    }
    destination = args.result / "analysis.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{'PASS' if complete else 'INVALID'}: {comparison['observed_probes']} probes; "
          f"{len(comparison['error_rows'])} error rows; analysis at {destination}")
    if not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
