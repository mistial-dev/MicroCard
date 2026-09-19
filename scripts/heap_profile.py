#!/usr/bin/env python3
"""Summarize simulator heap samples while running an existing acceptance workload."""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply an acceptance command after --")
    with tempfile.TemporaryDirectory(prefix="microcard-heap-") as directory:
        path = pathlib.Path(directory) / "samples.jsonl"
        result = subprocess.run(command, env={**os.environ, "MICROCARD_HEAP_REPORT": str(path)})
        samples = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    if not samples:
        raise SystemExit("no samples: build microcard-sim with --features heap-metrics first")
    stages = {}
    for sample in samples:
        if sample["peak_bytes"] < max(sample["before_bytes"], sample["live_bytes"]):
            raise SystemExit("invalid heap accounting")
        name = sample["stage"]
        if sample["ins"] >= 0:
            name += f"_{sample['ins']:02x}"
        stage = stages.setdefault(name, {"samples": 0, "peak_bytes": 0, "live_bytes": 0,
                                        "allocated_bytes": 0, "host_microseconds": 0})
        stage["samples"] += 1
        for field in ("peak_bytes", "live_bytes"):
            stage[field] = max(stage[field], sample[field])
        for field in ("allocated_bytes", "host_microseconds"):
            stage[field] += sample[field]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    report = {"format": 1, "source_revision": revision, "platform": platform.platform(), "command": command,
              "exit_code": result.returncode, "measurement": "host requested allocation bytes",
              "excludes": ["allocator metadata", "stack", "device latency"],
              "note": "Host file reads and pointer sizes differ from memory-mapped board flash.",
              "peak_bytes": max(s["peak_bytes"] for s in samples), "stages": stages}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Host heap peak: {report['peak_bytes']} bytes; report: {args.output}")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
