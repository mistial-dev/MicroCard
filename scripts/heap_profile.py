#!/usr/bin/env python3
"""Summarize simulator heap samples while running an existing acceptance workload."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def provenance():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT)
    status = git("status", "--porcelain")
    digest = hashlib.sha256(git("diff", "HEAD", "--binary"))
    digest.update(status)
    for name in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if name:
            path = ROOT / os.fsdecode(name)
            digest.update(name + b"\0")
            if path.is_symlink():
                digest.update(os.fsencode(os.readlink(path)))
            elif path.is_file():
                with path.open("rb") as source:
                    digest.update(hashlib.file_digest(source, "sha256").digest())
    simulator = ROOT / "target/debug/microcard-sim"
    with simulator.open("rb") as source:
        binary_hash = hashlib.file_digest(source, "sha256").hexdigest()
    return {"source_revision": git("rev-parse", "HEAD").decode().strip(),
            "working_tree_dirty": bool(status.strip()),
            "working_tree_sha256": digest.hexdigest(), "simulator_sha256": binary_hash}


def mark_phase(name):
    """Label subsequent samples after the caller's previous command has completed."""
    path = os.environ.get("MICROCARD_HEAP_REPORT")
    if path:
        with open(path, "a") as output:
            output.write(json.dumps({"phase": name}) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply an acceptance command after --")
    before = provenance()
    with tempfile.TemporaryDirectory(prefix="microcard-heap-") as directory:
        path = pathlib.Path(directory) / "samples.jsonl"
        result = subprocess.run(command, env={**os.environ, "MICROCARD_HEAP_REPORT": str(path)})
        samples = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    after = provenance()
    if not samples:
        raise SystemExit("no samples: build microcard-sim with --features heap-metrics first")
    stages = {}
    phases = {}
    phase = "unlabelled"
    measurements = []
    for sample in samples:
        if "phase" in sample:
            phase = sample["phase"]
            continue
        measurements.append(sample)
        if sample["peak_bytes"] < max(sample["before_bytes"], sample["live_bytes"]):
            raise SystemExit("invalid heap accounting")
        name = sample["stage"]
        if sample["ins"] >= 0:
            name += f"_{sample['ins']:02x}"
        for group in (stages, phases.setdefault(phase, {})):
            stage = group.setdefault(name, {"samples": 0, "peak_bytes": 0, "live_bytes": 0,
                                           "allocated_bytes": 0, "host_microseconds": 0})
            stage["samples"] += 1
            for field in ("peak_bytes", "live_bytes"):
                stage[field] = max(stage[field], sample[field])
            for field in ("allocated_bytes", "host_microseconds"):
                stage[field] += sample[field]
    if not measurements:
        raise SystemExit("no allocation samples: build microcard-sim with --features heap-metrics first")
    changed = before != after
    report = {"format": 1, "source_revision": before["source_revision"],
              "working_tree_dirty": before["working_tree_dirty"] or after["working_tree_dirty"] or changed,
              "inputs_changed_during_run": changed, "inputs_before": before, "inputs_after": after,
              "platform": platform.platform(), "command": command,
              "exit_code": result.returncode, "measurement": "host requested allocation bytes",
              "excludes": ["allocator metadata", "stack", "device latency"],
              "note": "Host file reads and pointer sizes differ from memory-mapped board flash.",
              "peak_bytes": max(s["peak_bytes"] for s in measurements), "stages": stages, "phases": phases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Host heap peak: {report['peak_bytes']} bytes; report: {args.output}")
    if changed:
        print("Inputs changed during measurement; this report is not a stable-revision baseline.")
    raise SystemExit(result.returncode or int(changed))


if __name__ == "__main__":
    main()
