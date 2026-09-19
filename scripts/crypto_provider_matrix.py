#!/usr/bin/env python3
"""Measure provider replacement stages; reject software dependencies in hardware builds."""
import argparse
import json
import hashlib
import subprocess
from board_budgets import BOARD, ROOT, measure
from firmware_link import SOFTWARE, inspect_link

STAGES = {
    "software": ["software-crypto"],
    "sha256": ["cc310-sha256", "software-hmac", "software-aes", "software-p256"],
    "p256": ["cc310-sha256", "cc310-p256", "software-hmac", "software-aes"],
    "hardware": ["cc310"],
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("mc04", "jcvm"), default="mc04")
    parser.add_argument("--layout", choices=("dk", "dongle"), default="dk")
    parser.add_argument("--output", help="write measurements as host JSON")
    args = parser.parse_args()
    results = {}
    for stage, providers in STAGES.items():
        features = [*providers, *(["dongle-layout"] if args.layout == "dongle" else [])]
        arguments = ["--no-default-features", "--features", ",".join(["development-debug", *features])]
        target = BOARD / "target" / "profiles" / f"crypto-{args.engine}-{args.layout}-{stage}"
        binary, link_map, result = measure(arguments, args.engine, target)
        result["elf_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        result["link_map"] = link_map.relative_to(ROOT).as_posix()
        result["link_inspection"] = inspect_link(binary, link_map, stage == "hardware")
        tree = subprocess.run(
            ["cargo", "tree", "--edges", "normal", "--prefix", "none", "--features", f"engine-{args.engine}", *arguments],
            cwd=BOARD, check=True, capture_output=True, text=True,
        ).stdout
        software = sorted({line.split()[0] for line in tree.splitlines()} & SOFTWARE)
        if stage == "hardware" and software:
            raise SystemExit(f"hardware firmware includes software crypto: {software}")
        result["software_dependencies"] = software
        result["features"] = [f"engine-{args.engine}", "development-debug", *features]
        results[stage] = result
        print(f"{stage}: {result['text_bytes']} text, {result['data_bytes']} data, {result['bss_bytes']} bss bytes")
    report = {"format": 1, "engine": args.engine, "layout": args.layout, "target": "thumbv7em-none-eabihf", "device_latency_measured": False, "stages": results}
    if args.output:
        with open(args.output, "w") as output:
            json.dump(report, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    main()
