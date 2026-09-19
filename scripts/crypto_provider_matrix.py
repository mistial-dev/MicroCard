#!/usr/bin/env python3
"""Measure provider replacement stages; reject software dependencies in hardware builds."""
import argparse
import json
import subprocess
from board_budgets import BOARD, measure

STAGES = {
    "software": ["software-crypto"],
    "sha256": ["cc310-sha256", "software-hmac", "software-aes", "software-p256"],
    "p256": ["cc310-sha256", "cc310-p256", "software-hmac", "software-aes"],
    "hardware": ["cc310"],
}
SOFTWARE = {"aes", "cmac", "ccm", "p256", "ecdsa", "elliptic-curve", "sha2", "hmac"}


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
        result = measure(arguments, args.engine)
        result.pop("ceilings")
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
