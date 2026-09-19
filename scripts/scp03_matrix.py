#!/usr/bin/env python3
"""Build and test every meaningful SCP03 capability combination of microcard-core."""
import argparse
import itertools
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CRATE = "microcard-core"
# scp03-renc implies scp03-rmac through Cargo, so the reserved b7 b6 = 10 encoding of
# SCP03 1.1.2.6 Table 5-1 cannot be selected and is absent from this sweep.
OPTIONAL = ["scp03-rmac", "scp03-renc", "scp03-s16", "scp03-pseudo-random"]


def combinations():
    """Every selectable set, with the ones Cargo would reject removed."""
    seen = []
    for size in range(len(OPTIONAL) + 1):
        for chosen in itertools.combinations(OPTIONAL, size):
            if "scp03-renc" in chosen and "scp03-rmac" not in chosen:
                continue
            seen.append(list(chosen))
    return seen


def oracle(features):
    """Replay the independent host implementation against a card built this way.

    Builds without R-MAC are skipped. The sample reader the acceptance script executes
    requires response integrity, so a card that cannot offer it refuses the reader by
    design, which says nothing about the secure channel.
    """
    arguments = ["--no-default-features"]
    if features:
        arguments += ["--features", ",".join(features)]
    environment = {
        **os.environ,
        "MICROCARD_BUILD": " ".join(["-p", "microcard-sim", *arguments]),
    }
    result = subprocess.run(
        ["python3", "scripts/scp03_acceptance.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
    )
    return result.returncode == 0, result.stdout + result.stderr


def run(features, check_only):
    arguments = ["--no-default-features", "--features", ",".join(["mc04", "software-crypto", *features])]
    command = ["cargo", "test" if not check_only else "check", "-p", CRATE, "--lib", "--release", *arguments]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compile only, skip the test run")
    parser.add_argument(
        "--oracle",
        action="store_true",
        help="also replay scripts/scp03_acceptance.py against a simulator built each way",
    )
    arguments = parser.parse_args()
    failures = []
    for features in combinations():
        label = ",".join(features) or "<none>"
        ok, output = run(features, arguments.check)
        print(f"{'PASS' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append((label, output))
        elif arguments.oracle and "scp03-rmac" in features:
            ok, output = oracle(features)
            print(f"{'PASS' if ok else 'FAIL'} {label} host oracle")
            if not ok:
                failures.append((f"{label} host oracle", output))
    for label, output in failures:
        print(f"\n--- {label} ---\n{output[-2000:]}", file=sys.stderr)
    if failures:
        raise SystemExit(f"{len(failures)} SCP03 capability combinations failed")
    print(f"PASS: {len(combinations())} SCP03 capability combinations build and test")


if __name__ == "__main__":
    main()
