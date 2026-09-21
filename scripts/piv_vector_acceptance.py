#!/usr/bin/env python3
"""Replay committed PIV commands against the Java Card engine.

This is the gated acceptance run for the Java Card engine. Unlike
`jcvm_applet_acceptance.py`, which takes a load file on the command line, everything this
needs is committed, so it runs on a clean checkout with no argument and no external build.

What it proves is narrow and worth stating. The card is blank, so most of these commands
answer that the object asked for is absent. That answer still comes from the applet's own
dispatch, its own data model and its own PIN state, so a wrong answer means the engine
mis-ran the applet. The expected values and their provenance are in the JSON fixture beside
the load file.
"""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM = ROOT / "target/debug/microcard-sim"
VECTORS = ROOT / "crates/microcard-engine-jcvm/tests/vectors"
FIXTURE = VECTORS / "piv_blank_card.json"


def main() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    load_file = VECTORS / fixture["load_file"]
    if not load_file.is_file():
        raise SystemExit(f"No load file at {load_file}")
    if not SIM.is_file():
        raise SystemExit(f"No simulator at {SIM}. Run cargo build first.")

    exchanges = fixture["exchanges"]
    result = subprocess.run(
        [str(SIM), "serve-jcvm", str(load_file)],
        input="\n".join(e["command"] for e in exchanges) + "\n",
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    if result.stderr:
        raise SystemExit(f"JCVM diagnostics reported:\n{result.stderr}")
    answers = result.stdout.split()
    if len(answers) != len(exchanges):
        raise SystemExit(
            f"Sent {len(exchanges)} commands and read {len(answers)} answers"
        )

    failures = []
    for exchange, answer in zip(exchanges, answers):
        expected = exchange["sw"].upper()
        # A response carrying data ends in its status word.
        actual = answer.upper()[-4:]
        if actual != expected:
            failures.append(
                f'{exchange["description"]}: expected {expected} and read {actual}'
            )
    if failures:
        raise SystemExit(
            "PIV vector replay failed:\n  " + "\n  ".join(failures)
        )
    print(f"PASS: {len(exchanges)} PIV commands answered by the applet on a blank card")


if __name__ == "__main__":
    main()
