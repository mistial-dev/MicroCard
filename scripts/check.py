#!/usr/bin/env python3
"""Host validation entry point. Sustained fuzzing is a separate gate."""
import argparse
import pathlib
from validation_common import ROOT, run, write_timings
from validation_quick import managed, rust, schemas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", action="store_true", help="run full host and recovery acceptance")
    parser.add_argument("--suite", choices=("all", "rust", "managed", "schemas", "analyzer", "compiler", "wallet", "board"), default="all")
    parser.add_argument("--jobs", type=int, default=1, help="bounded build, compiler-case, and acceptance workers (default: 1)")
    parser.add_argument("--timings", type=pathlib.Path, default=ROOT / "work/validation-timings.json")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.checkpoint and args.suite != "all":
        parser.error("--checkpoint requires --suite all; use a focused suite without --checkpoint")
    try:
        if args.suite in ("all", "schemas"):
            schemas()
        if args.checkpoint:
            from validation_checkpoint import run_checkpoint
            run_checkpoint(args.jobs)
        else:
            if args.suite in ("all", "rust"):
                rust()
            if args.suite in ("all", "managed"):
                managed(args.jobs)
            if args.suite == "analyzer":
                from analyzer_cases import run_analyzer_cases
                run_analyzer_cases()
            if args.suite == "compiler":
                from compiler_cases import run_compiler_cases
                run_compiler_cases(args.jobs)
            if args.suite == "wallet":
                run("python3", "scripts/wallet_acceptance.py")
            if args.suite == "board":
                run("python3", "scripts/board_budgets.py", "--check")
        print(f"PASS: {'checkpoint' if args.checkpoint else args.suite + ' quick'} validation")
    finally:
        write_timings(args.timings)


if __name__ == "__main__":
    main()
