#!/usr/bin/env python3
"""Differential checks for the direct, borrowed MC04 CIL executor."""
import json, pathlib, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM = ROOT / "target/debug/microcard-sim"
ASSEMBLY = ROOT / "work/counter.mca"
SUPPORTED = {"Arithmetic", "Object", "Array", "Bytes", "EmptyBytes", "EmptyIntegers",
             "CollectionBytes", "CollectionIntegers", "Remainder", "Divide", "UnsignedDivide",
             "UnsignedRemainder", "UnsignedLess", "UnsignedGreater", "UnsignedCheckedAdd",
             "CheckedByte", "CheckedSByte", "CheckedShort", "CheckedUShort", "AsUInt",
             "UnsignedThroughCall", "BitwiseNot", "Branch", "Switch"}

def main():
    cases = json.loads(subprocess.run(["dotnet", str(ROOT / "tests/Reference/bin/Release/net10.0/Reference.dll")],
                                      check=True, capture_output=True, text=True).stdout)
    mapping = json.loads((ROOT / "work/counter.map.json").read_text())
    methods = {(row["type"], row["method"]): row["id"] for row in mapping}
    checked = 0
    for case in cases:
        if case["method"] not in SUPPORTED:
            continue
        command = [str(SIM), "run-mc04", str(ASSEMBLY), str(methods[(case["type"], case["method"])])]
        command.extend(map(str, case["args"]))
        result = subprocess.run(command, capture_output=True, text=True)
        if case.get("error"):
            assert result.returncode != 0 and result.stderr.strip() == case["error"], (case, result.stdout, result.stderr)
        else:
            assert result.returncode == 0 and result.stdout.strip() == f"Some({case['expected']})", (case, result.stdout, result.stderr)
        checked += 1
    assert checked >= 50
    print(f"PASS: {checked} direct MC04 CIL differential cases from borrowed method bodies")

if __name__ == "__main__": main()
