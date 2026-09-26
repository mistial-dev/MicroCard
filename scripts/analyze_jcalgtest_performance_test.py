#!/usr/bin/env python3
"""Keep incomplete performance rows distinct from unsupported algorithms."""
from analyze_jcalgtest_performance import inspect_csv

sample = """
method name:; supported operation
operation stats (ms/op):;avg op:;0.65;min op:;0.64;max op:;0.66;
method name:; unsupported algorithm
NO_SUCH_ALGORITHM
method name:; operation not measured
CANT_BE_MEASURED
method name:; bad baseline
operation stats (ms/op):;avg op:;-0.20;min op:;-0.21;max op:;-0.19;
method name:; interrupted operation
"""
entries, counts = inspect_csv(sample)
assert len(entries) == 5
assert counts == {
    "measured": 1, "NO_SUCH_ALGORITHM": 1, "CANT_BE_MEASURED": 1,
    "invalid_measurement": 1, "incomplete": 1,
}
assert entries[0]["mean_ms_per_op"] == 0.65
print("PASS: JCAlgTest performance outcomes remain distinct")

