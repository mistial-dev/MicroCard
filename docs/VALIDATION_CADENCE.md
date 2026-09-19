# Validation cadence

Run the smallest gate that proves the current change, and retain the broader gates for checkpoints where their evidence is meaningful.

## Development loop

- Run directly affected unit or integration tests.
- Run `cargo check --workspace --all-targets --locked` for Rust interface changes.
- Run focused Clippy with warnings denied for changed crates.
- Cross-check the nRF52840 target when a portable or board-facing interface changes.
- Run the quick `scripts/check.py` gate after a consolidated host-side batch. Individual edits do not need it.

These checks should complete quickly. Record their exact scope. They do not imply that exhaustive recovery or fuzzing passed.

Each test should catch a distinct regression or cover a distinct integration boundary.
Use table-driven cases for related inputs instead of separate tests with repeated setup.
When replacing a format or implementation, remove tests and helpers that only exercise
the retired path. Preserve its relevant failure cases in the current contract tests;
do not retain obsolete decoders just to keep their tests running. Test counts are not
a quality target, and a commit alone is not a reason to add tests.

## Security checkpoint

Run `scripts/check.py --checkpoint`, complete workspace Clippy, both nRF52840 release variants and the relevant exhaustive power-loss suite after a consolidated security batch, before device loading, or before release acceptance. Do not repeat it for each individual change to package verification, linking, transactions, journals, domain management, secure messaging or native security services. The ordinary `scripts/check.py` command intentionally omits exhaustive recovery tests.

Consolidate several related changes when practical. A source-control checkpoint alone is not a reason to repeat this gate. Rerun it only when the accumulated changes affect its security evidence or before device/release acceptance.

This checkpoint does not run a sustained fuzz campaign.

## Focused suites and timings

Use `python3 scripts/check.py --suite rust`, `--suite managed`, or `--suite schemas` for a focused loop. `--suite analyzer` runs analyzer diagnostics in one compiler process. `--suite compiler` also emits the boundary and rejection assemblies and runs the independent preprocessor checks. `--suite wallet` runs the Java demonstration and `--suite board` links and checks the board variants. With no selection, the quick gate runs schemas, Rust checks, and managed reference tests.

Both quick and checkpoint gates build managed projects through one generated solution graph, so common dependencies share one build. Compiler cases reuse SDK reference assemblies and generated assembly attributes, and emit into separate directories. `--jobs N` bounds MSBuild workers, independent preprocessor checks, and checkpoint acceptance workers, with one worker as the portable default. Checkpoint builds wallet projects in the shared graph and passes freshly built artifacts to acceptance consumers; those workers do not launch managed builds. Standalone acceptance commands retain their build steps. Each concurrent suite has its own temporary state directory and retained log under `work/acceptance-*/`. Checkpoint retains real package-consumer and incremental MSBuild tests. Independent validation invocations must use separate worktrees because managed project output directories are shared.

Timed commands report elapsed time. `work/validation-timings.json` records overall wall time and command durations and exit codes, including the failing stage. Acceptance stages identify the suite and text/binary transport mode. Concurrent command durations overlap, so their sum is not wall time. Use `--timings PATH` to preserve a comparison run. These timings reflect existing caches unless a separate clean build directory is used.

A warm host sample with the same 17 acceptance invocations measured 43.312 seconds
for the complete checkpoint with one worker and 33.489 seconds with two. The
acceptance batch itself fell from 23.123 to 15.876 seconds. Both runs passed, including
wallet and board checks. Reproduce with `--checkpoint --jobs 1` and `--jobs 2`, recording
separate timing files. These are warm host measurements; cold builds and device latency
remain separate measurements.

## Continuous integration

CI runs quick validation, wallet and Java Card acceptance, workspace Clippy, and board release links. Linux CI additionally fetches verified CC310 inputs and cross-links the provider replacement matrix for both engines and board layouts. The local checkpoint now includes wallet acceptance and board budgets. Workspace Clippy remains an additional gate, and the full recovery checkpoint remains outside ordinary CI. Reproduce CI with `act` before pushing wallet, reader, or secure-channel changes.

## Dedicated fuzz checkpoint

Build the affected fuzz target when its interface changes. During ordinary development, stop there unless a focused regression exposes a reason for a short reproducer run. Accumulate related parser, verifier, native-boundary, cryptographic-boundary and state-transition changes, then run one sustained campaign at a dedicated fuzz checkpoint or release candidate. Run no scheduled sustained campaign during ordinary development. Documentation, isolated API wiring, managed-library changes and ordinary security checkpoints do not repeat long campaigns.

Fuzz campaigns remain separate from both `scripts/check.py` modes and require an explicit duration. Record the exact revision before treating a campaign as evidence.

Never reuse an older broad result as evidence for changed code. Keep the work-list item open until its required gate has run at the relevant revision.

## Heap measurements

Reuse an existing acceptance workload with simulator-only allocation counters:

```sh
cargo build -p microcard-sim --locked --features heap-metrics
python3 scripts/heap_profile.py --output work/jcvm-heap.json -- python3 scripts/jcvm_transport_acceptance.py
python3 scripts/heap_profile.py --output work/mc04-heap.json -- python3 scripts/credential_acceptance.py
```

The report groups startup and APDU operations by instruction. It records live and peak
requested allocation bytes, allocation traffic, and host execution time. It does not
include allocator metadata or stack use. Host file reads and pointer sizes differ from
the board, so these figures are optimization evidence, not a safe device heap bound.
The ordinary simulator and firmware builds omit the counters. No new applet behavior
suite is needed for profiling; the existing workload must still pass.

Board size checks use persistent per-profile target directories under
`board/nrf52840/target/profiles/`. Separate gate invocations cannot substitute another
profile's ELF or link map between the build and inspection. The first run fills each
profile's cache; later runs reuse it.
