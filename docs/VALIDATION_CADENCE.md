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

Both quick and checkpoint gates build .NET projects through one generated solution graph, so common dependencies share one build. The checkpoint also builds the Java wallet once with Maven before starting acceptance workers. Compiler cases reuse SDK reference assemblies and generated assembly attributes, and emit into separate directories. `--jobs N` bounds MSBuild workers, independent preprocessor checks, and checkpoint acceptance workers, with one worker as the portable default. Checkpoint passes freshly built .NET and Java artifacts to acceptance consumers; those workers do not launch managed builds. Standalone acceptance commands retain their build steps. Each concurrent suite has its own temporary state directory and retained log under `work/acceptance-*/`. Checkpoint retains real package-consumer and incremental MSBuild tests. Independent validation invocations must use separate worktrees because managed project output directories are shared.

Timed commands report elapsed time. `work/validation-timings.json` records overall wall time and command durations and exit codes, including the failing stage. Acceptance stages identify the suite and text/binary transport mode. Concurrent command durations overlap, so their sum is not wall time. Use `--timings PATH` to preserve a comparison run. These timings reflect existing caches unless a separate clean build directory is used.

A clean host checkpoint at revision `11e83f4` rebuilt Rust, .NET, and Java outputs in
55.467 seconds with four workers. Its 17 acceptance invocations took 10.817 seconds;
the wallet worker reused the single Maven build performed before the batch. Every
behavioral and link stage passed, and the final board-budget stage reported the three
tracked flash ceilings. Reproduce with `--checkpoint --jobs 4` and a separate timing
file. Device latency remains a separate measurement.

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

The report groups startup and APDU operations by instruction. The JCVM workload also
labels provisioning, oversized-object failure, interrupted-replacement reboot,
two-applet selection, forced renewal, and post-renewal operations in `phases`.
These labels separate different paths that share the SELECT instruction. Markers
are written only after the previous command completes and only when profiling is
enabled; they contain no APDU payloads or keys. Aggregate `stages` remain available.
Reports capture revision, tracked/untracked working-tree fingerprints, and simulator
SHA-256 before and after execution. Changed inputs make profiling exit nonzero while
preserving the report for diagnosis. These endpoint checks do not detect changes
that are reverted during the run; use an isolated checkout for release evidence and
build its simulator before measuring. A binary hash alone does not prove its source.
The report records live and peak
requested allocation bytes, allocation traffic, and host execution time. It does not
include allocator metadata or stack use. Host file reads and pointer sizes differ from
the board, so these figures are optimization evidence, not a safe device heap bound.
The JCVM workload also consumes nonce reservations in a closed simulator fixture
to exercise automatic renewal with provisioned keys and a certificate. This is host
fixture preparation, not a device operation. The ordinary simulator and firmware
builds omit the allocation counters. No new applet behavior
suite is needed for profiling; the existing workload must still pass.

[Recorded heap measurements](HEAP_MEASUREMENTS.json) bind the latest retained runs to
their source revision, build command, workload, platform, and dirty-tree status.
Keep `device_heap_safety_established` false until board-equivalent allocation and
physical peak measurements support a safe bound.

Board size checks use persistent per-profile target directories under
`board/nrf52840/target/profiles/`. Separate gate invocations cannot substitute another
profile's ELF or link map between the build and inspection. The first run fills each
profile's cache; later runs reuse it.

The gate reports every exceeded ceiling and writes revision/dirty-tree evidence to
`work/board-budget-latest.json` after all profiles link and pass isolation checks.
Running `python3 scripts/board_budgets.py` refreshes the documented measurements even
when budgets fail; its exit status remains nonzero. `--check` leaves the documented
report untouched and also rejects stale measurements. Neither mode changes ceilings.
