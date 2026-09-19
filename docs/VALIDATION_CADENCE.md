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

Use `python3 scripts/check.py --suite rust`, `--suite managed`, or `--suite schemas` for a focused loop. `--suite analyzer` runs the analyzer case corpus in one compiler process. `--suite wallet` runs the Java demonstration and `--suite board` links and checks the board variants. With no selection, the quick gate runs schemas, Rust checks, and managed reference tests.

The quick gate builds managed projects through one generated solution graph, so common dependencies share one build. `--jobs N` controls MSBuild workers, with one worker as the portable default. Independent invocations must use separate worktrees because managed output directories are shared.

Every command reports elapsed time. `work/validation-timings.json` records commands, durations, and exit codes, including the failing stage. Use `--timings PATH` to preserve a comparison run. These timings reflect existing caches unless a separate clean build directory is used.

## Continuous integration

CI runs quick validation, wallet and Java Card acceptance, workspace Clippy, and board release links. The local checkpoint now includes wallet acceptance and board budgets. Workspace Clippy remains an additional gate, and the full recovery checkpoint remains outside ordinary CI. Reproduce CI with `act` before pushing wallet, reader, or secure-channel changes.

## Dedicated fuzz checkpoint

Build the affected fuzz target when its interface changes. During ordinary development, stop there unless a focused regression exposes a reason for a short reproducer run. Accumulate related parser, verifier, native-boundary, cryptographic-boundary and state-transition changes, then run one sustained campaign at a dedicated fuzz checkpoint or release candidate. Run no scheduled sustained campaign during ordinary development. Documentation, isolated API wiring, managed-library changes and ordinary security checkpoints do not repeat long campaigns.

Fuzz campaigns remain separate from both `scripts/check.py` modes and require an explicit duration. Record the exact revision before treating a campaign as evidence.

Never reuse an older broad result as evidence for changed code. Keep the work-list item open until its required gate has run at the relevant revision.
