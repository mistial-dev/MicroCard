# Validation cadence

Run the smallest gate that proves the current change, and retain the broader gates for checkpoints where their evidence is meaningful.

## Development loop

- Run directly affected unit or integration tests.
- Run `cargo check --workspace --all-targets --locked` for Rust interface changes.
- Run focused Clippy with warnings denied for changed crates.
- Cross-check the nRF52840 target when a portable or board-facing interface changes.
- Run the quick `scripts/check.py` gate after a consolidated host-side batch. Individual edits do not need it.

These checks should complete quickly. Record their exact scope. They do not imply that exhaustive recovery or fuzzing passed.

## Security checkpoint

Run `scripts/check.py --checkpoint`, complete workspace Clippy, both nRF52840 release variants and the relevant exhaustive power-loss suite after a consolidated security batch, before device loading, or before release acceptance. Do not repeat it for each individual change to package verification, linking, transactions, journals, domain management, secure messaging or native security services. The ordinary `scripts/check.py` command intentionally omits exhaustive recovery tests.

Consolidate several related changes when practical. A source-control checkpoint alone is not a reason to repeat this gate. Rerun it only when the accumulated changes affect its security evidence or before device/release acceptance.

This checkpoint does not run a sustained fuzz campaign.

## Dedicated fuzz checkpoint

Build the affected fuzz target when its interface changes. During ordinary development, stop there unless a focused regression exposes a reason for a short reproducer run. Accumulate related parser, verifier, native-boundary, cryptographic-boundary and state-transition changes, then run one sustained campaign at a dedicated fuzz checkpoint or release candidate. Run no scheduled sustained campaign during ordinary development. Documentation, isolated API wiring, managed-library changes and ordinary security checkpoints do not repeat long campaigns.

Fuzz campaigns remain separate from both `scripts/check.py` modes and require an explicit duration. Record the exact revision before treating a campaign as evidence.

Never reuse an older broad result as evidence for changed code. Keep the work-list item open until its required gate has run at the relevant revision.
