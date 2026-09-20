# Contributing

MicroCard accepts focused changes with tests that exercise the affected security boundary.

1. Run `python3 scripts/check.py` during development.
2. Run `python3 scripts/check.py --checkpoint` before a release-facing change.
3. Keep package verification authoritative in Rust. Host analyzers and signing checks improve feedback, and they cannot grant device privileges.
4. Do not commit private keys, generated credential state, downloaded standards, or machine-specific hardware identifiers.
5. Use original code and test vectors with clear provenance. [The reference record](docs/REFERENCES.md) states what provenance means here.

By contributing, you agree that your contribution is licensed under AGPL-3.0-or-later.

## Setting up

The complete validation toolchain uses the following. Tools that affect generated
artifacts remain pinned; Rust follows the current stable channel.

- Current stable Rust, with the `thumbv7em-none-eabihf` target for board builds.
- .NET SDK 10.0.302.
- Java 21, with the committed Maven wrapper for the wallet.
- Python 3.12 or newer, then `pip install -r scripts/requirements.txt`.
- Arm GNU 13.3.Rel1 for firmware compilation and size gates. Run `python3 scripts/fetch_arm_toolchain.py` and add its printed bin directory to `PATH`; [crypto build setup](docs/CRYPTO_PROVIDERS.md#reproducible-build-inputs) also fetches the pinned vendor sources.

## Which gate does what

The **quick gate** is the development loop. It runs the generators in check mode, the structural audits, `cargo check` across the workspace, and the managed builds and unit tests.

The **checkpoint gate** adds `cargo test --release`, the in-process analyzer cases and real MSBuild package-consumer checks, the preprocessor bypass cases, the determinism and fixture assertions, and the acceptance suites, wallet demonstration, and board budgets. Failures must be resolved before accepting the batch.

CI runs the quick gate, the wallet acceptance run, `cargo clippy` with warnings denied, and both board link steps. The checkpoint gate is absent from CI entirely. Running it locally is therefore a real contribution. [The validation cadence](docs/VALIDATION_CADENCE.md) defines focused checks and checkpoint coverage.

## Documentation

Keep setup steps runnable and describe supported behavior precisely. Link to the authoritative contract instead of repeating it. The quick gate checks local inline link destinations and generated references. Prose punctuation is reviewed by people.

## Commit style

Commit messages are short imperative sentences describing what the change makes the card do, for example "Run array instructions against the heap". Keep a change to one such sentence's worth of work, because that is the granularity the history uses.
