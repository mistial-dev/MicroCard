# Contributing

MicroCard accepts focused changes with tests that exercise the affected security boundary.

1. Run `python3 scripts/check.py` during development.
2. Run `python3 scripts/check.py --checkpoint` before a release-facing change.
3. Keep package verification authoritative in Rust. Host analyzers and signing checks improve feedback, and they cannot grant device privileges.
4. Do not commit private keys, generated credential state, downloaded standards, or machine-specific hardware identifiers.
5. Use original code and test vectors with clear provenance. [The reference record](docs/REFERENCES.md) states what provenance means here.

By contributing, you agree that your contribution is licensed under AGPL-3.0-or-later.

## Setting up

The quick gate needs all of the following. The versions are pinned because the gate compares generated output byte for byte.

- Rust 1.94.1, with the `thumbv7em-none-eabihf` target for board builds.
- .NET SDK 10.0.302.
- Java 21 and Maven, for the wallet.
- Python 3, then `pip install -r scripts/requirements.txt`.
- `arm-none-eabi-objcopy`, `arm-none-eabi-objdump` and `arm-none-eabi-size` for the board size gates.

## Which gate does what

The **quick gate** is the development loop. It runs the generators in check mode, the structural audits, `cargo check` across the workspace, and the managed builds and unit tests.

The **checkpoint gate** adds `cargo test --release`, the analyzer negative cases, the preprocessor bypass cases, the determinism and fixture assertions, and the acceptance suites. It takes a long time and needs the full toolchain, so treat a failure there as expected feedback rather than as something you broke.

CI runs the quick gate, the wallet acceptance run, `cargo clippy` with warnings denied, and both board link steps. The checkpoint gate is absent from CI entirely. Running it locally is therefore a real contribution. [The validation cadence](docs/VALIDATION_CADENCE.md) has the details, including why reproducing the workflow with `act` before a push has caught failures a green checkpoint gate missed.

## The documentation style rule

`scripts/check.py` enforces two rules on `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `THIRD_PARTY_NOTICES.md` and every file under `docs/`. It runs first, before any build, so a documentation slip fails the whole gate in a few seconds.

1. **No semicolons anywhere in the file.** This is a plain substring test with no exemption for fenced code blocks, tables or inline code. A shell or Rust sample containing a semicolon fails the gate. This is why the generated appendices such as [MC04 opcodes](docs/MC04_OPCODES.md) are bare tables, and why code samples in these documents are single commands.
2. **No contrastive A-versus-B phrasing.** Two shapes fail. One is a comma followed immediately by a negation. The other is a negation joined later in the same sentence to a contrasting clause. Say what a thing is and give the contrast its own sentence.

The purpose is to keep public prose direct and to keep sentences short enough to be checked against the code they describe. Both rules are mechanical, so when the gate rejects a sentence, rewrite it as two sentences.

These rules apply to the files listed above. Source comments, commit messages and anything under `.github/` are untouched by them.

## Commit style

Commit messages are short imperative sentences describing what the change makes the card do, for example "Run array instructions against the heap". Keep a change to one such sentence's worth of work, because that is the granularity the history uses.
