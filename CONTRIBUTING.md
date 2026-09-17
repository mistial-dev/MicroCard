# Contributing

MicroCard accepts focused changes with tests that exercise the affected security boundary.

1. Run `python3 scripts/check.py` during development.
2. Run `python3 scripts/check.py --checkpoint` before a release-facing change.
3. Keep package verification authoritative in Rust. Host analyzers and signing checks improve feedback but cannot grant device privileges.
4. Do not commit private keys, generated credential state, downloaded standards, or machine-specific hardware identifiers.
5. Use original code and test vectors with clear provenance.

By contributing, you agree that your contribution is licensed under AGPL-3.0-or-later.
