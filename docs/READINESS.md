# Pre-flash readiness audit

Scope: prepare host testing, documentation, interpreter, SCP03, assembly loading/signing, persistent keystore and original sample applications, then stop before writing the nRF52840 DK. This audit covers the first development test build. Production certification requires separate evidence.

## Requirement evidence

1. Host corpus: `scripts/check.py --checkpoint` executes Rust tests and 76 C#/.NET versus interpreter cases. Deterministic preprocessing, MSBuild incremental behavior and incorrect framework pins are checked.
2. Interpreter: the original arithmetic, sealed-object, array, branch and switch fixtures run through normal compilation and lowering. Execution/fuel/arena bounds, malformed inputs and forged references have host tests.
3. SCP03: a separate Python/OpenSSL implementation exercises the supported levels, command encryption/MAC, response MAC, replay and teardown. INITIALIZE UPDATE advertises the implementation option derived from the enabled capabilities, verified against SCP03 Table 5-1.
4. Loading/signing: independent Rust and .NET P-256 packagers produce equal packages. Device-side verification precedes atomic activation. Tests cover each changed signed byte, first-load byte-mutation fault injection, immutable pinning, incarnations, rollback and retries.
5. Keystore: private persistent slots are reached through domain-owned opaque handles. HMAC/AES key-use separation, ownership, revocation and entropy/quota errors have direct tests. End-to-end samples exercise independent HMAC/CMAC values, CBC/CCM, shared keys, reboot and stale-handle rollback.
6. Sample applications: `Counter`, `Reader`, `Echo`, `ProtectedCommand`, `KeyOperations` and `KeyReader` are original class-library assemblies. They use the value store, secure context, hashing and key operations through managed APIs.
7. Transport: the shared binary decoder runs on host and target. The actual serial client is tested through a fragmented pseudo-terminal. The full loading/key corpus also runs over binary framing.
8. Board artifact: the release nRF52840 image links the same core. The preparation gate verifies load ranges, stack/reset vectors and static RAM margin, then emits ELF/HEX/bin and SHA-256 hashes. It never invokes a probe.
9. Documentation/provisioning: FIRST_FLASH.md gives separate private development credentials, checked probe-rs command syntax and a post-flash smoke test. Protocol, keystore, references and remaining production work are documented.
10. Stop boundary: no flash, reset, erase, recover or provisioning command has been run against a board. Hardware acceptance is intentionally subsequent work.

## Authoritative final gate

Run `python3 scripts/prepare_first_flash.py` from the committed worktree. Inspect `artifacts/first-flash/manifest.json`: its revision must equal HEAD, `working_tree_dirty` must be false, artifact hashes must match, and `hardware_flashed` must be false. The checked-in validation record describes the host evidence. The generated manifest binds the concrete artifacts to a revision.

## Explicit limits

Production wear leveling, physical rollback protection, sealed root-key storage, verified firmware updates, a complete CLI/BCL profile, sustained fuzz campaigns and actual DK measurements are not asserted by this pre-flash audit. MJ02 encrypts and authenticates framework storage, but the development security boundary still assumes trusted firmware and enabled debug recovery.
