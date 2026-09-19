# Release readiness

MicroCard is a development system. The current cleanup has not produced the separate .NET and JCVM firmware release candidates yet. Hardware testing of this cleanup is deferred.

## Current implementation

The .NET path compiles, verifies, signs, installs, and runs MC04 applications in the simulator and links for nRF52840. Package signing uses P-256 with uncompressed SEC1 keys and low-S signatures. Domain identities are SHA-256 key hashes. MP04 packages and MDB2 bundles reject their earlier formats. Native capability 21 remains reserved.

JCVM runs the supported applet corpus in the simulator. It still needs the board loading, persistence, and shared security-service integration described in [JCVM profile](JCVM_PROFILE.md). Neither a linked image nor host acceptance establishes hardware behavior.

## Required implementation work

- Produce separate MC04 and JCVM firmware builds, with only the selected engine linked.
- Replace device JSON manifests, management payloads, and journal snapshots. Prefer deterministic CBOR where it provides a compact bounded representation. Move immutable images and the JCVM heap out of the metadata journal.
- Enable CC310 providers while excluding their software replacements from board images. Provider failures must remain fatal to the operation.
- Replace whole-state transaction copies and compact MC04 object storage while preserving rollback, quotas, and object lifetime checks.
- Share native byte-copy and encoding services, compact runtime tables, and finish the documentation consolidation.

## Validation gates

[Validation cadence](VALIDATION_CADENCE.md) defines the focused, quick, and checkpoint commands. The quick gate uses one managed build graph. The analyzer suite runs the existing negative and boundary corpus in one compiler process, while checkpoint coverage retains real MSBuild integration tests.

Acceptance requires host and wallet tests, exhaustive recovery, workspace Clippy, affected fuzz-target builds, and both engines' board links and size checks. Timing reports under `work/` describe the executed commands and failures. They are local evidence, not a release certification or a sustained fuzz campaign.

Before hardware loading, run `python3 scripts/prepare_first_flash.py` from the committed worktree. Verify that the generated manifest names HEAD, reports a clean worktree, includes matching artifact hashes, and records `hardware_flashed` as false. This command prepares artifacts without operating a probe.

## Remaining hardware and production evidence

[Hardware smoke](HARDWARE_SMOKE.md) records earlier revision-specific device observations. Those results do not validate the current signing migration or future CC310 and JCVM changes. The dongle remains subject to the limits in [its guide](DONGLE.md).

Production acceptance still requires provisioning and sealed root-key storage, debug lockout, verified firmware updates, physical rollback policy, flash endurance, side-channel assessment, transport fault testing, and independent hardware-crypto validation. Full CLI/BCL and Java Card API coverage are not claimed.
