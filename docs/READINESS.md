# Release readiness

MicroCard is a development system. The current cleanup has not produced the separate .NET and JCVM firmware release candidates yet. Hardware testing of this cleanup is deferred.

## Current implementation

The .NET path compiles, verifies, signs, installs, and runs MC04 applications in the simulator and links for nRF52840. Package signing uses P-256 with uncompressed SEC1 keys and low-S signatures. Domain identities are SHA-256 key hashes. MP05 packages and MDB2 bundles reject their earlier formats. Native capability 21 remains reserved.

JCVM runs the supported applet corpus in the simulator. It still needs the board loading, persistence, and shared security-service integration described in [JCVM profile](JCVM_PROFILE.md). Neither a linked image nor host acceptance establishes hardware behavior.

The shared APDU endpoint is generic over `CardEngine`. It owns SCP03 authentication,
session reset, cancellation, and response protection; engine adapters receive verified
commands and raw AIDs. The core's `mc04` feature includes its loader and interpreter.
Disabling it leaves transport, journal, crypto, and hardware contracts available without
compiling MC04. Quick validation exercises that configuration with an independent test
engine. This boundary does not yet supply JCVM's durable management adapter or board profile.

The independent `jcvm` core feature exposes SHA-256 and entropy through the shared
provider adapter, now used by the simulator. Unsupported JCVM crypto factories raise
explicit Java Card exceptions. P-256/AES bindings, authenticated package loading, and
durable applet state still need integration before a JCVM firmware artifact is ready.

MC04 stores immutable packages in separate image slots and commits only descriptors
in its version-2 metadata snapshot. Recovery verifies image hashes and package
signatures. Interrupted activation protects both committed and uncertain candidate
images. Both board layouts reserve eight 16 KiB image slots; the simulator uses files.
Runtime package views still occupy RAM. JCVM heap partitioning and its management
adapter remain unfinished.

## Required implementation work

- Give every journal encryption attempt a durable unique nonce. MJ02 derives it from the committed generation, which can repeat after an interrupted attempt; recovery tests do not establish nonce uniqueness.
- Produce separate MC04 and JCVM firmware builds, with only the selected engine linked.
- MP05 manifests, lifecycle management names, and journal snapshots now use [bounded deterministic CBOR](DEVICE_CBOR.md), with coordinated repository clients. Allocate the separate JCVM heap journal in both board layouts.
- Finish CC310 size reduction and hardware validation before making the hardware profile the default. The explicit hardware build excludes RustCrypto; the current vendor implementation is larger than the software reference.
- Replace whole-state transaction copies and compact MC04 object storage while preserving rollback, quotas, and object lifetime checks.
- Share native byte-copy and encoding services, compact runtime tables, and finish the documentation consolidation.

CBOR removes device JSON parsing and canonical re-encoding. The snapshot migration reduces development text from 250,836 to 182,516 bytes. The credential-profile test records 5,792 bytes of separate active packages and a 1,404-byte metadata snapshot, down from 7,052 bytes with inline packages (12,549 before CBOR). Its interpreted execution metrics are unchanged. Image storage adds about 3 KiB of firmware text; it reduces journal payload and copying, not interpreter code. Heap high-water and device latency remain unmeasured.

## Crypto replacement measurements

`python3 scripts/crypto_provider_matrix.py --output work/crypto-provider-matrix.json` builds each replacement stage and rejects RustCrypto dependencies in the hardware-only build. [Recorded measurements](CRYPTO_PROVIDER_MEASUREMENTS.json) compare the same tree and development configuration: software 185,684 text bytes, SHA-256 replacement 188,584, SHA-256 plus P-256 202,692, and all hardware providers 211,688. These are regressions, not achieved optimization budgets. The default remains the software reference while this is resolved.

For a hardware-only cross-link, run `cargo build --release --locked --no-default-features --features cc310` in `board/nrf52840`. Missing primitive implementations are compile errors, not software retries. The in-place CCM recovery adapter now uses the hardware boundary; shared conformance includes valid, corrupted, and truncated in-place inputs with output clearing. Execution of that adapter, including vendor buffer aliasing behavior, remains unverified on hardware. Static RAM includes the reserved heap; these measurements establish neither heap high-water nor device latency.

## Validation gates

[Validation cadence](VALIDATION_CADENCE.md) defines the focused, quick, and checkpoint commands. The quick gate uses one managed build graph. The analyzer suite runs the existing negative and boundary corpus in one compiler process, while checkpoint coverage retains real MSBuild integration tests.

Acceptance requires host and wallet tests, exhaustive recovery, workspace Clippy, affected fuzz-target builds, and both engines' board links and size checks. Timing reports under `work/` describe the executed commands and failures. They are local evidence, not a release certification or a sustained fuzz campaign.

Before hardware loading, run `python3 scripts/prepare_first_flash.py` from the committed worktree. Verify that the generated manifest names HEAD, reports a clean worktree, includes matching artifact hashes, and records `hardware_flashed` as false. This command prepares artifacts without operating a probe.

## Remaining hardware and production evidence

[Hardware smoke](HARDWARE_SMOKE.md) records earlier revision-specific device observations. Those results do not validate the current signing migration or future CC310 and JCVM changes. The dongle remains subject to the limits in [its guide](DONGLE.md).

Production acceptance still requires provisioning and sealed root-key storage, debug lockout, verified firmware updates, physical rollback policy, flash endurance, side-channel assessment, transport fault testing, and independent hardware-crypto validation. Full CLI/BCL and Java Card API coverage are not claimed.
