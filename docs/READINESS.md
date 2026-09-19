# Release readiness

MicroCard is a development system, not yet a pre-hardware release candidate.
MC04 (.NET) and JCVM firmware are separate builds. Both cross-link for nRF52840;
current hardware execution and production certification remain unverified.
This page is the authoritative list of supported behavior and release blockers.

## Supported behavior

- **MC04:** annotated C# compilation, analysis, independent device verification,
  signed loading, installation, selection, execution, and reboot recovery. The Java
  wallet acceptance covers isolated credentials, P-256 signing, PIN recovery,
  package rejection, and persistence. See [the execution profile](PROFILE.md).
- **JCVM:** the supported CAP corpus installs and processes APDUs in the simulator.
  The shared SCP03 path supports authenticated loading, installation, selection,
  deletion, and recovery through dedicated image and heap storage. SHA-256 and
  entropy use shared providers; unsupported crypto factories throw Java Card errors.
  See [the applet profile and its limits](JCVM_PROFILE.md).
- **Shared platform:** APDU transport, SCP03, cancellation, quotas, authenticated
  persistence, image activation, and hardware-provider contracts. Board gates reject
  configurations with both or neither engine and check that the unselected interpreter
  and diagnostic name tables are absent.
- **Device formats:** bounded deterministic CBOR, MP05 packages, MDB2 bundles, and
  MJ03 journals. Old formats are rejected without automatic erasure. Packages use
  P-256, 65-byte uncompressed SEC1 keys, low-S signatures, and 32-byte dependency
  key hashes. Capability 21 remains reserved. [Device contracts](DEVICE_CBOR.md)
  define the bytes and bounds; [protocol](PROTOCOL.md) defines the transport.

## Memory and atomicity

Immutable images occupy dedicated flash slots. Journal activation protects the prior
committed generation and uncertain candidates. JCVM holds authenticated image handles;
MC04 still owns runtime package buffers in RAM. Both board layouts reserve separate
JCVM heap banks. MJ03 reserves a durable nonce before every encryption attempt,
independently of the committed generation, including failed attempts.

MC04 no longer copies the whole runtime state for transactions. It stages affected
application records, keys, and credentials, and uses small undo records for metadata.
Credential retry floors survive failed lifecycle callbacks. The compact MC04 slab
and JCVM heap share checked allocation sizing; native copies and bounded BER/DER
reading replace interpreted utility loops while preserving engine-specific checks.

Inactive JCVM instances retain reset-scoped transient arrays in a zeroizing RAM cache
with a 64 KiB logical limit. Records are bound to installation identity; reset and
deletion clear them. Admission failure is explicit, without eviction. Transient key
bytes and initialization flags clear together. Durable snapshots exclude transient
values and PIN validation. These bounds do not prove that peak workloads fit the
board's reserved heap.

## Required before the pre-hardware release candidate

- Complete JCVM P-256/AES applet bindings through shared providers, with explicit
  errors for unsupported algorithms and no software fallback.
- Reduce vendor dispatch overhead. Default firmware now selects hardware-only CC310;
  software is an explicit reference profile. Pinned compiler and vendor setup is wired
  into CI and release packaging, with cross-host execution still requiring CI evidence. [Provider measurements](CRYPTO_PROVIDER_MEASUREMENTS.json)
  record the current MC04 DK comparison: 185,708 software text bytes versus 211,608
  with all hardware providers. Vendor dispatch also links non-profile ChaCha20/Poly1305
  symbols despite the absence of RustCrypto. Remeasure the final tree; this is not an achieved optimization.
- Remove remaining MC04 runtime image ownership, finish domain modularization, and
  reduce affected-application staging where bounded undo improves measured cost
  while preserving rollback, cancellation, quota, and persistence invariants.
- Finish native utility integration and the dead-code/dependency review. Preserve
  useful generated references and provenance; avoid a maintenance fork solely to
  unify dependency version numbers.
- Record reproducible cold/warm validation, representative load/invoke work, flash,
  static RAM, and host heap peaks for the final tree. Establish final budgets from
  achieved measurements. Do not lower the device heap without supporting evidence.
- Complete the final host/wallet/recovery checkpoint, workspace Clippy, generated
  artifact and contract checks, affected fuzz-target builds, and all required board
  profile links and dependency/symbol inspections. Produce two firmware artifacts
  from a clean committed tree, with revision and artifact hashes recorded.

The cleanup intentionally breaks old packages and state. Rebuild clients and packages;
there is no legacy decoder or automatic migration. Physical execution is a later gate,
not a prerequisite for finishing these implementation tasks.

## Measurements and validation

[Board budgets](BOARD_BUDGETS.json) record hardware-default links and explicit software
reference builds, with profile-specific ceilings and engine/provider isolation checks.
[Assembly budgets](ASSEMBLY_BUDGETS.json) record managed image sizes;
[runtime budgets](RUNTIME_BUDGETS.md) record logical work. Final-tree measurements remain
required. Static RAM includes the reserved heap.

CBOR and image separation reduced the credential metadata snapshot to 1,408 bytes,
with 5,792 bytes of separately stored packages. The measured credential workload's
host allocation peak reached 39,313 requested bytes after transaction and slab changes.
Native copy and TLV services reduce interpreted code but add firmware text; no device
latency improvement or smaller safe heap has been established. Historical per-change
comparisons remain in Git history; reproduce current results before using them as budgets.

[Validation cadence](VALIDATION_CADENCE.md) defines focused, quick, checkpoint, and CI
coverage. Managed builds share a graph, compiler cases run in process, and acceptance
reuses outputs with bounded workers and isolated logs/state. A warm host sample measured
43.312 seconds with one worker and 33.489 with two for the full checkpoint, with the
same 17 acceptance invocations. Cold-build measurements remain outstanding.

Run `python3 scripts/check.py --checkpoint --jobs 2` and
`cargo clippy --workspace --all-targets -- -D warnings` for the consolidated host gate.
Checkpoint builds fuzz targets but does not run sustained campaigns. Before hardware
loading, use [first-flash preparation](FIRST_FLASH.md) from a clean committed tree;
verify the engine, revision, artifact hashes, and `hardware_flashed: false` in its manifest.

## Hardware and production blockers

[Hardware smoke](HARDWARE_SMOKE.md) records earlier revision-specific DK observations;
they do not validate this cleanup. The [dongle guide](DONGLE.md) records its unresolved
boot evidence. Neither cross-linking nor host tests prove physical behavior.

Physical acceptance must cover both engine builds, CC310 independent vectors and
forced failures, buffer aliasing, stack/heap peaks, latency and sustained throughput,
USB abort/disconnect/suspend, and power interruption during ownership, activation,
commit, credential retries, sequence reservation, and deletion. Complete a bounded
release fuzz campaign and archive revision-bound results. Verify Linux and Windows
release bundles in CI before claiming those distributions are supported.

Production additionally requires provisioning and sealed root keys, debug lockout,
verified boot/update policy, MPU and rollback policy, secure recovery/disposal,
flash endurance, side-channel assessment, and independent crypto review.

## Outside this cleanup

Full CLI/BCL and Java Card coverage, every OpenFIPS201 variant, and software replacements
for unsupported hardware algorithms are not promised. Additional default APIs, samples,
extended APDUs, compatible schema migration, and retirement of proprietary loading are
future work. Engine choice remains explicit at build time.
