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
  deletion, and recovery through dedicated image and heap storage. SHA-256, entropy, and AES-128 ECB/CBC
  use shared providers; unsupported crypto factories throw Java Card errors.
  See [the applet profile and its limits](JCVM_PROFILE.md).
- **Shared platform:** APDU transport, SCP03, cancellation, quotas, authenticated
  persistence, image activation, and hardware-provider contracts. Board gates reject
  configurations with both or neither engine and check that the unselected interpreter
  and diagnostic name tables are absent.
- **Device formats:** bounded deterministic CBOR, MP05 packages, MDB2 bundles, and
  MJ03 management journals and MJ04 JCVM heap journals. Old formats are rejected without automatic erasure. Packages use
  P-256, 65-byte uncompressed SEC1 keys, low-S signatures, and 32-byte dependency
  key hashes. Capability 21 remains reserved. [Device contracts](DEVICE_CBOR.md)
  define the bytes and bounds; [protocol](PROTOCOL.md) defines the transport.

## Memory and atomicity

Immutable images occupy dedicated flash slots. Journal activation protects the prior
committed generation and uncertain candidates. JCVM holds authenticated image handles;
MC04 retains metadata and descriptors, borrowing verified flash images for loading,
recovery and execution. Both board layouts reserve separate JCVM heap banks. Both journal formats reserve a durable nonce before every encryption attempt,
independently of the committed generation, including failed attempts.

MC04 domain management separates state/recovery, authenticated commands, execution,
native services, application staging, lifecycle changes, metadata, snapshots and
linking into focused modules; its regression suite is separate from production code.
MC04 no longer copies the whole runtime state for transactions. It stages affected
application records, keys, and credentials, and uses small undo records for metadata.
Credential retry floors survive failed lifecycle callbacks. The compact MC04 slab
and JCVM heap share checked allocation sizing; native copies and bounded BER/DER
reading replace interpreted utility loops while preserving engine-specific checks.

Inactive JCVM instances retain reset-scoped transient arrays in a zeroizing RAM cache
with a 64 KiB logical limit. Records are bound to installation identity; reset and
deletion clear them. Admission failure is explicit, without eviction. Transient key
bytes and initialization flags clear together. Durable snapshots exclude transient
values and PIN validation. JCVM digest calls borrow input directly and stage only
the fixed digest, validating output bounds and provider lengths before publication. These bounds do not prove that peak workloads fit the
board's reserved heap.

## Required before the pre-hardware release candidate

- Complete host interruption coverage for personalized OpenFIPS201 provisioning.
  The original ICAM object-only workflow passes exact readback of 11 objects after
  reopening, and the separate P-256 NIST profile passes 37 of 63 contact vectors.
  The combined derived P-256 identity now imports all objects and keys and verifies
  readback after reopening. Repeated ISO status exceptions previously grew the heap
  until the snapshot exceeded capacity; runtime exception reuse fixes that failure.
  The combined profile passes 58 of 63 contact vectors, with four CHUID/certificate
  failures and one skip. These profile limitations remain visible. See the reproducible
  commands and profile distinctions in [JCVM acceptance](JCVM_PROFILE.md).
  Abrupt simulator termination between encrypted certificate fragments preserves
  the prior certificate; a fresh authenticated upload then replaces it and survives
  reboot. This covers command-boundary recovery, not arbitrary torn flash writes.
  The real applet object-update test separately samples byte-write failures across
  journal stages and verifies complete old/new content after reopening storage.
  P-256 keys, generation, ECDH, ECDSA/SHA-256, and AES-128 ECB/CBC are connected. Ordinary PIV access, reselect,
  secure-channel reset, chained certificate upload, and certificate retrieval now pass
  through the managed simulator path.
  The same workload personalizes the real applet and reads its lifecycle through the
  applet status command: `07` before personalization and `0F` across subsequent
  callbacks, abrupt process termination/reboot, and heap-counter renewal.
  Management-key creation/import, PIV challenge-response, PIN provisioning, P-256
  generation, and independently verified signing before/after reboot now pass through
  the shared simulator path. Slot 9C requires a fresh PIN verification for each signature;
  reboot does not preserve PIN validation. These do not establish hardware execution.
- Complete the remaining JCVM native API audit against Java Card 3.0.5, including
  internal failure boundaries. Instruction, transaction, PIN, and lifecycle changes
  checkpoint committed state while excluding open applet transactions. Existing tests
  cover rollback, allocation and undo exhaustion, partial construction, cancellation,
  failed providers, and failed persistence. [JCVM semantics](JCVM_PROFILE.md) records
  the exact supported behavior and source clauses.
- Qualify journal renewal capacity and memory for all supported workloads. Automatic
  command-boundary renewal preserves the live applet and uses authenticated staging
  to recover interrupted bank replacement. Root registry counters remain finite;
  host memory bounds remain required, with physical service-life testing later.
  See [renewal and recovery invariants](STORAGE.md#jcvm-counter-renewal).
- Finish cross-link and host memory measurements for the Makerdiary JCVM image. A connected board
  answered USB/PCSC and read-only GlobalPlatform discovery on 2026-09-19, but its flashed
  revision and engine are unknown. The current JCVM dongle links at 223,264 text bytes,
  148 data bytes and 198,284 BSS bytes, within
  its 288 KiB firmware region. Functional OpenFIPS201 delivery takes priority over size
  optimization. The unchanged 178,000-byte optimization ceiling still fails; the
  refreshed budget report records current failures rather than historical passing sizes.
  All seven profiles cross-linked in the consolidated checkpoint described below. MC04 no
  longer retains package image buffers in runtime state; recovery reads verified
  flash guards and retains metadata. MC04 hardware release text is 212,580 bytes
  against 212,000, and software reference text is 186,464 against 186,000. Seven text
  ceilings still fail; none were raised. The matched credential workload reduced host
  heap peak from 43,227 to 35,137 bytes and reopened retained allocations from 13,215
  to 4,989 bytes; [measurement evidence](HEAP_MEASUREMENTS.json) records both binaries.
  The provisioned JCVM transport workload forces counter renewal and peaks at
  184,681 host-requested allocation bytes after validating the saved heap by borrowing
  it (previously 266,721). This is below the 196,608-byte board reservation for this
  workload, but does not establish device heap safety. The expanded personalization
  workload at clean revision `5fb8307` reproduces the same 184,681-byte peak
  (`work/jcvm-personalized-heap.json`). The two-applet extension at clean
  revision `37a95dd` peaks at 185,913 bytes with both banks occupied and one blank
  applet's reset-scoped arrays retained (`work/jcvm-two-applet-clean-heap.json`).
  Neither run fills both applets to their maximum supported allocations. A larger
  accepted certificate capacity of 20,000 bytes passes all functional checks but peaks
  at **341,421 host-requested bytes**, including 341,421 during SELECT and 286,330
  during open (clean revision `5e3efcc`, `work/jcvm-large-certificate-clean-heap.json`).
  This exceeds the board heap reservation; investigate recovery/selection allocation
  overlap and separate host file buffers from board costs before hardware readiness. Direct
  patch replay reduces that matched workload to **251,517 bytes** at clean revision
  `54c67b1` (`work/jcvm-direct-replay-clean-heap.json`), saving 89,904 bytes.
  Releasing idle execution frames reduces the matched file-backed host peak further
  to **234,109 bytes** at clean revision `502d921` (`work/jcvm-idle-frames-clean-heap.json`).
  The host fallback still exceeds the board reservation. Board renewal additionally
  borrows mapped staging ciphertext; its physical peak remains unmeasured. Bound supported workloads and
  board allocations before declaring this path ready for hardware. Host figures
  exclude allocator metadata and stack and include file-backed image reads.
  At clean revision `a18c7b9`, a 24,000-byte certificate capacity completes the same
  lifecycle at **250,609 host-requested bytes** (`work/jcvm-24k-certificate-heap.json`).
  A 32,767-byte capacity fails object creation with `6F00`; the applet allocates two
  such arrays, which cannot fit the configured 64 KiB VM heap with their headers.
  Its 194,804-byte failed-run peak is not a qualification result
  (`work/jcvm-max-certificate-heap.json`). The acceptance runner's argument range is
  an allocation probe, not a promise that every capacity is supported. A supported
  personalization profile must budget all current and replacement buffers together.
  The transport workload also rejects an oversized second certificate object after
  provisioning, then verifies the original certificate, reboot, replacement, signing,
  and key agreement. This checks preservation of existing data, not reclamation of
  unreachable allocations left by a failed applet constructor.
  The default-capacity workload including this failure peaks at **236,188 host
  allocation bytes** at clean revision `c8fcd77`
  (`work/jcvm-failed-object-clean-heap.json`); failure paths must be included when
  establishing the board heap bound.
- Reduce vendor dispatch overhead. Default firmware now selects hardware-only CC310;
  software is an explicit reference profile. Pinned compiler and vendor setup is wired
  into CI and release packaging, with cross-host execution still requiring CI evidence. [Provider measurements](CRYPTO_PROVIDER_MEASUREMENTS.json)
  record the current MC04 DK comparison: 185,708 software text bytes versus 211,608
  with all hardware providers. Vendor dispatch also links non-profile ChaCha20/Poly1305
  symbols despite the absence of RustCrypto. Remeasure the final tree; this is not an achieved optimization.
- Reduce affected-application staging where bounded undo improves measured cost
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
host allocation peak reached 39,335 requested bytes at `c1950b1`. The personalized
OpenFIPS201 workload, including transaction/PIN checkpoints and interrupted certificate
replacement, reached 178,430 requested bytes at `84f5b0b`, down from 192,261 after
reusing the snapshot allocation for journal encryption. [Heap measurements](HEAP_MEASUREMENTS.json)
record both clean-revision runs and per-instruction samples. These host figures omit
allocator overhead and stack and include host-specific storage costs; they do not
establish that the board's 196,608-byte reserved heap is sufficient.
Native copy and TLV services reduce interpreted code but add firmware text; no device
latency improvement or smaller safe heap has been established. Historical per-change
comparisons remain in Git history; reproduce current results before using them as budgets.

[Validation cadence](VALIDATION_CADENCE.md) defines focused, quick, checkpoint, and CI
coverage. Managed builds share a graph, compiler cases run in process, and acceptance
reuses outputs with bounded workers and isolated logs/state. The checkpoint after the
APDU API fixes ran at clean revision `9e89009` and took 60.677 seconds with two workers
and incremental rebuilding (`work/checkpoint-apdu-audit.json`). The tree remained
unchanged throughout the run. Host, Java wallet, recovery, generated
artifacts, and fuzz-target builds passed; workspace Clippy also passed. The workspace
run includes the JCVM registry, transport lifecycle, and session recovery tests.
All seven firmware profiles linked with engine/provider isolation checks. The only
failing stage was the seven unchanged flash optimization ceilings. This is not a
cold-build measurement; final-tree cold/warm measurements remain required.

Run `python3 scripts/check.py --checkpoint --jobs 2` and
`cargo clippy --workspace --all-targets -- -D warnings` for the consolidated host gate.
Checkpoint builds fuzz targets but does not run sustained campaigns. Before hardware
loading, use [first-flash preparation](FIRST_FLASH.md) from a clean committed tree;
verify the engine, revision, artifact hashes, and `hardware_flashed: false` in its manifest.

## Hardware and production blockers

[Hardware smoke](HARDWARE_SMOKE.md) records earlier revision-specific DK observations;
they do not validate this cleanup. The [dongle guide](DONGLE.md) records its unresolved
revision-unknown USB/APDU observation. Neither that observation nor host tests validate
this JCVM build's physical behavior.

Hardware access is deferred. Physical acceptance must prove the personalized OpenFIPS201
workflow on Makerdiary and cover both engine builds, CC310 independent vectors and
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
