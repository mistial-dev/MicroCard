# Release readiness

MicroCard is a development system, not yet a pre-hardware release candidate.
MC04 (.NET) and JCVM firmware are separate builds. Both cross-link for nRF52840;
the Makerdiary JCVM baseline has run on hardware, while complete physical acceptance
and production certification remain unfinished.
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
committed generation and uncertain candidates. JCVM pins a digest-verified slot so it cannot
be reclaimed while selected and reuses that mapping without hashing it on each APDU;
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
  reopening.
  The combined derived P-256 identity now imports all objects and keys and verifies
  readback after reopening. Repeated ISO status exceptions previously grew the heap
  until the snapshot exceeded capacity; runtime exception reuse fixes that failure.
  The combined profile reports 61 passed, 0 failed, and 2 not applicable among 63
  contact vectors. One exclusion is unadvertised secure messaging. The other is a
  Test Runner 5.0.1 defect that asks the agreement-only 9D key to sign. The runner still
  executes all six profile checks; provisioning independently validates the complete 9D
  certificate profile and proves its key binding through ECDH before that result is
  superseded. See the reproducible commands and profile distinctions in
  [JCVM acceptance](JCVM_PROFILE.md).
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
  reboot does not preserve PIN validation. These paths still need complete physical
  NIST execution and fault-injection coverage.
- Complete the remaining JCVM native API audit against Java Card 3.0.5, including
  internal failure boundaries. Instruction, transaction, PIN, and lifecycle changes
  checkpoint committed state while excluding open applet transactions. Existing tests
  cover rollback, allocation and undo exhaustion, partial construction, cancellation,
  failed providers, and failed persistence. OpenFIPS201 and the vendored JCAlgTest run
  under native diagnostics in CI and the checkpoint; any reached unimplemented native
  method or rejected instruction fails their raw and managed acceptance paths. JCAlgTest
  also queries all 104 algorithm values in its contiguous 3.0.5 factory tables and
  requires exact supported/unsupported results from the configured provider. This
  makes exercised gaps visible, but does not replace the remaining method-by-method
  audit. The committed static surface resolves all 145 applet references to 105 unique
  3.0.5 API methods and the quick gate catches drift. [JCVM semantics](JCVM_PROFILE.md)
  records the exact supported behavior and source clauses.
- Qualify journal renewal capacity and memory for all supported workloads. Automatic
  command-boundary renewal preserves the live applet and uses authenticated staging
  to recover interrupted bank replacement. Root registry counters remain finite;
  host memory bounds remain required, with physical service-life testing later.
  See [renewal and recovery invariants](STORAGE.md#jcvm-counter-renewal).
- Qualify the Makerdiary JCVM memory bound. Its current image links at 226,616 text
  bytes, 148 data bytes, and 198,284 BSS bytes, within the 288 KiB firmware region.
  All seven profiles link, but seven flash optimization ceilings still fail; none
  were raised. [Board budgets](BOARD_BUDGETS.json) contain the exact measurements.
  Earlier 2026-09-20 UF2 attempts used an invalid family and were ignored by the
  bootloader. The corrected image later booted, enumerated over USB CCID, passed its
  CC310 startup checks, and ran the signed OpenFIPS201 load/install/select smoke test.
  The final tree still needs the full physical closeout described below.
- Bound complete personalization workloads, including failures and renewal. At clean
  revision `f1adbf4`, the full OpenFIPS transport workload peaks at **217,368 requested
  host allocation bytes** with a 4,096-byte certificate capacity, and **238,910 bytes**
  with 24,000-byte capacity. Both pass provisioning, oversized-object rejection,
  interrupted replacement, reboot, signing/ECDH, two-instance selection, and renewal.
  Forced renewal sets both peaks. These exceed the board's 196,608-byte reservation
  on the host metric; they do not establish the board peak. Neither workload fills
  both applets to maximum allocations.
  [Heap evidence](HEAP_MEASUREMENTS.json) records current profiles and historical
  comparisons. Host figures include file-backed image/ciphertext buffers and exclude
  allocator overhead and stack. The board borrows mapped flash, but subtracting host
  buffers from an aggregate peak would not prove device safety.
  Fixed certificate objects need both current and replacement buffers. A 32,767-byte
  capacity fails creation with `6F00`: those arrays plus headers exceed the 64 KiB VM
  heap. The runner's accepted argument range is a probe, not a supported-capacity
  promise. Existing data survives oversized creation failure; reclamation of
  unreachable constructor allocations is not established. Define aggregate profile
  limits before claiming memory qualification or reducing the device heap.
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

[Hardware smoke](HARDWARE_SMOKE.md) records revision-bound DK results and the current
Makerdiary JCVM result. The Makerdiary image now boots, enumerates over USB CCID, opens
SCP03, and loads, installs, persists, and selects the signed OpenFIPS201 fixture.

Further physical acceptance must prove the personalized OpenFIPS201 NIST workflow on
Makerdiary and cover both engine builds, CC310 independent vectors and
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
