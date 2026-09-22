# Readability cleanup baseline

This baseline was recorded from revision `76230bd` before the assembly API and authoring cleanup. It identifies review targets rather than imposing line-count limits.

## Validation time

Warm local validation on an Apple Silicon development host:

- Rust quick gate: 7.479 seconds total.
  - Workspace check: 3.485 seconds.
  - Shared transport test: 0.956 seconds.
  - Focused JCVM library tests: 3.036 seconds.
- Managed quick gate: 3.415 seconds total.
  - Managed solution build: 2.906 seconds.
  - Five focused reference and format executables: 0.505 seconds.

Host time is evidence about the development loop. It is not a device-latency measurement.

## Main ownership problems

- `domains.rs` mixes bounded collections, persisted domain state, package state, policy, credentials, transactions, and engine composition.
- `assembly.rs` combines binary decoding, metadata access, validation, and a large inline test suite.
- the JCVM applet module combines lifecycle, invocation, persistent heap coordination, and image ownership.
- the board entry point combines startup, diagnostics, CC310, flash, image staging, USB, reset, and engine composition.
- the managed analyzer and writer each combine unrelated validation and transformation stages.
- the MC04 ABI is repeated in the compiler, writer, analyzer, and Rust import resolver.

## Abstraction rule

An abstraction stays only when it owns an invariant, removes behavior duplicated by at least two callers, creates a real hardware or host seam, or reduces state passed through a call path. File movement alone is not a cleanup result.

## Invariants to preserve

- MC04 assemblies and JCVM applets remain separate concepts.
- ordinary execution does not allocate transaction rollback state.
- explicit transaction and PIN durability boundaries remain synchronous.
- signed packages remain the device trust boundary.
- board profiles contain one engine and use hardware cryptography without fallback.
- compile-time authoring references never become device dependencies.

## Comparison gates

Each structural commit must keep the relevant quick gate green. Changes on a hot path also compare generated package size, firmware flash, allocation count, and representative host APDU latency with this revision. A regression must be explained or removed before the cleanup continues.

## Post-cleanup comparison

Warm validation on the same host after the cleanup:

- Rust quick gate: **2.142 seconds**, down from 7.479 seconds.
- Managed quick gate: **1.956 seconds**, down from 3.415 seconds.
- The isolated SDK pack, template install, conversion, and signed host execution smoke
  takes about **4.9 seconds** and runs only in the checkpoint.
- Individual conversions in the checkpoint take **0.07 to 0.09 seconds** after the
  managed build is complete.

The authoring API adds readable context and service references to emitted metadata.
The Counter image still shrank from 2,476 to **2,464 bytes**. The default ISD bundle
grew from 10,242 to **10,975 bytes**, mostly because the ISO 7816 and cryptography
facades now use the typed API and shared checked copy path. Splitting DER-only
validation out of the shared TLV core reduced the ISO 7816 image from an intermediate
2,821 bytes to **2,157 bytes**. All assembly and package ceilings still pass.

Representative MC04 execution retains **zero transaction snapshots and zero transaction
clone allocations** on ordinary commands. The credential workload now peaks at 86
instructions, 20 evaluation slots, 152 transient bytes, and three transient objects.
Its authenticated state is 1,428 bytes.

Both MakerDiary engine profiles link and the link-map checks prove that each artifact
contains only its selected interpreter. The existing USB profiles remain above their
tracked flash ceilings: MC04 USB CCID is 234,324 bytes, MC04 dongle is 237,356 bytes,
and JCVM dongle is 232,288 bytes. The ceilings were not raised; this cleanup records
the remaining size work without blocking host correctness.
