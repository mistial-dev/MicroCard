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
