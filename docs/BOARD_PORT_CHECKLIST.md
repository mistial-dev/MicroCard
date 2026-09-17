# MicroCard board-port checklist

Complete every applicable item for a production board. Record commands, tool versions, measurements and artifact digests in the board directory. An unsupported item needs an explicit design decision and compensating control.

## 1. Board identity and toolchain

- [ ] Record board revision, processor part/revision, errata set and schematic revision.
- [ ] Pin the Rust target, compiler, linker, probe tools, vendor SDK components and licenses.
- [ ] Provide a reproducible command that builds production and development variants from a clean checkout.
- [ ] Record hashes for the ELF, loadable image, linker map and signed release envelope.
- [ ] Return an immutable, non-secret device identity through `DeviceIdentity` without heap allocation. Document its source, stability and collision properties.

## 2. Memory and boot chain

- [ ] Define non-overlapping linker regions for firmware, staged assembly uploads, both journal generations, management keys, rollback anchor, boot metadata and future update slots.
- [ ] Assert region boundaries at link time and reject an image that overlaps persistent data.
- [ ] Measure production and development flash, static RAM, native stack and heap high-water marks. Set enforced regression ceilings with operating margin.
- [ ] Verify immutable boot code authenticates firmware before execution and rejects rollback according to the production update policy.
- [ ] Verify staged firmware update, interrupted update recovery and recovery-image authentication.
- [ ] Configure the MPU before processing untrusted input. Test forbidden execute, write and peripheral accesses.

## 3. Entropy and cryptography

- [ ] Map each `CryptoProvider` operation to the selected hardware or constant-time native implementation. Managed code cannot select a provider or request fallback.
- [ ] Run known-answer, malformed-input, output-bound and failure-clearing tests through the actual provider.
- [ ] Verify the hardware random source startup, health-test and failure behavior. `fill_entropy` must fill the complete caller buffer or return an error with no partially trusted result.
- [ ] Measure provider latency, energy, stack, scratch RAM and bridge copies at maximum supported input sizes.
- [ ] Confirm vendor library provenance, configuration, license and required secure/non-secure memory placement.
- [ ] Audit key-dependent timing, fault response and secret zeroization in success, error, timeout and reset paths.

## 4. Keys and provisioning

- [ ] Define separate management, assembly-signing, storage-encryption and firmware-signing key hierarchies.
- [ ] Keep private assembly-signing and firmware-signing keys off-device. Label every development key as test-only.
- [ ] Provision management and storage roots through an authenticated, auditable process. Never print or commit secret material.
- [ ] Protect stored roots from ordinary reads and writes after boot. Verify the protection survives every supported reset path.
- [ ] Map opaque key handles to device-owned keys and enforce domain, algorithm and usage ownership before provider dispatch.
- [ ] Test erased, zero, malformed, duplicated and partially provisioned key states. There is no ownership reset or format upgrade path.

## 5. Persistent flash

- [ ] Implement `JournalFlash` and staging flash with checked offsets, caller-owned buffers and real erase/program constraints.
- [ ] Confirm erase size, write size, alignment, one-to-zero programming, endurance and data-retention limits from the processor specification.
- [ ] Inject power loss at every byte or minimum hardware mutation for activation, key pinning, storage, lifecycle and deletion commits.
- [ ] Verify authenticated corruption never rolls back to an older state silently.
- [ ] Implement and test the trusted monotonic anchor used to reject replay of older valid journal ciphertext.
- [ ] Define wear leveling, exhausted-media behavior and safe physical reclamation. Logical deletion must revoke access immediately.

## 6. Time, watchdog and reset

- [ ] Implement wrapping-safe monotonic ticks and document frequency, drift, wrap-sampling requirement and behavior during sleep/debug halt.
- [ ] Apply explicit deadlines to transport and native operations. Timeouts must abort the command and its pending transaction.
- [ ] Arm and feed the watchdog through the HAL. Verify an intentional expiry resets the board and reports `ResetReason::Watchdog` after boot.
- [ ] Map reset registers without inventing precision the hardware lacks. Preserve or clear cumulative flags according to documented policy.
- [ ] Run reboot recovery after pin reset, watchdog reset, software reset, brownout/power interruption and debugger reset where distinguishable.

## 7. Logical hardware capabilities

- [ ] Expose only provisioned logical GPIO and peripheral identifiers. Reject raw pins, invalid values and resources absent from the domain policy.
- [ ] Confirm capability denial before touching a peripheral.
- [ ] Bound native work and apply per-operation deadlines independently from bytecode instruction fuel.
- [ ] Ensure irreversible hardware output is unreachable from a managed transaction.

## 8. APDU transports

- [ ] Route every transport into the same APDU endpoint and security-domain execution path.
- [ ] Enforce the short-command and short-response limits before dispatch. Reject inconsistent lengths, stale fragments and sequence errors.
- [ ] Test fragmentation, timeout, disconnect, reconnect, back-to-back frames and malformed lengths.
- [ ] Keep UART development framing documented and disabled or policy-controlled for production.
- [ ] For USB CCID, verify descriptors, one-slot state, power commands, transfer blocks, abort handling, interrupt status and PC/SC enumeration on macOS and Linux.
- [ ] For NFC, keep field detection and framing outside trusted command semantics and run contactless timing/interoperability tests separately.

## 9. Debug and production policy

- [ ] Keep recoverable debug enabled only in labeled development images.
- [ ] Define the production debug-lock transition, evidence capture and authorized recovery policy before locking devices.
- [ ] Confirm debug policy cannot rewrite protected storage, bypass verified boot or expose keys.
- [ ] Record security-relevant silicon configuration registers before and after provisioning.
- [ ] Preserve a non-destructive development route for diagnostics. Never require erase-all during ordinary acceptance.

## 10. Required acceptance evidence

- [ ] Pass the quick host gate, exhaustive checkpoint gate and sustained sanitizer-backed fuzz campaigns at the documented cadence.
- [ ] Run the reusable HAL conformance scenarios through the board host adapter.
- [ ] Run signed-load, dependency, storage-isolation, transaction, SCP03 and reboot-recovery scenarios on physical hardware.
- [ ] Verify GlobalPlatform-profile discovery and management through GlobalPlatformPro after USB CCID is implemented.
- [ ] Capture deterministic transport-independent SCP03 regression vectors using test-only keys.
- [ ] Publish command latency, energy, flash wear, peak RAM/stack and binary-size results with thresholds.
- [ ] Record every known limitation and incomplete production control in `ROADMAP.md`.

## Port completion gate

A board port is complete only when its production image passes the same managed assembly, package, domain, storage and secure-messaging behavior as the simulator. All board-specific security controls have direct evidence. And no required checklist item remains unexplained.
