# 0.1-wip status

MicroCard has a working simulator path from annotated C# source to verified execution: compile, analyze, reduce CIL, sign, authenticate with SCP03, stage, verify, activate, install, select, execute, commit, and recover after restart.

## Implemented

- Compact MC04 assemblies retaining recognizable ECMA-335 metadata, signatures, tokens, and supported CIL.
- Host Roslyn diagnostics, metadata-only preprocessing, deterministic packaging, and independent Rust verification.
- Ed25519-signed MP03 packages with exact domain, incarnation, signer, dependency, version, capability, and resource binding.
- Permanent ISD ownership and SSD signer binding, transactional activation, rollback protection, and dependency linking.
- Bounded interpreter execution with typed verification, stack/frame/arena/fuel limits, native work budgets, and transaction safety.
- Domain stores, opaque keys, PIN/PUK retry floors, SHA-256, HMAC, AES-CMAC/CBC/CCM, Ed25519 verification, and P-256 operations.
- A Java Card virtual machine that installs and runs a real applet. OpenFIPS201 selects and answers PIV commands in the simulator, with its own PIN retry counter surviving from one command to the next.
- A committed OpenFIPS201 load file and a corpus of PIV commands with their expected status words, replayed by the checkpoint gate and by CI, so that claim has an automated check behind it.
- SCP03 in S16 mode with a derived card challenge, at security levels 01, 03, 11, 13 and 33, which is every combination carrying a command MAC. Management requires that MAC and accepts any of them. Optional capabilities are cargo features, and both the advertised implementation option and the accepted levels are derived from the enabled set, so the card cannot offer protection it does not apply. A level outside that set is refused at EXTERNAL AUTHENTICATE with 6982.
- Java wallet using GlobalPlatformPro, a persistent simulator, and a cross-compiled nRF52840 image.
- Personal and Work credential demonstration covering isolation, signing, recovery, rejection cases, and reboot persistence.

## Hardware evidence

The nRF52840 DK has run UART SCP03, signed loading, installed assembly execution, persistent domain storage, and key-continuity checks across reboot. It has also enumerated as a USB CCID reader and carried SCP03 at every security level through GlobalPlatformPro and the Java wallet. Development debug access remains enabled. Abort timing, disconnect, sustained throughput and the optional CryptoCell paths still require physical testing.

A DK has separately confirmed over USB that GlobalPlatformPro reads GlobalPlatform 2.3.1 and `GP SCP03 (i=71)` from the card, that its S16 retry path is exercised, and that one load file backs three applet instances under AIDs of their own.

**A dongle image builds and has not yet booted.** The Makerdiary nRF52840 MDK USB Dongle layout, its UF2 packaging and the test-key fallback are all implemented and the image links and fits. One flash attempt ended with the copy reporting an input and output error, and the board did not re-enumerate afterwards. Only the application region was ever targeted, so the bootloader and the SoftDevice are intact and the board recovers by being put back into bootloader mode. [The dongle guide](DONGLE.md) records what to try next. Treat every dongle claim as unproven until that is settled.

## Release limits

The profile and wire formats may change before v1. The firmware has not completed production provisioning, debug lockout, verified-boot, side-channel, flash-endurance, USB CCID fault, or independent hardware-crypto acceptance. See the [roadmap](ROADMAP.md) and [hardware evidence](HARDWARE_SMOKE.md).
