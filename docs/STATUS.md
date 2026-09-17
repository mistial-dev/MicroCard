# 0.1-wip status

MicroCard has a working simulator path from annotated C# source to verified execution: compile, analyze, reduce CIL, sign, authenticate with SCP03, stage, verify, activate, install, select, execute, commit, and recover after restart.

## Implemented

- Compact MC04 assemblies retaining recognizable ECMA-335 metadata, signatures, tokens, and supported CIL.
- Host Roslyn diagnostics, metadata-only preprocessing, deterministic packaging, and independent Rust verification.
- Ed25519-signed MP03 packages with exact domain, incarnation, signer, dependency, version, capability, and resource binding.
- Permanent ISD ownership and SSD signer binding, transactional activation, rollback protection, and dependency linking.
- Bounded interpreter execution with typed verification, stack/frame/arena/fuel limits, native work budgets, and transaction safety.
- Domain stores, opaque keys, PIN/PUK retry floors, SHA-256, HMAC, AES-CMAC/CBC/CCM, Ed25519 verification, and P-256 operations.
- SCP03 security levels 01, 03, 11, and 13. Management requires a command MAC, so every one of those levels is served. A session requesting response encryption is refused at EXTERNAL AUTHENTICATE with 6982, because R-ENCRYPTION is advertised as unsupported.
- Java wallet using GlobalPlatformPro, a persistent simulator, and a cross-compiled nRF52840 image.
- Personal and Work credential demonstration covering isolation, signing, recovery, rejection cases, and reboot persistence.

## Hardware evidence

The nRF52840 DK has run UART SCP03, signed loading, installed assembly execution, persistent domain storage, and key-continuity checks across reboot. Development debug access remains enabled. USB CCID and optional CryptoCell paths compile but still require physical interoperability and fault testing.

## Release limits

The profile and wire formats may change before v1. The firmware has not completed production provisioning, debug lockout, verified-boot, side-channel, flash-endurance, USB CCID, or independent hardware-crypto acceptance. See the [roadmap](ROADMAP.md) and [hardware evidence](HARDWARE_SMOKE.md).
