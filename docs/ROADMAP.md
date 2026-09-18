# Implementation roadmap

This is the authoritative public work list. Checked items have repeatable repository evidence. Hardware items require a physical target.

## 0.1-wip host release

- [x] Reduced .NET assembly format, preprocessor, interpreter, and simulator.
- [x] Roslyn analyzer package with Rider-compatible diagnostics.
- [x] Signed packages, on-runtime executable verification, dependency linking, and rollback checks.
- [x] ISD ownership, SSD isolation, native cryptography, transactions, and encrypted journal recovery.
- [x] Java wallet using GlobalPlatformPro SCP03 and a multi-identity credential demonstration.
- [x] SCP03 in S16 mode with a derived card challenge, response integrity and response encryption, with the advertised implementation option derived from the build.
- [x] Repeatable macOS build and acceptance path.
- [ ] Validate Linux x64 and Windows x64 release bundles in CI.
- [ ] Complete one bounded release fuzz campaign and archive its summary.

## nRF52840 production work

- [x] Bare-metal Rust build, UART transport, flash, entropy, timer, watchdog, GPIO, and development smoke test.
- [x] Reboot recovery and persistent-key continuity evidence.
- [ ] Run the complete signed-loading adversarial suite after hardware reboot.
- [x] USB CCID enumeration and GlobalPlatformPro interoperability on physical hardware, at every security level carrying a command MAC.
- [ ] Complete USB CCID abort timing, disconnect, suspend and sustained throughput on physical hardware.
- [ ] Capture deterministic GlobalPlatformPro SCP03 regression vectors from the physical reader path.
- [ ] Validate optional CryptoCell known-answer tests, forced failures, copy counts, latency, energy, and stack use.
- [ ] Validate power interruption at ownership, activation, storage commit, credential retry, secure-channel sequence reservation, and deletion boundaries.
- [ ] Measure release flash, RAM, command latency, and endurance on final hardware.
- [ ] Define production provisioning, verified boot, MPU policy, debug lockout, recovery, and secure disposal.

## Managed platform

- [ ] Expand default `System` and cryptography facades where credential applications need them.
- [ ] Add schema migration policy before permitting compatible in-place assembly replacement.
- [ ] Add further original credential samples and interoperability vectors.

## Transport and loading

- [ ] Accept extended-length APDUs over T=1, bounded by a build-time ceiling.
- [ ] Load through GlobalPlatform alone, with the engine deciding from the loaded file which kind of package it holds.
- [ ] Retire the proprietary staging path once every host emits GlobalPlatform frames.

## Java Card VM

- [x] Select a Java Card version, CAP subset, and API profile. See [JCVM_PROFILE.md](JCVM_PROFILE.md).
- [ ] Specify persistent objects, firewall contexts, transactions, lifecycle, and domain mapping.
- [x] Read the CAP container and verify a package structurally, checked against real applet packages.
- [x] Interpret the instruction set below the API layer, including fields, arrays, invocation and exceptions.
- [x] Implement interface dispatch and the applet lifecycle.
- [x] Implement the native API classes an applet needs to install, select and process.
- [x] Run a real applet in the simulator. OpenFIPS201 installs, selects and answers PIV commands through `serve-jcvm`.
- [x] Commit a load file and a PIV command corpus, and check the applet's answers in the gate and in CI.
- [ ] Answer the cipher, signature and key agreement operations through the card.
- [ ] Deliver a package to the engine through GlobalPlatform loading rather than a file path.
- [ ] Compile the engine into the board image and back it with dedicated code and heap regions.
- [ ] Add independent conformance and cross-engine isolation tests.
