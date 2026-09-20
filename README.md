# MicroCard

MicroCard is a programmable smart-card runtime written in Rust. Version **0.1-wip** provides separate .NET and Java Card firmware builds. A reduced .NET/CIL engine builds annotated C# class libraries into compact signed assemblies and executes them in isolated security domains. A Java Card virtual machine loads a standard CAP file and runs it. A desktop simulator and a bare-metal nRF52840 image use the same runtime.

This is a development release. It carries a complete simulator demonstration and hardware evidence from an nRF52840 DK. Current capabilities and release blockers are tracked in [release readiness](docs/READINESS.md). Start with the [documentation index](docs/README.md) to find anything below in more detail.

## What works today

- **The .NET engine** runs the credential wallet demonstration end to end, covering domain isolation, P-256 signing, PIN recovery, package rejection and persistence across a restart.
- **The Java Card engine** installs OpenFIPS201, registers it, accepts a SELECT and answers PIV commands with the applet's own status words. Four of the eight OpenFIPS201 release variants reach that point. See [the Java Card profile](docs/JCVM_PROFILE.md) for what each part of the engine does and what is still missing.
- **The secure channel** is SCP03 with implementation option `0x71`, meaning S16 mode, a derived card challenge, R-MAC and R-ENCRYPTION. It serves security levels 01, 03, 11, 13 and 33, which is every combination carrying a command MAC.
- **Earlier DK firmware** enumerated as a USB CCID reader and carried SCP03 through GlobalPlatformPro and the Java wallet. Current firmware still requires physical acceptance.

JCVM cipher, signature, and key-agreement operations remain unimplemented. Both engine
builds cross-link; [earlier DK observations](docs/HARDWARE_SMOKE.md) do not establish
hardware acceptance of the current tree.

## Try the credential wallet

The demonstration provisions separate **Personal** and **Work** credentials, creates P-256 keys inside their security domains, signs fresh challenges, exhausts and recovers a PIN, rejects invalid packages, then restarts the simulator and verifies persistence.

Requirements: Rust 1.94.1, .NET SDK 10.0.302, Java 21, Maven, and Python 3 with `scripts/requirements.txt` installed.

```sh
python3 scripts/wallet_acceptance.py
```

The Java client uses GlobalPlatformPro for SCP03 command encryption, command MAC, and response MAC. MicroCard performs package and executable verification again inside the Rust runtime. See the [wallet guide](docs/WALLET.md) for individual commands and PC/SC use.

## Try the Java Card engine

An OpenFIPS201 build is committed, so this runs on a clean checkout.

```sh
cargo build
python3 scripts/piv_vector_acceptance.py
python3 scripts/jcvm_transport_acceptance.py
```

That replays twelve PIV commands through `microcard-sim serve-jcvm` and compares the applet's own status words against committed expectations. Half of those commands are authentic encodings captured from real cards. Their provenance and license are recorded beside them in `crates/microcard-engine-jcvm/tests/vectors`. Pass a different Load File Data Block to `scripts/jcvm_applet_acceptance.py` to drive another build, producing one with `scripts/jcvm_cap_inventory.py --load-file`.

The raw `serve-jcvm` corpus runner is memory-only, including transaction checkpoints.
Use the managed mode for persistence and recovery validation.

The transport acceptance uses `serve-jcvm-managed MANAGEMENT_KEYS STATE_DIR` to load
signed packages through SCP03 and check persistent recovery. Add `-binary` to that
mode for length-prefixed transport. Each state directory permits one simulator process.

## Security model

- The first assembly assigned to the ISD takes permanent ownership of the card through its signer identity.
- Each SSD binds permanently to the signer of its first valid assembly.
- Dependencies must already exist. Both provider and consumer policies constrain versions, signers, digests, and scope.
- Package signatures authorize .NET code, as P-256 ECDSA over SHA-256. SCP03 authorizes management commands. Both checks are required.
- A package carries its signer as a 65-byte uncompressed key. What a domain binds to is that key's SHA-256 digest. A compressed key is refused, and so is the malleable twin of a signature, so one signed package has exactly one encoding.
- JCVM device loading requires a signed MP05 package, the same envelope used by .NET, with a JCVM-specific manifest and verified CAP image. Raw CAP files remain a simulator input. See [the Java Card profile](docs/JCVM_PROFILE.md) for the delivery gaps.
- Rust verifies the reduced CIL before activation and enforces domain identity, memory limits, call targets, transactions, key ownership, and native-call budgets.
- Private keys are opaque native handles. Managed code receives only approved cryptographic operations.
- Persistent updates use an authenticated transactional journal. Interrupted activation exposes either the old state or the complete new state.

The [architecture overview](docs/ARCHITECTURE.md) explains the Rust, .NET, Java and Java Card boundaries without repeating setup instructions.

## Development

```sh
python3 scripts/check.py
python3 scripts/check.py --checkpoint
```

The quick gate builds Rust and managed code and runs structural checks. The checkpoint adds security, recovery, interoperability, wallet, and board checks. Use `--suite compiler --jobs 2` for analyzer and preprocessor cases, or choose another [focused suite](docs/VALIDATION_CADENCE.md#focused-suites-and-timings). Sustained fuzzing runs separately. See [contributing](CONTRIBUTING.md) for setup and [Rider authoring](docs/RIDER.md) for the standard Roslyn analyzer package.

Build one nRF52840 engine:

```sh
cd board/nrf52840
cargo build --release --locked --features engine-mc04
# Or build the Java Card engine:
cargo build --release --locked --features engine-jcvm
```

Selecting neither engine or both is an error. The board budget gate saves separate
ELF and link-map artifacts under `artifacts/firmware/`. These are development builds;
[readiness](docs/READINESS.md) lists the remaining release blockers.

The USB dongle requires no debug probe, but its boot acceptance remains unresolved. See [the dongle guide](docs/DONGLE.md). For the nRF52840 DK, read the [board guide](docs/BOARD.md) and [first flash](docs/FIRST_FLASH.md) before provisioning or flashing.

## Repository map

- `crates/microcard-core`: portable `no_std` verifier, CIL interpreter, domains, storage, secure messaging, and native services.
- `crates/microcard-engine-jcvm`: portable `no_std` Java Card engine, covering the CAP container, structural verification, the object heap, linking, the interpreter and the native API classes.
- `crates/microcard-memory`: checked allocation arithmetic shared by the two engines.
- `crates/microcard-sim`: persistent desktop simulator, package inspection, and the Java Card serving mode.
- `managed`: framework assemblies, Roslyn analyzers, preprocessor, packager, and bundle tools.
- `wallet`: Java 21 client using GlobalPlatformPro.
- `samples`: executable assemblies and reusable-library examples.
- `board/nrf52840`: bare-metal transport, flash, entropy, watchdog, GPIO, USB CCID, and optional hardware crypto integration.
- `format`: machine-readable opcode and API tables that generate Rust source and reference appendices.
- `scripts`: the validation gates, the acceptance suites, and the generators.
- `tests`, `fuzz`: shared vectors and fixtures, and the coverage-guided fuzz targets.
- `docs`: format, protocol, security policy, hardware, and development references, indexed by [docs/README.md](docs/README.md).

## License

MicroCard is licensed under [AGPL-3.0-or-later](LICENSE). Dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Firmware defaults use CC310. Run the [pinned compiler and vendor setup](docs/CRYPTO_PROVIDERS.md#reproducible-build-inputs) before board builds. Software reference builds require `--no-default-features --features engine-mc04,software-crypto` (or `engine-jcvm`).
