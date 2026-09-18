# MicroCard

MicroCard is a programmable smart-card runtime written in Rust. Version **0.1-wip** runs two execution engines on one card. A reduced .NET/CIL engine builds annotated C# class libraries into compact signed assemblies and executes them in isolated security domains. A Java Card virtual machine loads a standard CAP file and runs it. A desktop simulator and a bare-metal nRF52840 image use the same runtime.

This is a development release. It carries a complete simulator demonstration and hardware evidence from an nRF52840 DK. Production hardening remains in the [roadmap](docs/ROADMAP.md). Start with the [documentation index](docs/README.md) to find anything below in more detail.

## What works today

- **The .NET engine** runs the credential wallet demonstration end to end, covering domain isolation, P-256 signing, PIN recovery, package rejection and persistence across a restart.
- **The Java Card engine** installs OpenFIPS201, registers it, accepts a SELECT and answers PIV commands with the applet's own status words. Four of the eight OpenFIPS201 release variants reach that point. See [the Java Card profile](docs/JCVM_PROFILE.md) for what each part of the engine does and what is still missing.
- **The secure channel** is SCP03 with implementation option `0x71`, meaning S16 mode, a derived card challenge, R-MAC and R-ENCRYPTION. It serves security levels 01, 03, 11, 13 and 33, which is every combination carrying a command MAC.
- **The board** enumerates as a USB CCID reader and has carried SCP03 at every one of those levels through GlobalPlatformPro and the Java wallet.

The [status record](docs/STATUS.md) states the limits of each claim, and the honest summary of the Java Card engine is that a card loaded this way answers from an empty card. Cipher, signature and key agreement operations are unimplemented.

## Try the credential wallet

The demonstration provisions separate **Personal** and **Work** credentials, creates P-256 keys inside their security domains, signs fresh challenges, exhausts and recovers a PIN, rejects invalid packages, then restarts the simulator and verifies persistence.

Requirements: Rust 1.94.1, .NET SDK 10.0.302, Java 21, Maven, and Python 3 with `scripts/requirements.txt` installed.

```sh
python3 scripts/wallet_acceptance.py
```

The Java client uses GlobalPlatformPro for SCP03 command encryption, command MAC, and response MAC. MicroCard performs package and executable verification again inside the Rust runtime. See the [wallet guide](docs/WALLET.md) for individual commands and PC/SC use.

## Try the Java Card engine

Build a Load File Data Block from a CAP file, then run it. The CAP file is a third-party build output and stays outside this repository.

```sh
python3 scripts/jcvm_cap_inventory.py OpenFIPS201-standard-CS2-attestation-false.cap --load-file applet.lfdb
cargo build
python3 scripts/jcvm_applet_acceptance.py applet.lfdb
```

That drives a SELECT, a GET DATA and two VERIFY commands through `microcard-sim serve-jcvm` and checks the applet's own answers, including that its PIN retry counter goes down and stays down.

## Security model

- The first assembly assigned to the ISD takes permanent ownership of the card through its Ed25519 signer.
- Each SSD binds permanently to the signer of its first valid assembly.
- Dependencies must already exist. Both provider and consumer policies constrain versions, signers, digests, and scope.
- Package signatures authorize .NET code. SCP03 authorizes management commands. Both checks are required.
- A Java Card package carries no signature of its own, so on-card verification and the secure channel are the whole safety boundary for it. This is a deliberate difference from the .NET engine and [the Java Card profile](docs/JCVM_PROFILE.md) explains it.
- Rust verifies the reduced CIL before activation and enforces domain identity, memory limits, call targets, transactions, key ownership, and native-call budgets.
- Private keys are opaque native handles. Managed code receives only approved cryptographic operations.
- Persistent updates use an authenticated transactional journal. Interrupted activation exposes either the old state or the complete new state.

The [architecture overview](docs/ARCHITECTURE.md) explains the Rust, .NET, Java and Java Card boundaries without repeating setup instructions.

## Development

```sh
python3 scripts/check.py
python3 scripts/check.py --checkpoint
```

The quick gate builds Rust and managed code and runs structural checks. The checkpoint gate performs the security and interoperability suite and takes a long time. Sustained fuzzing is reserved for release checkpoints. Read [CONTRIBUTING.md](CONTRIBUTING.md) before a first change, because the gate enforces a documentation style rule that has surprised people. Rider consumes the standard Roslyn analyzer package. See [Rider authoring](docs/RIDER.md).

Build the nRF52840 image:

```sh
cd board/nrf52840
cargo build --release --locked
```

Read the [board guide](docs/BOARD.md) and [first flash](docs/FIRST_FLASH.md) before provisioning or flashing.

## Repository map

- `crates/microcard-core`: portable `no_std` verifier, CIL interpreter, domains, storage, secure messaging, and native services.
- `crates/microcard-engine-jcvm`: portable `no_std` Java Card engine, covering the CAP container, structural verification, the object heap, linking, the interpreter and the native API classes.
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
