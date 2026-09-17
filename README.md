# MicroCard

MicroCard is a programmable smart-card runtime written in Rust. Version **0.1-wip** can build annotated C# class libraries into compact, signed assemblies, load them through SCP03, and execute them in isolated security domains. A desktop simulator and a bare-metal nRF52840 development image use the same runtime.

This useful development release includes a complete simulator demonstration and early DK evidence. Production hardening remains in the [roadmap](docs/ROADMAP.md).

## Try the credential wallet

The demonstration provisions separate **Personal** and **Work** credentials, creates P-256 keys inside their security domains, signs fresh challenges, exhausts and recovers a PIN, rejects invalid packages, then restarts the simulator and verifies persistence.

Requirements: Rust 1.94.1, .NET SDK 10.0.302, Java 21, Maven, and Python 3.

```sh
python3 scripts/wallet_acceptance.py
```

The Java client uses GlobalPlatformPro for SCP03 command encryption, command MAC, and response MAC. MicroCard performs package and executable verification again inside the Rust runtime. See the [wallet guide](docs/WALLET.md) for individual commands and PC/SC use.

## Security model

- The first ISD assembly is `mscorlib`. Its Ed25519 signer takes permanent ownership of the card.
- Each SSD binds permanently to the signer of its first valid assembly.
- Dependencies must already exist. Both provider and consumer policies constrain versions, signers, digests, and scope.
- Package signatures authorize code. SCP03 authorizes management commands. Both checks are required.
- Rust verifies the reduced CIL before activation and enforces domain identity, memory limits, call targets, transactions, key ownership, and native-call budgets.
- Private keys are opaque native handles. Managed code receives only approved cryptographic operations.
- Persistent updates use an authenticated transactional journal. Interrupted activation exposes either the old state or the complete new state.

The [architecture overview](docs/ARCHITECTURE.md) explains the Rust, .NET, Java, and planned Java Card VM boundaries without repeating setup instructions.

## Development

```sh
python3 scripts/check.py
python3 scripts/check.py --checkpoint
```

The quick gate builds Rust and managed code and runs structural checks. The checkpoint gate performs the security and interoperability suite. Sustained fuzzing is reserved for release checkpoints. Rider consumes the standard Roslyn analyzer package. See [Rider authoring](docs/RIDER.md).

Build the nRF52840 image:

```sh
cd board/nrf52840
cargo build --release --locked
```

Read the [board guide](docs/BOARD.md) before provisioning or flashing.

## Repository map

- `crates/microcard-core`: portable `no_std` verifier, interpreter, domains, storage, secure messaging, and native services.
- `crates/microcard-sim`: persistent desktop simulator and package inspection commands.
- `managed`: framework assemblies, Roslyn analyzers, preprocessor, packager, and bundle tools.
- `wallet`: Java 21 client using GlobalPlatformPro.
- `samples`: executable assemblies and reusable-library examples.
- `board/nrf52840`: bare-metal transport, flash, entropy, watchdog, GPIO, and optional hardware crypto integration.
- `docs`: format, protocol, security policy, hardware, and development references.

MicroCard currently implements the reduced **.NET/CIL engine**. A future **Java Card VM** will provide a second Rust execution engine that shares management, storage, crypto, and hardware services.

## License

MicroCard is licensed under [AGPL-3.0-or-later](LICENSE). Dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
