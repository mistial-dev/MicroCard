# MicroCard

MicroCard is part of the [OpenPhysical ecosystem](https://github.com/OpenPhysical).
It is a work in progress.

This repository contains a Rust-based smart-card virtualization environment for the
Nordic nRF52840. MicroCard has two separate execution modes:

- **MC04** runs verified ECMA-335 assemblies produced from annotated .NET class
  libraries.
- **JCVM** loads and runs Java Card CAP files.

The nRF52840 firmware is built for one engine at a time. The host simulator includes
both engines so they can be developed and tested independently against the same
transport, security, persistence, and cryptographic service boundaries.

The eventual goal is an open stack for running open-source secure-element firmware,
so a system can use auditable code from its host through its security boundary. The
same work also provides lightweight Java Card and .NET runtimes for constrained
application firmware.

MicroCard is not production ready. Current capabilities and remaining release work
are tracked in [release readiness](docs/READINESS.md).

## Current status

The **JCVM environment is functional host-side**. It installs and runs the
[OpenPhysical OpenFIPS201 fork](https://github.com/OpenPhysical/OpenFIPS201), including
selection, PIV commands, personalization, PIN handling, P-256 signing and key
agreement, persistent storage, reboot recovery, and authenticated package loading.
The committed OpenFIPS201 fixture runs from a clean checkout.

The full derived P-256 host profile currently reports **61 passed, 0 failed, and
2 not applicable among 63 NIST contact vectors**. Secure messaging is not advertised,
and NIST Test Runner 5.0.1 incorrectly asks the agreement-only 9D key to sign; the
harness verifies that certificate binding with a real ECDH exchange before excluding
that assertion. These results are development evidence rather than a conformance claim. The
[Java Card profile](docs/JCVM_PROFILE.md) records the exact supported API surface,
test results, and known gaps.

The **MC04 environment is also functional host-side**. It compiles annotated C#
libraries into signed assemblies and runs them in isolated security domains. The
credential-wallet acceptance flow covers provisioning, P-256 signing, PIN recovery,
package rejection, and persistence across restart.

Both firmware engines cross-link for the nRF52840 DK and Makerdiary nRF52840 MDK USB
Dongle. The current JCVM firmware has not yet completed physical hardware acceptance.

## Run OpenFIPS201 locally

The shortest path uses the committed OpenFIPS201 load file and expected PIV responses.
It does not require hardware, an external OpenFIPS201 checkout, or the NIST test
runner.

Requirements:

- Rust **1.94.1**
- Python **3.12 or newer**

```sh
git clone https://github.com/mistial-dev/MicroCard.git
cd MicroCard
cargo build -p microcard-sim
python3 scripts/piv_vector_acceptance.py
```

This starts the JCVM simulator, installs the committed OpenFIPS201 applet, and replays
twelve PIV commands. A successful run ends with:

```text
PASS: 12 PIV commands answered by the applet on a blank card
```

To exercise authenticated loading, personalization, cryptography, persistence,
interrupted certificate replacement, reboot recovery, two installed applets, and
journal renewal, install the Python dependencies and run the managed transport
acceptance:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r scripts/requirements.txt
python3 scripts/jcvm_transport_acceptance.py
```

The simulator is at `target/debug/microcard-sim`. The raw `serve-jcvm` mode is useful
for a fixed command corpus. `serve-jcvm-managed` uses signed packages, SCP03, and a
persistent state directory. See the [Java Card profile](docs/JCVM_PROFILE.md) for
manual commands and alternate CAP files.

## Run the upstream NIST vectors

The upstream integration requires:

- the OpenPhysical OpenFIPS201 checkout pinned to the revision documented in the
  [Java Card profile](docs/JCVM_PROFILE.md#openfips201-provisioning);
- the separately distributed NIST PIV Test Runner **5.0.1**;
- the OpenFIPS201 test tools built according to their upstream instructions.

Generate the complete P-256 test identity and run the contact suite without a physical
card:

```sh
python3 scripts/nist_identity.py \
  --upstream /path/to/OpenFIPS201 \
  --out work/p256-identity

python3 scripts/nist_acceptance.py \
  --upstream /path/to/OpenFIPS201 \
  --config work/p256-identity/config.xml \
  --identity-folder work/p256-identity/identity \
  --provision-config \
  --suite card-contact \
  --out work/p256-identity-contact
```

The adapter stages an isolated copy of the upstream harness. It does not rewrite the
checkout or vector expectations. Reports retain preparation logs, JUnit results,
configuration hashes, simulator hashes, timings, skips, and failures.

## Run the MC04 wallet

The wallet requires .NET SDK **10.0.302**, Java **21**, Maven, and the Python
dependencies above.

```sh
python3 scripts/wallet_acceptance.py
```

The demonstration provisions separate Personal and Work credentials, signs fresh
challenges, exhausts and recovers a PIN, rejects invalid packages, and verifies state
after restarting the simulator. See the [wallet guide](docs/WALLET.md).

## Architecture and security boundaries

Both engines share APDU transport, GlobalPlatform/SCP03 management, authenticated
persistence, immutable image storage, quotas, key services, and hardware-provider
interfaces. Engine-specific loading, verification, linking, and execution remain
separate.

Packages use deterministic CBOR manifests and P-256 signatures. Persistent updates
use authenticated journals with explicit recovery rules. The runtimes independently
validate executable structure, bounds, native calls, ownership, and resource limits
before executing code. Private keys remain behind opaque native handles.

The [architecture overview](docs/ARCHITECTURE.md), [device contracts](docs/DEVICE_CBOR.md),
and [protocol](docs/PROTOCOL.md) describe these boundaries in detail.

## Development

Run the quick validation loop while developing:

```sh
python3 scripts/check.py
```

Run the broader host, wallet, recovery, generated-artifact, and board-link checkpoint
before release-facing changes:

```sh
python3 scripts/check.py --checkpoint --jobs 2
cargo clippy --workspace --all-targets -- -D warnings
```

Sustained fuzzing is a separate release gate. See [validation cadence](docs/VALIDATION_CADENCE.md)
and [fuzzing](docs/FUZZING.md). Contributor toolchain requirements and policies are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Build one nRF52840 firmware engine from `board/nrf52840`:

```sh
cargo build --release --locked --features engine-mc04
cargo build --release --locked --features engine-jcvm
```

Each command produces a separate firmware image. Selecting both engines or neither is
an error. Firmware defaults to the hardware-only CC310 provider; reproducible vendor
and compiler setup is documented in [crypto providers](docs/CRYPTO_PROVIDERS.md).

## Repository map

- `crates/microcard-core`: shared `no_std` transport, security, persistence, native
  services, and the MC04 runtime.
- `crates/microcard-engine-jcvm`: `no_std` CAP verification, Java Card linking,
  interpreter, object heap, firewall checks, and native APIs.
- `crates/microcard-memory`: checked allocation primitives shared by both engines.
- `crates/microcard-sim`: desktop simulator and persistent host backends.
- `managed`: .NET analyzers, framework assemblies, preprocessor, and packaging tools.
- `wallet`: Java host client using GlobalPlatformPro.
- `board/nrf52840`: board transport, flash, entropy, watchdog, USB CCID, and CC310
  integration.
- `scripts`: validation, acceptance, measurement, and generation tools.
- `tests` and `fuzz`: shared vectors, fixtures, and coverage-guided targets.
- `docs`: task-oriented documentation indexed by [docs/README.md](docs/README.md).

## License

MicroCard is licensed under [AGPL-3.0-or-later](LICENSE). Dependency notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
