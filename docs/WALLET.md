# Credential wallet

The Java 21 wallet is an executable 0.1-wip demonstration and a management client. It uses GlobalPlatformPro for SCP03 rather than maintaining a second secure-channel implementation.

## Complete simulator acceptance

```sh
python3 scripts/wallet_acceptance.py
```

The script builds the simulator, managed dependencies, Personal and Work assemblies, and the Java client. It runs from a temporary path containing spaces and verifies first ownership, ISD dependency loading, isolated Personal and Work keys, host signature validation, PIN recovery, invalid-package rejection, and restart persistence.

The demonstration creates only test keys and host-issued demonstration certificates. Those certificates establish that the returned public key signed a fresh challenge. They do not assert a real-world identity.

## Build manually

```sh
cargo build -p microcard-sim
python3 scripts/build_wallet_assets.py --output work/wallet-assets
cd wallet
./mvnw package
```

Run a fresh disposable demonstration:

```sh
java -cp 'wallet/target/classes:wallet/target/lib/*' \
  dev.mistial.microcard.wallet.Main demo \
  --sim target/debug/microcard-sim \
  --assets work/wallet-assets
```

Pass `--workspace DIR` to retain the encrypted simulator journal and generated certificate files. Use a new or empty directory for each full `demo` run.

## Persistent commands

```sh
microcard-wallet setup --sim SIM --assets ASSETS --state STATE --management-key KEY
microcard-wallet inventory --sim SIM --assets ASSETS --state STATE --management-key KEY
microcard-wallet sign --identity personal --message 'challenge' --pin 1234 CONNECTION_OPTIONS
microcard-wallet recover --identity personal --recovery 12345678 --new-pin 2468 CONNECTION_OPTIONS
```

The development management-key file is exactly 32 bytes: the first 16 bytes are used for ENC and DEK, and the second 16 bytes for MAC. Production provisioning must replace this development convention.

Command-line secrets can be visible to local process inspection. Use the interactive command for non-scripted entry:

```sh
microcard-wallet interactive CONNECTION_OPTIONS
```

## PC/SC reader

List readers, then replace simulator options with an exact reader name:

```sh
microcard-wallet readers
microcard-wallet inventory --reader 'MicroCard' --assets ASSETS --management-key KEY
```

Physical USB CCID interoperability remains a hardware acceptance item. The simulator path exercises the same Rust management and execution code but does not prove host USB behavior.
