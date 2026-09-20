# Preparing nRF52840 test builds

Preparation stops **before flashing**. No command in `prepare_first_flash.py` contacts a probe or writes a device. Passing its gates prepares a development test image. It does not establish hardware correctness or production security.

## Prepare and verify

Complete the [pinned compiler and vendor setup](CRYPTO_PROVIDERS.md#reproducible-build-inputs) first. Both engine builds now default to CC310; physical provider acceptance remains pending.

```sh
python3 scripts/prepare_first_flash.py --engine mc04
python3 scripts/prepare_first_flash.py --engine jcvm
```

Each engine has its own ignored `artifacts/first-flash/<engine>/dk/` directory containing
ELF, Intel HEX, binary, and a SHA-256 manifest. MC04 also includes both sample micro
images, metadata, and maps. The script runs host acceptance, Clippy, the release
cross-build, flash-load-range checks, initial stack/reset-vector checks and a minimum
static stack-margin check.

The manifest names the engine and linker layout and hashes the layout and every
artifact. Builds use separate target directories per engine/layout. Preparation
stages a fresh bundle, then replaces the previous generated directory, so stale
files cannot enter its manifest. A failed publication restores the prior bundle;
if restoration fails, its `.previous-*` backup remains for recovery.

The host gate includes .NET differential execution, deterministic preprocessing/signing, incremental MSBuild/pin checks, first-load failure injection, independent SCP03, persistent key operations, binary UART framing, and the real serial adapter through a fragmented pseudo-terminal. See `scripts/check.py --checkpoint` and the keystore documentation for the scenarios.

## Development credentials

The local `.keys/first-test-management.key` contains ENC16 || MAC16 for the first test board. `.keys/first-test-signing.seed` is an independent assembly-signing seed. Both are random, mode 0600 and ignored by Git. Keep them off shared artifact storage. No universal key is compiled into firmware. The public artifact manifest contains no secret keys.

To generate a fresh set in another checkout, create a mode-0700 `.keys` directory and run:

```sh
cargo run -p microcard-sim -- keygen .keys/first-test-management.key
cargo run -p microcard-sim -- keygen .keys/first-test-signing.seed
```

The keygen command refuses to overwrite existing files. Use development credentials only. MJ03 journals use AES-CCM authenticated encryption. Development key provisioning
and debug access do not provide production key protection.

## Commands for the later flashing step

These **MC04 DK** commands are documented, **not executed**. JCVM uses a different
flash layout and key page; never reuse the MC04 provisioning address for it. See
[board layouts](BOARD.md#flash-layout). First confirm a dedicated nRF52840 DK and preserve any firmware/data you need. Identify the intended probe with `probe-rs list`. Add `--probe` if more than one is connected. Do not use erase-all/recovery or chip-erase as an automatic fallback.

```sh
probe-rs download --chip nRF52840_xxAA --connect-under-reset --verify artifacts/first-flash/mc04/dk/microcard.elf
probe-rs download --chip nRF52840_xxAA --connect-under-reset --verify --binary-format bin --base-address 0xE0000 .keys/first-test-management.key
```

The key file is exactly 32 bytes. Offset 32 in the same 4 KiB page must remain erased. Firmware programs that ownership word before creating the first journal record. Existing markerless state is rejected with no migration path. After ownership, erasing the journals and anchor requires erasing the key page and provisioning new management keys.

Power-cycle the DK after both writes. UART uses the debugger's virtual serial port at 115200 8N1, TX P0.06/RX P0.08. Do not open a terminal concurrently. The key page is read/write locked by reset-scoped ACL after boot, so subsequent provisioning needs a controlled reset. Flash writes must stay out of journal regions 0xC0000–0xDFFFF.

Then run, with the actual serial port and a new domain identifier:

```sh
python3 scripts/dk_smoke.py --port /dev/cu.YOUR_DK_PORT --management-key .keys/first-test-management.key --signing-seed .keys/first-test-signing.seed --domain first-test
```

This script opens SCP03, creates an SSD, signs for its returned incarnation, uploads an assembly, installs two of its lifecycle entries, and exercises shared keys, values, HMAC/CMAC and CBC/CCM. It never erases an existing domain and never flashes firmware.

## After first flash

Hardware acceptance still needs actual UART/RNG/ACL behavior, reboot and interrupted-flash tests, peak heap/stack, watchdog behavior and latency measurements. Snapshot wear leveling, production key protection, full library/type coverage and firmware update trust remain production work. They must not be confused with the first-test-build stopping point.
