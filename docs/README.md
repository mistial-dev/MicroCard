# Documentation index

Use the [root README](../README.md) to run a simulator demonstration. [Release readiness](READINESS.md)
is the authoritative list of supported behavior, unfinished implementation, and hardware blockers.

## Build, change, and validate

- [Contributing](../CONTRIBUTING.md): install the pinned toolchain and make a focused change.
- [Validation cadence](VALIDATION_CADENCE.md): select a focused suite, checkpoint, or measurement run.
- [Architecture](ARCHITECTURE.md): locate shared services and engine-specific security boundaries.
- [Device contracts](DEVICE_CBOR.md): implement package, management, and persistence formats.

## Using the card

- [Wallet](WALLET.md) — the Java 21 client, its commands and PC/SC use.
- [Protocol](PROTOCOL.md) — the wire and persistence profile, including SCP03 and the management command table.
- [GlobalPlatform profile](GLOBALPLATFORM_PROFILE.md) — the supported subset of GlobalPlatform 2.3.1.
- [Domain policy](DOMAIN_POLICY.md) — per-SSD capability and resource policy.
- [Storage](STORAGE.md) and [persistent storage schema](PERSISTENT_STORAGE_SCHEMA.md) — the application store.
- [Key store](KEYSTORE.md) — the eight per-SSD key slots and their opaque handles.
- [Transactions](TRANSACTIONS.md) — what the transaction attribute means and where it stops.

## The .NET engine

- [Assembly format](ASSEMBLY_FORMAT.md) — the MC04 binary format.
- [MC04 opcodes](MC04_OPCODES.md) and [MC04 tables](MC04_TABLES.md) — generated reference appendices.
- [Profile](PROFILE.md) — the execution profile limits.
- [Profile enforcement](PROFILE_ENFORCEMENT.md) — how host diagnostics map to runtime invariants.
- [Image verification](IMAGE_VERIFICATION.md) — why the device check is independent of the signature.
- [Default assemblies](DEFAULT_ASSEMBLIES.md) and [default bundle](DEFAULT_BUNDLE.md) — the supported set.
- [Rider](RIDER.md) — analyzer package setup for authoring.
- [Kdf108 profile](KDF108_PROFILE.md) — the demonstration assembly profile.
- [Runtime budgets](RUNTIME_BUDGETS.md) — interpreter high-water marks.

## The Java Card engine

- [Java Card profile](JCVM_PROFILE.md) — the target, what is implemented, and what is missing.
- [Java Card opcodes](JCVM_OPCODES.md) and [Java Card API](JCVM_API.md) — generated reference appendices.

## Hardware

- [Dongle](DONGLE.md) — flashing a USB dongle, which needs no debug probe.
- [Board](BOARD.md) — the nRF52840 backend guide.
- [First flash](FIRST_FLASH.md) — preparing artifacts and provisioning a device.
- [Hardware smoke](HARDWARE_SMOKE.md) — what has actually run on a board, bound to a revision.
- [CCID profile](CCID_PROFILE.md) — the USB CCID descriptor and feature profile.
- [nRF52840 HAL](NRF52840_HAL.md) — peripheral mapping.
- [nRF52840 crypto inventory](NRF52840_CRYPTO_INVENTORY.md) — the hardware crypto survey and size budgets.
- [Board port checklist](BOARD_PORT_CHECKLIST.md) — what a production board port must satisfy.
- [HAL conformance](HAL_CONFORMANCE.md) — the portable scenario runner.
- [Crypto providers](CRYPTO_PROVIDERS.md) — the native crypto ABI and provider selection.

## Assurance and provenance

- [References](REFERENCES.md) — normative standards, editions and clause map, with the provenance rules for test vectors.
- [Readiness](READINESS.md) — current release blockers and required validation.
- [Copy audit](COPY_AUDIT.md) — the rationale for every retained buffer-copy site.
- [Fuzzing](FUZZING.md) — targets and campaign policy.

## Machine-readable records

These are data files consumed by scripts under `scripts/` rather than prose.

- `ASSEMBLY_BUDGETS.json`, `BOARD_BUDGETS.json` — size ceilings enforced by the budget scripts.
- `GLOBALPLATFORMPRO_PIN.json` — the pinned GlobalPlatformPro release and its digest.
- `NRF52840_CC310_PLATFORM_SPIKE.json` — measurements from the CryptoCell spike.
- `references.json`, `validation.json` — reference pins and the validation record.
