# Flashing a dongle

Build separate MC04 or JCVM firmware for the Makerdiary nRF52840 MDK USB Dongle.
Its UF2 bootloader accepts images without a debug probe; MicroCard communicates
with the host over USB CCID.

Read [the security note](#what-you-are-agreeing-to) before using one for anything you care about.

## Build the image

```sh
python3 scripts/prepare_first_flash.py --engine mc04 --features dongle
python3 scripts/prepare_first_flash.py --engine jcvm --features dongle
```

That runs the checkpoint gate first, so expect it to take a while. It writes `artifacts/first-flash/<engine>/dongle/microcard.uf2` along with the ELF, the hex and a manifest recording the revision, the flash window and a digest of every artifact. It never touches a device.

## Put the dongle in bootloader mode

Hold the button while inserting the dongle, or press reset twice quickly if it is already inserted. A volume named `UF2BOOT` appears.

## Copy the image

The example below selects MC04. For JCVM use its separate `jcvm/dongle` artifact.
Verify the selected engine and addresses in the generated manifest first. Current
[size-budget failures](READINESS.md) prevent preparation from completing; do not
treat older artifacts as a validated build of the current tree.

For a working hardware-iteration image while those optimization ceilings remain red,
add `--development-only`. The result is kept under `artifacts/development-firmware`,
and its manifest does not claim the skipped host gates.

```sh
cp artifacts/first-flash/mc04/dongle/microcard.uf2 /Volumes/UF2BOOT/
```

The dongle reboots itself when the copy finishes. The volume disappears and a smart card reader called `MicroCard MicroCard virtual smart card` takes its place.

If startup cannot safely open card state, the firmware still enumerates as CCID but
answers APDUs with a proprietary diagnostic status. `6F01` is watchdog setup, `6F02`
management-key provisioning, `6F03` an ownership/state mismatch, `6F04` hardware
self-test, `6F05` storage-key derivation, `6F06` ownership-marker programming,
`6F07` incompatible persistent state, and `6F08` another storage-open failure. This
mode is read-only: it never erases or repairs state.

## Check that it answers

```sh
opensc-tool -l
```

The reader appears in that list. Its ATR is `3B 80 01 81`.

```sh
java -jar gp.jar -i
```

That reports GlobalPlatform 2.3.1 and `GP SCP03 (i=71)`, which is S16 mode with a derived card challenge, R-MAC and R-ENCRYPTION. A freshly flashed dongle answers the GlobalPlatform test keys, which is what tooling tries when given no keys, so `gp -l` lists an empty registry with no further arguments.

## What you are agreeing to

A dongle built with the `dongle` feature answers the well-known GlobalPlatform test keys while its key page is erased. Anyone who can reach the USB port can open a secure channel and load code onto it until its first signed assembly takes permanent ownership. This exists so a board with no debug probe can be reached at all, and it is the same position a stock development card ships in.

Two features make this explicit. `dongle-layout` is the flash map alone. `gp-test-keys` is the key fallback alone. The `dongle` feature is both, for convenience during development. A board meant for real use takes `dongle-layout` with a provisioned key page and leaves `gp-test-keys` out, and then an erased key page refuses to start rather than accepting a known key.

## Where the flash goes

This board keeps a UF2 bootloader above `0xEA000` and an S140 SoftDevice below `0x27000`. MicroCard may overwrite neither, so the image links at `0x27000` and divides the 780 KiB between them. [The board guide](BOARD.md) has the region table, and the linker reads `board/nrf52840/memory-dongle.x` for MC04 or
`board/nrf52840/memory-dongle-jcvm.x` for JCVM. Their persistent regions differ.

Those addresses were read from the bootloader's own `CURRENT.UF2` readback rather than from documentation. Confirm them against the board in front of you before trusting them, because a different bootloader version moves them.

## If the DK is what you have

The nRF52840 DK takes the same firmware through a debug probe instead. [First flash](FIRST_FLASH.md) covers that route, which also lets you provision a real key page and use the UART management transport.

## Known state

On 2026-09-19, the connected board enumerated as `MicroCard virtual smart card`
(USB `20A0:430A`). macOS PC/SC opened it with T=1 and returned ATR `3B800181`.
Read-only `80CA006600` returned GlobalPlatform recognition data ending in `9000`,
advertising SCP03 `i=71`. The flashed revision and engine are unknown; this confirms
USB and APDU operation for that image, not the current JCVM build. No image was
flashed or persistent data changed during this check. PC/SC required access outside
the development sandbox; inside it, context creation reported service unavailable.

On 2026-09-20, the same USB identity again answered ISD SELECT and read-only card
recognition data with `9000`. A 16-byte SCP03 INITIALIZE UPDATE then caused PC/SC to
report `SCARD_E_NOT_TRANSACTED` while the reader disconnected and re-enumerated. The
same failure reproduced with a raw short APDU, independently of GlobalPlatformPro.
The flashed revision and engine are still unknown, so this is a reproducible observation
about that image rather than evidence of a defect in the current tree. No debug probe or
`UF2BOOT` volume was exposed, so an unattended update was not possible.

Revision `9f44ff0` was built as JCVM development firmware and copied to `UF2BOOT` on
2026-09-20. The copy completed normally and the bootloader volume disappeared, but no
USB device or PC/SC reader enumerated afterward. The image therefore reaches neither
the observable CCID startup path nor OpenFIPS201 acceptance. Its initial stack pointer
is `0x20040000`, reset vector is `0x27101`, and every loadable section is inside the
application window. The remaining fault is in boot handoff or startup before USB
initialization; storage-open and CC310 self-test failures are currently silent on this
USB-only board because USB is initialized after both checks.

One flash attempt ended with the copy reporting an input and output error, the `UF2BOOT` volume disappearing, and the board never re-enumerating. That error is ambiguous on its own, because a UF2 bootloader reboots the moment it has every block and severs the copy, which produces the same message as a write that stopped early.

Two things are worth separating before flashing again.

Copy the file with a tool that reports a short write rather than `cp`, so a truncated transfer is visible instead of being guessed at. The image is over thirteen hundred blocks and `cp` shows no progress.

Then rule out the handover. This board's bootloader starts an application through the SoftDevice's master boot record, and a bare image linked at the application origin may need forwarding that a SoftDevice-based application arranges for itself. That would be a property of the image rather than of the transfer, and it needs the reset path checked rather than another copy.

Recovery is expected to work, because only the application region is ever targeted. The bootloader above `0xEA000` and the SoftDevice below `0x27000` are named in no block of the file.
