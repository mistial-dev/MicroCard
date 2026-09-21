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

From a running MicroCard development image, ask GlobalPlatformPro to authenticate and
enter UF2 mode:

```sh
gp --secure-apdu 80FE55AA
```

The command requires the SCP03 management key. The firmware sends the protected success
response, writes the bootloader's documented `0x57` request to `GPREGRET`, and resets.
A volume named `UF2BOOT` appears. If the application cannot start, hold the button while
inserting the dongle or press reset twice quickly.

If startup reaches MicroCard's read-only diagnostic mode but cannot establish SCP03, send
the same four-byte APDU without secure messaging (`gp --apdu 80FE55AA`). It is accepted
only in that already unusable state and performs no operation other than entering UF2.

Dongle builds also use that documented handoff after a Rust panic or Cortex-M hard fault.
A failed replacement therefore returns to `UF2BOOT` instead of becoming unreachable. A
power-loss or corrupt-vector failure can still require the physical recovery gesture.

## Copy the image

The example below selects MC04. For JCVM use its separate `jcvm/dongle` artifact.
Verify the selected engine and addresses in the generated manifest first. Current
[size-budget failures](READINESS.md) prevent preparation from completing; do not
treat older artifacts as a validated build of the current tree.

For a working hardware-iteration image while those optimization ceilings remain red,
add `--development-only`. The result is kept under `artifacts/development-firmware`,
and its manifest does not claim the skipped host gates.

The generated UF2 uses the nRF52840 application family `0xADA52840` required by the
board's Adafruit-derived bootloader. USB vendor/product identifiers are not UF2 family
identifiers; using one causes the copy to finish while the bootloader ignores every
payload block.

```sh
cp artifacts/first-flash/mc04/dongle/microcard.uf2 /Volumes/UF2BOOT/
```

The dongle reboots itself when the complete UF2 copy finishes. The runtime sets VTOR to
the application vector table before initializing RAM, so that bootloader-to-application
handoff does not need a physical disconnect. The volume disappears and a smart card
reader called `MicroCard MicroCard virtual smart card` takes its place.

To prove what was written after returning to bootloader mode, compare the bootloader's
readback by flash address:

```sh
python3 scripts/verify_uf2_readback.py \
  --expected artifacts/development-firmware/jcvm/dongle/microcard.uf2 \
  --current /Volumes/UF2BOOT/CURRENT.UF2
```

This checks every application byte and reports the first missing or different address.

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

The current UF2 bootloader reports `SoftDevice: not found`, starts applications at `0x1000`, and remains protected above `0xEA000`. MicroCard links at `0x1000` while retaining the established persistent-region addresses. [The board guide](BOARD.md) has the region table, and the linker reads `board/nrf52840/memory-dongle.x` for MC04 or
`board/nrf52840/memory-dongle-jcvm.x` for JCVM. Their persistent regions differ.

The application origin comes from a successful official OpenSK image and a minimal reset probe at `0x1000`. The protected upper boundary comes from the bootloader's `CURRENT.UF2` readback. A different bootloader version may use a different map.

## If the DK is what you have

The nRF52840 DK takes the same firmware through a debug probe instead. [First flash](FIRST_FLASH.md) covers that route, which also lets you provision a real key page and use the UART management transport.

## Known state

On 2026-09-20, the official Makerdiary OpenSK UF2 enumerated on the connected board,
proving the bootloader, USB wiring, and host port. Its bootloader reported no SoftDevice.
A minimal Rust image linked at `0x1000` executed and returned to UF2. A full JCVM image
then enumerated through `usbd-ccid` and `nrf-usbd`, exposed ATR `3B 80 01 81`, and answered
APDUs. Its hardware-provider startup stopped with diagnostic `6F04`, so CC310 remains a
board acceptance blocker.

The Cortex-M runtime sets VTOR to the application vector table before Rust data
initialization can overwrite the MBR's RAM forwarding word. The next hardware run must
verify software-requested UF2 entry, automatic boot after copying, and the corrected
provider startup before applet loading begins.
