# Flashing a dongle

The quickest way to get a MicroCard you can talk to. A Makerdiary nRF52840 MDK USB Dongle needs no debug probe and no serial port, because it carries a UF2 bootloader and MicroCard reaches the host over USB CCID.

Read [the security note](#what-you-are-agreeing-to) before using one for anything you care about.

## Build the image

```sh
python3 scripts/prepare_first_flash.py --features dongle
```

That runs the checkpoint gate first, so expect it to take a while. It writes `artifacts/first-flash/microcard.uf2` along with the ELF, the hex and a manifest recording the revision, the flash window and a digest of every artifact. It never touches a device.

## Put the dongle in bootloader mode

Hold the button while inserting the dongle, or press reset twice quickly if it is already inserted. A volume named `UF2BOOT` appears.

## Copy the image

```sh
cp artifacts/first-flash/microcard.uf2 /Volumes/UF2BOOT/
```

The dongle reboots itself when the copy finishes. The volume disappears and a smart card reader called `MicroCard MicroCard virtual smart card` takes its place.

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

This board keeps a UF2 bootloader above `0xEA000` and an S140 SoftDevice below `0x27000`. MicroCard may overwrite neither, so the image links at `0x27000` and divides the 780 KiB between them. [The board guide](BOARD.md) has the region table, and `board/nrf52840/memory-dongle.x` is the file the linker actually reads.

Those addresses were read from the bootloader's own `CURRENT.UF2` readback rather than from documentation. Confirm them against the board in front of you before trusting them, because a different bootloader version moves them.

## If the DK is what you have

The nRF52840 DK takes the same firmware through a debug probe instead. [First flash](FIRST_FLASH.md) covers that route, which also lets you provision a real key page and use the UART management transport.
