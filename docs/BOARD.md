# nRF52840 DK development backend

Target PCA10056 / Cortex-M4F. Bare-metal Rust, no RTOS. The same `Endpoint`, `Card`, package verifier and VM are linked into the simulator and board image.

## Current hardware use

- UART: P0.06 TX / P0.08 RX, 115200 8N1, no flow control. Binary framing is a two-byte little-endian length followed by a short APDU. Replies use the same framing.
- TIMER0: 1 MHz free-running clock. Hardware operations have bounded waits and UART partial frames expire after one second.
- RNG: the default image uses the hardware RNG peripheral with digital error correction enabled. Entropy failures reject requests. The experimental `cc310-entropy` feature instead uses CryptoCell's documented TRNG path.
- NVMC: three AES-CCM encrypted/authenticated MJ03 journal slots plus separate append-only generation and nonce regions. One nonce bit is reserved before encryption; journal commit closes before its generation bit is consumed. No generic arbitrary-address native API.
- WDT: ten-second reset deadline. Loops feed it. VM fuel and native work limits independently bound managed work.
- Logical GPIO resource 0: active-low DK LED1 on P0.13. Other resources are rejected.
- Optional native USB: one full-speed CCID interface with 64-byte bulk endpoints and a two-byte interrupt endpoint. The board loop polls it at least once per millisecond while also retaining UART management framing. Disconnect clears partial commands and reconnect forces re-enumeration.
- ACL: firmware region write/erase protection after initialization, and read/write blocking of the provisioning page after management keys enter framework RAM. The write-protected range ends at the selected linker layout’s firmware boundary, leaving image, staging, and journal regions writable. Each protected region obeys the half-flash maximum. Registers are reset-scoped. Debug recovery remains enabled.
- Ownership marker: one word immediately after the 32 management-key bytes shares their 4 KiB erase page. Any programmed bit means the keys have owned persistent state. Boot accepts only an erased marker with completely erased durable state, or a programmed marker with present durable state.

ACL behavior and register offsets follow Nordic's [ACL specification](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/acl.html). It prevents the configured flash accesses until reset. It does not provide secure-element isolation or a complete verified boot chain. CryptoCell validation, MPU hardening, firmware signing and production APPROTECT policy remain work items. Software RustCrypto implementations perform cryptography in the default image.

## Flash layout

`memory-dk.x` reserves 576 KiB for code, 128 KiB for immutable packages, 64 KiB for package staging, three 64 KiB journal slots, a 4 KiB key page, a 4 KiB append-only generation anchor, and a 4 KiB nonce counter. The staging region is four 16 KiB banks. Each upload programs one bank directly, uses an erased bank before recycling an older one, and is forgotten across reboot unless activation has copied it to an image slot and committed the descriptor to the authenticated journal. Eight 16 KiB image slots occupy 0x90000 through 0xAFFFF on the DK and 0xC9000 through 0xE8FFF on the dongle. A replacement needs a free slot until its metadata commits. The build checks page alignment, overlap, and protected bootloader boundaries. The key page begins at 0xE0000 and must contain device-specific ENC16 || MAC16 management keys followed by an erased ownership word at offset 32. An erased/all-zero key pair refuses startup. On first boot, firmware programs the ownership word before creating the initial journal state. Markerless existing state has no migration path. If durable state is later erased while the marker survives, boot requires erasing the whole key page and provisioning fresh keys. A partial marker write counts as ownership and fails closed. No universal development key is compiled in. The anchor at 0xE1000 consumes one bit per commit and provides 32,768 commits without an erase. Journal slot 2 uses 0xE2000 through 0xF1FFF. The nonce counter occupies 0xF2000 on the DK and 0xE9000 on the dongle, and permits 32,768 encryption attempts including failed attempts.

The Makerdiary nRF52840 MDK USB Dongle uses `memory-dongle.x` instead, selected by the `dongle` cargo feature. That board keeps a UF2 bootloader above 0xEA000 and an S140 SoftDevice below 0x27000, neither of which MicroCard may overwrite, so the image links at 0x27000 and has 780 KiB to divide. Code takes 384 KiB there and every other region keeps the size it has on the DK, because a journal slot has to hold a serialized state and that ceiling does not depend on the board. The key page moves to 0xC7000 and the anchor to 0xC8000.

Both files define `_microcard_flash_origin`. The firmware references it, so an image that picked up a linker script from some other crate fails to link rather than running against a flash layout its own constants disagree with. The region constants the firmware reads are generated by `build.rs` from whichever file it selected.

Provisioning/flash commands are intentionally not automatically run: no DK/debug probe was detected. The first-test provisioning procedure in FIRST_FLASH.md preserves journal regions and keeps key bytes out of command logs. Securely store the corresponding host credentials separately from assembly-signing seeds.

## Build and measurements

```sh
cd board/nrf52840
cargo build --release --locked
arm-none-eabi-size target/thumbv7em-none-eabihf/release/microcard-nrf52840
```

The CCID image is opt-in and refuses to build without product-owned, nonzero identifiers:

```sh
MICROCARD_USB_VID=0x1234 MICROCARD_USB_PID=0x5678 cargo build --release --locked --features usb-ccid
```

The values above are compile-only examples. Assign identifiers authorized for the finished product before distributing firmware.

Experimental CryptoCell providers are opt-in:

```sh
python3 scripts/nrf_cc310_platform_spike.py --check
```

The script verifies the pinned Nordic source, archives, headers and licenses before building `cc310-sha256`, `cc310-entropy`, `cc310-cmac`, `cc310-hmac`, `cc310-aes`, `cc310-cbc`, `cc310-ccm` and `cc310-p256`. The PSA builds compile the pinned driver wrapper with a minimal configuration. P-256 also compiles two exact sdk-nrf CC3XX driver sources. Build-time pins cover the 35-file MAC, 36-file cipher, 37-file AEAD and 48/49/50-file P-256 dependency closures. The script records each isolated variant plus the combined provider image, exact symbols, C-allocation absence and bridge-stack evidence in [NRF52840_CC310_PLATFORM_SPIKE.json](NRF52840_CC310_PLATFORM_SPIKE.json). All eight features are compile/link evidence only and must remain disabled in deployable images until their physical test lists pass.

[BOARD_BUDGETS.json](BOARD_BUDGETS.json) records exact software-reference link measurements and the current flash/static-RAM ceilings. [Crypto provider measurements](CRYPTO_PROVIDER_MEASUREMENTS.json) separately record staged hardware-provider replacement; the vendor path still needs size reduction and physical validation. Test-only measurement counters are absent from firmware. `scripts/board_budgets.py --check` builds from the board directory so Cargo applies `.cargo/config.toml`. Building with only `--manifest-path` from the repository root does not apply that linker configuration.

BSS includes a 192 KiB heap reservation. These link-time sizes provide no measured peaks. Stack margin, allocator exhaustion, maximum-domain workloads and command latency require board testing.

## Hardware acceptance still required

Run the host SCP03 scenarios through binary UART framing and USB CCID. Verify enumeration, SELECT, counter storage, shared-domain storage, echo and protected commands. Capture GlobalPlatformPro CCID and SCP03 vectors after physical enumeration. Power-cycle after activation and after counter changes. Interrupt power during erase/program operations, then verify complete old/new state. Measure peak memory, maximum-case P-256 verification latency, watchdog behavior, entropy failure, flash endurance and ACL behavior. The current snapshot journal erases many pages per commit. Production wear leveling is not implemented.

## Development debug access

The default `development-debug` feature writes APPROTECT.DISABLE=0x5A at startup only if UICR.APPROTECT already contains HwDisabled (low byte 0x5A). It never writes UICR or performs recovery. This implements the software half of the Fxx-and-later development setup described in [Nordic's Debug and trace specification](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/dif.html), APPROTECT base 0x40000000, DISABLE offset 0x558. [UICR.APPROTECT](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/uicr.html) is at 0x10001208. Build with `--no-default-features --features software-crypto` to omit the development unlock in the software reference build. Use `--no-default-features --features cc310` for the hardware-only cross-link described in [readiness](READINESS.md). Doing so does not by itself establish a production debug policy.

The connected DK currently reports a locked core. Its exact silicon revision and UICR value have not been read, so improved APPROTECT is a likely explanation. Verification of that diagnosis remains pending. The original first-flash firmware lacks this startup path. Loading the fix on a locked device may require destructive recovery. No such recovery is authorized or performed automatically. A successful compile does not prove the existing board can reset through J-Link.
