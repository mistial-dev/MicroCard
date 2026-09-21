# nRF52840 HAL mapping

The board crate owns all peripheral addresses and startup policy. Portable runtime code depends only on `microcard_core::hal` and the journal flash contract.

Startup selects the supported 64 MHz external crystal before opening storage or CC310 and enables the nRF52840's 2 KiB instruction cache. NVMC and ACL control use the generated PAC register types. Flash programming skips words that already contain the requested value; page erase remains explicit and is used only when a storage slot is reclaimed.

## Service mapping

- `usbd-ccid` owns the board APDU transport. The board keeps USB polling during applet work and uses the library's standard time-extension and reset paths.
- `BoardWatchdog` converts microsecond HAL ticks to the 32.768 kHz watchdog counter with checked arithmetic. A ten-second request programs `CRV=327679`, following `timeout=(CRV+1)/32768`.
- `Hardware` implements entropy, logical GPIO and the board-selected cryptographic provider. Managed code cannot select a provider or raw GPIO pin.
- `Nvm` rotates authenticated snapshots through three 64 KiB journal slots and keeps separate 4 KiB append-only generation and nonce counters behind the portable flash interface. Each counter programs one fresh 32-bit word per committed generation or encryption attempt, giving 1,024 values. Recovery accepts only a contiguous programmed prefix followed by erased words, then copies only the fixed header, trailer and declared authenticated record. It never allocates a complete slot buffer. Runtime code has no counter erase operation.
- `StagingNvm` implements the portable staging interface over four 16 KiB banks in the linker-defined 64 KiB region. Upload chunks program flash directly. Duplicate chunk checks use 64 bytes of stack scratch. Activation reads one exact package allocation, verifies it, and moves that allocation into persistent state. Failure leaves the flash upload available for retry. Volatile bank selection is intentionally lost at reset, so incomplete uploads never become executable.
- `BoardIdentity` returns the immutable eight-byte `FICR.DEVICEID` into caller-owned storage.
- `BoardResetReport` reads cumulative `POWER.RESETREAS`. Watchdog, reset-pin and software reasons map explicitly. A zero value remains `Unknown` because Nordic defines it as either power-on or brownout and the register cannot distinguish them.

Identity and erased-slot inspection allocate no heap memory. Oversized USB CCID frames fail before APDU dispatch, invalid protected-key provider output is cleared by the portable HAL helper, and journal reads validate every offset before copying into an exact caller-owned buffer.

## Register references

- Nordic nRF52840 Product Specification, [TIMER](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/timer.html), timer frequency and prescaler behavior.
- Nordic nRF52840 Product Specification, [POWER `RESETREAS`](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/power.html), offset `0x400`, cumulative flags and the ambiguous zero value.
- Nordic nRF52840 Product Specification, [FICR](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/ficr.html), `DEVICEID[0]` and `DEVICEID[1]` offsets `0x060` and `0x064`.
- Nordic WDT peripheral specification, watchdog counter relation `timeout=(CRV+1)/32768`.

## Current verification

Locked release builds for both `engine-mc04` and `engine-jcvm`, plus the JCVM dongle and software-reference profiles, cross-compile the board with this path. Host HAL tests enforce transport and protected-key output bounds. Physical flash timing, deadline, watchdog-reset and USB reconnect acceptance remain in the board work list.
