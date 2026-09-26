# nRF52840 firmware reliability audit

Checked against the firmware in this tree and these documents:

- `~/Documents/Reference Library/01_Standards/Technical_Specifications/Hardware/2023_Nordic_nRF52840_Product_Specification_v1.8.pdf` (4413_417 v1.8, 2023-12-01)
- `~/Documents/Reference Library/01_Standards/Technical_Specifications/Hardware/2023_Nordic_nRF52840_Revision_3_Errata_v1.2.pdf` (4413_679 v1.2, 2023-06-05)
- `~/Documents/Reference Library/01_Standards/Technical_Specifications/Hardware/2023_Nordic_nRF52840_Revision_2_Errata_v1.6.pdf` (4413_510 v1.6, 2023-06-05)
- `~/Documents/Reference Library/09_Vendor_Documentation/Makerdiary/2018_Makerdiary_nRF52840_MDK_USB_Dongle_Schematic_v1.0.pdf`
- `~/Documents/Reference Library/09_Vendor_Documentation/Nordic/2020_Nordic_nRF52840_DK_User_Guide_v1.4.1.pdf` (board identity only; no firmware defect depends on it)

Revision 3 lists errata 36, 166, 171, 187, 199, 213, 233, and 242 as inherited from Revision 2. Each anomaly still has its own applicable build codes. Record the board chip's build code before attributing a failure to one of them. This audit uses the complete v1.8 specification held in the Reference Library.

## Findings and remaining checks

### A snapshot rotation can halt the CPU for a full page erase

Product Specification section 4.3.10.1 specifies a page erase of 85 ms typical while the 32 MHz crystal is running, and a 32-bit write of 41 µs. Sections 4.3.1 and 4.3.2 state that the CPU is halted for the operation when it is executing from flash. Section 4.3.2 points to partial page erase as the way to divide that time into shorter pieces.

`board/nrf52840/src/storage.rs` waits for `NVMC.READY` from code linked in flash. It erases a whole region one 4 KiB page at a time and does not use partial erase. It feeds the watchdog and yields to USB only after a page has finished, and during programming only every 32 words.

`crates/microcard-core/src/journal.rs` `commit_owned_with_nonce` prepares the next snapshot slot before programming the new record. MC04 snapshot slots are 64 KiB, or 16 pages. JCVM registry slots are 8 KiB, or 2 pages; JCVM heap slots are 64 KiB, or 16 pages. The board adapter skips already-erased pages. Ordinary JCVM append records do not erase a slot. USB interrupts and watchdog feeding cannot run during each page erase from flash-executing code.

Section 4.3.10.1 specifies 10,000 erase cycles per page. A rotation spends one cycle on each non-erased page of the replacement slot. Partial erase can split the stall, but section 4.3.7 says page contents are undefined until the cumulative erase is complete. Only an idle, non-authoritative slot may be prepared this way.

### A flash word may be written only twice before its page is erased

Section 4.3.1 and the `nWRITE` row of section 4.3.10.1 allow two writes of the same 32-bit word before a page erase. The limit still applies when unchanged bits are written back as 1. The controller can only change a 1 to a 0.

The previous journal layout placed commit, reclaim-start, and reclaim-complete bytes in one aligned word. Over a slot's lifetime, that caused three word writes, a confirmed `nWRITE` violation. The current journal versions use separate aligned marker words; the host flash model rejects a third write. `program_region` still does not count writes or read each word back after `READY`, so each board writer must keep the program-once invariant.

### USB power-up and reconnection

Section 6.35.4 and Figure 197 specify this order: detect VBUS, enable USBD, start the crystal, wait for `EVENTCAUSE.READY` and for `USBPWRRDY`, then connect the D+ pull-up. The same section says that on VBUS removal, software should wait for the current EasyDMA transfer to finish and then disable USBD. `USBREMOVED` is the removal signal.

VBUS detection is the correct pre-enable gate in `board/nrf52840/src/usb_ccid.rs`: the regulator cannot report ready before USBD is enabled. The original `nrf-usbd` 0.3.0 connected after `EVENTCAUSE.READY` alone. The pinned local patch also waits for `POWER.USBREGSTATUS.OUTPUTRDY`, which reports the same information as `USBPWRRDY`, before connecting. Its readiness wait is bounded. Physical verification remains pending.

The original reconnect path only called `force_reset`. It now disables USBD on VBUS removal and repeats the enable sequence on return. The driver's EasyDMA operations are synchronous inside critical sections, so software VBUS handling cannot interrupt one. In-flight transfer behavior and disconnect recovery still require physical tests.

### Errata 199 is not applied

Revision 3 errata 199 applies to its listed QIAA-Fx0 and CKAA-Fx0 build codes. While a USBD EasyDMA transfer is in progress, incoming USB tasks are not performed. The published workaround writes `0x40027C1C` to `0x00000082` before a DMA transfer and clears it afterward.

The pinned driver does not yet contain that write. Its synchronous transfer path has not been shown to issue a conflicting task during DMA, so this is an applicability and trace question, not an established cause of reader loss. Record the chip build code when hardware returns before enabling the workaround.

### Errata 171 and 187 are applied on each USBD enable

Both are present on Revision 2 and Revision 3.

- Errata 171: enabling USBD, or clearing `LOWPOWER`, and then entering sleep before the module has powered up can leave USB dead. The workaround is the `0x4006EC00` / `0x4006EC14` sequence around enable and after the ready event.
- Errata 187: after a soft reset, a CPU lockup reset, or a firmware update, writing `ENABLE` may never produce `EVENTCAUSE.READY`. The workaround is the `0x4006EC00` / `0x4006ED14` sequence around the same enable.

`nrf-usbd` runs both sequences during enable and runs the 171 sequence again on wake. The dongle clean-boot path and a failed maintenance command both use `SCB::sys_reset` (`recovery.rs`, `rtic_runtime.rs`), a condition for errata 187. The first enable after reset runs the workarounds. The patched reconnect path now disables and re-enables USBD, so it also repeats them.

### The dongle build stores a bootloader request before the host configures it

`POWER.GPREGRET` is a retention register (section 5.3.7.16). The `dongle` feature includes `development-recovery`. `initialize_usb` writes `GPREGRET` to `0x57` before the USB stack exists, and the USB task writes it again on reconnect (`main.rs`, `rtic_runtime.rs`). `enter_uf2` writes the same value and does a system reset (`recovery.rs`).

On a dongle build, the USB task starts a 5 second deadline when the stack is created (`now() + 5_000_000` on the 1 MHz timer). If the device is still not in `Configured` when that deadline passes, `report_usb_failure` resets into the UF2 bootloader (`diagnostics.rs`). Panic, HardFault, and a CryptoCell abort take the same path (`main.rs`, `cc310.rs`).

The Makerdiary programming guide describes holding the button to enter that bootloader. A reset while `0x57` is set, including the five-second path, returns to the bootloader rather than CCID. Successful USB configuration clears the marker, so an ordinary later maintenance reset does not itself request UF2. A reset before configuration or during unsuccessful reconnect can. This is dongle development-recovery behavior, not the DK policy.

## Checked and consistent with the documents

The watchdog arming value is 10 seconds (`main.rs`, `watchdog.arm(10_000_000)`). Section 6.36 defines `timeout = (CRV + 1) / 32768`. The conversion in `platform.rs` produces `CRV` 327679, which is 10 seconds, inside the specified range of 458 µs to 36 hours. The reload value written is `0x6E524635`, which is the value section 6.36.4.10 requires. Writing `CONFIG` as 1 keeps the watchdog running while the CPU sleeps and pauses it while a debugger halts the CPU. That is the register's reset value.

Section 6.36 says that once started, the watchdog forces the internal 32.768 kHz RC on if no other 32.768 kHz source is running. The firmware does not start `LFCLK`. That matches the watchdog chapter. The RC is specified at ±500 ppm (section 5.4). The dongle schematic fits a 32.768 kHz crystal, `Y2`, with 12 pF load capacitors. The firmware never selects that crystal. The watchdog still has the RC source the specification says it will force on.

Errata 233 says `READYNEXT` is not reliable while executing from flash and that software must wait on `READY`. `storage.rs` waits on `READY`. The write-overlap in section 4.3.1 is therefore unavailable, and the 41 µs halt per word remains.

Errata 36 retains `CLOCK.EVENTS_DONE`, `EVENTS_CTTO`, and `CTIV` across a soft reset, watchdog reset, lockup reset, or pin reset. `EVENTS_HFCLKSTARTED` is not in that list. The firmware does not use the three retained registers.

Errata 242 hangs the CPU if an NVMC operation overlaps `POFWARN`. `POFCON` resets disabled (section 5.3.7.15), and the firmware does not enable it.

Errata 166 is the isochronous double-buffer fault. This device is bulk CCID and does not use isochronous endpoints.

Errata 213 clears the watchdog configuration on wake from System OFF. The firmware does not enter System OFF.

The dongle schematic uses an external buck to produce 3.3 V, a 10 µH inductor on the chip regulator pin, a 32 MHz crystal with 12 pF capacitors, and an RGB LED on P0.22 green, P0.23 red, and P0.24 blue. The firmware starts the high-frequency crystal before storage and USB, and its LED mask uses those three pins. Figure 197 shows the crystal start as part of USB enumeration. The USB bus type is built only with `ExternalOscillator`, so an image that does not take the crystal does not compile.

## Physical checks after the board returns

- Read the chip's build code and apply errata 199 only if the documented variant matches. A missing workaround alone does not identify the cause of the earlier reader loss.
- Capture the opt-in SWD trace across a full registry and heap rotation. It already records page erases, programmed words, maintenance time, and maximum USB polling gap. If a page erase causes reader loss or a missed command deadline, divide erasure into bounded idle-slot steps; do not treat a partially erased slot as recoverable.
- Exercise USB removal during an idle period and during a CCID transfer, then reconnect and confirm SCP03 and applet state recover. Repeat the complete JCAlgTest scan after these changes.
