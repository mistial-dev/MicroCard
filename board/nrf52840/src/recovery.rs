#[cfg(feature = "dongle-layout")]
use nrf52840_pac as pac;

#[cfg(feature = "usb-ccid")]
use microcard_core::transport::ENTER_BOOTLOADER_APDU;

#[cfg(feature = "dongle-layout")]
const CLEAN_BOOT_MAGIC: u8 = 0xa5;

#[cfg(feature = "dongle-layout")]
pub(crate) fn enter_uf2() -> ! {
    // The Makerdiary bootloader documents 0x57 in GPREGRET as its application-to-UF2
    // handoff. Use the generated peripheral API so the register address and field width
    // continue to come from Nordic's device description.
    unsafe {
        (&*pac::POWER::ptr())
            .gpregret
            .write(|w| w.gpregret().bits(0x57));
    }
    cortex_m::peripheral::SCB::sys_reset()
}

#[cfg(feature = "dongle-layout")]
pub(crate) fn ensure_clean_bootloader_handoff() {
    let power = unsafe { &*pac::POWER::ptr() };
    if power.gpregret2.read().gpregret().bits() != CLEAN_BOOT_MAGIC {
        // Makerdiary UF2 transfers control with a direct branch, so active USB state can survive
        // into the application. One ordinary system reset gives the bootloader a clean run that
        // skips DFU and tears its board state down before branching back to us. GPREGRET2 is not
        // used by the installed bootloader and prevents a reset loop.
        power
            .gpregret2
            .write(|w| unsafe { w.gpregret().bits(CLEAN_BOOT_MAGIC) });
        cortex_m::asm::dsb();
        cortex_m::peripheral::SCB::sys_reset();
    }
    power.gpregret2.write(|w| unsafe { w.gpregret().bits(0) });
}

#[cfg(feature = "usb-ccid")]
pub(crate) fn is_enter_uf2_command(command: &[u8]) -> bool {
    cfg!(feature = "development-recovery") && command == ENTER_BOOTLOADER_APDU
}

#[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
pub(crate) fn set_uf2_recovery_marker(value: u8) {
    unsafe {
        (&*pac::POWER::ptr())
            .gpregret
            .write(|w| w.gpregret().bits(value));
    }
}
