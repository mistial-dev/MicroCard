use microcard_core::{
    hal::{DeviceIdentity, ResetReason, ResetReport, Watchdog},
    Error, Result,
};
use nrf52840_pac as pac;

#[cfg(not(feature = "cc310-entropy"))]
pub(crate) const RNG: usize = 0x4000D000;
const TIMER: usize = 0x40008000;
const WDT: usize = 0x40010000;

// Register offsets follow nRF52840 Product Specification peripheral register tables.
pub(crate) unsafe fn read(address: usize) -> u32 {
    core::ptr::read_volatile(address as *const u32)
}

pub(crate) unsafe fn write(address: usize, value: u32) {
    core::ptr::write_volatile(address as *mut u32, value)
}

pub(crate) fn enable_instruction_cache() {
    let nvmc = unsafe { &*pac::NVMC::ptr() };
    nvmc.icachecnf.write(|w| w.cacheen().enabled());
}

pub(crate) fn start_hfxo() -> Result<()> {
    // Leave EVENTS_HFCLKSTARTED set. The HAL consumes and clears it when it later takes
    // ownership of CLOCK for USB, while storage and CC310 already run from the crystal.
    let clock = unsafe { &*pac::CLOCK::ptr() };
    clock
        .tasks_hfclkstart
        .write(|w| w.tasks_hfclkstart().set_bit());
    let start = now();
    while clock.events_hfclkstarted.read().bits() == 0 {
        feed();
        if now().wrapping_sub(start) > 1_000_000 {
            return Err(Error::Native);
        }
    }
    Ok(())
}

pub(crate) fn now() -> u32 {
    unsafe {
        write(TIMER + 0x040, 1);
        read(TIMER + 0x540)
    }
}

#[cfg(not(feature = "cc310-entropy"))]
pub(crate) fn wait(address: usize) -> Result<()> {
    let start = now();
    while unsafe { read(address) } == 0 {
        if now().wrapping_sub(start) > 1_000_000 {
            return Err(Error::Native);
        }
    }
    Ok(())
}

pub(crate) fn feed() {
    unsafe { write(WDT + 0x600, 0x6E524635) }
}

pub(crate) struct BoardWatchdog;

impl Watchdog for BoardWatchdog {
    fn arm(&mut self, timeout_ticks: u64) -> Result<()> {
        if timeout_ticks == 0 {
            return Err(Error::Bounds);
        }
        let counter = timeout_ticks
            .checked_mul(32_768)
            .and_then(|value| value.checked_div(1_000_000))
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::Bounds)?;
        unsafe {
            write(WDT + 0x504, counter);
            write(WDT + 0x508, 1);
            write(WDT + 0x50C, 1);
            write(WDT, 1);
        }
        Ok(())
    }

    fn feed(&mut self) -> Result<()> {
        feed();
        Ok(())
    }
}

pub(crate) struct BoardIdentity;

impl DeviceIdentity for BoardIdentity {
    fn read_identity(&self, output: &mut [u8]) -> Result<usize> {
        if output.len() < 8 {
            return Err(Error::Bounds);
        }
        output[..4].copy_from_slice(&unsafe { read(0x10000060) }.to_le_bytes());
        output[4..8].copy_from_slice(&unsafe { read(0x10000064) }.to_le_bytes());
        Ok(8)
    }
}

pub(crate) struct BoardResetReport(u32);

impl BoardResetReport {
    pub(crate) fn capture() -> Self {
        Self(unsafe { read(0x40000400) })
    }
}

impl ResetReport for BoardResetReport {
    fn reset_reason(&self) -> ResetReason {
        if self.0 & (1 << 1) != 0 {
            ResetReason::Watchdog
        } else if self.0 & 1 != 0 {
            ResetReason::Pin
        } else if self.0 & (1 << 2) != 0 {
            ResetReason::Software
        } else {
            ResetReason::Unknown
        }
    }
}
