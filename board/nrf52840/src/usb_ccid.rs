//! nRF52840 USB CCID bindings.
//!
//! The CCID device class itself comes from `usbd-ccid`, which is generic over any
//! `usb-device` bus. Porting the transport to another microcontroller means supplying
//! the bus type, the VBUS predicate and the USB identifiers below, and nothing else.
include!(concat!(env!("OUT_DIR"), "/usb_identity.rs"));

/// Largest APDU carried in either direction, covering the 261-byte short command and
/// the 258-byte short response with room to spare.
pub const APDU_BYTES: usize = 512;

pub type ApduChannel = interchange::Channel<heapless::Vec<u8, APDU_BYTES>, heapless::Vec<u8, APDU_BYTES>>;
pub type ApduResponder<'a> =
    interchange::Responder<'a, heapless::Vec<u8, APDU_BYTES>, heapless::Vec<u8, APDU_BYTES>>;
pub type CcidClass<'a> = usbd_ccid::Ccid<'a, 'a, UsbBus, APDU_BYTES>;

/// The HAL's USB peripheral borrows a started external oscillator, so the type system
/// refuses a bus built on the internal RC. USBD does not work from the RC source.
pub type UsbBus = nrf52840_hal::usbd::Usbd<nrf52840_hal::usbd::UsbPeripheral<'static>>;

/// VBUS is present on the USB connector.
///
/// `USBREGSTATUS` also carries `OUTPUTRDY`, which reports that the USB regulator has
/// settled. Waiting for it here deadlocks, because the regulator only settles once USBD
/// is enabled, and USBD is what this gate guards. Measured on a DK with the cable
/// attached, `USBREGSTATUS` holds at `0x1` indefinitely. Enabling on `VBUSDETECT` alone
/// matches Nordic's own order, which enables USBD on detection and only then waits for
/// the regulator before asserting the pull-up.
pub fn power_ready() -> bool {
    const POWER_USBREGSTATUS: usize = 0x4000_0438;
    const VBUSDETECT: u32 = 0b1;
    // SAFETY: USBREGSTATUS is a read-only, word-aligned POWER register.
    unsafe { core::ptr::read_volatile(POWER_USBREGSTATUS as *const u32) & VBUSDETECT == VBUSDETECT }
}

/// Complete the nRF52840 USB power sequence that `nrf-usbd` leaves unfinished.
///
/// The Product Specification requires the D+ pull-up to be asserted only after the USB
/// supply regulator has settled, which `POWER.EVENTS_USBPWRRDY` and the `OUTPUTRDY` bit
/// of `USBREGSTATUS` report. `nrf_usbd`'s `enable()` asserts the pull-up as soon as
/// `EVENTCAUSE.READY` is set, so a host can begin enumerating against an unstable
/// supply and the device answers the device descriptor and then fails.
///
/// The regulator does not report ready until USBD is enabled, so the wait cannot happen
/// before the bus is built. This drops the pull-up that `enable()` raised, waits for the
/// regulator, then re-attaches, which is the documented order as the host observes it.
pub fn attach_when_regulator_ready(deadline_ticks: impl Fn() -> bool) {
    const POWER_EVENTS_USBPWRRDY: usize = 0x4000_0110;
    const POWER_USBREGSTATUS: usize = 0x4000_0438;
    const USBD_USBPULLUP: usize = 0x4002_7504;
    const OUTPUTRDY: u32 = 0b10;
    // SAFETY: each address is a word-aligned POWER or USBD register owned by this module
    // for the duration of the attach sequence.
    unsafe {
        core::ptr::write_volatile(USBD_USBPULLUP as *mut u32, 0);
        while core::ptr::read_volatile(POWER_USBREGSTATUS as *const u32) & OUTPUTRDY == 0 {
            if deadline_ticks() {
                break;
            }
        }
        core::ptr::write_volatile(POWER_EVENTS_USBPWRRDY as *mut u32, 0);
        core::ptr::write_volatile(USBD_USBPULLUP as *mut u32, 1);
    }
}
