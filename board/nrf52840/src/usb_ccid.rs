//! nRF52840 USB CCID bindings.
//!
//! The CCID device class itself comes from `usbd-ccid`, which is generic over any
//! `usb-device` bus. Porting the transport to another microcontroller means supplying
//! the bus type, the VBUS predicate and the USB identifiers below, and nothing else.
include!(concat!(env!("OUT_DIR"), "/usb_identity.rs"));

/// Largest APDU carried in either direction, covering the 261-byte short command and
/// the 258-byte short response with room to spare.
pub const APDU_BYTES: usize = 512;

pub type ApduChannel =
    interchange::Channel<heapless::Vec<u8, APDU_BYTES>, heapless::Vec<u8, APDU_BYTES>>;
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
    power().usbregstatus.read().vbusdetect().is_vbus_present()
}

fn power() -> &'static nrf52840_hal::pac::power::RegisterBlock {
    // SAFETY: this returns the PAC's shared register view. Mutating access remains
    // restricted to individual volatile register methods.
    unsafe { &*nrf52840_hal::pac::POWER::ptr() }
}
