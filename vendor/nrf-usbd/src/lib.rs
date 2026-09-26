//! USB peripheral driver for nRF microcontrollers.

#![no_std]
// The bundled PAC was generated before this lint existed.
#![allow(mismatched_lifetime_syntaxes)]

mod errata;
mod pac;
mod usbd;

pub use usbd::Usbd;

/// A trait for device-specific USB peripherals. Implement this to add support for a new hardware
/// platform. Peripherals that have this trait must have the same register block as NRF52 USBD
/// peripherals.
pub unsafe trait UsbPeripheral: Send {
    /// Pointer to the register block
    const REGISTERS: *const ();

    /// Whether the USB PHY regulator has settled after USBD was enabled.
    /// Boards without a separate PHY supply can use the default.
    fn phy_ready() -> bool {
        true
    }

    /// Whether this silicon needs the USBD EasyDMA task workaround (erratum 199).
    fn errata_199_applicable() -> bool {
        false
    }
}
