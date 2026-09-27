use microcard_core::hal::Watchdog;
#[cfg(feature = "dongle-layout")]
use nrf52840_pac as pac;

use crate::platform::BoardWatchdog;
#[cfg(any(feature = "dongle-layout", feature = "usb-ccid"))]
use crate::platform::{feed, now};

#[cfg(feature = "dongle-layout")]
const LED_MASK: u32 = (1 << 22) | (1 << 23) | (1 << 24);

#[cfg(feature = "dongle-layout")]
#[derive(Clone, Copy)]
pub(crate) enum LedColor {
    Off,
    Red,
    Green,
    Blue,
    Cyan,
    Yellow,
    Magenta,
}

#[cfg(feature = "dongle-layout")]
pub(crate) fn led_init() {
    let gpio = unsafe { &*pac::P0::ptr() };
    // The common-anode RGB LED is active low. Set every output high before changing
    // direction so startup cannot produce a misleading flash.
    gpio.outset.write(|w| unsafe { w.bits(LED_MASK) });
    gpio.dirset.write(|w| unsafe { w.bits(LED_MASK) });
}

#[cfg(feature = "dongle-layout")]
pub(crate) fn led_color(color: LedColor) {
    let gpio = unsafe { &*pac::P0::ptr() };
    gpio.outset.write(|w| unsafe { w.bits(LED_MASK) });
    let active = match color {
        LedColor::Off => 0,
        LedColor::Red => 1 << 23,
        LedColor::Green => 1 << 22,
        LedColor::Blue => 1 << 24,
        LedColor::Cyan => (1 << 22) | (1 << 24),
        LedColor::Yellow => (1 << 22) | (1 << 23),
        LedColor::Magenta => (1 << 23) | (1 << 24),
    };
    gpio.outclr.write(|w| unsafe { w.bits(active) });
}

#[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
pub(crate) fn report_usb_failure(code: u8) -> ! {
    for _ in 0..2 {
        led_color(LedColor::Red);
        let deadline = now().wrapping_add(400_000);
        while now().wrapping_sub(deadline) >= 0x8000_0000 {
            feed();
        }
        led_color(LedColor::Off);
        let deadline = now().wrapping_add(150_000);
        while now().wrapping_sub(deadline) >= 0x8000_0000 {
            feed();
        }
        for _ in 0..code {
            led_color(LedColor::Blue);
            let deadline = now().wrapping_add(150_000);
            while now().wrapping_sub(deadline) >= 0x8000_0000 {
                feed();
            }
            led_color(LedColor::Off);
            let deadline = now().wrapping_add(150_000);
            while now().wrapping_sub(deadline) >= 0x8000_0000 {
                feed();
            }
        }
    }
    crate::recovery::enter_uf2()
}

/// Keep a USB-only board observable when startup cannot safely open card state.
///
/// These failures remain terminal and never erase or repair storage. Returning a
/// proprietary `6Fxx` status lets unattended hardware tests distinguish the failure
/// boundary after the ordinary CCID power-on and ATR exchange succeeds.
pub(crate) fn halt_with_diagnostic(watchdog: &mut BoardWatchdog, _code: u8) -> ! {
    #[cfg(feature = "diagnostic-apdu")]
    crate::diagnostic_apdu::startup_failure(_code);
    #[cfg(feature = "usb-ccid")]
    let mut usb_stack = None;
    #[cfg(feature = "usb-ccid")]
    let mut attempted = false;
    #[cfg(feature = "dongle-layout")]
    led_init();
    #[cfg(feature = "dongle-layout")]
    let (blink_color, blink_count) = match _code {
        0x41..=0x44 => (LedColor::Blue, _code - 0x40),
        0x45 => (LedColor::Cyan, 1),
        0x46..=0x4a => (LedColor::Yellow, _code - 0x45),
        0x4b..=0x4d => (LedColor::Magenta, _code - 0x4a),
        _ => (LedColor::Blue, _code.clamp(1, 8)),
    };
    #[cfg(feature = "dongle-layout")]
    let mut blinks_remaining = 0;
    #[cfg(feature = "dongle-layout")]
    let mut blink_on = false;
    #[cfg(feature = "dongle-layout")]
    let mut led_deadline = now();
    loop {
        let _ = watchdog.feed();
        #[cfg(feature = "dongle-layout")]
        if now().wrapping_sub(led_deadline) < 0x8000_0000 {
            if blinks_remaining == 0 {
                led_color(LedColor::Red);
                blinks_remaining = blink_count;
                blink_on = false;
                led_deadline = now().wrapping_add(800_000);
            } else if blink_on {
                led_color(LedColor::Off);
                blink_on = false;
                blinks_remaining -= 1;
                led_deadline = now().wrapping_add(150_000);
            } else {
                led_color(blink_color);
                blink_on = true;
                led_deadline = now().wrapping_add(150_000);
            }
        }
        #[cfg(feature = "usb-ccid")]
        {
            #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
            use usb_device::device::UsbDeviceState;

            let powered = crate::usb_ccid::power_ready();
            if powered && !attempted {
                attempted = true;
                // Startup has failed before RTIC can dispatch tasks. There is no
                // concurrent peripheral owner in this terminal diagnostic path.
                let peripherals = unsafe { nrf52840_pac::Peripherals::steal() };
                if let Some((requester, responder)) = crate::APDU_CHANNEL.split() {
                    usb_stack =
                        crate::initialize_usb(peripherals.CLOCK, peripherals.USBD, requester)
                            .map(|(device, class)| (device, class, responder));
                }
            }
            if let Some((device, class, responder)) = usb_stack.as_mut() {
                if powered {
                    let _ = device.poll(&mut [class]);
                    #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
                    if device.state() == UsbDeviceState::Configured {
                        crate::recovery::set_uf2_recovery_marker(0);
                    }
                    if let Some(request) = responder.take_request() {
                        let mut response = heapless::Vec::new();
                        let uf2_requested = cfg!(feature = "dongle-layout")
                            && crate::recovery::is_enter_uf2_command(&request);
                        let reset_requested = request.as_slice() == crate::recovery::FAULT_RESET_APDU;
                        #[cfg(feature = "diagnostic-apdu")]
                        if let Some(diagnostic) = crate::diagnostic_apdu::response(&request) {
                            let _ = responder.respond(diagnostic);
                            class.check_for_app_response();
                            continue;
                        }
                        let status = if uf2_requested || reset_requested {
                            [0x90, 0x00]
                        } else {
                            [0x6f, _code]
                        };
                        let _ = response.extend_from_slice(&status);
                        let queued = responder.respond(response).is_ok();
                        if queued && (reset_requested || uf2_requested) {
                            // Let CCID finish the status packet before resetting the USB device.
                            let deadline = now().wrapping_add(1_000_000);
                            while !class.take_response_drained()
                                && now().wrapping_sub(deadline) >= 0x8000_0000 {
                                feed();
                                let _ = device.poll(&mut [class]);
                                class.check_for_app_response();
                            }
                            if reset_requested { cortex_m::peripheral::SCB::sys_reset(); }
                            #[cfg(feature = "dongle-layout")]
                            if uf2_requested { crate::recovery::enter_uf2(); }
                        }
                    }
                    class.check_for_app_response();
                }
            }
        }
    }
}
