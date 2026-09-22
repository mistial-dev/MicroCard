#![no_std]
#![no_main]
extern crate alloc;
#[cfg(feature = "cc310-sha256")]
mod cc310;
mod diagnostics;
mod hardware;
#[cfg(feature = "engine-jcvm")]
mod jcvm;
mod platform;
mod recovery;
mod storage;
#[cfg(feature = "usb-ccid")]
mod usb_ccid;
use cortex_m_rt::entry;
#[cfg(feature = "development-recovery")]
use cortex_m_rt::{exception, ExceptionFrame};
#[cfg(feature = "usb-ccid")]
use microcard_core::transport::Endpoint;
use microcard_core::{
    hal::{DeviceIdentity, ResetReport, Watchdog},
    provisioning::{ownership_marker_action, OwnershipMarkerAction},
    scp03::Keys,
    Error,
};
#[cfg(feature = "usb-ccid")]
use nrf52840_hal::{
    clocks::{Clocks, ExternalOscillator, Internal, LfOscStopped},
    usbd::UsbPeripheral,
};
use nrf52840_pac as pac;
#[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
use usb_device::device::UsbDeviceState;
#[cfg(feature = "usb-ccid")]
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid},
    LangID,
};
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
static mut HEAP_MEMORY: [u8; 196608] = [0; 196608];
use diagnostics::halt_with_diagnostic;
#[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
use diagnostics::report_usb_failure;
#[cfg(feature = "dongle-layout")]
use diagnostics::{led_color, led_init, LedColor};
use hardware::Hardware;
use platform::{
    enable_instruction_cache, start_hfxo, BoardIdentity, BoardResetReport, BoardWatchdog,
};
#[cfg(feature = "usb-ccid")]
use platform::{feed, now};
#[cfg(feature = "development-debug")]
use platform::{read, write};
#[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
use recovery::set_uf2_recovery_marker;
#[cfg(feature = "dongle-layout")]
use recovery::{ensure_clean_bootloader_handoff, enter_uf2};
pub(crate) use storage::Nvm;
pub(crate) use storage::StagingNvm;
// The flash region map the linker used, so the firmware and the linker cannot disagree.
mod layout {
    // Generated for every region. A given build reads the ones its configuration needs.
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/flash_layout.rs"));
}

unsafe extern "C" {
    /// Defined by a MicroCard memory map alone. Referencing it makes a build that picked up
    /// another crate's `memory.x` fail to link, rather than run against a flash layout the
    /// firmware's own constants disagree with.
    ///
    /// The reference has to be opaque to the optimizer. Comparing this address against a
    /// generated base folds away when that base is zero, because a symbol address is never
    /// null, and the whole image behind the comparison folds with it.
    static _microcard_flash_origin: u8;
}
use layout::{KEYS_BASE, KEYS_BYTES};
pub(crate) const OWNERSHIP_MARKER_OFFSET: usize = 32;

#[cfg(feature = "usb-ccid")]
pub(crate) type BoardUsbDevice = UsbDevice<'static, usb_ccid::UsbBus>;
#[cfg(feature = "usb-ccid")]
pub(crate) type BoardCcidClass = usb_ccid::CcidClass<'static>;
/// APDUs cross between the CCID class and the runtime through this channel. It is
/// static because both halves are held for the lifetime of the USB stack.
#[cfg(feature = "usb-ccid")]
static APDU_CHANNEL: usb_ccid::ApduChannel = interchange::Channel::new();

#[cfg(feature = "usb-ccid")]
pub(crate) fn initialize_usb() -> Option<(
    BoardUsbDevice,
    BoardCcidClass,
    usb_ccid::ApduResponder<'static>,
)> {
    #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
    set_uf2_recovery_marker(0x57);

    let initialized = (|| {
        let peripherals = pac::Peripherals::take()?;
        // Taking the external oscillator by value is what lets `UsbPeripheral` exist at all,
        // so an image that forgets the crystal fails to compile rather than to enumerate.
        let clocks = cortex_m::singleton!(
            : Clocks<ExternalOscillator, Internal, LfOscStopped> =
                Clocks::new(peripherals.CLOCK).enable_ext_hfosc()
        )?;
        let allocator = cortex_m::singleton!(
            : UsbBusAllocator<usb_ccid::UsbBus> = UsbBusAllocator::new(usb_ccid::UsbBus::new(
                UsbPeripheral::new(peripherals.USBD, clocks)
            ))
        )?;
        let (requester, responder) = APDU_CHANNEL.split()?;
        let class = BoardCcidClass::new(allocator, requester, None);
        // Hosts conventionally request strings with EN_US rather than neutral EN, and
        // usb-device matches the requested identifier exactly.
        let strings = [StringDescriptors::new(LangID::EN_US)
            .manufacturer("MicroCard")
            .product("MicroCard virtual smart card")];
        let device =
            UsbDeviceBuilder::new(allocator, UsbVidPid(usb_ccid::USB_VID, usb_ccid::USB_PID))
                .strings(&strings)
                .ok()?
                .max_packet_size_0(64)
                .ok()?
                .device_release(0x0100)
                .build();
        Some((device, class, responder))
    })();

    #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
    if initialized.is_none() {
        enter_uf2();
    }
    initialized
}

#[entry]
fn main() -> ! {
    #[cfg(feature = "dongle-layout")]
    ensure_clean_bootloader_handoff();
    enable_instruction_cache();
    unsafe {
        // Nordic PS Debug and trace: Fxx+ needs both HwDisabled and SwDisable.
        // Respect the provisioned hardware policy; never rewrite UICR at startup.
        #[cfg(feature = "development-debug")]
        if read(0x10001208) & 0xff == 0x5a {
            write(0x40000558, 0x5a);
        }
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEMORY) as usize, 196608);
    }
    let mut watchdog = BoardWatchdog;
    #[cfg(feature = "dongle-layout")]
    {
        led_init();
        led_color(LedColor::Blue);
    }
    if watchdog.arm(10_000_000).is_err() {
        halt_with_diagnostic(&mut watchdog, 0x01);
    }
    if start_hfxo().is_err() {
        halt_with_diagnostic(&mut watchdog, 0x09);
    }
    let _reset_reason = BoardResetReport::capture().reset_reason();
    let mut device_identity = [0; 8];
    let _ = BoardIdentity.read_identity(&mut device_identity);
    // Ties the image to a MicroCard memory map at link time. The generated region constants
    // come from the same file the linker consumed, so they agree by construction once this
    // resolves.
    core::hint::black_box(&raw const _microcard_flash_origin);
    let key = unsafe { core::slice::from_raw_parts(KEYS_BASE as *const u8, 32) };
    let unprovisioned = key.iter().all(|b| *b == 255) || key.iter().all(|b| *b == 0);
    // A development board with no debug probe cannot be handed a key page, because its only
    // transport is the one the keys protect. Such a build answers the GlobalPlatform
    // well-known test keys instead, which is what ordinary tooling tries first. The board is
    // then claimable by anyone until its first signed assembly takes ownership, exactly as a
    // stock development card is.
    #[cfg(feature = "gp-test-keys")]
    const DEFAULT_KEY: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4e, 0x4f,
    ];
    #[cfg(feature = "gp-test-keys")]
    let key: &[u8] = if unprovisioned { &DEFAULT_KEY } else { key };
    #[cfg(not(feature = "gp-test-keys"))]
    if unprovisioned {
        halt_with_diagnostic(&mut watchdog, 0x02);
    }
    let keys = Keys {
        enc: key[..16].try_into().unwrap(),
        mac: key[16..].try_into().unwrap(),
    };
    let ownership_action = match Nvm::persistent_storage_erased()
        .and_then(|erased| ownership_marker_action(Nvm::ownership_marker(), erased))
    {
        Ok(action) => action,
        Err(_) => {
            halt_with_diagnostic(&mut watchdog, 0x03);
        }
    };
    let mut hardware = Hardware::new();
    if hardware.self_test().is_err() {
        let stage = hardware.self_test_stage.min(0x0f);
        halt_with_diagnostic(&mut watchdog, 0x40 | stage);
    }
    let storage_key = match keys.storage_key_with(&mut hardware) {
        Ok(key) => key,
        Err(_) => {
            halt_with_diagnostic(&mut watchdog, 0x05);
        }
    };
    if ownership_action == OwnershipMarkerAction::ProgramBeforeOpen
        && Nvm::program_ownership_marker().is_err()
    {
        halt_with_diagnostic(&mut watchdog, 0x06);
    }
    #[cfg(feature = "engine-mc04")]
    let opened = microcard_core::domains::Mc04Engine::open_with_staging(
        Nvm::new(),
        hardware,
        storage_key,
        microcard_core::staging::FlashStaging::new(StagingNvm::new()),
    );
    #[cfg(feature = "engine-jcvm")]
    let opened = jcvm::open(hardware, storage_key);
    let card = match opened {
        Ok(c) => c,
        Err(error) => {
            let code = if error == Error::IncompatibleState {
                0x07
            } else {
                0x08
            };
            halt_with_diagnostic(&mut watchdog, code);
        }
    };
    #[cfg(feature = "usb-ccid")]
    let mut endpoint = Endpoint::new(card, keys);
    #[cfg(not(feature = "usb-ccid"))]
    let _ = (card, keys);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // ACL entries are reset-scoped. Keep debug recovery enabled; protect firmware writes.
    // Each entry covers at most half of flash. Stop at the linked firmware boundary:
    // images and upload staging must remain writable even when the layout changes.
    let acl = unsafe { &*pac::ACL::ptr() };
    let firmware_end = layout::FLASH_BASE + layout::FLASH_BYTES;
    for (slot, start, size, block_read) in [
        (0, 0, firmware_end.min(0x80000) as u32, false),
        (
            1,
            0x80000,
            firmware_end.saturating_sub(0x80000) as u32,
            false,
        ),
        (2, KEYS_BASE as u32, KEYS_BYTES as u32, true),
    ] {
        if size == 0 {
            continue;
        }
        let region = &acl.acl[slot];
        region.addr.write(|w| unsafe { w.addr().bits(start) });
        region.size.write(|w| unsafe { w.size().bits(size) });
        region.perm.write(|w| {
            let w = w.write().disable();
            if block_read {
                w.read().disable()
            } else {
                w
            }
        });
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    #[cfg(feature = "usb-ccid")]
    let mut usb_stack: Option<(
        BoardUsbDevice,
        BoardCcidClass,
        usb_ccid::ApduResponder<'static>,
    )> = None;
    #[cfg(feature = "usb-ccid")]
    let mut usb_was_powered = false;
    #[cfg(feature = "usb-ccid")]
    let mut maintenance_at = None;
    #[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
    let mut usb_configuration_deadline = None;
    #[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
    let mut enter_uf2_at = None;
    loop {
        #[cfg(feature = "usb-ccid")]
        {
            let powered = usb_ccid::power_ready();
            if powered && usb_stack.is_none() {
                usb_stack = initialize_usb();
                usb_was_powered = usb_stack.is_some();
                #[cfg(feature = "dongle-layout")]
                if usb_was_powered {
                    usb_configuration_deadline = Some(now().wrapping_add(5_000_000));
                }
            }
            if let Some((device, class, responder)) = usb_stack.as_mut() {
                if powered {
                    if !usb_was_powered {
                        #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
                        set_uf2_recovery_marker(0x57);
                        let _ = device.force_reset();
                        usb_was_powered = true;
                        #[cfg(feature = "dongle-layout")]
                        {
                            led_color(LedColor::Blue);
                            usb_configuration_deadline = Some(now().wrapping_add(5_000_000));
                        }
                    }
                    let _ = device.poll(&mut [class]);
                    #[cfg(feature = "dongle-layout")]
                    match device.state() {
                        UsbDeviceState::Configured => {
                            if usb_configuration_deadline.take().is_some() {
                                #[cfg(feature = "development-recovery")]
                                set_uf2_recovery_marker(0);
                                led_color(LedColor::Green);
                            }
                        }
                        state => {
                            if usb_configuration_deadline
                                .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                            {
                                report_usb_failure(if state == UsbDeviceState::Addressed {
                                    6
                                } else {
                                    5
                                });
                            }
                        }
                    }
                    // One APDU is in flight at a time, so the runtime answers it
                    // synchronously and hands the reply straight back to the class.
                    if let Some(request) = responder.take_request() {
                        let mut wait_extension_at = match class.did_start_processing() {
                            usbd_ccid::Status::ReceivedData(_) => Some(now().wrapping_add(750_000)),
                            usbd_ccid::Status::Idle => None,
                        };
                        let reply = endpoint.exchange_with_cancel(&request, &mut || {
                            feed();
                            if !usb_ccid::power_ready() {
                                return true;
                            }
                            // Long JCVM callbacks remain one APDU. Keep USB serviced and use
                            // the CCID library's standard time-extension response until the
                            // runtime publishes the final reply.
                            let _ = device.poll(&mut [class]);
                            if wait_extension_at
                                .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                            {
                                wait_extension_at = match class.send_wait_extension() {
                                    usbd_ccid::Status::ReceivedData(_) => {
                                        Some(now().wrapping_add(750_000))
                                    }
                                    usbd_ccid::Status::Idle => None,
                                };
                            }
                            false
                        });
                        let mut outgoing = heapless::Vec::new();
                        if outgoing.extend_from_slice(&reply).is_ok()
                            && responder.respond(outgoing).is_ok()
                        {
                            // Give usbd-ccid time to drain the response before flash can stall USB.
                            if maintenance_at.is_none() {
                                maintenance_at = Some(now().wrapping_add(250_000));
                            }
                        }
                        #[cfg(feature = "dongle-layout")]
                        if endpoint.take_bootloader_request() {
                            // Keep polling long enough to transmit the protected response before
                            // asking the installed Adafruit-derived bootloader to enter UF2.
                            enter_uf2_at = Some(now().wrapping_add(250_000));
                        }
                    }
                    class.check_for_app_response();
                    if maintenance_at
                        .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                    {
                        if endpoint
                            .maintenance_with_cancel(&mut || {
                                feed();
                                false
                            })
                            .is_err()
                        {
                            // Startup recovery owns an uncertain published renewal.
                            cortex_m::peripheral::SCB::sys_reset();
                        }
                        maintenance_at = None;
                    }
                    #[cfg(feature = "dongle-layout")]
                    if enter_uf2_at
                        .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                    {
                        enter_uf2();
                    }
                } else if usb_was_powered {
                    endpoint.reset();
                    usb_was_powered = false;
                    maintenance_at = None;
                    #[cfg(feature = "dongle-layout")]
                    {
                        led_color(LedColor::Blue);
                        usb_configuration_deadline = None;
                    }
                }
            }
        }
        #[cfg(not(feature = "usb-ccid"))]
        {
            let _ = watchdog.feed();
            cortex_m::asm::wfi();
        }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "development-recovery")]
    enter_uf2();
    #[cfg(not(feature = "development-recovery"))]
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(feature = "development-recovery")]
#[exception]
unsafe fn HardFault(_: &ExceptionFrame) -> ! {
    enter_uf2()
}
