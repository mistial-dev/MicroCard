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
#[cfg(feature = "usb-ccid")]
mod rtic_runtime;
mod storage;
#[cfg(feature = "latency-trace")]
mod trace;
#[cfg(feature = "usb-ccid")]
mod usb_ccid;
#[cfg(not(feature = "usb-ccid"))]
use cortex_m_rt::entry;
#[cfg(feature = "development-recovery")]
use cortex_m_rt::{exception, ExceptionFrame};
#[cfg(feature = "usb-ccid")]
use microcard_core::transport::Endpoint;
use microcard_core::{
    hal::{DeviceIdentity, ResetReport, Watchdog},
    provisioning::{ownership_marker_action, OwnershipMarkerAction},
    scp03::Keys,
};
#[cfg(not(feature = "latency-trace"))]
use microcard_core::Error;
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
#[cfg(feature = "latency-trace")]
struct TracedHeap(embedded_alloc::LlffHeap);

#[cfg(feature = "latency-trace")]
unsafe impl core::alloc::GlobalAlloc for TracedHeap {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let result = unsafe { core::alloc::GlobalAlloc::alloc(&self.0, layout) };
        if result.is_null() {
            trace::record(trace::event::OOM_SIZE, layout.size() as u32);
            trace::record(trace::event::OOM_FREE, self.0.free() as u32);
        }
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        unsafe { core::alloc::GlobalAlloc::dealloc(&self.0, ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: core::alloc::Layout, new_size: usize) -> *mut u8 {
        let result = unsafe { core::alloc::GlobalAlloc::realloc(&self.0, ptr, layout, new_size) };
        if result.is_null() {
            trace::record(trace::event::OOM_SIZE, new_size as u32);
            trace::record(trace::event::OOM_FREE, self.0.free() as u32);
        }
        result
    }
}

#[cfg(feature = "latency-trace")]
impl TracedHeap {
    unsafe fn init(&self, start: usize, size: usize) {
        unsafe { self.0.init(start, size) }
    }
}

#[cfg(feature = "latency-trace")]
#[global_allocator]
static HEAP: TracedHeap = TracedHeap(embedded_alloc::LlffHeap::empty());
#[cfg(not(feature = "latency-trace"))]
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
    enable_instruction_cache, start_hfxo, start_monotonic_timer, BoardIdentity, BoardResetReport,
    BoardWatchdog,
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
#[cfg(feature = "engine-jcvm")]
type BoardCard = jcvm::BoardCard;
#[cfg(feature = "engine-mc04")]
type BoardCard = microcard_core::domains::Mc04Engine<
    Nvm,
    Hardware,
    microcard_core::staging::FlashStaging<StagingNvm>,
>;
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
pub(crate) fn initialize_usb(
    clock: pac::CLOCK,
    usbd: pac::USBD,
    requester: usb_ccid::ApduRequester<'static>,
) -> Option<(BoardUsbDevice, BoardCcidClass)> {
    #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
    set_uf2_recovery_marker(0x57);

    let initialized = (|| {
        // Taking the external oscillator by value is what lets `UsbPeripheral` exist at all,
        // so an image that forgets the crystal fails to compile rather than to enumerate.
        let clocks = cortex_m::singleton!(
            : Clocks<ExternalOscillator, Internal, LfOscStopped> =
                Clocks::new(clock).enable_ext_hfosc()
        )?;
        let allocator = cortex_m::singleton!(
            : UsbBusAllocator<usb_ccid::UsbBus> = UsbBusAllocator::new(usb_ccid::UsbBus::new(
                usb_ccid::BoardUsbPeripheral(UsbPeripheral::new(usbd, clocks))
            ))
        )?;
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
        device.bus().power_ready().then_some((device, class))
    })();

    initialized
}

fn initialize_card() -> (BoardCard, Keys) {
    // An Fxx+ development card needs both provisioned HwDisabled and this
    // reset-scoped write. Production builds omit development-debug.
    #[cfg(feature = "development-debug")]
    unsafe {
        if read(0x10001208) & 0xff == 0x5a {
            write(0x40000558, 0x5a);
        }
    }
    #[cfg(feature = "dongle-layout")]
    ensure_clean_bootloader_handoff();
    enable_instruction_cache();
    start_monotonic_timer();
    unsafe {
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEMORY) as usize, 196608);
    }
    let mut watchdog = BoardWatchdog;
    #[cfg(feature = "dongle-layout")]
    {
        led_init();
        led_color(LedColor::Blue);
    }
    let watchdog_window = if cfg!(feature = "crypto-profile-self-test") {
        300_000_000
    } else {
        10_000_000
    };
    if watchdog.arm(watchdog_window).is_err() {
        halt_with_diagnostic(&mut watchdog, 0x01);
    }
    if start_hfxo().is_err() {
        halt_with_diagnostic(&mut watchdog, 0x09);
    }
    let _reset_reason = BoardResetReport::capture().reset_reason();
    #[cfg(feature = "latency-trace")]
    {
        let power = unsafe { &*pac::POWER::ptr() };
        let reset_reason = power.resetreas.read().bits();
        trace::boot(reset_reason);
        power.resetreas.write(|w| unsafe { w.bits(reset_reason) });
    }
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
        let stage = hardware.self_test_stage.min(0x1f);
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
            #[cfg(feature = "latency-trace")]
            let code = 0x20 + error as u8;
            #[cfg(not(feature = "latency-trace"))]
            let code = if error == Error::IncompatibleState { 0x07 } else { 0x08 };
            halt_with_diagnostic(&mut watchdog, code);
        }
    };
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
    (card, keys)
}

#[cfg(not(feature = "usb-ccid"))]
#[entry]
fn main() -> ! {
    let (_card, _keys) = initialize_card();
    loop {
        platform::feed();
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "latency-trace")]
    if let Some(location) = info.location() {
        let hash = location.file().as_bytes().iter().fold(0x811c9dc5u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
        });
        trace::record(trace::event::PANIC_FILE, hash);
        trace::record(trace::event::PANIC, location.line());
    } else {
        trace::record(trace::event::PANIC, 0);
    }
    #[cfg(not(feature = "latency-trace"))]
    let _ = info;
    #[cfg(feature = "development-recovery")]
    enter_uf2();
    #[cfg(not(feature = "development-recovery"))]
    cortex_m::peripheral::SCB::sys_reset();
}


#[cfg(feature = "development-recovery")]
#[exception]
unsafe fn HardFault(_: &ExceptionFrame) -> ! {
    #[cfg(feature = "latency-trace")]
    trace::record(trace::event::HARD_FAULT, 0);
    enter_uf2()
}
