#![no_std]
#![no_main]
extern crate alloc;
#[cfg(feature = "engine-jcvm")]
mod jcvm;
#[cfg(feature = "usb-ccid")]
mod usb_ccid;
use cortex_m_rt::entry;
#[cfg(feature = "development-recovery")]
use cortex_m_rt::{exception, ExceptionFrame};
#[cfg(feature = "usb-ccid")]
use microcard_core::transport::ENTER_BOOTLOADER_APDU;
use microcard_core::{
    hal::{
        receive_command, send_response, ApduTransport, DeviceIdentity, Entropy, LogicalGpio,
        MonotonicClock, ResetReason, ResetReport, StagingFlash, TickExtender, Watchdog,
        MAX_SHORT_COMMAND_BYTES,
    },
    journal::{decode_program_once_words, next_program_once_word, Flash},
    provisioning::{ownership_marker_action, OwnershipMarkerAction, PROGRAMMED_OWNERSHIP_MARKER},
    scp03::Keys,
    transport::Endpoint,
    Error, Result,
};
#[cfg(feature = "usb-ccid")]
use nrf52840_hal::{
    clocks::{Clocks, ExternalOscillator, Internal, LfOscStopped},
    pac,
    usbd::UsbPeripheral,
};
#[cfg(feature = "usb-ccid")]
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbDeviceState, UsbVidPid},
    LangID,
};
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
static mut HEAP_MEMORY: [u8; 196608] = [0; 196608];
// Register offsets follow nRF52840 Product Specification peripheral register tables.
unsafe fn read(a: usize) -> u32 {
    core::ptr::read_volatile(a as *const u32)
}
unsafe fn write(a: usize, v: u32) {
    core::ptr::write_volatile(a as *mut u32, v)
}
const UART: usize = 0x40002000;
#[cfg(not(feature = "cc310-entropy"))]
const RNG: usize = 0x4000D000;
const TIMER: usize = 0x40008000;
const NVMC: usize = 0x4001E000;
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
const OWNERSHIP_MARKER_OFFSET: usize = 32;

#[cfg(feature = "dongle-layout")]
const LED_MASK: u32 = (1 << 22) | (1 << 23) | (1 << 24);

#[cfg(feature = "dongle-layout")]
const CLEAN_BOOT_MAGIC: u8 = 0xa5;

#[cfg(feature = "dongle-layout")]
#[derive(Clone, Copy)]
enum LedColor {
    Off,
    Red,
    Green,
    Blue,
    Cyan,
    Yellow,
    Magenta,
}

#[cfg(feature = "dongle-layout")]
fn led_init() {
    let gpio = unsafe { &*pac::P0::ptr() };
    // The common-anode RGB LED is active low. Set every output high before changing
    // direction so startup cannot produce a misleading flash.
    gpio.outset.write(|w| unsafe { w.bits(LED_MASK) });
    gpio.dirset.write(|w| unsafe { w.bits(LED_MASK) });
}

#[cfg(feature = "dongle-layout")]
fn led_color(color: LedColor) {
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

#[cfg(feature = "dongle-layout")]
fn enter_uf2() -> ! {
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
fn ensure_clean_bootloader_handoff() {
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
fn is_enter_uf2_command(command: &[u8]) -> bool {
    cfg!(feature = "development-recovery") && command == ENTER_BOOTLOADER_APDU
}

#[cfg(feature = "usb-ccid")]
type BoardUsbDevice = UsbDevice<'static, usb_ccid::UsbBus>;
#[cfg(feature = "usb-ccid")]
type BoardCcidClass = usb_ccid::CcidClass<'static>;
/// APDUs cross between the CCID class and the runtime through this channel. It is
/// static because both halves are held for the lifetime of the USB stack.
#[cfg(feature = "usb-ccid")]
static APDU_CHANNEL: usb_ccid::ApduChannel = interchange::Channel::new();

#[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
fn report_usb_failure(code: u8) -> ! {
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
    enter_uf2()
}

#[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
fn set_uf2_recovery_marker(value: u8) {
    unsafe {
        (&*pac::POWER::ptr())
            .gpregret
            .write(|w| w.gpregret().bits(value));
    }
}

#[cfg(feature = "usb-ccid")]
fn initialize_usb() -> Option<(
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

/// Keep a USB-only board observable when startup cannot safely open card state.
///
/// These failures remain terminal and never erase or repair storage. Returning a
/// proprietary `6Fxx` status lets unattended hardware tests distinguish the failure
/// boundary after the ordinary CCID power-on and ATR exchange succeeds.
fn halt_with_diagnostic(transport: &mut BoardUart, message: &[u8], _code: u8) -> ! {
    let deadline = transport.deadline_after(1_000_000);
    let _ = transport.write_raw(message, deadline);
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
        _ => (LedColor::Blue, _code.min(8).max(1)),
    };
    #[cfg(feature = "dongle-layout")]
    let mut blinks_remaining = 0;
    #[cfg(feature = "dongle-layout")]
    let mut blink_on = false;
    #[cfg(feature = "dongle-layout")]
    let mut led_deadline = now();
    loop {
        let _ = transport.watchdog.feed();
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
            let powered = usb_ccid::power_ready();
            if powered && !attempted {
                attempted = true;
                usb_stack = initialize_usb();
            }
            if let Some((device, class, responder)) = usb_stack.as_mut() {
                if powered {
                    let _ = device.poll(&mut [class]);
                    #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
                    if device.state() == UsbDeviceState::Configured {
                        set_uf2_recovery_marker(0);
                    }
                    if let Some(request) = responder.take_request() {
                        let mut response = heapless::Vec::new();
                        let uf2_requested = is_enter_uf2_command(&request);
                        let status = if uf2_requested {
                            [0x90, 0x00]
                        } else {
                            [0x6f, _code]
                        };
                        let _ = response.extend_from_slice(&status);
                        let _ = responder.respond(response);
                        #[cfg(feature = "dongle-layout")]
                        if uf2_requested {
                            // The card cannot establish SCP03 in diagnostic mode. This exact
                            // command only resets an already unusable development dongle into
                            // its bootloader, and remains unavailable during normal operation.
                            let deadline = now().wrapping_add(250_000);
                            while now().wrapping_sub(deadline) >= 0x8000_0000 {
                                feed();
                                let _ = device.poll(&mut [class]);
                                class.check_for_app_response();
                            }
                            enter_uf2();
                        }
                    }
                    class.check_for_app_response();
                }
            }
        }
    }
}
const WDT: usize = 0x40010000;
fn now() -> u32 {
    unsafe {
        write(TIMER + 0x040, 1);
        read(TIMER + 0x540)
    }
}
fn wait(a: usize) -> Result<()> {
    let start = now();
    while unsafe { read(a) } == 0 {
        if now().wrapping_sub(start) > 1_000_000 {
            return Err(Error::Native);
        }
    }
    Ok(())
}
fn feed() {
    unsafe { write(WDT + 0x600, 0x6E524635) }
}
#[cfg(feature = "cc310-sha256")]
mod cc310 {
    use core::ffi::{c_char, c_void};

    #[repr(C)]
    struct AbortApis {
        handle: *mut c_void,
        abort: unsafe extern "C" fn(*const c_char),
    }

    unsafe impl Sync for AbortApis {}

    unsafe extern "C" fn abort(_reason: *const c_char) {
        #[cfg(feature = "development-recovery")]
        super::enter_uf2();
        #[cfg(not(feature = "development-recovery"))]
        cortex_m::peripheral::SCB::sys_reset()
    }

    static ABORT_APIS: AbortApis = AbortApis {
        handle: core::ptr::null_mut(),
        abort,
    };

    unsafe extern "C" {
        #[cfg(feature = "cc310-p256")]
        pub(super) fn microcard_cc310_sha256_stream(
            state: *mut u8,
            state_size: usize,
            input: *const u8,
            input_size: usize,
            output: *mut u8,
        ) -> i32;
        fn nrf_cc3xx_platform_set_abort(apis: *const AbortApis);
        #[cfg(feature = "cc310-entropy")]
        fn nrf_cc3xx_platform_init() -> i32;
        #[cfg(not(feature = "cc310-entropy"))]
        fn nrf_cc3xx_platform_init_no_rng() -> i32;
        #[cfg(feature = "cc310-entropy")]
        fn nrf_cc3xx_platform_entropy_get(
            output: *mut u8,
            length: usize,
            output_length: *mut usize,
        ) -> i32;
        fn nrf_cc3xx_platform_sha256_hash(
            ram_buffer: *mut c_void,
            ram_buffer_size: usize,
            data: *mut c_void,
            length: usize,
            output: *mut c_void,
        ) -> i32;
        #[cfg(feature = "cc310-cmac")]
        fn microcard_cc310_cmac_begin(
            storage: *mut c_void,
            storage_size: usize,
            key: *const u8,
            key_size: usize,
        ) -> i32;
        #[cfg(any(feature = "cc310-cmac", feature = "cc310-hmac"))]
        fn microcard_cc310_mac_update(
            storage: *mut c_void,
            storage_size: usize,
            input: *const u8,
            input_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-cmac")]
        fn microcard_cc310_cmac_finish(
            storage: *mut c_void,
            storage_size: usize,
            output: *mut u8,
            output_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-hmac")]
        fn microcard_cc310_hmac_sha256_begin(
            storage: *mut c_void,
            storage_size: usize,
            key: *const u8,
            key_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-hmac")]
        fn microcard_cc310_hmac_sha256_finish(
            storage: *mut c_void,
            storage_size: usize,
            output: *mut u8,
            output_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-aes")]
        fn microcard_cc310_aes128_encrypt_block(
            key: *const u8,
            key_size: usize,
            input: *const u8,
            input_size: usize,
            output: *mut u8,
            output_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-aes")]
        fn microcard_cc310_aes128_cbc_in_place(
            key: *const u8,
            key_size: usize,
            iv: *const u8,
            iv_size: usize,
            buffer: *mut u8,
            buffer_size: usize,
            encrypt: i32,
        ) -> i32;
        #[cfg(feature = "cc310-ccm")]
        fn microcard_cc310_aes128_ccm_encrypt(
            key: *const u8,
            key_size: usize,
            nonce: *const u8,
            nonce_size: usize,
            aad: *const u8,
            aad_size: usize,
            plaintext: *const u8,
            plaintext_size: usize,
            ciphertext: *mut u8,
            ciphertext_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-ccm")]
        fn microcard_cc310_aes128_ccm_decrypt(
            key: *const u8,
            key_size: usize,
            nonce: *const u8,
            nonce_size: usize,
            aad: *const u8,
            aad_size: usize,
            ciphertext: *const u8,
            ciphertext_size: usize,
            plaintext: *mut u8,
            plaintext_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-p256")]
        fn microcard_cc310_p256_public_key(
            private_key: *const u8,
            private_key_size: usize,
            public_key: *mut u8,
            public_key_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-p256")]
        fn microcard_cc310_p256_sign_hash(
            private_key: *const u8,
            private_key_size: usize,
            hash: *const u8,
            hash_size: usize,
            signature: *mut u8,
            signature_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-p256")]
        fn microcard_cc310_p256_verify_hash(
            public_key: *const u8,
            public_key_size: usize,
            hash: *const u8,
            hash_size: usize,
            signature: *const u8,
            signature_size: usize,
        ) -> i32;
        #[cfg(feature = "cc310-p256")]
        fn microcard_cc310_p256_ecdh(
            private_key: *const u8,
            private_key_size: usize,
            peer_public_key: *const u8,
            peer_public_key_size: usize,
            secret: *mut u8,
            secret_size: usize,
        ) -> i32;
    }

    #[no_mangle]
    extern "C" fn nrf_cc3xx_platform_abort_init() {
        unsafe { nrf_cc3xx_platform_set_abort(&ABORT_APIS) }
    }

    #[no_mangle]
    extern "C" fn nrf_cc3xx_platform_mutex_init() {}

    #[repr(align(4))]
    struct WordAligned<T>(T);

    #[cfg(any(feature = "cc310-cmac", feature = "cc310-hmac"))]
    #[repr(align(8))]
    struct MacState([u8; 544]);

    pub(super) fn initialize() -> bool {
        nrf_cc3xx_platform_abort_init();
        nrf_cc3xx_platform_mutex_init();
        #[cfg(feature = "cc310-entropy")]
        unsafe {
            nrf_cc3xx_platform_init() == 0
        }
        #[cfg(not(feature = "cc310-entropy"))]
        unsafe {
            nrf_cc3xx_platform_init_no_rng() == 0
        }
    }

    pub(super) fn sha256(data: &[u8], output: &mut [u8; 32]) -> bool {
        let mut dma_scratch = WordAligned([0u8; 16]);
        let mut result = [0u8; 32];
        let status = unsafe {
            nrf_cc3xx_platform_sha256_hash(
                dma_scratch.0.as_mut_ptr().cast(),
                dma_scratch.0.len(),
                data.as_ptr().cast_mut().cast(),
                data.len(),
                result.as_mut_ptr().cast(),
            )
        };
        dma_scratch.0.fill(0);
        if status != 0 {
            result.fill(0);
            return false;
        }
        *output = result;
        result.fill(0);
        true
    }

    #[cfg(feature = "cc310-entropy")]
    pub(super) fn fill_entropy(output: &mut [u8]) -> bool {
        if output.is_empty() {
            return true;
        }
        let mut written = 0usize;
        let status = unsafe {
            nrf_cc3xx_platform_entropy_get(output.as_mut_ptr(), output.len(), &mut written)
        };
        if status != 0 || written != output.len() {
            output.fill(0);
            return false;
        }
        true
    }

    #[cfg(feature = "cc310-cmac")]
    pub(super) fn aes_cmac_parts(key: &[u8; 16], parts: &[&[u8]], output: &mut [u8; 16]) -> bool {
        let mut state = MacState([0; 544]);
        let mut result = [0; 16];
        let state_pointer = state.0.as_mut_ptr().cast();
        let mut status = unsafe {
            microcard_cc310_cmac_begin(state_pointer, state.0.len(), key.as_ptr(), key.len())
        };
        for part in parts {
            if status != 0 {
                break;
            }
            status = unsafe {
                microcard_cc310_mac_update(state_pointer, state.0.len(), part.as_ptr(), part.len())
            };
        }
        if status == 0 {
            status = unsafe {
                microcard_cc310_cmac_finish(
                    state_pointer,
                    state.0.len(),
                    result.as_mut_ptr(),
                    result.len(),
                )
            };
        }
        state.0.fill(0);
        if status != 0 {
            result.fill(0);
            return false;
        }
        *output = result;
        result.fill(0);
        true
    }

    #[cfg(feature = "cc310-hmac")]
    pub(super) fn hmac_sha256(key: &[u8], data: &[u8], output: &mut [u8; 32]) -> bool {
        let mut state = MacState([0; 544]);
        let mut result = [0; 32];
        let state_pointer = state.0.as_mut_ptr().cast();
        let mut status = unsafe {
            microcard_cc310_hmac_sha256_begin(state_pointer, state.0.len(), key.as_ptr(), key.len())
        };
        if status == 0 {
            status = unsafe {
                microcard_cc310_mac_update(state_pointer, state.0.len(), data.as_ptr(), data.len())
            };
        }
        if status == 0 {
            status = unsafe {
                microcard_cc310_hmac_sha256_finish(
                    state_pointer,
                    state.0.len(),
                    result.as_mut_ptr(),
                    result.len(),
                )
            };
        }
        state.0.fill(0);
        if status != 0 {
            result.fill(0);
            return false;
        }
        *output = result;
        result.fill(0);
        true
    }

    #[cfg(feature = "cc310-aes")]
    pub(super) fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) -> bool {
        let mut result = [0; 16];
        let status = unsafe {
            microcard_cc310_aes128_encrypt_block(
                key.as_ptr(),
                key.len(),
                block.as_ptr(),
                block.len(),
                result.as_mut_ptr(),
                result.len(),
            )
        };
        if status != 0 {
            result.fill(0);
            return false;
        }
        *block = result;
        result.fill(0);
        true
    }

    #[cfg(feature = "cc310-aes")]
    pub(super) fn aes128_cbc_in_place(
        key: &[u8; 16],
        iv: &[u8; 16],
        buffer: &mut [u8],
        encrypt: bool,
    ) -> bool {
        let status = unsafe {
            microcard_cc310_aes128_cbc_in_place(
                key.as_ptr(),
                key.len(),
                iv.as_ptr(),
                iv.len(),
                buffer.as_mut_ptr(),
                buffer.len(),
                i32::from(encrypt),
            )
        };
        if status != 0 {
            buffer.fill(0);
            return false;
        }
        true
    }

    #[cfg(feature = "cc310-ccm")]
    pub(super) fn aes128_ccm_encrypt(
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> i32 {
        unsafe {
            microcard_cc310_aes128_ccm_encrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            )
        }
    }

    #[cfg(feature = "cc310-ccm")]
    pub(super) fn aes128_ccm_encrypt_in_place(
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> i32 {
        let Some(length) = buffer.len().checked_sub(16) else {
            return -1;
        };
        // Pass raw pointers through FFI, never overlapping Rust references.
        let pointer = buffer.as_mut_ptr();
        unsafe {
            microcard_cc310_aes128_ccm_encrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                pointer,
                length,
                pointer,
                buffer.len(),
            )
        }
    }

    #[cfg(feature = "cc310-ccm")]
    pub(super) fn aes128_ccm_decrypt(
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> i32 {
        unsafe {
            microcard_cc310_aes128_ccm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                plaintext.as_mut_ptr(),
                plaintext.len(),
            )
        }
    }

    #[cfg(feature = "cc310-ccm")]
    pub(super) fn aes128_ccm_decrypt_in_place(
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> i32 {
        let Some(length) = ciphertext.len().checked_sub(16) else {
            return 1;
        };
        // Pass one buffer through FFI without constructing aliased Rust references.
        let pointer = ciphertext.as_mut_ptr();
        unsafe {
            microcard_cc310_aes128_ccm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                aad.as_ptr(),
                aad.len(),
                pointer,
                ciphertext.len(),
                pointer,
                length,
            )
        }
    }

    #[cfg(feature = "cc310-p256")]
    pub(super) fn p256_public_key(private_key: &[u8; 32], output: &mut [u8; 65]) -> bool {
        unsafe {
            microcard_cc310_p256_public_key(
                private_key.as_ptr(),
                private_key.len(),
                output.as_mut_ptr(),
                output.len(),
            ) == 0
        }
    }

    #[cfg(feature = "cc310-p256")]
    pub(super) fn p256_sign_hash(
        private_key: &[u8; 32],
        hash: &[u8; 32],
        output: &mut [u8; 64],
    ) -> bool {
        unsafe {
            microcard_cc310_p256_sign_hash(
                private_key.as_ptr(),
                private_key.len(),
                hash.as_ptr(),
                hash.len(),
                output.as_mut_ptr(),
                output.len(),
            ) == 0
        }
    }

    #[cfg(feature = "cc310-p256")]
    pub(super) fn p256_verify_hash(public_key: &[u8], hash: &[u8; 32], signature: &[u8]) -> i32 {
        unsafe {
            microcard_cc310_p256_verify_hash(
                public_key.as_ptr(),
                public_key.len(),
                hash.as_ptr(),
                hash.len(),
                signature.as_ptr(),
                signature.len(),
            )
        }
    }

    #[cfg(feature = "cc310-p256")]
    pub(super) fn p256_ecdh(
        private_key: &[u8; 32],
        peer_public_key: &[u8],
        output: &mut [u8; 32],
    ) -> i32 {
        unsafe {
            microcard_cc310_p256_ecdh(
                private_key.as_ptr(),
                private_key.len(),
                peer_public_key.as_ptr(),
                peer_public_key.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        }
    }
}

struct Hardware {
    #[cfg(feature = "cc310-sha256")]
    cc310_initialized: bool,
    self_test_stage: u8,
}

impl Hardware {
    fn new() -> Self {
        Self {
            #[cfg(feature = "cc310-sha256")]
            cc310_initialized: false,
            self_test_stage: 0,
        }
    }

    #[cfg(feature = "cc310-sha256")]
    fn ensure_cc310(&mut self) -> Result<()> {
        if !self.cc310_initialized {
            if !cc310::initialize() {
                return Err(Error::Native);
            }
            self.cc310_initialized = true;
        }
        Ok(())
    }

    fn self_test(&mut self) -> Result<()> {
        #[cfg(feature = "cc310-sha256")]
        {
            use microcard_core::crypto::CryptoProvider;

            const EMPTY_DIGEST: [u8; 32] = [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ];
            const ABC_DIGEST: [u8; 32] = [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ];
            static FLASH_INPUT: [u8; 3] = *b"abc";

            self.self_test_stage = 1;
            let mut digest = [0; 32];
            self.sha256_into(&[], &mut digest)?;
            if digest != EMPTY_DIGEST {
                return Err(Error::Native);
            }
            self.self_test_stage = 2;
            self.sha256_into(&FLASH_INPUT, &mut digest)?;
            if digest != ABC_DIGEST {
                return Err(Error::Native);
            }
            self.self_test_stage = 3;
            let ram_input = *b"abc";
            self.sha256_into(&ram_input, &mut digest)?;
            if digest != ABC_DIGEST {
                return Err(Error::Native);
            }
            #[cfg(feature = "cc310-p256")]
            {
                self.self_test_stage = 4;
                let mut state = [0; microcard_core::crypto::SHA256_STATE_BYTES];
                self.sha256_stream(&mut state, &FLASH_INPUT[..1], None)?;
                self.sha256_stream(&mut state, &ram_input[1..], Some(&mut digest))?;
                if digest != ABC_DIGEST || state.iter().any(|byte| *byte != 0) {
                    return Err(Error::Native);
                }
            }
            #[cfg(feature = "cc310-entropy")]
            {
                self.self_test_stage = 5;
                let mut first = [0; 32];
                let mut second = [0; 32];
                if !cc310::fill_entropy(&mut first)
                    || !cc310::fill_entropy(&mut second)
                    || first == second
                    || first.iter().all(|byte| *byte == 0)
                    || first.iter().all(|byte| *byte == 0xff)
                    || second.iter().all(|byte| *byte == 0)
                    || second.iter().all(|byte| *byte == 0xff)
                {
                    first.fill(0);
                    second.fill(0);
                    return Err(Error::Native);
                }
                first.fill(0);
                second.fill(0);
            }
            #[cfg(feature = "cc310-cmac")]
            {
                self.self_test_stage = 6;
                const KEY: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ];
                static MESSAGE: [u8; 64] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
                    0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
                    0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
                    0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
                ];
                const EXPECTED_EMPTY: [u8; 16] = [
                    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b,
                    0x75, 0x67, 0x46,
                ];
                const EXPECTED_16: [u8; 16] = [
                    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0,
                    0x4a, 0x28, 0x7c,
                ];
                const EXPECTED_42: [u8; 16] = [
                    0x17, 0xb0, 0x9c, 0xab, 0xe5, 0x09, 0x25, 0xeb, 0xd0, 0x5a, 0xc5, 0x60, 0x66,
                    0x83, 0xdb, 0xf3,
                ];
                const EXPECTED_64: [u8; 16] = [
                    0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79,
                    0x36, 0x3c, 0xfe,
                ];
                let mut mac = [0; 16];
                self.aes_cmac_parts_into(&KEY, &[&[]], &mut mac)?;
                if mac != EXPECTED_EMPTY {
                    return Err(Error::Native);
                }
                self.aes_cmac_parts_into(&KEY, &[&MESSAGE[..16]], &mut mac)?;
                if mac != EXPECTED_16 {
                    return Err(Error::Native);
                }
                self.aes_cmac_parts_into(&KEY, &[&MESSAGE[..26], &MESSAGE[26..42]], &mut mac)?;
                if mac != EXPECTED_42 {
                    return Err(Error::Native);
                }
                let mut ram_message = MESSAGE;
                core::hint::black_box(&mut ram_message);
                self.aes_cmac_parts_into(&KEY, &[&ram_message], &mut mac)?;
                ram_message.fill(0);
                if mac != EXPECTED_64 {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                mac.fill(0);
            }
            #[cfg(feature = "cc310-hmac")]
            {
                self.self_test_stage = 7;
                const KEY: [u8; 20] = [0x0b; 20];
                const EXPECTED: [u8; 32] = [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ];
                let mut message = *b"Hi There";
                core::hint::black_box(&mut message);
                let mut mac = [0; 32];
                self.hmac_sha256_into(&KEY, &message, &mut mac)?;
                message.fill(0);
                if mac != EXPECTED {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                const EXPECTED_EMPTY: [u8; 32] = [
                    0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7, 0x78,
                    0xc3, 0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53, 0xc6, 0xc7,
                    0x12, 0x14, 0x42, 0x92, 0xc5, 0xad,
                ];
                self.hmac_sha256_into(&[], &[], &mut mac)?;
                if mac != EXPECTED_EMPTY {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                mac.fill(0);
            }
            #[cfg(feature = "cc310-aes")]
            {
                self.self_test_stage = 8;
                const KEY: [u8; 16] = [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ];
                const EXPECTED: [u8; 16] = [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ];
                const PLAINTEXT: [u8; 16] = [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ];
                let mut block = PLAINTEXT;
                core::hint::black_box(&mut block);
                self.aes128_encrypt_block_in_place(&KEY, &mut block)?;
                if block != EXPECTED {
                    block.fill(0);
                    return Err(Error::Native);
                }
                self.aes128_decrypt_block_in_place(&KEY, &mut block)?;
                if block != PLAINTEXT {
                    block.fill(0);
                    return Err(Error::Native);
                }
                block.fill(0);
            }
            #[cfg(feature = "cc310-cbc")]
            {
                self.self_test_stage = 9;
                const KEY: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ];
                const IV: [u8; 16] = [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ];
                const PLAINTEXT: [u8; 16] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ];
                const CIPHERTEXT: [u8; 16] = [
                    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
                    0xe9, 0x19, 0x7d,
                ];
                let mut ciphertext = [0; 32];
                let ciphertext_length =
                    self.aes_cbc_encrypt(&KEY, IV, &PLAINTEXT, &mut ciphertext)?;
                if ciphertext_length != ciphertext.len() || ciphertext[..16] != CIPHERTEXT {
                    ciphertext.fill(0);
                    return Err(Error::Native);
                }
                let mut plaintext = [0; 32];
                let plaintext_length = self.aes_cbc_decrypt(
                    &KEY,
                    IV,
                    &ciphertext[..ciphertext_length],
                    &mut plaintext,
                )?;
                ciphertext.fill(0);
                if plaintext_length != PLAINTEXT.len() || plaintext[..plaintext_length] != PLAINTEXT
                {
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                plaintext.fill(0);
            }
            #[cfg(feature = "cc310-ccm")]
            {
                self.self_test_stage = 10;
                const KEY: [u8; 16] = [
                    0xd2, 0x4a, 0x3d, 0x3d, 0xde, 0x8c, 0x84, 0x83, 0x02, 0x80, 0xcb, 0x87, 0xab,
                    0xad, 0x0b, 0xb3,
                ];
                const NONCE: [u8; 13] = [
                    0xf1, 0x10, 0x00, 0x35, 0xbb, 0x24, 0xa8, 0xd2, 0x60, 0x04, 0xe0, 0xe2, 0x4b,
                ];
                const PLAINTEXT: [u8; 24] = [
                    0x7c, 0x86, 0x13, 0x5e, 0xd9, 0xc2, 0xa5, 0x15, 0xaa, 0xae, 0x0e, 0x9a, 0x20,
                    0x81, 0x33, 0x89, 0x72, 0x69, 0x22, 0x0f, 0x30, 0x87, 0x00, 0x06,
                ];
                const CIPHERTEXT: [u8; 40] = [
                    0x1f, 0xae, 0xb0, 0xee, 0x2c, 0xa2, 0xcd, 0x52, 0xf0, 0xaa, 0x39, 0x66, 0x57,
                    0x83, 0x44, 0xf2, 0x4e, 0x69, 0xb7, 0x42, 0xc4, 0xab, 0x37, 0xab, 0x11, 0x23,
                    0x30, 0x12, 0x19, 0xc7, 0x05, 0x99, 0xb7, 0xc3, 0x73, 0xad, 0x4b, 0x3a, 0xd6,
                    0x7b,
                ];
                // CC310's AEAD path consumes the payload through DMA. Real APDUs are in RAM,
                // so keep this vector in RAM instead of relying on a promoted flash constant.
                let plaintext = PLAINTEXT;
                core::hint::black_box(&plaintext);
                let mut ciphertext = [0; 40];
                let ciphertext_length =
                    self.aes_ccm_encrypt(&KEY, &NONCE, &[], &plaintext, &mut ciphertext)?;
                if ciphertext_length != ciphertext.len() || ciphertext != CIPHERTEXT {
                    ciphertext.fill(0);
                    return Err(Error::Native);
                }
                let mut plaintext = [0; 24];
                let plaintext_length =
                    self.aes_ccm_decrypt(&KEY, &NONCE, &[], &ciphertext, &mut plaintext)?;
                if plaintext_length != plaintext.len() || plaintext != PLAINTEXT {
                    ciphertext.fill(0);
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                ciphertext[39] ^= 1;
                plaintext.fill(0xa5);
                if self.aes_ccm_decrypt(&KEY, &NONCE, &[], &ciphertext, &mut plaintext)
                    != Err(Error::Authentication)
                    || plaintext.iter().any(|byte| *byte != 0)
                {
                    ciphertext.fill(0);
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                ciphertext.fill(0);
                plaintext.fill(0);
            }
            #[cfg(feature = "cc310-p256")]
            {
                self.self_test_stage = 11;
                const PRIVATE_KEY: [u8; 32] = [
                    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67,
                    0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a,
                    0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
                ];
                const PUBLIC_KEY: [u8; 65] = [
                    0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
                    0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6,
                    0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8,
                    0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2,
                    0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
                ];
                const SIGNATURE: [u8; 64] = [
                    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4,
                    0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d,
                    0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c,
                    0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb,
                    0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
                ];
                const PEER_PUBLIC_KEY: [u8; 65] = [
                    0x04, 0x55, 0x0f, 0x47, 0x10, 0x03, 0xf3, 0xdf, 0x97, 0xc3, 0xdf, 0x50, 0x6a,
                    0xc7, 0x97, 0xf6, 0x72, 0x1f, 0xb1, 0xa1, 0xfb, 0x7b, 0x8f, 0x6f, 0x83, 0xd2,
                    0x24, 0x49, 0x8a, 0x65, 0xc8, 0x8e, 0x24, 0x13, 0x60, 0x93, 0xd7, 0x01, 0x2e,
                    0x50, 0x9a, 0x73, 0x71, 0x5c, 0xbd, 0x0b, 0x00, 0xa3, 0xcc, 0x0f, 0xf4, 0xb5,
                    0xc0, 0x1b, 0x3f, 0xfa, 0x19, 0x6a, 0xb1, 0xfb, 0x32, 0x70, 0x36, 0xb8, 0xe6,
                ];
                const SHARED_SECRET: [u8; 32] = [
                    0x1a, 0x6f, 0xfb, 0x29, 0x06, 0x9a, 0xce, 0x9c, 0x04, 0xba, 0x94, 0x28, 0x91,
                    0x1b, 0xd0, 0x09, 0x0f, 0x87, 0x26, 0xae, 0xb3, 0x2e, 0x81, 0xd4, 0x7b, 0x24,
                    0x1a, 0x1f, 0x88, 0x04, 0xe4, 0x7d,
                ];
                let mut public_key = [0; 65];
                self.p256_public_key_into(&PRIVATE_KEY, &mut public_key)?;
                if public_key != PUBLIC_KEY {
                    public_key.fill(0);
                    return Err(Error::Native);
                }
                let mut signature = [0; 64];
                self.self_test_stage = 12;
                self.p256_ecdsa_sign_into(&PRIVATE_KEY, b"sample", &mut signature)?;
                if signature != SIGNATURE
                    || !self.p256_ecdsa_verify(&public_key, b"sample", &signature)?
                    || self.p256_ecdsa_verify(&public_key, b"changed", &signature)?
                {
                    public_key.fill(0);
                    signature.fill(0);
                    return Err(Error::Native);
                }
                let mut shared_secret = [0; 32];
                self.self_test_stage = 13;
                self.p256_ecdh_into(&PRIVATE_KEY, &PEER_PUBLIC_KEY, &mut shared_secret)?;
                if shared_secret != SHARED_SECRET {
                    public_key.fill(0);
                    signature.fill(0);
                    shared_secret.fill(0);
                    return Err(Error::Native);
                }
                public_key.fill(0);
                signature.fill(0);
                shared_secret.fill(0);
            }
        }
        self.self_test_stage = 0;
        Ok(())
    }
}

impl microcard_core::crypto::CryptoProvider for Hardware {
    #[cfg(feature = "cc310-p256")]
    fn sha256_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        mut output: Option<&mut [u8; 32]>,
    ) -> Result<()> {
        if let Some(output) = output.as_mut() {
            output.fill(0);
        }
        let result = (|| {
            self.ensure_cc310()?;
            let pointer = output
                .as_mut()
                .map_or(core::ptr::null_mut(), |value| value.as_mut_ptr());
            let status = unsafe {
                cc310::microcard_cc310_sha256_stream(
                    state.as_mut_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    pointer,
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(Error::Native)
            }
        })();
        if result.is_err() {
            state.fill(0);
            if let Some(output) = output {
                output.fill(0);
            }
        }
        result
    }

    #[cfg(feature = "cc310-sha256")]
    fn sha256_into(&mut self, data: &[u8], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::sha256(data, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-hmac")]
    fn hmac_sha256_into(&mut self, key: &[u8], data: &[u8], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::hmac_sha256(key, data, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes128_encrypt_block_in_place(
        &mut self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(block, ready)?;
        let result = if cc310::aes128_encrypt_block(key, block) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(block, result)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes128_decrypt_block_in_place(
        &mut self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<()> {
        // One CBC block with a zero IV is raw AES decryption.
        self.aes_cbc_in_place(key, &[0; 16], block, false)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes_cbc_in_place(
        &mut self,
        key: &[u8; 16],
        iv: &[u8; 16],
        buffer: &mut [u8],
        encrypt: bool,
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(buffer, ready)?;
        if buffer.is_empty() || !buffer.len().is_multiple_of(16) {
            buffer.fill(0);
            return Err(Error::Bounds);
        }
        let result = if cc310::aes128_cbc_in_place(key, iv, buffer, encrypt) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(buffer, result)
    }

    #[cfg(feature = "cc310-cbc")]
    #[inline(never)]
    fn aes_cbc_encrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        let padded = microcard_core::crypto::cbc_pad_into(data, output);
        let length = microcard_core::crypto::clear_output_on_error(output, padded)?;
        let result = self
            .aes_cbc_in_place(key, &iv, &mut output[..length], true)
            .map(|()| length);
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-cbc")]
    #[inline(never)]
    fn aes_cbc_decrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(Error::Authentication);
        }
        if output.len() < data.len() {
            return Err(Error::Bounds);
        }
        let plaintext = &mut output[..data.len()];
        plaintext.copy_from_slice(data);
        if let Err(error) = self.aes_cbc_in_place(key, &iv, plaintext, false) {
            output.fill(0);
            return Err(error);
        }
        let result = microcard_core::crypto::cbc_unpad_in_place(plaintext);
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    #[inline(never)]
    fn aes_ccm_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        self.ensure_cc310()?;
        let length = plaintext.len().checked_add(16).ok_or(Error::Bounds)?;
        if output.len() < length {
            return Err(Error::Bounds);
        }
        let result =
            if cc310::aes128_ccm_encrypt(key, nonce, aad, plaintext, &mut output[..length]) == 0 {
                Ok(length)
            } else {
                Err(Error::Native)
            };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    fn aes_ccm_encrypt_in_place(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize> {
        let result = (|| {
            self.ensure_cc310()?;
            if buffer.len() < 16 {
                return Err(Error::Bounds);
            }
            if cc310::aes128_ccm_encrypt_in_place(key, nonce, aad, buffer) == 0 {
                Ok(buffer.len())
            } else {
                Err(Error::Native)
            }
        })();
        microcard_core::crypto::clear_output_on_error(buffer, result)
    }

    #[cfg(feature = "cc310-ccm")]
    #[inline(never)]
    fn aes_ccm_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        self.ensure_cc310()?;
        let length = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(Error::Authentication)?;
        if output.len() < length {
            return Err(Error::Bounds);
        }
        let result =
            match cc310::aes128_ccm_decrypt(key, nonce, aad, ciphertext, &mut output[..length]) {
                0 => Ok(length),
                1 => Err(Error::Authentication),
                _ => Err(Error::Native),
            };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    fn aes_ccm_decrypt_in_place(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        let result = (|| {
            self.ensure_cc310()?;
            let length = ciphertext
                .len()
                .checked_sub(16)
                .ok_or(Error::Authentication)?;
            match cc310::aes128_ccm_decrypt_in_place(key, nonce, aad, ciphertext) {
                0 => {
                    ciphertext[length..].fill(0);
                    Ok(length)
                }
                1 => Err(Error::Authentication),
                _ => Err(Error::Native),
            }
        })();
        microcard_core::crypto::clear_output_on_error(ciphertext, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_public_key_into(
        &mut self,
        private_key: &[u8; 32],
        output: &mut [u8; 65],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = if cc310::p256_public_key(private_key, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdsa_sign_into(
        &mut self,
        private_key: &[u8; 32],
        message: &[u8],
        output: &mut [u8; 64],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let mut hash = [0; 32];
        self.sha256_into(message, &mut hash)?;
        let result = self.p256_sign_hash_into(private_key, &hash, output);
        hash.fill(0);
        result
    }

    #[cfg(feature = "cc310-p256")]
    fn p256_sign_hash_into(
        &mut self,
        private_key: &[u8; 32],
        hash: &[u8; 32],
        output: &mut [u8; 64],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = if cc310::p256_sign_hash(private_key, hash, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdsa_verify(
        &mut self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.ensure_cc310()?;
        let mut hash = [0; 32];
        self.sha256_into(message, &mut hash)?;
        let result = self.p256_verify_hash(public_key, &hash, signature);
        hash.fill(0);
        result
    }

    #[cfg(feature = "cc310-p256")]
    fn p256_verify_hash(
        &mut self,
        public_key: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool> {
        self.ensure_cc310()?;
        match cc310::p256_verify_hash(public_key, hash, signature) {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(Error::Native),
        }
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdh_into(
        &mut self,
        private_key: &[u8; 32],
        peer_public_key: &[u8],
        output: &mut [u8; 32],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = match cc310::p256_ecdh(private_key, peer_public_key, output) {
            0 => Ok(()),
            1 => Err(Error::Authentication),
            _ => Err(Error::Native),
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-cmac")]
    fn aes_cmac_parts_into(
        &mut self,
        key: &[u8; 16],
        parts: &[&[u8]],
        output: &mut [u8; 16],
    ) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::aes_cmac_parts(key, parts, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }
}
impl Entropy for Hardware {
    fn fill_entropy(&mut self, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        #[cfg(feature = "cc310-entropy")]
        {
            self.ensure_cc310()?;
            let result = if cc310::fill_entropy(out) {
                Ok(())
            } else {
                Err(Error::Native)
            };
            microcard_core::crypto::clear_output_on_error(out, result)
        }
        #[cfg(not(feature = "cc310-entropy"))]
        unsafe {
            write(RNG + 0x504, 1);
            write(RNG, 1);
        }
        #[cfg(not(feature = "cc310-entropy"))]
        for index in 0..out.len() {
            unsafe {
                write(RNG + 0x100, 0);
            }
            if let Err(error) = wait(RNG + 0x100) {
                out.fill(0);
                unsafe {
                    write(RNG + 0x004, 1);
                }
                return Err(error);
            }
            out[index] = unsafe { read(RNG + 0x508) } as u8;
        }
        #[cfg(not(feature = "cc310-entropy"))]
        unsafe {
            write(RNG + 0x004, 1);
        }
        #[cfg(not(feature = "cc310-entropy"))]
        Ok(())
    }
}
impl LogicalGpio for Hardware {
    fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()> {
        if resource != 0 || !(0..=1).contains(&value) {
            return Err(Error::Bounds);
        }
        unsafe {
            write(0x50000518, 1 << 13);
            write(if value == 0 { 0x50000508 } else { 0x5000050C }, 1 << 13);
        }
        Ok(())
    }
}
struct Nvm {
    slots: [usize; 3],
    count: usize,
    size: usize,
    monotonic: usize,
    nonces: usize,
}
impl Nvm {
    const COUNTER_BYTES: usize = 4096;
    fn new() -> Self {
        Self {
            slots: [layout::JOURNAL0_BASE, layout::JOURNAL1_BASE, {
                #[cfg(feature = "engine-mc04")]
                {
                    layout::JOURNAL2_BASE
                }
                #[cfg(not(feature = "engine-mc04"))]
                {
                    0
                }
            }],
            count: if cfg!(feature = "engine-mc04") { 3 } else { 2 },
            size: layout::JOURNAL0_BYTES,
            monotonic: layout::MONOTONIC_BASE,
            nonces: layout::NONCES_BASE,
        }
    }

    fn base(&self, slot: usize) -> Result<usize> {
        if slot >= self.count {
            return Err(Error::Bounds);
        }
        Ok(self.slots[slot])
    }

    fn persistent_storage_erased() -> Result<bool> {
        let flash = Self::new();
        for slot in 0..flash.slot_count() {
            if !flash.is_erased(slot)? {
                return Ok(false);
            }
        }
        if unsafe {
            core::slice::from_raw_parts(
                crate::layout::IMAGES_BASE as *const u8,
                crate::layout::IMAGES_BYTES,
            )
        }
        .iter()
        .any(|byte| *byte != 0xff)
        {
            return Ok(false);
        }
        #[cfg(feature = "engine-jcvm")]
        for bank in 0..2 {
            let heap = jcvm::Heaps::region(bank)?;
            for slot in 0..heap.slot_count() {
                if !heap.is_erased(slot)? {
                    return Ok(false);
                }
            }
            if heap.monotonic_generation()? != 0 || heap.nonce_generation()? != 0 {
                return Ok(false);
            }
        }
        Ok(
            Self::word_counter(layout::MONOTONIC_BASE, layout::MONOTONIC_BYTES)? == 0
                && Self::word_counter(crate::layout::NONCES_BASE, crate::layout::NONCES_BYTES)? == 0,
        )
    }

    fn ownership_marker() -> u32 {
        unsafe { read(KEYS_BASE + OWNERSHIP_MARKER_OFFSET) }
    }

    fn program_ownership_marker() -> Result<()> {
        Self::program_region(
            KEYS_BASE,
            KEYS_BYTES,
            OWNERSHIP_MARKER_OFFSET,
            &PROGRAMMED_OWNERSHIP_MARKER.to_le_bytes(),
        )
    }
    fn ready() -> Result<()> {
        wait(NVMC + 0x400)
    }
    fn read_region(base: usize, size: usize, offset: usize, output: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(output.len()).ok_or(Error::Bounds)?;
        if end > size {
            return Err(Error::Bounds);
        }
        output.copy_from_slice(unsafe {
            core::slice::from_raw_parts((base + offset) as *const u8, output.len())
        });
        Ok(())
    }
    fn erase_region(base: usize, size: usize) -> Result<()> {
        if !size.is_multiple_of(4096) {
            return Err(Error::Bounds);
        }
        unsafe { write(NVMC + 0x504, 2) }
        let result = (|| {
            for page in (base..base + size).step_by(4096) {
                unsafe { write(NVMC + 0x508, page as u32) }
                Self::ready()?;
                feed();
            }
            Ok(())
        })();
        unsafe { write(NVMC + 0x504, 0) }
        result
    }
    fn program_region(base: usize, size: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        if offset.checked_add(bytes.len()).is_none_or(|end| end > size) {
            return Err(Error::Bounds);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        unsafe { write(NVMC + 0x504, 1) }
        let result = (|| {
            let end = offset + bytes.len();
            for pos in ((offset & !3)..((end + 3) & !3)).step_by(4) {
                let mut word = unsafe { read(base + pos) }.to_le_bytes();
                for (index, byte) in word.iter_mut().enumerate() {
                    let location = pos + index;
                    if location >= offset && location < end {
                        let new = bytes[location - offset];
                        if *byte & new != new {
                            return Err(Error::Storage);
                        }
                        *byte = new;
                    }
                }
                unsafe { write(base + pos, u32::from_le_bytes(word)) }
                Self::ready()?;
                feed();
            }
            Ok(())
        })();
        unsafe { write(NVMC + 0x504, 0) }
        result
    }
}

struct StagingNvm {
    bank: Option<usize>,
    next_bank: usize,
}
impl StagingNvm {
    const BASE: usize = crate::layout::STAGING_BASE;
    const BANK_BYTES: usize = if cfg!(feature = "engine-jcvm") {
        64 * 1024
    } else {
        16 * 1024
    };
    const BANKS: usize = layout::STAGING_BYTES / Self::BANK_BYTES;

    const fn new() -> Self {
        Self {
            bank: None,
            next_bank: 0,
        }
    }
    fn bank_base(&self) -> Result<usize> {
        self.bank
            .map(|bank| Self::BASE + bank * Self::BANK_BYTES)
            .ok_or(Error::Storage)
    }
    fn bank_is_erased(bank: usize) -> bool {
        unsafe {
            core::slice::from_raw_parts(
                (Self::BASE + bank * Self::BANK_BYTES) as *const u8,
                Self::BANK_BYTES,
            )
        }
        .iter()
        .all(|byte| *byte == 0xff)
    }
}
impl StagingFlash for StagingNvm {
    fn mapped(&self, offset: usize, length: usize) -> Result<Option<&[u8]>> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > Self::BANK_BYTES)
        {
            return Err(Error::Bounds);
        }
        let base = self.bank_base()?;
        // This bank is exclusively owned by staging. Mutations require &mut self,
        // and registry/heap writes use disjoint flash regions.
        Ok(Some(unsafe {
            core::slice::from_raw_parts((base + offset) as *const u8, length)
        }))
    }
    fn capacity(&self) -> usize {
        Self::BANK_BYTES
    }
    fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        Nvm::read_region(self.bank_base()?, Self::BANK_BYTES, offset, output)
    }
    fn erase(&mut self) -> Result<()> {
        let selected = (0..Self::BANKS)
            .map(|offset| {
                let bank = self.next_bank + offset;
                if bank < Self::BANKS {
                    bank
                } else {
                    bank - Self::BANKS
                }
            })
            .find(|bank| Self::bank_is_erased(*bank))
            .unwrap_or(self.next_bank);
        let base = Self::BASE + selected * Self::BANK_BYTES;
        if !Self::bank_is_erased(selected) {
            Nvm::erase_region(base, Self::BANK_BYTES)?;
        }
        self.bank = Some(selected);
        self.next_bank = if selected + 1 == Self::BANKS {
            0
        } else {
            selected + 1
        };
        Ok(())
    }
    fn program(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        Nvm::program_region(self.bank_base()?, Self::BANK_BYTES, offset, bytes)
    }
}
impl Nvm {
    const IMAGE_SLOT_BYTES: usize = if cfg!(feature = "engine-jcvm") {
        64 * 1024
    } else {
        16 * 1024
    };
    const IMAGE_SLOTS: usize = crate::layout::IMAGES_BYTES / Self::IMAGE_SLOT_BYTES;

    fn image_base(index: usize) -> Result<usize> {
        if index >= Self::IMAGE_SLOTS {
            return Err(Error::Bounds);
        }
        Ok(crate::layout::IMAGES_BASE + index * Self::IMAGE_SLOT_BYTES)
    }
}
impl microcard_core::image_store::ImageFlash for Nvm {
    fn slot_count(&self) -> usize {
        Self::IMAGE_SLOTS
    }
    fn slot_size(&self) -> usize {
        Self::IMAGE_SLOT_BYTES
    }
    type Image<'a> = &'a [u8];
    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        let base = Self::image_base(index)?;
        if range.start > range.end || range.end > Self::IMAGE_SLOT_BYTES {
            return Err(Error::Bounds);
        }
        // The borrow prevents programming or erasing through this Nvm handle.
        Ok(unsafe { core::slice::from_raw_parts((base + range.start) as *const u8, range.len()) })
    }
    fn erase(&mut self, index: usize) -> Result<()> {
        Nvm::erase_region(Self::image_base(index)?, Self::IMAGE_SLOT_BYTES)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Nvm::program_region(
            Self::image_base(index)?,
            Self::IMAGE_SLOT_BYTES,
            offset,
            bytes,
        )
    }
}
impl Nvm {
    fn word_counter(base: usize, capacity: usize) -> Result<u64> {
        decode_program_once_words(unsafe {
            core::slice::from_raw_parts(base as *const u8, capacity)
        })
    }
    fn advance_word_counter(base: usize, capacity: usize, generation: u64) -> Result<()> {
        let counter = unsafe { core::slice::from_raw_parts(base as *const u8, capacity) };
        let word_offset = next_program_once_word(counter, generation)?;
        let address = base + word_offset;
        if unsafe { read(address) } != u32::MAX {
            return Err(Error::Storage);
        }
        unsafe {
            write(NVMC + 0x504, 1);
            write(address, 0);
        }
        let result = Self::ready();
        unsafe {
            write(NVMC + 0x504, 0);
        }
        result?;
        if unsafe { read(address) } != 0 {
            return Err(Error::Storage);
        }
        Ok(())
    }
}
impl Flash for Nvm {
    fn slot_count(&self) -> usize {
        self.count
    }
    fn slot_size(&self) -> usize {
        self.size
    }
    fn monotonic_capacity(&self) -> u64 {
        (Self::COUNTER_BYTES / 4) as u64
    }
    fn monotonic_generation(&self) -> Result<u64> {
        Self::word_counter(self.monotonic, Self::COUNTER_BYTES)
    }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        Self::advance_word_counter(self.monotonic, Self::COUNTER_BYTES, generation)
    }
    fn nonce_capacity(&self) -> u64 {
        (Self::COUNTER_BYTES / 4) as u64
    }
    fn nonce_generation(&self) -> Result<u64> {
        Self::word_counter(self.nonces, Self::COUNTER_BYTES)
    }
    fn reserve_nonce(&mut self) -> Result<u64> {
        let next = self
            .nonce_generation()?
            .checked_add(1)
            .ok_or(Error::Quota)?;
        Self::advance_word_counter(self.nonces, Self::COUNTER_BYTES, next)?;
        Ok(next)
    }
    fn is_erased(&self, slot: usize) -> Result<bool> {
        Ok(
            unsafe { core::slice::from_raw_parts(self.base(slot)? as *const u8, self.size) }
                .iter()
                .all(|byte| *byte == 0xff),
        )
    }
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()> {
        Self::read_region(self.base(slot)?, self.size, offset, output)
    }
    fn erase(&mut self, slot: usize) -> Result<()> {
        Self::erase_region(self.base(slot)?, self.size)
    }
    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Self::program_region(self.base(slot)?, self.size, offset, bytes)
    }
}
#[derive(Default)]
struct BoardClock {
    ticks: TickExtender,
}
impl BoardClock {
    fn init() -> Self {
        unsafe {
            write(TIMER + 0x504, 0);
            write(TIMER + 0x508, 3);
            write(TIMER + 0x510, 4);
            write(TIMER, 1);
        }
        Self::default()
    }
}
impl MonotonicClock for BoardClock {
    fn ticks(&mut self) -> u64 {
        self.ticks.update(now())
    }

    fn ticks_per_second(&self) -> u32 {
        1_000_000
    }
}

struct BoardWatchdog;
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

struct BoardUart {
    clock: BoardClock,
    watchdog: BoardWatchdog,
    decoder: microcard_core::framing::Decoder,
}
impl BoardUart {
    fn init() -> Self {
        unsafe {
            // PCA10056 debug UART: TX P0.06, RX P0.08, no flow control, 115200 baud.
            write(0x50000508, 1 << 6);
            write(0x50000700 + 6 * 4, 3);
            write(0x50000700 + 8 * 4, 0);
            write(UART + 0x50C, 6);
            write(UART + 0x514, 8);
            write(UART + 0x508, u32::MAX);
            write(UART + 0x510, u32::MAX);
            write(UART + 0x524, 0x01D7E000);
            write(UART + 0x56C, 0);
            write(UART + 0x500, 4);
            write(UART + 0x008, 1);
            write(UART, 1);
        }
        Self {
            clock: BoardClock::init(),
            watchdog: BoardWatchdog,
            decoder: microcard_core::framing::Decoder::default(),
        }
    }

    fn deadline_after(&mut self, duration_ticks: u64) -> u64 {
        self.clock.ticks().saturating_add(duration_ticks)
    }

    fn write_raw(&mut self, bytes: &[u8], deadline_ticks: u64) -> Result<()> {
        for byte in bytes {
            unsafe {
                write(UART + 0x11C, 0);
                write(UART + 0x51C, u32::from(*byte));
            }
            while unsafe { read(UART + 0x11C) } == 0 {
                self.watchdog.feed()?;
                if self.clock.ticks() >= deadline_ticks {
                    return Err(Error::Native);
                }
            }
        }
        Ok(())
    }
}
impl ApduTransport for BoardUart {
    fn receive(&mut self, output: &mut [u8], deadline_ticks: u64) -> Result<usize> {
        loop {
            self.watchdog.feed()?;
            let current = self.clock.ticks();
            self.decoder.expire(current as u32);
            if current >= deadline_ticks {
                return Err(Error::Native);
            }
            if unsafe { read(UART + 0x124) } != 0 {
                unsafe {
                    write(UART + 0x124, 0);
                    let errors = read(UART + 0x480);
                    write(UART + 0x480, errors);
                }
                self.decoder = microcard_core::framing::Decoder::default();
            }
            if unsafe { read(UART + 0x108) } == 0 {
                continue;
            }
            let byte = unsafe { read(UART + 0x518) } as u8;
            unsafe {
                write(UART + 0x108, 0);
            }
            if let Some(frame) = self.decoder.push(byte, current as u32) {
                if frame.len() > output.len() {
                    self.decoder = microcard_core::framing::Decoder::default();
                    return Err(Error::Bounds);
                }
                let length = frame.len();
                output[..length].copy_from_slice(frame);
                return Ok(length);
            }
        }
    }

    fn send(&mut self, input: &[u8], deadline_ticks: u64) -> Result<()> {
        let length = u16::try_from(input.len()).map_err(|_| Error::Bounds)?;
        self.write_raw(&length.to_le_bytes(), deadline_ticks)?;
        self.write_raw(input, deadline_ticks)
    }
}

struct BoardIdentity;
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

struct BoardResetReport(u32);
impl BoardResetReport {
    fn capture() -> Self {
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
#[entry]
fn main() -> ! {
    #[cfg(feature = "dongle-layout")]
    ensure_clean_bootloader_handoff();
    unsafe {
        // Nordic PS Debug and trace: Fxx+ needs both HwDisabled and SwDisable.
        // Respect the provisioned hardware policy; never rewrite UICR at startup.
        #[cfg(feature = "development-debug")]
        if read(0x10001208) & 0xff == 0x5a {
            write(0x40000558, 0x5a);
        }
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEMORY) as usize, 196608);
    }
    let mut transport = BoardUart::init();
    #[cfg(feature = "dongle-layout")]
    {
        led_init();
        led_color(LedColor::Blue);
    }
    if transport.watchdog.arm(10_000_000).is_err() {
        halt_with_diagnostic(
            &mut transport,
            b"MicroCard: watchdog startup failed\r\n",
            0x01,
        );
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
        halt_with_diagnostic(
            &mut transport,
            b"MicroCard: provision management keys at the key page\r\n",
            0x02,
        );
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
            halt_with_diagnostic(
                &mut transport,
                b"MicroCard: persistent state erased after ownership; provision fresh management keys\r\n",
                0x03,
            );
        }
    };
    let mut hardware = Hardware::new();
    if hardware.self_test().is_err() {
        let stage = hardware.self_test_stage.min(0x0f);
        halt_with_diagnostic(
            &mut transport,
            b"MicroCard: hardware self-test failed\r\n",
            0x40 | stage,
        );
    }
    let storage_key = match keys.storage_key_with(&mut hardware) {
        Ok(key) => key,
        Err(_) => {
            halt_with_diagnostic(
                &mut transport,
                b"MicroCard: storage-key derivation failed\r\n",
                0x05,
            );
        }
    };
    if ownership_action == OwnershipMarkerAction::ProgramBeforeOpen
        && Nvm::program_ownership_marker().is_err()
    {
        halt_with_diagnostic(
            &mut transport,
            b"MicroCard: ownership marker write failed\r\n",
            0x06,
        );
    }
    #[cfg(feature = "engine-mc04")]
    let opened = microcard_core::domains::Card::open_with_staging(
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
            let (message, code): (&[u8], u8) = if error == Error::IncompatibleState {
                (
                    b"MicroCard: incompatible persistent state; explicit provisioning required\r\n",
                    0x07,
                )
            } else {
                (b"MicroCard: persistent state open failed\r\n", 0x08)
            };
            halt_with_diagnostic(&mut transport, message, code);
        }
    };
    let mut endpoint = Endpoint::new(card, keys);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // ACL entries are reset-scoped. Keep debug recovery enabled; protect firmware writes.
    // Each entry covers at most half of flash. Stop at the linked firmware boundary:
    // images and upload staging must remain writable even when the layout changes.
    unsafe {
        let firmware_end = layout::FLASH_BASE + layout::FLASH_BYTES;
        for (slot, start, size, perm) in [
            (0, 0, firmware_end.min(0x80000) as u32, 2),
            (1, 0x80000, firmware_end.saturating_sub(0x80000) as u32, 2),
            (2, KEYS_BASE as u32, KEYS_BYTES as u32, 6),
        ] {
            if size == 0 {
                continue;
            }
            let base = NVMC + 0x800 + slot * 16;
            write(base, start);
            write(base + 4, size);
            write(base + 8, perm);
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    #[cfg(feature = "usb-ccid")]
    let mut usb_stack: Option<(
        BoardUsbDevice,
        BoardCcidClass,
        usb_ccid::ApduResponder<'static>,
    )> = None;
    #[cfg(feature = "usb-ccid")]
    let mut usb_was_powered = false;
    #[cfg(all(feature = "usb-ccid", feature = "dongle-layout"))]
    let mut usb_configuration_deadline = None;
    let mut command = [0; MAX_SHORT_COMMAND_BYTES];
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
                        if outgoing.extend_from_slice(&reply).is_ok() {
                            let _ = responder.respond(outgoing);
                        }
                        #[cfg(feature = "dongle-layout")]
                        if endpoint.take_bootloader_request() {
                            // Keep polling long enough to transmit the protected response before
                            // asking the installed Adafruit-derived bootloader to enter UF2.
                            enter_uf2_at = Some(now().wrapping_add(250_000));
                        }
                    }
                    class.check_for_app_response();
                    #[cfg(feature = "dongle-layout")]
                    if enter_uf2_at
                        .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                    {
                        enter_uf2();
                    }
                } else if usb_was_powered {
                    endpoint.reset();
                    usb_was_powered = false;
                    #[cfg(feature = "dongle-layout")]
                    {
                        led_color(LedColor::Blue);
                        usb_configuration_deadline = None;
                    }
                }
            }
        }
        #[cfg(feature = "usb-ccid")]
        let receive_ticks = 1_000;
        #[cfg(not(feature = "usb-ccid"))]
        let receive_ticks = 1_000_000;
        let deadline = transport.deadline_after(receive_ticks);
        let Ok(length) = receive_command(&mut transport, &mut command, deadline) else {
            continue;
        };
        let response = endpoint.exchange(&command[..length]);
        let deadline = transport.deadline_after(1_000_000);
        let _ = send_response(&mut transport, &response, deadline);
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
