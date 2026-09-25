//! Opt-in SWD trace retained across warm resets without flash writes.
use core::{
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::platform::now;

const MAGIC: u32 = 0x4d43_5452;
const VERSION: u32 = 2;
const EVENTS: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    sequence: u32,
    time_us: u32,
    kind: u32,
    detail: u32,
}

#[repr(C)]
struct RetainedTrace {
    magic: u32,
    version: u32,
    next: u32,
    boot_count: u32,
    reset_reason: u32,
    last_poll_us: u32,
    max_poll_gap_us: u32,
    previous_last_poll_us: u32,
    previous_max_poll_gap_us: u32,
    events: [Event; EVENTS],
}

// cortex-m-rt excludes .uninit from startup clearing. RTIC tasks serialize writes.
#[link_section = ".uninit.microcard_trace"]
#[no_mangle]
static mut MICROCARD_RETAINED_TRACE: MaybeUninit<RetainedTrace> = MaybeUninit::uninit();

fn retained() -> *mut RetainedTrace {
    ptr::addr_of_mut!(MICROCARD_RETAINED_TRACE).cast()
}

pub(crate) mod event {
    pub const BOOT: u32 = 1;
    pub const USB_READY: u32 = 2;
    pub const REQUEST: u32 = 3;
    pub const EXECUTION_DONE: u32 = 4;
    pub const RESPONSE_QUEUED: u32 = 5;
    pub const MAINTENANCE_START: u32 = 6;
    pub const MAINTENANCE_DONE: u32 = 7;
    pub const ERASE_PAGE_START: u32 = 8;
    pub const ERASE_PAGE_DONE: u32 = 9;
    pub const PROGRAM_START: u32 = 10;
    pub const PROGRAM_DONE: u32 = 11;
    pub const WAIT_EXTENSION: u32 = 12;
    pub const USB_POWER_LOST: u32 = 13;
    pub const PANIC: u32 = 14;
    #[cfg(feature = "development-recovery")]
    pub const HARD_FAULT: u32 = 15;
    pub const RENEW_PHASE: u32 = 16;
    pub const PANIC_FILE: u32 = 17;
}

#[no_mangle]
pub extern "C" fn microcard_trace_phase(stage: u32) {
    record(event::RENEW_PHASE, stage);
}

pub(crate) fn boot(reset_reason: u32) {
    let trace = retained();
    unsafe {
        if ptr::read_volatile(ptr::addr_of!((*trace).magic)) != MAGIC
            || ptr::read_volatile(ptr::addr_of!((*trace).version)) != VERSION
        {
            ptr::write_bytes(trace.cast::<u8>(), 0, core::mem::size_of::<RetainedTrace>());
            (*trace).magic = MAGIC;
            (*trace).version = VERSION;
        }
        (*trace).boot_count = (*trace).boot_count.wrapping_add(1);
        (*trace).reset_reason = reset_reason;
        (*trace).previous_last_poll_us = (*trace).last_poll_us;
        (*trace).previous_max_poll_gap_us = (*trace).max_poll_gap_us;
        (*trace).last_poll_us = 0;
        (*trace).max_poll_gap_us = 0;
    }
    record(event::BOOT, reset_reason);
}

pub(crate) fn record(kind: u32, detail: u32) {
    cortex_m::interrupt::free(|_| {
        let trace = retained();
        unsafe {
            if (*trace).magic != MAGIC {
                return;
            }
            let index = (*trace).next as usize % EVENTS;
            let sequence = (*trace).next.wrapping_add(1);
            let entry = &mut (*trace).events[index];
            entry.sequence = 0;
            entry.time_us = now();
            entry.kind = kind;
            entry.detail = detail;
            core::sync::atomic::compiler_fence(Ordering::Release);
            entry.sequence = sequence;
            (*trace).next = sequence;
        }
    });
}

pub(crate) fn usb_poll() {
    cortex_m::interrupt::free(|_| {
        let trace = retained();
        unsafe {
            let at = now();
            let last = (*trace).last_poll_us;
            if last != 0 {
                let gap = at.wrapping_sub(last);
                if gap > (*trace).max_poll_gap_us {
                    (*trace).max_poll_gap_us = gap;
                }
            }
            (*trace).last_poll_us = at;
        }
    });
}

#[repr(C)]
pub(crate) struct LatencyTrace {
    pub apdu_count: AtomicU32,
    pub apdu_start: AtomicU32,
    pub apdu_us: AtomicU32,
    pub cancel_polls: AtomicU32,
    pub wait_extensions: AtomicU32,
    pub erase_count: AtomicU32,
    pub erase_us: AtomicU32,
    pub program_words: AtomicU32,
    pub program_us: AtomicU32,
    pub maintenance_count: AtomicU32,
    pub maintenance_us: AtomicU32,
    pub maintenance_error: AtomicU32,
    pub erase_base: AtomicU32,
    pub erase_size: AtomicU32,
}

#[no_mangle]
pub(crate) static MICROCARD_LATENCY_TRACE: LatencyTrace = LatencyTrace {
    apdu_count: AtomicU32::new(0),
    apdu_start: AtomicU32::new(0),
    apdu_us: AtomicU32::new(0),
    cancel_polls: AtomicU32::new(0),
    wait_extensions: AtomicU32::new(0),
    erase_count: AtomicU32::new(0),
    erase_us: AtomicU32::new(0),
    program_words: AtomicU32::new(0),
    program_us: AtomicU32::new(0),
    maintenance_count: AtomicU32::new(0),
    maintenance_us: AtomicU32::new(0),
    maintenance_error: AtomicU32::new(0),
    erase_base: AtomicU32::new(0),
    erase_size: AtomicU32::new(0),
};

#[repr(C)]
pub(crate) struct MaximumApduTrace {
    max_apdu_us: AtomicU32,
    erase_calls: AtomicU32,
    erase_us: AtomicU32,
    program_words: AtomicU32,
    program_us: AtomicU32,
    wait_extensions: AtomicU32,
    total_erase_calls: AtomicU32,
    total_program_words: AtomicU32,
}

#[no_mangle]
pub(crate) static MICROCARD_MAX_APDU_TRACE: MaximumApduTrace = MaximumApduTrace {
    max_apdu_us: AtomicU32::new(0),
    erase_calls: AtomicU32::new(0),
    erase_us: AtomicU32::new(0),
    program_words: AtomicU32::new(0),
    program_us: AtomicU32::new(0),
    wait_extensions: AtomicU32::new(0),
    total_erase_calls: AtomicU32::new(0),
    total_program_words: AtomicU32::new(0),
};

pub(crate) fn apdu_start() {
    let trace = &MICROCARD_LATENCY_TRACE;
    trace.apdu_count.fetch_add(1, Ordering::Relaxed);
    trace.apdu_start.store(now(), Ordering::Relaxed);
    trace.cancel_polls.store(0, Ordering::Relaxed);
    trace.wait_extensions.store(0, Ordering::Relaxed);
    trace.erase_count.store(0, Ordering::Relaxed);
    trace.erase_us.store(0, Ordering::Relaxed);
    trace.program_words.store(0, Ordering::Relaxed);
    trace.program_us.store(0, Ordering::Relaxed);
}
pub(crate) fn apdu_end() {
    let trace = &MICROCARD_LATENCY_TRACE;
    let start = trace.apdu_start.load(Ordering::Relaxed);
    let elapsed = now().wrapping_sub(start);
    trace.apdu_us.store(elapsed, Ordering::Relaxed);
    let maximum = &MICROCARD_MAX_APDU_TRACE;
    if elapsed > maximum.max_apdu_us.load(Ordering::Relaxed) {
        maximum.max_apdu_us.store(elapsed, Ordering::Relaxed);
        maximum
            .erase_calls
            .store(trace.erase_count.load(Ordering::Relaxed), Ordering::Relaxed);
        maximum
            .erase_us
            .store(trace.erase_us.load(Ordering::Relaxed), Ordering::Relaxed);
        maximum.program_words.store(
            trace.program_words.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        maximum
            .program_us
            .store(trace.program_us.load(Ordering::Relaxed), Ordering::Relaxed);
        maximum.wait_extensions.store(
            trace.wait_extensions.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
}
pub(crate) fn cancel_poll() {
    MICROCARD_LATENCY_TRACE
        .cancel_polls
        .fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn wait_extension() {
    MICROCARD_LATENCY_TRACE
        .wait_extensions
        .fetch_add(1, Ordering::Relaxed);
    record(event::WAIT_EXTENSION, 0);
}
pub(crate) fn erase(start: u32, base: usize, size: usize) {
    MICROCARD_MAX_APDU_TRACE
        .total_erase_calls
        .fetch_add(1, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .erase_count
        .fetch_add(1, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .erase_us
        .fetch_add(now().wrapping_sub(start), Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .erase_base
        .store(base as u32, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .erase_size
        .store(size as u32, Ordering::Relaxed);
}
pub(crate) fn program(start: u32, words: u32) {
    MICROCARD_MAX_APDU_TRACE
        .total_program_words
        .fetch_add(words, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .program_words
        .fetch_add(words, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE
        .program_us
        .fetch_add(now().wrapping_sub(start), Ordering::Relaxed);
}
pub(crate) fn maintenance(start: u32, failed: bool) {
    let trace = &MICROCARD_LATENCY_TRACE;
    trace.maintenance_count.fetch_add(1, Ordering::Relaxed);
    trace
        .maintenance_us
        .store(now().wrapping_sub(start), Ordering::Relaxed);
    trace
        .maintenance_error
        .store(failed as u32, Ordering::Relaxed);
}
