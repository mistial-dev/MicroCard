//! Development-only APDU timing counters, readable over SWD without a serial transport.
use core::sync::atomic::{AtomicU32, Ordering};

use crate::platform::now;

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
    trace.apdu_us.store(now().wrapping_sub(start), Ordering::Relaxed);
}

pub(crate) fn cancel_poll() {
    MICROCARD_LATENCY_TRACE.cancel_polls.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn wait_extension() {
    MICROCARD_LATENCY_TRACE.wait_extensions.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn erase(start: u32, base: usize, size: usize) {
    MICROCARD_LATENCY_TRACE.erase_count.fetch_add(1, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE.erase_us.fetch_add(now().wrapping_sub(start), Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE.erase_base.store(base as u32, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE.erase_size.store(size as u32, Ordering::Relaxed);
}

pub(crate) fn program(start: u32, words: u32) {
    MICROCARD_LATENCY_TRACE.program_words.fetch_add(words, Ordering::Relaxed);
    MICROCARD_LATENCY_TRACE.program_us.fetch_add(now().wrapping_sub(start), Ordering::Relaxed);
}

pub(crate) fn maintenance(start: u32, failed: bool) {
    let trace = &MICROCARD_LATENCY_TRACE;
    trace.maintenance_count.fetch_add(1, Ordering::Relaxed);
    trace.maintenance_us.store(now().wrapping_sub(start), Ordering::Relaxed);
    trace.maintenance_error.store(failed as u32, Ordering::Relaxed);
}
