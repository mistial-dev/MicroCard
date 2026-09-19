//! Host requested-byte accounting, excluding allocator metadata and stack storage.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::File,
    io::Write,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
    ALLOCATED.fetch_add(bytes, Relaxed);
}

// Forward the exact pointer/layout contract to System. Only successful allocations
// enter the counters; realloc failure leaves the original allocation alive.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(pointer, layout, size) };
        if !next.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(size);
        }
        next
    }
}

pub(crate) struct Report(Option<File>);
impl Report {
    pub(crate) fn open() -> std::io::Result<Self> {
        let file = std::env::var_os("MICROCARD_HEAP_REPORT")
            .map(|path| {
                crate::private_open_options()
                    .create(true)
                    .append(true)
                    .open(path)
            })
            .transpose()?;
        Ok(Self(file))
    }

    /// Simulator execution is single-threaded. Keep reporting allocations outside
    /// the measured operation; the response remains live when its sample is taken.
    pub(crate) fn measure<T>(
        &mut self,
        stage: &str,
        ins: Option<u8>,
        run: impl FnOnce() -> T,
    ) -> T {
        let Some(file) = self.0.as_mut() else {
            return run();
        };
        let before = LIVE.load(Relaxed);
        PEAK.store(before, Relaxed);
        ALLOCATED.store(0, Relaxed);
        let started = Instant::now();
        let value = run();
        let micros = started.elapsed().as_micros();
        let live = LIVE.load(Relaxed);
        let peak = PEAK.load(Relaxed);
        let allocated = ALLOCATED.load(Relaxed);
        // Only public command identifiers are recorded, never APDU data or keys.
        writeln!(file,
            "{{\"pid\":{},\"stage\":\"{}\",\"ins\":{},\"before_bytes\":{},\"live_bytes\":{},\"peak_bytes\":{},\"allocated_bytes\":{},\"host_microseconds\":{}}}",
            std::process::id(), stage, ins.map_or(-1, i16::from), before, live, peak, allocated, micros
        ).expect("cannot write heap report");
        value
    }
}
