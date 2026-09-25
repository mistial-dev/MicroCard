//! Opt-in allocation and tracked write counters, readable through SWD.
//! Write counters cover `remember` paths, not direct runtime metadata updates.
use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
pub(super) struct HeapTrace {
    allocations: AtomicU32,
    allocated_bytes: AtomicU32,
    transient_arrays: AtomicU32,
    transient_payload_bytes: AtomicU32,
    dirty_heap_writes: AtomicU32,
    dirty_heap_bytes: AtomicU32,
    dirty_static_writes: AtomicU32,
    dirty_static_bytes: AtomicU32,
}

#[no_mangle]
pub(super) static MICROCARD_JCVM_HEAP_TRACE: HeapTrace = HeapTrace {
    allocations: AtomicU32::new(0),
    allocated_bytes: AtomicU32::new(0),
    transient_arrays: AtomicU32::new(0),
    transient_payload_bytes: AtomicU32::new(0),
    dirty_heap_writes: AtomicU32::new(0),
    dirty_heap_bytes: AtomicU32::new(0),
    dirty_static_writes: AtomicU32::new(0),
    dirty_static_bytes: AtomicU32::new(0),
};

pub(super) fn allocation(bytes: usize) {
    MICROCARD_JCVM_HEAP_TRACE.allocations.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_HEAP_TRACE.allocated_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub(super) fn transient_array(bytes: usize) {
    MICROCARD_JCVM_HEAP_TRACE.transient_arrays.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_HEAP_TRACE.transient_payload_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub(super) fn heap_write(bytes: usize) {
    MICROCARD_JCVM_HEAP_TRACE.dirty_heap_writes.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_HEAP_TRACE.dirty_heap_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub(super) fn static_write(bytes: usize) {
    MICROCARD_JCVM_HEAP_TRACE.dirty_static_writes.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_HEAP_TRACE.dirty_static_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}
