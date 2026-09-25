//! Development-only view of patch decisions, readable through a debug probe.
use core::sync::atomic::{AtomicU32, Ordering};

use microcard_engine_jcvm::applet::PersistentView;
use microcard_engine_jcvm::host::CheckpointReason;

#[repr(C)]
pub struct PatchTrace {
    reason: AtomicU32,
    heap_start: AtomicU32,
    heap_end: AtomicU32,
    static_start: AtomicU32,
    static_end: AtomicU32,
    snapshot_required: AtomicU32,
    patch_bytes: AtomicU32,
    snapshot_bytes: AtomicU32,
    maximum_bytes: AtomicU32,
    heap_bytes: AtomicU32,
    append_commits: AtomicU32,
    snapshot_commits: AtomicU32,
    checkpoint_attempts: [AtomicU32; 4],
    fallback_counts: [AtomicU32; 4],
    patch_payload_bytes: AtomicU32,
    snapshot_payload_bytes: AtomicU32,
    idle_compactions: AtomicU32,
}

#[no_mangle]
pub static MICROCARD_JCVM_PATCH_TRACE: PatchTrace = PatchTrace {
    reason: AtomicU32::new(0),
    heap_start: AtomicU32::new(0),
    heap_end: AtomicU32::new(0),
    static_start: AtomicU32::new(0),
    static_end: AtomicU32::new(0),
    snapshot_required: AtomicU32::new(0),
    patch_bytes: AtomicU32::new(0),
    snapshot_bytes: AtomicU32::new(0),
    maximum_bytes: AtomicU32::new(0),
    heap_bytes: AtomicU32::new(0),
    append_commits: AtomicU32::new(0),
    snapshot_commits: AtomicU32::new(0),
    checkpoint_attempts: [const { AtomicU32::new(0) }; 4],
    fallback_counts: [const { AtomicU32::new(0) }; 4],
    patch_payload_bytes: AtomicU32::new(0),
    snapshot_payload_bytes: AtomicU32::new(0),
    idle_compactions: AtomicU32::new(0),
};

#[no_mangle]
pub static MICROCARD_JCVM_ENGINE_ERROR: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static MICROCARD_JCVM_CORE_ERROR: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static MICROCARD_JCVM_CHECKPOINT_ERROR: AtomicU32 = AtomicU32::new(0);

pub(crate) fn record_session_error(stage: u32, code: u32) {
    match stage {
        1 => MICROCARD_JCVM_ENGINE_ERROR.store(code, Ordering::Relaxed),
        2 => MICROCARD_JCVM_CORE_ERROR.store(code, Ordering::Relaxed),
        3 | 4 => MICROCARD_JCVM_CHECKPOINT_ERROR.store((stage << 16) | code, Ordering::Relaxed),
        _ => {}
    }
}

pub(crate) fn renewal_phase(stage: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        extern "C" {
            fn microcard_trace_phase(stage: u32);
        }
        microcard_trace_phase(stage);
    }
    #[cfg(not(target_arch = "arm"))]
    let _ = stage;
}

pub(super) fn capture_view(view: PersistentView<'_>, reason: CheckpointReason) {
    let trace = &MICROCARD_JCVM_PATCH_TRACE;
    let reason_index = match reason {
        CheckpointReason::Installation => 0,
        CheckpointReason::ApduEnd => 1,
        CheckpointReason::OwnerPin => 2,
        CheckpointReason::TransactionCommit => 3,
    };
    trace.checkpoint_attempts[reason_index].fetch_add(1, Ordering::Relaxed);
    let writes = view.pending_writes();
    let heap = writes.and_then(|value| value.heap_range());
    let statics = writes.and_then(|value| value.static_range());
    trace.reason.store(0, Ordering::Relaxed);
    trace.heap_start.store(heap.as_ref().map_or(0, |range| range.start) as u32, Ordering::Relaxed);
    trace.heap_end.store(heap.as_ref().map_or(0, |range| range.end) as u32, Ordering::Relaxed);
    trace.static_start.store(statics.as_ref().map_or(0, |range| range.start) as u32, Ordering::Relaxed);
    trace.static_end.store(statics.as_ref().map_or(0, |range| range.end) as u32, Ordering::Relaxed);
    trace.snapshot_required.store(writes.is_none_or(|value| value.snapshot_required()) as u32, Ordering::Relaxed);
    trace.patch_bytes.store(0, Ordering::Relaxed);
}

pub(super) fn capacity(snapshot: usize, maximum: usize, heap: usize) {
    MICROCARD_JCVM_PATCH_TRACE.snapshot_bytes.store(snapshot as u32, Ordering::Relaxed);
    MICROCARD_JCVM_PATCH_TRACE.maximum_bytes.store(maximum as u32, Ordering::Relaxed);
    MICROCARD_JCVM_PATCH_TRACE.heap_bytes.store(heap as u32, Ordering::Relaxed);
}

pub(super) fn fallback(reason: u32) {
    MICROCARD_JCVM_PATCH_TRACE.reason.store(reason, Ordering::Relaxed);
    if (reason as usize) < MICROCARD_JCVM_PATCH_TRACE.fallback_counts.len() {
        MICROCARD_JCVM_PATCH_TRACE.fallback_counts[reason as usize].fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn patch(bytes: usize) {
    MICROCARD_JCVM_PATCH_TRACE.reason.store(4, Ordering::Relaxed);
    MICROCARD_JCVM_PATCH_TRACE.patch_bytes.store(bytes as u32, Ordering::Relaxed);
}

pub(super) fn committed_patch(bytes: usize) {
    MICROCARD_JCVM_PATCH_TRACE.append_commits.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_PATCH_TRACE.patch_payload_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub(super) fn committed_snapshot(bytes: usize) {
    MICROCARD_JCVM_PATCH_TRACE.snapshot_commits.fetch_add(1, Ordering::Relaxed);
    MICROCARD_JCVM_PATCH_TRACE.snapshot_payload_bytes.fetch_add(bytes as u32, Ordering::Relaxed);
}

pub(super) fn idle_compaction(bytes: usize) {
    MICROCARD_JCVM_PATCH_TRACE.idle_compactions.fetch_add(1, Ordering::Relaxed);
    committed_snapshot(bytes);
}
