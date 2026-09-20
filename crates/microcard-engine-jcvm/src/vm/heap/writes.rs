//! Conservative changed intervals, bounded independently of the number of writes.
use core::ops::Range;

#[derive(Clone, Copy, Default)]
struct Span { start: u16, end: u16 }
impl Span {
    fn include(&mut self, at: usize, length: usize) -> Option<()> {
        if length == 0 { return Some(()); }
        let end = u16::try_from(at.checked_add(length)?).ok()?;
        let start = u16::try_from(at).ok()?;
        if self.end == 0 { self.start = start; self.end = end; }
        else { self.start = self.start.min(start); self.end = self.end.max(end); }
        Some(())
    }
    fn range(self) -> Option<Range<usize>> {
        (self.end != 0).then_some(self.start as usize..self.end as usize)
    }
}

/// Changed committed bytes since the last acknowledged checkpoint.
/// Intervals may include unchanged bytes. Transaction commits request a snapshot.
#[derive(Clone, Copy, Default)]
pub struct PendingWrites {
    heap: Span,
    statics: Span,
    snapshot: bool,
}
impl PendingWrites {
    pub fn heap_range(self) -> Option<Range<usize>> { self.heap.range() }
    pub fn static_range(self) -> Option<Range<usize>> { self.statics.range() }
    pub fn snapshot_required(self) -> bool { self.snapshot }
    pub(crate) fn for_committed_heap(mut self, length: usize) -> Self {
        if let Ok(end) = u16::try_from(length) {
            self.heap.end = self.heap.end.min(end);
            if self.heap.start >= self.heap.end { self.heap = Span::default(); }
        } else { self.snapshot = true; }
        self
    }
    pub(super) fn any(self) -> bool { self.snapshot || self.heap.end != 0 || self.statics.end != 0 }
    pub(super) fn heap(&mut self, at: usize, length: usize) {
        if self.heap.include(at, length).is_none() { self.snapshot = true; }
    }
    pub(super) fn statics(&mut self, at: usize, length: usize) {
        if self.statics.include(at, length).is_none() { self.snapshot = true; }
    }
    pub(super) fn require_snapshot(&mut self) { self.snapshot = true; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_preserve_all_writes_and_overflow_requires_a_snapshot() {
        let mut writes = PendingWrites::default();
        writes.heap(usize::MAX, 0);
        assert!(!writes.any());
        for (at, length) in [(12, 2), (4, 3), (6, 5), (8, 1)] {
            writes.heap(at, length);
            let range = writes.heap_range().unwrap();
            assert!(range.start <= at && range.end >= at + length);
        }
        assert_eq!(writes.heap_range(), Some(4..14));
        writes.statics(1, 2);
        assert_eq!(writes.static_range(), Some(1..3));
        assert_eq!(writes.for_committed_heap(9).heap_range(), Some(4..9));
        assert_eq!(writes.for_committed_heap(4).heap_range(), None);
        writes.heap(usize::MAX, 1);
        assert!(writes.snapshot_required());
        assert_eq!(writes.heap_range(), Some(4..14));
        writes.statics(u16::MAX as usize, 1);
        assert!(writes.snapshot_required());
        assert_eq!(writes.static_range(), Some(1..3));
    }
}
