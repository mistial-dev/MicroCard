//! Bounded changed intervals, independent of the number of writes.
use core::ops::Range;

const HEAP_SPANS: usize = 8;

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
    heap: [Span; HEAP_SPANS],
    heap_count: u8,
    statics: Span,
    snapshot: bool,
}
impl PendingWrites {
    pub fn heap_range(self) -> Option<Range<usize>> {
        let mut ranges = self.heap_ranges();
        let first = ranges.next()?;
        Some(first.start..ranges.last().map_or(first.end, |range| range.end))
    }
    pub fn heap_ranges(self) -> impl Iterator<Item = Range<usize>> + Clone {
        self.heap.into_iter().take(self.heap_count as usize).filter_map(Span::range)
    }
    pub fn static_range(self) -> Option<Range<usize>> { self.statics.range() }
    pub fn snapshot_required(self) -> bool { self.snapshot }
    pub(crate) fn for_committed_heap(mut self, length: usize) -> Self {
        if let Ok(end) = u16::try_from(length) {
            let mut kept = 0;
            for index in 0..self.heap_count as usize {
                let mut span = self.heap[index];
                span.end = span.end.min(end);
                if span.start < span.end {
                    self.heap[kept] = span;
                    kept += 1;
                }
            }
            self.heap_count = kept as u8;
        } else { self.snapshot = true; }
        self
    }
    pub(crate) fn any(self) -> bool { self.snapshot || self.heap_count != 0 || self.statics.end != 0 }
    pub(crate) fn merge(&mut self, other: Self) {
        for range in other.heap_ranges() { self.heap(range.start, range.len()); }
        if let Some(range) = other.statics.range() { self.statics(range.start, range.len()); }
        self.snapshot |= other.snapshot;
    }
    pub(super) fn heap(&mut self, at: usize, length: usize) {
        if length == 0 { return; }
        let mut span = Span::default();
        if span.include(at, length).is_none() { self.snapshot = true; return; }
        let mut position = 0;
        while position < self.heap_count as usize && self.heap[position].end < span.start {
            position += 1;
        }
        while position < self.heap_count as usize && self.heap[position].start <= span.end {
            span.start = span.start.min(self.heap[position].start);
            span.end = span.end.max(self.heap[position].end);
            for index in position..self.heap_count as usize - 1 {
                self.heap[index] = self.heap[index + 1];
            }
            self.heap_count -= 1;
        }
        if self.heap_count as usize == HEAP_SPANS { self.snapshot = true; return; }
        for index in (position..self.heap_count as usize).rev() {
            self.heap[index + 1] = self.heap[index];
        }
        self.heap[position] = span;
        self.heap_count += 1;
    }
    pub(super) fn statics(&mut self, at: usize, length: usize) {
        if self.statics.include(at, length).is_none() { self.snapshot = true; }
    }
    pub(crate) fn require_snapshot(&mut self) { self.snapshot = true; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

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
        assert_eq!(writes.heap_ranges().collect::<Vec<_>>(), vec![4..11, 12..14]);
        writes.heap(30, 2);
        assert_eq!(writes.heap_ranges().collect::<Vec<_>>(), vec![4..11, 12..14, 30..32]);
        writes.statics(1, 2);
        assert_eq!(writes.static_range(), Some(1..3));
        assert_eq!(writes.for_committed_heap(9).heap_range(), Some(4..9));
        assert_eq!(writes.for_committed_heap(4).heap_range(), None);
        writes.heap(usize::MAX, 1);
        assert!(writes.snapshot_required());
        assert_eq!(writes.heap_range(), Some(4..32));
        writes.statics(u16::MAX as usize, 1);
        assert!(writes.snapshot_required());
        assert_eq!(writes.static_range(), Some(1..3));
        let mut bounded = PendingWrites::default();
        for at in (0..HEAP_SPANS).map(|index| index * 4) { bounded.heap(at, 1); }
        assert!(!bounded.snapshot_required());
        bounded.heap(HEAP_SPANS * 4, 1);
        assert!(bounded.snapshot_required());
    }
}
