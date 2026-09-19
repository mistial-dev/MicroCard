//! Bounded before-images. Records end in offset/length so rollback needs no index.
use alloc::vec::Vec;
use zeroize::Zeroize;
use crate::{Error, Result};

pub(super) struct Undo {
    records: Vec<u8>,
    limit: usize,
}

impl Drop for Undo {
    fn drop(&mut self) { self.records.zeroize(); }
}

impl Undo {
    pub(super) fn new(limit: usize) -> Self { Self { records: Vec::new(), limit } }

    pub(super) fn remaining(&self) -> usize { self.limit - self.records.len() }

    pub(super) fn record(&mut self, at: usize, before: &[u8]) -> Result<()> {
        if before.is_empty() { return Ok(()); }
        let end = at.checked_add(before.len()).ok_or(Error::Bounds)?;
        if end > u16::MAX as usize { return Err(Error::Bounds); }
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            // Repeated writes to an already saved span need no additional space.
            if offset <= at && end <= offset + length { return Ok(()); }
            cursor = start;
        }
        let cost = before.len().checked_add(4).ok_or(Error::Quota)?;
        if cost > self.remaining() { return Err(Error::Quota); }
        self.records.try_reserve_exact(cost).map_err(|_| Error::Quota)?;
        self.records.extend_from_slice(before);
        self.records.extend_from_slice(&(at as u16).to_be_bytes());
        self.records.extend_from_slice(&(before.len() as u16).to_be_bytes());
        Ok(())
    }

    // Unconditional writes, notably PIN retries, must survive even when an earlier
    // conditional write saved the same bytes. Update every overlapping before-image.
    pub(super) fn preserve(&mut self, at: usize, value: &[u8]) {
        let end = at + value.len();
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            let lo = at.max(offset);
            let hi = end.min(offset + length);
            if lo < hi {
                self.records[start + lo - offset..start + hi - offset]
                    .copy_from_slice(&value[lo - at..hi - at]);
            }
            cursor = start;
        }
    }

    pub(super) fn restore(&self, bytes: &mut [u8]) {
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            bytes[offset..offset + length].copy_from_slice(&self.records[start..start + length]);
            cursor = start;
        }
    }

    fn entry(&self, end: usize) -> (usize, usize, usize) {
        let offset = u16::from_be_bytes([self.records[end - 4], self.records[end - 3]]) as usize;
        let length = u16::from_be_bytes([self.records[end - 2], self.records[end - 1]]) as usize;
        (end - 4 - length, offset, length)
    }
}
