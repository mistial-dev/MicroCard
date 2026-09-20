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
    pub(super) fn new(limit: usize) -> Result<Self> {
        // Reserve once, before any secrets enter the log. Growing a populated Vec
        // would free copies of before-images without wiping those old allocations.
        let mut records = Vec::new();
        records.try_reserve_exact(limit).map_err(|_| Error::TransactionFull)?;
        Ok(Self { records, limit })
    }

    pub(super) fn remaining(&self) -> usize { self.limit - self.records.len() }

    pub(super) fn rewind(&mut self, remaining: usize) {
        let length = self.limit - remaining;
        self.records[length..].zeroize();
        self.records.truncate(length);
    }

    pub(super) fn record(&mut self, at: usize, before: &[u8], statics: bool) -> Result<()> {
        if before.is_empty() { return Ok(()); }
        let end = at.checked_add(before.len()).ok_or(Error::Bounds)?;
        if end > u16::MAX as usize { return Err(Error::Bounds); }
        let at = at | (usize::from(statics) << 16);
        let end = end | (usize::from(statics) << 16);
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            // Repeated writes to an already saved span need no additional space.
            if offset <= at && end <= offset + length { return Ok(()); }
            cursor = start;
        }
        let cost = before.len().checked_add(6).ok_or(Error::TransactionFull)?;
        if cost > self.remaining() { return Err(Error::TransactionFull); }
        self.records.extend_from_slice(before);
        self.records.extend_from_slice(&(at as u32).to_be_bytes());
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

    pub(super) fn restore(&self, heap: &mut [u8], statics: &mut [u8]) {
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            let bytes = if offset >> 16 == 0 { &mut *heap } else { &mut *statics };
            let offset = offset & 0xffff;
            bytes[offset..offset + length].copy_from_slice(&self.records[start..start + length]);
            cursor = start;
        }
    }

    pub(super) fn project(&self, output: &mut [u8], statics: bool) -> Result<()> {
        self.project_range(output, 0, output.len(), statics)
    }

    pub(super) fn project_range(&self, output: &mut [u8], at: usize, total: usize,
            statics: bool) -> Result<()> {
        let end = at.checked_add(output.len()).filter(|end| *end <= total).ok_or(Error::Bounds)?;
        let mut cursor = self.records.len();
        while cursor != 0 {
            let (start, offset, length) = self.entry(cursor);
            if (offset >> 16 != 0) == statics {
                let offset = offset & 0xffff;
                // A heap projection excludes objects allocated after begin.
                if statics || offset < total {
                    let record_end = offset.checked_add(length)
                        .filter(|end| *end <= total).ok_or(Error::Bounds)?;
                    let lo = at.max(offset);
                    let hi = end.min(record_end);
                    if lo < hi {
                        output[lo - at..hi - at]
                            .copy_from_slice(&self.records[start + lo - offset..start + hi - offset]);
                    }
                }
            }
            cursor = start;
        }
        Ok(())
    }

    fn entry(&self, end: usize) -> (usize, usize, usize) {
        let offset = u32::from_be_bytes(self.records[end - 6..end - 2].try_into().unwrap()) as usize;
        let length = u16::from_be_bytes([self.records[end - 2], self.records[end - 1]]) as usize;
        (end - 6 - length, offset, length)
    }
}
