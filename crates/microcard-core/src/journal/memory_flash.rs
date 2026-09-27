use super::{decode_monotonic_words, Flash};
use crate::{Error, Result};
use alloc::{vec, vec::Vec};

/// Host fault model. Erase may stop at any byte; a word program is indivisible.
#[derive(Clone)]
pub struct MemoryFlash {
    pub(super) slots: Vec<Vec<u8>>,
    pub(super) slot_word_writes: Vec<Vec<u8>>,
    images: Vec<Vec<u8>>,
    image_word_writes: Vec<Vec<u8>>,
    image_size: usize,
    pub(super) monotonic: Vec<u8>,
    pub(super) nonces: Vec<u8>,
    pub fail_after: Option<usize>,
    #[cfg(test)]
    metrics: FlashMetrics,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FlashMetrics {
    pub(crate) program_calls: usize,
    pub(crate) programmed_bytes: usize,
    pub(crate) erase_calls: usize,
    pub(crate) erased_bytes: usize,
}
impl MemoryFlash {
    #[cfg(test)]
    pub(crate) fn reset_metrics(&mut self) { self.metrics = FlashMetrics::default(); }
    #[cfg(test)]
    pub(crate) fn metrics(&self) -> FlashMetrics { self.metrics }
    #[cfg(all(test, feature = "jcvm", feature = "software-crypto"))]
    pub(crate) fn leave_nonce_reservations_for_test(&mut self, remaining: usize) {
        let end = self.nonces.len().checked_sub(remaining.checked_mul(4).unwrap()).unwrap();
        assert!(self.nonces[end..].iter().all(|byte| *byte == 0xff));
        // Model already consumed reservations without replaying thousands of full
        // counter scans. Only clear bits; committed records and generations stay put.
        self.nonces[..end].fill(0);
    }
    pub fn new(size: usize) -> Self {
        Self::with_slots(size, 2)
    }
    pub fn with_images(size: usize, image_count: usize, image_size: usize) -> Result<Self> {
        if !(2..=64).contains(&image_count) || image_size == 0 { return Err(Error::Storage); }
        let mut flash = Self::new(size);
        flash.images.truncate(image_count);
        flash.image_word_writes.truncate(image_count);
        flash.image_size = image_size;
        Ok(flash)
    }
    pub(super) fn with_slots(size: usize, slot_count: usize) -> Self {
        Self {
            slots: (0..slot_count).map(|_| vec![255; size]).collect(),
            slot_word_writes: (0..slot_count).map(|_| vec![0; size.div_ceil(4)]).collect(),
            images: (0..64).map(|_| Vec::new()).collect(),
            image_word_writes: (0..64).map(|_| Vec::new()).collect(),
            image_size: crate::staging::MAX_PACKAGE_BYTES,
            monotonic: vec![255; size],
            nonces: vec![255; size],
            fail_after: None,
            #[cfg(test)]
            metrics: FlashMetrics::default(),
        }
    }
    fn tick(&mut self) -> Result<()> {
        if let Some(n) = self.fail_after.as_mut() {
            if *n == 0 {
                return Err(Error::Storage);
            }
            *n -= 1;
        }
        Ok(())
    }
}
impl MemoryFlash {
    fn advance_word_counter(&mut self, generation: u64, nonce: bool) -> Result<()> {
        let index = usize::try_from(generation.checked_sub(1).ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        let offset = index.checked_mul(4).ok_or(Error::Storage)?;
        let counter = if nonce { &self.nonces } else { &self.monotonic };
        let word = counter
            .get(offset..offset + 4)
            .ok_or(Error::Quota)?;
        if word.iter().any(|byte| *byte != 0xff) {
            return Err(Error::Storage);
        }
        #[cfg(test)]
        { self.metrics.program_calls += 1; }
        for byte in offset..offset + 4 {
            self.tick()?;
            if nonce { self.nonces[byte] = 0; } else { self.monotonic[byte] = 0; }
            #[cfg(test)]
            { self.metrics.programmed_bytes += 1; }
        }
        Ok(())
    }
}
pub struct MemoryImageReader {
    images: Vec<Vec<u8>>,
    image_size: usize,
}
impl crate::image_store::ImageReader for MemoryImageReader {
    fn slot_count(&self) -> usize { self.images.len() }
    fn slot_size(&self) -> usize { self.image_size }
    type Image<'a> = &'a [u8];
    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        let image = self.images.get(index).ok_or(Error::Bounds)?;
        if image.is_empty() { return Err(Error::Storage); }
        image.get(range).ok_or(Error::Bounds)
    }
}
impl crate::image_store::ImageReader for MemoryFlash {
    fn slot_count(&self) -> usize { self.images.len() }
    fn slot_size(&self) -> usize { self.image_size }
    type Image<'a> = &'a [u8];
    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        let image = self.images.get(index).ok_or(Error::Bounds)?;
        if image.is_empty() { return Err(Error::Storage); }
        image.get(range).ok_or(Error::Bounds)
    }
}
impl crate::image_store::ImageFlash for MemoryFlash {
    type Reader = MemoryImageReader;
    fn image_reader(&self) -> Result<Self::Reader> {
        Ok(MemoryImageReader { images: self.images.clone(), image_size: self.image_size })
    }
    fn erase(&mut self, index: usize) -> Result<()> {
        let image = self.images.get_mut(index).ok_or(Error::Bounds)?;
        if image.is_empty() {
            image.try_reserve_exact(self.image_size).map_err(|_| Error::Quota)?;
            image.resize(self.image_size, 255);
            self.image_word_writes[index].resize(self.image_size.div_ceil(4), 0);
        }
        #[cfg(test)]
        { self.metrics.erase_calls += 1; }
        for offset in 0..image.len() {
            self.tick()?;
            self.images[index][offset] = 255;
            #[cfg(test)]
            { self.metrics.erased_bytes += 1; }
        }
        self.image_word_writes[index].fill(0);
        Ok(())
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        let old = self.images.get(index).and_then(|image| image.get(offset..end)).ok_or(Error::Bounds)?;
        if old.iter().zip(bytes).any(|(old, new)| old & new != *new) { return Err(Error::Storage); }
        #[cfg(test)]
        if !bytes.is_empty() { self.metrics.program_calls += 1; }
        for pos in ((offset & !3)..((end + 3) & !3)).step_by(4) {
            let word_end = (pos + 4).min(self.image_size);
            let mut merged = self.images[index][pos..word_end].to_vec();
            for (at, byte) in merged.iter_mut().enumerate() {
                let location = pos + at;
                if location >= offset && location < end { *byte = bytes[location - offset]; }
            }
            if merged == self.images[index][pos..word_end] { continue; }
            if self.image_word_writes[index][pos / 4] >= 2 { return Err(Error::Storage); }
            for _ in pos..word_end { self.tick()?; }
            self.images[index][pos..word_end].copy_from_slice(&merged);
            self.image_word_writes[index][pos / 4] += 1;
            #[cfg(test)]
            { self.metrics.programmed_bytes += word_end - pos; }
        }
        Ok(())
    }
}
impl Flash for MemoryFlash {
    fn slot_count(&self) -> usize {
        self.slots.len()
    }
    fn slot_size(&self) -> usize {
        self.slots[0].len()
    }
    fn monotonic_capacity(&self) -> u64 {
        (self.monotonic.len() / 4) as u64
    }
    fn monotonic_generation(&self) -> Result<u64> {
        decode_monotonic_words(&self.monotonic)
    }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        self.advance_word_counter(generation, false)
    }
    fn nonce_generation(&self) -> Result<u64> { decode_monotonic_words(&self.nonces) }
    fn reserve_nonce(&mut self) -> Result<u64> {
        let next = self.nonce_generation()?.checked_add(1).ok_or(Error::Quota)?;
        self.advance_word_counter(next, true)?;
        Ok(next)
    }
    fn is_erased(&self, s: usize) -> Result<bool> {
        Ok(self
            .slots
            .get(s)
            .ok_or(Error::Bounds)?
            .iter()
            .all(|byte| *byte == 0xff))
    }
    fn read(&self, s: usize, o: usize, output: &mut [u8]) -> Result<()> {
        let slot = self.slots.get(s).ok_or(Error::Bounds)?;
        let end = o.checked_add(output.len()).ok_or(Error::Bounds)?;
        output.copy_from_slice(slot.get(o..end).ok_or(Error::Bounds)?);
        Ok(())
    }
    fn erase(&mut self, s: usize) -> Result<()> {
        #[cfg(test)]
        { self.metrics.erase_calls += 1; }
        for i in 0..self.slot_size() {
            self.tick()?;
            self.slots[s][i] = 255;
            #[cfg(test)]
            { self.metrics.erased_bytes += 1; }
        }
        self.slot_word_writes[s].fill(0);
        Ok(())
    }
    fn program(&mut self, s: usize, o: usize, b: &[u8]) -> Result<()> {
        if o.checked_add(b.len()).is_none_or(|n| n > self.slot_size()) {
            return Err(Error::Bounds);
        }
        #[cfg(test)]
        if !b.is_empty() { self.metrics.program_calls += 1; }
        for pos in ((o & !3)..((o + b.len() + 3) & !3)).step_by(4) {
            let end = (pos + 4).min(self.slot_size());
            let mut merged = self.slots[s][pos..end].to_vec();
            for (index, byte) in merged.iter_mut().enumerate() {
                let location = pos + index;
                if location >= o && location < o + b.len() {
                    let new = b[location - o];
                    if *byte & new != new { return Err(Error::Storage); }
                    *byte = new;
                }
            }
            if merged == self.slots[s][pos..end] { continue; }
            if self.slot_word_writes[s][pos / 4] >= 2 { return Err(Error::Storage); }
            for _ in pos..end { self.tick()?; }
            self.slots[s][pos..end].copy_from_slice(&merged);
            self.slot_word_writes[s][pos / 4] += 1;
            #[cfg(test)]
            { self.metrics.programmed_bytes += end - pos; }
        }
        Ok(())
    }
}
