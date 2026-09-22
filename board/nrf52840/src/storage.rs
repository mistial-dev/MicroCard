use microcard_core::{
    hal::StagingFlash,
    journal::{decode_program_once_words, next_program_once_word, Flash},
    provisioning::PROGRAMMED_OWNERSHIP_MARKER,
    Error, Result,
};
use nrf52840_pac as pac;

use crate::{
    layout,
    platform::{feed, now, read, write},
    KEYS_BASE, KEYS_BYTES, OWNERSHIP_MARKER_OFFSET,
};

pub(crate) struct Nvm {
    pub(crate) slots: [usize; 3],
    pub(crate) count: usize,
    pub(crate) size: usize,
    pub(crate) monotonic: usize,
    pub(crate) nonces: usize,
}

impl Nvm {
    const COUNTER_BYTES: usize = 4096;

    pub(crate) fn new() -> Self {
        Self {
            slots: [layout::JOURNAL0_BASE, layout::JOURNAL1_BASE, {
                #[cfg(feature = "engine-mc04")]
                {
                    layout::JOURNAL2_BASE
                }
                #[cfg(not(feature = "engine-mc04"))]
                {
                    0
                }
            }],
            count: if cfg!(feature = "engine-mc04") { 3 } else { 2 },
            size: layout::JOURNAL0_BYTES,
            monotonic: layout::MONOTONIC_BASE,
            nonces: layout::NONCES_BASE,
        }
    }

    fn base(&self, slot: usize) -> Result<usize> {
        if slot >= self.count {
            return Err(Error::Bounds);
        }
        Ok(self.slots[slot])
    }

    pub(crate) fn persistent_storage_erased() -> Result<bool> {
        let flash = Self::new();
        for slot in 0..flash.slot_count() {
            if !flash.is_erased(slot)? {
                return Ok(false);
            }
        }
        if unsafe {
            core::slice::from_raw_parts(layout::IMAGES_BASE as *const u8, layout::IMAGES_BYTES)
        }
        .iter()
        .any(|byte| *byte != 0xff)
        {
            return Ok(false);
        }
        #[cfg(feature = "engine-jcvm")]
        for bank in 0..2 {
            let heap = crate::jcvm::Heaps::region(bank)?;
            for slot in 0..heap.slot_count() {
                if !heap.is_erased(slot)? {
                    return Ok(false);
                }
            }
            if heap.monotonic_generation()? != 0 || heap.nonce_generation()? != 0 {
                return Ok(false);
            }
        }
        Ok(
            Self::word_counter(layout::MONOTONIC_BASE, layout::MONOTONIC_BYTES)? == 0
                && Self::word_counter(layout::NONCES_BASE, layout::NONCES_BYTES)? == 0,
        )
    }

    pub(crate) fn ownership_marker() -> u32 {
        unsafe { read(KEYS_BASE + OWNERSHIP_MARKER_OFFSET) }
    }

    pub(crate) fn program_ownership_marker() -> Result<()> {
        Self::program_region(
            KEYS_BASE,
            KEYS_BYTES,
            OWNERSHIP_MARKER_OFFSET,
            &PROGRAMMED_OWNERSHIP_MARKER.to_le_bytes(),
        )
    }

    fn ready() -> Result<()> {
        let nvmc = unsafe { &*pac::NVMC::ptr() };
        let start = now();
        while nvmc.ready.read().ready().is_busy() {
            if now().wrapping_sub(start) > 1_000_000 {
                return Err(Error::Native);
            }
        }
        Ok(())
    }

    fn read_region(base: usize, size: usize, offset: usize, output: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(output.len()).ok_or(Error::Bounds)?;
        if end > size {
            return Err(Error::Bounds);
        }
        output.copy_from_slice(unsafe {
            core::slice::from_raw_parts((base + offset) as *const u8, output.len())
        });
        Ok(())
    }

    pub(crate) fn erase_region(base: usize, size: usize) -> Result<()> {
        if !size.is_multiple_of(4096) {
            return Err(Error::Bounds);
        }
        let nvmc = unsafe { &*pac::NVMC::ptr() };
        nvmc.config.write(|w| w.wen().een());
        let result = (|| {
            for page in (base..base + size).step_by(4096) {
                nvmc.erasepage()
                    .write(|w| unsafe { w.erasepage().bits(page as u32) });
                Self::ready()?;
                feed();
            }
            Ok(())
        })();
        nvmc.config.write(|w| w.wen().ren());
        result
    }

    fn program_region(base: usize, size: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        if offset.checked_add(bytes.len()).is_none_or(|end| end > size) {
            return Err(Error::Bounds);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let nvmc = unsafe { &*pac::NVMC::ptr() };
        nvmc.config.write(|w| w.wen().wen());
        let result = (|| {
            let end = offset + bytes.len();
            for pos in ((offset & !3)..((end + 3) & !3)).step_by(4) {
                let current = unsafe { read(base + pos) };
                let mut word = current.to_le_bytes();
                for (index, byte) in word.iter_mut().enumerate() {
                    let location = pos + index;
                    if location >= offset && location < end {
                        let new = bytes[location - offset];
                        if *byte & new != new {
                            return Err(Error::Storage);
                        }
                        *byte = new;
                    }
                }
                let word = u32::from_le_bytes(word);
                if word == current {
                    continue;
                }
                unsafe { write(base + pos, word) }
                Self::ready()?;
                feed();
            }
            Ok(())
        })();
        nvmc.config.write(|w| w.wen().ren());
        result
    }

    const IMAGE_SLOT_BYTES: usize = if cfg!(feature = "engine-jcvm") {
        64 * 1024
    } else {
        16 * 1024
    };
    const IMAGE_SLOTS: usize = layout::IMAGES_BYTES / Self::IMAGE_SLOT_BYTES;

    fn image_base(index: usize) -> Result<usize> {
        if index >= Self::IMAGE_SLOTS {
            return Err(Error::Bounds);
        }
        Ok(layout::IMAGES_BASE + index * Self::IMAGE_SLOT_BYTES)
    }

    fn word_counter(base: usize, capacity: usize) -> Result<u64> {
        decode_program_once_words(unsafe {
            core::slice::from_raw_parts(base as *const u8, capacity)
        })
    }

    fn advance_word_counter(base: usize, capacity: usize, generation: u64) -> Result<()> {
        let counter = unsafe { core::slice::from_raw_parts(base as *const u8, capacity) };
        let word_offset = next_program_once_word(counter, generation)?;
        let address = base + word_offset;
        if unsafe { read(address) } != u32::MAX {
            return Err(Error::Storage);
        }
        let nvmc = unsafe { &*pac::NVMC::ptr() };
        nvmc.config.write(|w| w.wen().wen());
        unsafe { write(address, 0) };
        let result = Self::ready();
        nvmc.config.write(|w| w.wen().ren());
        result?;
        if unsafe { read(address) } != 0 {
            return Err(Error::Storage);
        }
        Ok(())
    }
}

pub(crate) struct StagingNvm {
    bank: Option<usize>,
    next_bank: usize,
}

impl StagingNvm {
    const BASE: usize = layout::STAGING_BASE;
    const BANK_BYTES: usize = if cfg!(feature = "engine-jcvm") {
        64 * 1024
    } else {
        16 * 1024
    };
    const BANKS: usize = layout::STAGING_BYTES / Self::BANK_BYTES;

    pub(crate) const fn new() -> Self {
        Self {
            bank: None,
            next_bank: 0,
        }
    }

    fn bank_base(&self) -> Result<usize> {
        self.bank
            .map(|bank| Self::BASE + bank * Self::BANK_BYTES)
            .ok_or(Error::Storage)
    }

    fn bank_is_erased(bank: usize) -> bool {
        unsafe {
            core::slice::from_raw_parts(
                (Self::BASE + bank * Self::BANK_BYTES) as *const u8,
                Self::BANK_BYTES,
            )
        }
        .iter()
        .all(|byte| *byte == 0xff)
    }
}

impl StagingFlash for StagingNvm {
    fn mapped(&self, offset: usize, length: usize) -> Result<Option<&[u8]>> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > Self::BANK_BYTES)
        {
            return Err(Error::Bounds);
        }
        let base = self.bank_base()?;
        // This bank is exclusively owned by staging. Mutations require &mut self,
        // and registry/heap writes use disjoint flash regions.
        Ok(Some(unsafe {
            core::slice::from_raw_parts((base + offset) as *const u8, length)
        }))
    }

    fn capacity(&self) -> usize {
        Self::BANK_BYTES
    }

    fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        Nvm::read_region(self.bank_base()?, Self::BANK_BYTES, offset, output)
    }

    fn erase(&mut self) -> Result<()> {
        let selected = (0..Self::BANKS)
            .map(|offset| {
                let bank = self.next_bank + offset;
                if bank < Self::BANKS {
                    bank
                } else {
                    bank - Self::BANKS
                }
            })
            .find(|bank| Self::bank_is_erased(*bank))
            .unwrap_or(self.next_bank);
        let base = Self::BASE + selected * Self::BANK_BYTES;
        if !Self::bank_is_erased(selected) {
            Nvm::erase_region(base, Self::BANK_BYTES)?;
        }
        self.bank = Some(selected);
        self.next_bank = if selected + 1 == Self::BANKS {
            0
        } else {
            selected + 1
        };
        Ok(())
    }

    fn program(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        Nvm::program_region(self.bank_base()?, Self::BANK_BYTES, offset, bytes)
    }
}

pub(crate) struct NvmImageReader;

impl microcard_core::image_store::ImageReader for NvmImageReader {
    fn slot_count(&self) -> usize {
        Nvm::IMAGE_SLOTS
    }

    fn slot_size(&self) -> usize {
        Nvm::IMAGE_SLOT_BYTES
    }

    type Image<'a> = &'a [u8];

    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        let base = Nvm::image_base(index)?;
        if range.start > range.end || range.end > Nvm::IMAGE_SLOT_BYTES {
            return Err(Error::Bounds);
        }
        // MC04 retains this read-only handle while journal writes use disjoint flash pages.
        Ok(unsafe { core::slice::from_raw_parts((base + range.start) as *const u8, range.len()) })
    }
}

impl microcard_core::image_store::ImageReader for Nvm {
    fn slot_count(&self) -> usize {
        Nvm::IMAGE_SLOTS
    }

    fn slot_size(&self) -> usize {
        Nvm::IMAGE_SLOT_BYTES
    }

    type Image<'a> = &'a [u8];

    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        NvmImageReader.read_range(index, range)
    }
}

impl microcard_core::image_store::ImageFlash for Nvm {
    type Reader = NvmImageReader;

    fn image_reader(&self) -> Result<Self::Reader> {
        Ok(NvmImageReader)
    }

    fn erase(&mut self, index: usize) -> Result<()> {
        Nvm::erase_region(Self::image_base(index)?, Self::IMAGE_SLOT_BYTES)
    }

    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Nvm::program_region(
            Self::image_base(index)?,
            Self::IMAGE_SLOT_BYTES,
            offset,
            bytes,
        )
    }
}

impl Flash for Nvm {
    fn slot_count(&self) -> usize {
        self.count
    }

    fn slot_size(&self) -> usize {
        self.size
    }

    fn monotonic_capacity(&self) -> u64 {
        (Self::COUNTER_BYTES / 4) as u64
    }

    fn monotonic_generation(&self) -> Result<u64> {
        Self::word_counter(self.monotonic, Self::COUNTER_BYTES)
    }

    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        Self::advance_word_counter(self.monotonic, Self::COUNTER_BYTES, generation)
    }

    fn nonce_capacity(&self) -> u64 {
        (Self::COUNTER_BYTES / 4) as u64
    }

    fn nonce_generation(&self) -> Result<u64> {
        Self::word_counter(self.nonces, Self::COUNTER_BYTES)
    }

    fn reserve_nonce(&mut self) -> Result<u64> {
        let next = self
            .nonce_generation()?
            .checked_add(1)
            .ok_or(Error::Quota)?;
        Self::advance_word_counter(self.nonces, Self::COUNTER_BYTES, next)?;
        Ok(next)
    }

    fn is_erased(&self, slot: usize) -> Result<bool> {
        Ok(
            unsafe { core::slice::from_raw_parts(self.base(slot)? as *const u8, self.size) }
                .iter()
                .all(|byte| *byte == 0xff),
        )
    }

    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()> {
        Self::read_region(self.base(slot)?, self.size, offset, output)
    }

    fn erase(&mut self, slot: usize) -> Result<()> {
        Self::erase_region(self.base(slot)?, self.size)
    }

    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Self::program_region(self.base(slot)?, self.size, offset, bytes)
    }
}
