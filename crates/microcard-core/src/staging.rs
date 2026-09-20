//! Bounded upload staging with volatile and flash-backed implementations.

pub const MAX_PACKAGE_BYTES: usize = 16 * 1024;

use crate::{Error, Result, hal::StagingFlash};
use alloc::vec::Vec;

pub trait PackageStaging {
    /// Durable bytes are addressed by authenticated registry metadata, not upload length.
    fn persistent_capacity(&self) -> usize { 0 }
    fn mapped_persistent(&self, _offset: usize, _length: usize) -> Result<Option<&[u8]>> { Ok(None) }
    fn read_persistent(&self, _offset: usize, _output: &mut [u8]) -> Result<()> { Err(Error::Unsupported) }
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn as_slice(&self) -> Option<&[u8]>;
    fn read_all(&self) -> Result<Vec<u8>>;
    fn append(&mut self, bytes: &[u8]) -> Result<()>;
    fn matches(&self, offset: usize, bytes: &[u8]) -> Result<bool>;
    fn take(&mut self) -> Result<Vec<u8>>;
    fn restore(&mut self, bytes: Vec<u8>) -> Result<()>;
    fn reset(&mut self);
}

pub type RamStaging = BoundedRamStaging<MAX_PACKAGE_BYTES>;
pub type FlashStaging<S> = BoundedFlashStaging<S, MAX_PACKAGE_BYTES>;

#[derive(Default)]
pub struct BoundedRamStaging<const MAX: usize> {
    pub(crate) bytes: Vec<u8>,
}

impl<const MAX: usize> PackageStaging for BoundedRamStaging<MAX> {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(&self.bytes)
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.bytes.len())
            .map_err(|_| Error::Quota)?;
        bytes.extend_from_slice(&self.bytes);
        Ok(bytes)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::Quota)?;
        if end > MAX {
            return Err(Error::Quota);
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Quota)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn matches(&self, offset: usize, bytes: &[u8]) -> Result<bool> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        Ok(end <= self.bytes.len() && self.bytes[offset..end] == *bytes)
    }

    fn take(&mut self) -> Result<Vec<u8>> {
        Ok(core::mem::take(&mut self.bytes))
    }

    fn restore(&mut self, bytes: Vec<u8>) -> Result<()> {
        if !self.bytes.is_empty() || bytes.len() > MAX {
            return Err(Error::Storage);
        }
        self.bytes = bytes;
        Ok(())
    }

    fn reset(&mut self) {
        self.bytes.clear();
    }
}

pub struct BoundedFlashStaging<S, const MAX: usize> {
    flash: S,
    len: usize,
    prepared: bool,
}

impl<S, const MAX: usize> BoundedFlashStaging<S, MAX> {
    pub const fn new(flash: S) -> Self {
        Self {
            flash,
            len: 0,
            prepared: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.flash
    }
}

impl<S: StagingFlash, const MAX: usize> PackageStaging for BoundedFlashStaging<S, MAX> {
    fn persistent_capacity(&self) -> usize { self.flash.capacity() }
    fn mapped_persistent(&self, offset: usize, length: usize) -> Result<Option<&[u8]>> {
        if offset.checked_add(length).is_none_or(|end| end > self.flash.capacity()) {
            return Err(Error::Bounds);
        }
        self.flash.mapped(offset, length)
    }
    fn read_persistent(&self, offset: usize, output: &mut [u8]) -> Result<()> { self.flash.read(offset, output) }
    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> Option<&[u8]> {
        None
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.len)
            .map_err(|_| Error::Quota)?;
        bytes.resize(self.len, 0);
        self.flash.read(0, &mut bytes)?;
        Ok(bytes)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.len.checked_add(bytes.len()).ok_or(Error::Quota)?;
        if end > MAX || end > self.flash.capacity() {
            return Err(Error::Quota);
        }
        if !self.prepared {
            self.flash.erase()?;
            self.prepared = true;
        }
        self.flash.program(self.len, bytes)?;
        self.len = end;
        Ok(())
    }

    fn matches(&self, offset: usize, bytes: &[u8]) -> Result<bool> {
        let end = offset.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        if end > self.len {
            return Ok(false);
        }
        let mut cursor = 0usize;
        let mut scratch = [0u8; 64];
        while cursor < bytes.len() {
            let count = (bytes.len() - cursor).min(scratch.len());
            self.flash.read(offset + cursor, &mut scratch[..count])?;
            if scratch[..count] != bytes[cursor..cursor + count] {
                return Ok(false);
            }
            cursor += count;
        }
        Ok(true)
    }

    fn take(&mut self) -> Result<Vec<u8>> {
        self.read_all()
    }

    fn restore(&mut self, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() != self.len || !self.matches(0, &bytes)? {
            return Err(Error::Storage);
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.len = 0;
        self.prepared = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryStaging {
        bytes: [u8; 32],
        erase_count: usize,
        fail_after: Option<usize>,
    }

    impl MemoryStaging {
        fn new() -> Self {
            Self {
                bytes: [0; 32],
                erase_count: 0,
                fail_after: None,
            }
        }
    }

    impl StagingFlash for MemoryStaging {
        fn mapped(&self, offset: usize, length: usize) -> Result<Option<&[u8]>> {
            Ok(Some(self.bytes.get(offset..offset.checked_add(length).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?))
        }
        fn capacity(&self) -> usize {
            self.bytes.len()
        }

        fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
            let end = offset.checked_add(output.len()).ok_or(Error::Bounds)?;
            let input = self.bytes.get(offset..end).ok_or(Error::Bounds)?;
            output.copy_from_slice(input);
            Ok(())
        }

        fn erase(&mut self) -> Result<()> {
            self.bytes.fill(0xff);
            self.erase_count += 1;
            Ok(())
        }

        fn program(&mut self, offset: usize, input: &[u8]) -> Result<()> {
            let end = offset.checked_add(input.len()).ok_or(Error::Bounds)?;
            let output = self.bytes.get_mut(offset..end).ok_or(Error::Bounds)?;
            if output.iter().zip(input).any(|(old, new)| old & new != *new) {
                return Err(Error::Storage);
            }
            for (old, new) in output.iter_mut().zip(input) {
                if let Some(left) = self.fail_after.as_mut() {
                    if *left == 0 {
                        return Err(Error::Native);
                    }
                    *left -= 1;
                }
                *old = *new;
            }
            Ok(())
        }
    }

    #[test]
    fn flash_staging_erases_once_per_upload_and_restores_without_writing() {
        let mut staging = FlashStaging::new(MemoryStaging::new());
        staging.append(&[1, 2]).unwrap();
        staging.append(&[3, 4]).unwrap();
        assert_eq!(staging.flash.erase_count, 1);
        assert!(staging.matches(1, &[2, 3]).unwrap());
        let bytes = staging.take().unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
        let mapped = staging.mapped_persistent(0, 4).unwrap().unwrap();
        assert_eq!(mapped, bytes);
        assert_eq!(mapped.as_ptr(), staging.flash.bytes.as_ptr());
        assert!(matches!(staging.mapped_persistent(usize::MAX, 1), Err(Error::Bounds)));
        assert!(matches!(staging.mapped_persistent(31, 2), Err(Error::Bounds)));
        staging.restore(bytes).unwrap();
        assert_eq!(staging.flash.erase_count, 1);
        staging.reset();
        staging.append(&[5]).unwrap();
        assert_eq!(staging.flash.erase_count, 2);
    }

    #[test]
    fn partial_program_retry_reuses_the_same_erased_bank() {
        let mut staging = FlashStaging::new(MemoryStaging::new());
        staging.flash.fail_after = Some(2);
        assert_eq!(staging.append(&[1, 2, 3, 4]), Err(Error::Native));
        assert_eq!(staging.len(), 0);
        assert_eq!(staging.flash.erase_count, 1);

        staging.flash.fail_after = None;
        staging.append(&[1, 2, 3, 4]).unwrap();
        assert_eq!(staging.read_all().unwrap(), [1, 2, 3, 4]);
        assert_eq!(staging.flash.erase_count, 1);
    }
}
