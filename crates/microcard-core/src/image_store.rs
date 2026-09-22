//! Immutable image slots. Only an authenticated metadata commit activates a descriptor.
use crate::{crypto::CryptoProvider, Error, Result};
#[cfg(feature = "jcvm")]
use alloc::{rc::Rc, vec::Vec};
#[cfg(feature = "jcvm")]
use core::cell::{Cell, RefCell};
use core::ops::Range;

/// Read-only image access that can outlive the handle used for journal writes.
/// Implementations must keep returned mappings stable for the reader's lifetime.
pub trait ImageReader {
    /// Scoped image storage: a mapped slice, owned file buffer, or shared read guard.
    type Image<'a>: core::ops::Deref<Target = [u8]> where Self: 'a;
    /// Raw bytes only. Executable consumers must authenticate the image descriptor.
    fn read_range(&self, index: usize, range: Range<usize>) -> Result<Self::Image<'_>>;
    fn slot_count(&self) -> usize;
    fn slot_size(&self) -> usize;
}

/// A stable set of independently erasable, memory-mapped slots owned by the image store.
/// Reads must reflect completed writes; programming only clears bits and reports failure.
pub trait ImageFlash: ImageReader {
    /// A read-only handle independent from journal ownership. MC04 keeps this handle while
    /// a native checkpoint writes the disjoint journal region.
    type Reader: ImageReader;
    fn image_reader(&self) -> Result<Self::Reader>;
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        self.with_range(index, 0..self.slot_size(), read)
    }
    fn with_range<T>(
        &self,
        index: usize,
        range: Range<usize>,
        read: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let bytes = self.read_range(index, range)?;
        read(&bytes)
    }
    fn erase(&mut self, index: usize) -> Result<()>;
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()>;
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::SoftwareCrypto;

    #[derive(Clone)]
    struct Memory {
        slots: [[u8; 32]; 2],
        remaining: Option<usize>,
    }
    impl Memory {
        fn change(remaining: &mut Option<usize>, byte: &mut u8, value: u8) -> Result<()> {
            if let Some(left) = remaining {
                if *left == 0 {
                    return Err(Error::Storage);
                }
                *left -= 1;
            }
            *byte = value;
            Ok(())
        }
    }
    impl ImageReader for Memory {
        fn slot_count(&self) -> usize {
            self.slots.len()
        }
        fn slot_size(&self) -> usize {
            32
        }
        type Image<'a> = &'a [u8];
        fn read_range(&self, index: usize, range: Range<usize>) -> Result<Self::Image<'_>> {
            self.slots.get(index).and_then(|slot| slot.get(range)).ok_or(Error::Bounds)
        }
    }
    impl ImageFlash for Memory {
        type Reader = Self;
        fn image_reader(&self) -> Result<Self::Reader> { Ok(self.clone()) }
        fn erase(&mut self, index: usize) -> Result<()> {
            for byte in &mut self.slots[index] {
                Self::change(&mut self.remaining, byte, 255)?;
            }
            Ok(())
        }
        fn program(&mut self, index: usize, offset: usize, input: &[u8]) -> Result<()> {
            for (byte, value) in self.slots[index][offset..offset + input.len()]
                .iter_mut()
                .zip(input)
            {
                if *byte & value != *value {
                    return Err(Error::Storage);
                }
                Self::change(&mut self.remaining, byte, *value)?;
            }
            Ok(())
        }
    }

    #[test]
    fn interrupted_staging_preserves_committed_images_and_reclaims_only_orphans() {
        let mut images = Images::new(Memory {
            slots: [[255; 32]; 2],
            remaining: None,
        })
        .unwrap();
        let committed = images.stage(b"old", &[], &mut SoftwareCrypto).unwrap();
        let baseline = images.into_flash().unwrap();
        // Multiple scoped views borrow their slots rather than copying image bytes.
        let first = baseline.read_range(0, 0..3).unwrap();
        let second = baseline.read_range(1, 4..8).unwrap();
        assert_eq!(first.as_ptr(), baseline.slots[0].as_ptr());
        assert_eq!(second.as_ptr(), baseline.slots[1][4..].as_ptr());
        assert_eq!(first, b"old");
        let verified = committed.read_verified(&baseline, &mut SoftwareCrypto).unwrap();
        assert_eq!(verified.as_ptr(), first.as_ptr());
        for invalid in [Descriptor { length: 0, ..committed }, Descriptor { slot: 2, ..committed }] {
            assert_eq!(invalid.read_verified(&baseline, &mut SoftwareCrypto), Err(Error::Bounds));
        }
        let invalid = Descriptor { digest: [0; 32], ..committed };
        assert_eq!(invalid.read_verified(&baseline, &mut SoftwareCrypto), Err(Error::Authentication));
        struct FailedHash;
        impl CryptoProvider for FailedHash {
            fn sha256_into(&mut self, _: &[u8], output: &mut [u8; 32]) -> Result<()> {
                output.fill(0);
                Err(Error::Native)
            }
        }
        assert_eq!(committed.read_verified(&baseline, &mut FailedHash), Err(Error::Native));
        assert_eq!(second, &[255; 4]);
        for (slot, start, end) in [(2, 0, 1), (0, 31, 33), (0, 5, 4)] {
            assert_eq!(baseline.read_range(slot, start..end), Err(Error::Bounds));
        }
        for interruption in 0..=38 {
            let mut flash = baseline.clone();
            flash.remaining = Some(interruption);
            let mut images = Images::new(flash).unwrap();
            let outcome = images.stage(b"update", &[committed], &mut SoftwareCrypto);
            assert_eq!(outcome.is_ok(), interruption == 38);
            assert_eq!(
                images.read(&committed, &mut SoftwareCrypto).unwrap(),
                b"old"
            );
            let mut flash = images.into_flash().unwrap();
            flash.remaining = None;
            // On reboot only authenticated committed metadata is authoritative.
            let mut images = Images::new(flash).unwrap();
            let next = images
                .stage(b"update", &[committed], &mut SoftwareCrypto)
                .unwrap();
            assert_eq!(images.read(&next, &mut SoftwareCrypto).unwrap(), b"update");
            assert_eq!(
                images.stage(b"third", &[committed, next], &mut SoftwareCrypto),
                Err(Error::Quota)
            );
            assert_eq!(
                images.stage(b"update", &[committed, next], &mut SoftwareCrypto),
                Ok(next)
            );
            let replacement = images
                .stage(b"third", &[next], &mut SoftwareCrypto)
                .unwrap();
            assert_eq!(replacement.slot, committed.slot);
            assert_eq!(images.read(&next, &mut SoftwareCrypto).unwrap(), b"update");
        }
        let mut damaged = baseline;
        damaged.slots[committed.slot as usize][0] ^= 1;
        let images = Images::new(damaged).unwrap();
        assert_eq!(
            images.read(&committed, &mut SoftwareCrypto),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn invalid_protection_and_hash_failures_do_not_authorize_activation() {
        struct FailingHash {
            calls: usize,
            fail_on: usize,
        }
        impl CryptoProvider for FailingHash {
            fn sha256_into(&mut self, input: &[u8], output: &mut [u8; 32]) -> Result<()> {
                self.calls += 1;
                if self.calls == self.fail_on {
                    return Err(Error::Native);
                }
                SoftwareCrypto.sha256_into(input, output)
            }
        }
        let mut images = Images::new(Memory {
            slots: [[255; 32]; 2],
            remaining: None,
        })
        .unwrap();
        let committed = images.stage(b"old", &[], &mut SoftwareCrypto).unwrap();
        let baseline = images.into_flash().unwrap();
        for descriptor in [
            Descriptor {
                slot: 2,
                ..committed
            },
            Descriptor {
                length: 0,
                ..committed
            },
            Descriptor {
                length: 33,
                ..committed
            },
        ] {
            let mut images = Images::new(baseline.clone()).unwrap();
            assert_eq!(
                images.stage(b"new", &[descriptor], &mut SoftwareCrypto),
                Err(Error::Bounds)
            );
            assert_eq!(images.into_flash().unwrap().slots, baseline.slots);
        }
        for fail_on in [1, 2] {
            let mut images = Images::new(baseline.clone()).unwrap();
            let mut provider = FailingHash { calls: 0, fail_on };
            assert_eq!(
                images.stage(b"new", &[committed], &mut provider),
                Err(Error::Native)
            );
            assert_eq!(
                provider.calls, fail_on,
                "provider failure must not retry in software"
            );
            assert_eq!(
                images.read(&committed, &mut SoftwareCrypto).unwrap(),
                b"old"
            );
            if fail_on == 1 {
                assert_eq!(images.into_flash().unwrap().slots, baseline.slots);
            }
        }
    }

    #[cfg(feature = "jcvm")]
    #[test]
    fn pinned_code_blocks_reclamation_and_reuses_its_verified_mapping() {
        struct CountingHash {
            calls: usize,
        }
        impl CryptoProvider for CountingHash {
            fn sha256_into(&mut self, input: &[u8], output: &mut [u8; 32]) -> Result<()> {
                self.calls += 1;
                SoftwareCrypto.sha256_into(input, output)
            }
        }
        let mut images = Images::new(Memory {
            slots: [[255; 32]; 2],
            remaining: None,
        })
        .unwrap();
        let mut provider = CountingHash { calls: 0 };
        let first = images.stage(b"first", &[], &mut provider).unwrap();
        let pin = images.pin(&first, 1..4, &mut provider).unwrap();
        let second = images.stage(b"second", &[], &mut SoftwareCrypto).unwrap();
        assert_ne!(first.slot, second.slot);
        assert_eq!(
            images.stage(b"third", &[second], &mut SoftwareCrypto),
            Err(Error::Quota)
        );
        pin.with_bytes(&mut provider, |bytes, provider| {
            assert_eq!(bytes, b"irs");
            assert_eq!(images.stage(b"third", &[], provider), Err(Error::Busy));
            assert_eq!(bytes, b"irs");
            Ok(())
        })
        .unwrap();
        let verified_calls = provider.calls;
        pin.with_bytes(&mut provider, |bytes, _| {
            assert_eq!(bytes, b"irs");
            Ok(())
        })
        .unwrap();
        assert_eq!(provider.calls, verified_calls, "a pinned image is hashed only when pinned");
        drop(pin);
        let replacement = images
            .stage(b"third", &[second], &mut SoftwareCrypto)
            .unwrap();
        assert_eq!(replacement.slot, first.slot);
        let pin = images.pin(&replacement, 0..5, &mut SoftwareCrypto).unwrap();
        assert!(matches!(images.into_flash(), Err(Error::Busy)));
        pin.with_bytes(&mut SoftwareCrypto, |bytes, _| {
            assert_eq!(bytes, b"third");
            Ok(())
        })
        .unwrap();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub slot: u8,
    pub length: u32,
    pub digest: [u8; 32],
}

impl Descriptor {
    fn validate(&self, slot_count: usize, slot_size: usize) -> Result<()> {
        if !(2..=64).contains(&slot_count) || usize::from(self.slot) >= slot_count
            || self.length == 0 || self.length as usize > slot_size {
            return Err(Error::Bounds);
        }
        Ok(())
    }

    /// Authenticate the complete descriptor before lending its scoped storage guard.
    /// The provider is released after verification so execution can use it independently.
    pub fn read_verified<'a, F: ImageReader, P: CryptoProvider>(
        &self, flash: &'a F, provider: &mut P,
    ) -> Result<F::Image<'a>> {
        self.validate(flash.slot_count(), flash.slot_size())?;
        let bytes = flash.read_range(usize::from(self.slot), 0..self.length as usize)?;
        if bytes.len() != self.length as usize { return Err(Error::Storage); }
        if provider.sha256(&bytes)? != self.digest { return Err(Error::Authentication); }
        Ok(bytes)
    }
}

#[cfg(feature = "jcvm")]
struct Shared<F> {
    flash: RefCell<F>,
    pins: [Cell<u16>; 64],
}

pub struct Images<F> {
    #[cfg(feature = "jcvm")]
    shared: Rc<Shared<F>>,
    #[cfg(not(feature = "jcvm"))]
    flash: F,
    slot_count: usize,
    slot_size: usize,
}

/// Code can be owned RAM or a checked borrow from immutable storage.
#[cfg(feature = "jcvm")]
pub trait CodeImage {
    fn with_bytes<P: CryptoProvider, T>(
        &self,
        provider: &mut P,
        read: impl FnOnce(&[u8], &mut P) -> Result<T>,
    ) -> Result<T>;
}
#[cfg(feature = "jcvm")]
impl CodeImage for Vec<u8> {
    fn with_bytes<P: CryptoProvider, T>(
        &self,
        provider: &mut P,
        read: impl FnOnce(&[u8], &mut P) -> Result<T>,
    ) -> Result<T> {
        read(self, provider)
    }
}

/// A retained image prevents reclamation, without retaining a copy of its code.
#[cfg(feature = "jcvm")]
pub struct PinnedImage<F> {
    images: Images<F>,
    descriptor: Descriptor,
    range: Range<usize>,
}
#[cfg(feature = "jcvm")]
impl<F: ImageFlash> CodeImage for PinnedImage<F> {
    fn with_bytes<P: CryptoProvider, T>(
        &self,
        provider: &mut P,
        read: impl FnOnce(&[u8], &mut P) -> Result<T>,
    ) -> Result<T> {
        self.images.with_flash(|flash| {
            let bytes = flash.read_range(usize::from(self.descriptor.slot), self.range.clone())?;
            if bytes.len() != self.range.len() {
                return Err(Error::Storage);
            }
            read(&bytes, provider)
        })
    }
}
#[cfg(feature = "jcvm")]
impl<F> Drop for PinnedImage<F> {
    fn drop(&mut self) {
        let pin = &self.images.shared.pins[usize::from(self.descriptor.slot)];
        pin.set(pin.get() - 1);
    }
}

impl<F: ImageFlash> Images<F> {
    pub fn new(flash: F) -> Result<Self> {
        let slot_count = flash.slot_count();
        let slot_size = flash.slot_size();
        if !(2..=64).contains(&slot_count) {
            return Err(Error::Storage);
        }
        Ok(Self {
            #[cfg(feature = "jcvm")]
            shared: Rc::new(Shared {
                flash: RefCell::new(flash),
                pins: core::array::from_fn(|_| Cell::new(0)),
            }),
            #[cfg(not(feature = "jcvm"))]
            flash,
            slot_count,
            slot_size,
        })
    }

    /// Authenticate before retaining a range. The pin prevents the verified slot from being
    /// erased or replaced, so subsequent mapped reads do not hash the complete image again.
    #[cfg(feature = "jcvm")]
    pub fn pin(
        &self,
        descriptor: &Descriptor,
        range: Range<usize>,
        provider: &mut impl CryptoProvider,
    ) -> Result<PinnedImage<F>> {
        self.with_verified_image(descriptor, provider, |bytes, _| {
            if range.is_empty() || bytes.get(range.clone()).is_none() {
                return Err(Error::Bounds);
            }
            let pin = &self.shared.pins[usize::from(descriptor.slot)];
            pin.set(pin.get().checked_add(1).ok_or(Error::Quota)?);
            Ok(PinnedImage {
                images: Self {
                    shared: Rc::clone(&self.shared),
                    slot_count: self.slot_count,
                    slot_size: self.slot_size,
                },
                descriptor: *descriptor,
                range,
            })
        })
    }

    /// Borrow verified bytes; memory-mapped backends need no image allocation.
    pub fn with_image<T>(
        &self,
        descriptor: &Descriptor,
        provider: &mut impl CryptoProvider,
        read: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        self.with_verified_image(descriptor, provider, |bytes, _| read(bytes))
    }

    /// Keep provider access inside the verified borrow for signature/engine checks.
    pub fn with_verified_image<P: CryptoProvider, T>(
        &self,
        descriptor: &Descriptor,
        provider: &mut P,
        read: impl FnOnce(&[u8], &mut P) -> Result<T>,
    ) -> Result<T> {
        self.with_flash(|flash| {
            let bytes = descriptor.read_verified(flash, provider)?;
            read(&bytes, provider)
        })
    }

    fn with_flash<T>(&self, read: impl FnOnce(&F) -> Result<T>) -> Result<T> {
        #[cfg(feature = "jcvm")]
        {
            read(&*self.shared.flash.try_borrow().map_err(|_| Error::Busy)?)
        }
        #[cfg(not(feature = "jcvm"))]
        {
            read(&self.flash)
        }
    }

    fn with_flash_mut<T>(&mut self, write: impl FnOnce(&mut F) -> Result<T>) -> Result<T> {
        #[cfg(feature = "jcvm")]
        {
            write(
                &mut *self
                    .shared
                    .flash
                    .try_borrow_mut()
                    .map_err(|_| Error::Busy)?,
            )
        }
        #[cfg(not(feature = "jcvm"))]
        {
            write(&mut self.flash)
        }
    }

    fn validate(&self, descriptor: &Descriptor) -> Result<()> {
        descriptor.validate(self.slot_count, self.slot_size)
    }

    #[cfg(test)]
    fn read(
        &self,
        descriptor: &Descriptor,
        provider: &mut impl CryptoProvider,
    ) -> Result<alloc::vec::Vec<u8>> {
        self.with_image(descriptor, provider, |bytes| Ok(bytes.to_vec()))
    }

    /// `protected` includes every descriptor reachable by committed or pending state.
    /// Keep the returned descriptor protected until activation commits or is abandoned.
    /// Unreferenced partial writes are reclaimable; this method never changes metadata.
    pub fn stage(
        &mut self,
        image: &[u8],
        protected: &[Descriptor],
        provider: &mut impl CryptoProvider,
    ) -> Result<Descriptor> {
        self.stage_with_cancel(image, protected, provider, &mut || false)
    }

    /// Cancellation can abandon an unreferenced candidate, never a protected image.
    pub fn stage_with_cancel(
        &mut self,
        image: &[u8],
        protected: &[Descriptor],
        provider: &mut impl CryptoProvider,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Descriptor> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        let length = u32::try_from(image.len()).map_err(|_| Error::Quota)?;
        if image.is_empty() {
            return Err(Error::Format);
        }
        let mut occupied = 0u64;
        #[cfg(feature = "jcvm")]
        for (slot, pins) in self.shared.pins.iter().enumerate() {
            if pins.get() != 0 {
                occupied |= 1u64 << slot;
            }
        }
        for descriptor in protected {
            self.validate(descriptor)?;
            occupied |= 1u64 << descriptor.slot;
        }
        let digest = provider.sha256(image)?;
        for descriptor in protected {
            if descriptor.length == length && descriptor.digest == digest {
                // Reuse only after verifying the physical bytes, not the cached hash.
                if self.with_image(descriptor, provider, |bytes| Ok(bytes != image))? {
                    return Err(Error::Authentication);
                }
                if cancel() {
                    return Err(Error::Cancelled);
                }
                return Ok(*descriptor);
            }
        }
        let mut candidate = None;
        for slot in 0..self.slot_count {
            if occupied & (1u64 << slot) == 0 && self.slot_size >= image.len() {
                candidate = Some(slot);
                break;
            }
        }
        let slot = candidate.ok_or(Error::Quota)?;
        if cancel() {
            return Err(Error::Cancelled);
        }
        self.with_flash_mut(|flash| flash.erase(slot))?;
        for (chunk, bytes) in image.chunks(256).enumerate() {
            if cancel() {
                return Err(Error::Cancelled);
            }
            self.with_flash_mut(|flash| flash.program(slot, chunk * 256, bytes))?;
        }
        let descriptor = Descriptor {
            slot: slot as u8,
            length,
            digest,
        };
        self.with_image(&descriptor, provider, |_| Ok(()))?;
        if cancel() {
            return Err(Error::Cancelled);
        }
        Ok(descriptor)
    }

    pub fn into_flash(self) -> Result<F> {
        #[cfg(feature = "jcvm")]
        {
            Rc::try_unwrap(self.shared)
                .map(|shared| shared.flash.into_inner())
                .map_err(|_| Error::Busy)
        }
        #[cfg(not(feature = "jcvm"))]
        {
            Ok(self.flash)
        }
    }
}

impl<F: ImageFlash> ImageReader for &mut F {
    fn slot_count(&self) -> usize {
        F::slot_count(self)
    }
    fn slot_size(&self) -> usize {
        F::slot_size(self)
    }
    type Image<'a> = F::Image<'a> where Self: 'a;
    fn read_range(&self, index: usize, range: Range<usize>) -> Result<Self::Image<'_>> {
        F::read_range(self, index, range)
    }
}
impl<F: ImageFlash> ImageFlash for &mut F {
    type Reader = F::Reader;
    fn image_reader(&self) -> Result<Self::Reader> { F::image_reader(self) }
    fn erase(&mut self, index: usize) -> Result<()> {
        F::erase(self, index)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        F::program(self, index, offset, bytes)
    }
}
