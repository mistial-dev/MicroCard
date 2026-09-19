//! Immutable image slots. Only an authenticated metadata commit activates a descriptor.
use crate::{crypto::CryptoProvider, Error, Result};
#[cfg(feature = "jcvm")]
use alloc::{rc::Rc, vec::Vec};
#[cfg(feature = "jcvm")]
use core::cell::{Cell, RefCell};
use core::ops::Range;

/// A stable set of independently erasable, memory-mapped slots owned by the image store.
/// Reads must reflect completed writes; programming only clears bits and reports failure.
pub trait ImageFlash {
    fn slot_count(&self) -> usize;
    fn slot_size(&self) -> usize;
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T>;
    fn with_range<T>(
        &self,
        index: usize,
        range: Range<usize>,
        read: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        self.with_slot(index, |bytes| read(bytes.get(range).ok_or(Error::Bounds)?))
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
    impl ImageFlash for Memory {
        fn slot_count(&self) -> usize {
            self.slots.len()
        }
        fn slot_size(&self) -> usize {
            32
        }
        fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
            read(self.slots.get(index).ok_or(Error::Bounds)?)
        }
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
    fn pinned_code_blocks_reclamation_and_overlapping_writes_and_checks_each_read() {
        let mut images = Images::new(Memory {
            slots: [[255; 32]; 2],
            remaining: None,
        })
        .unwrap();
        let first = images.stage(b"first", &[], &mut SoftwareCrypto).unwrap();
        let pin = images.pin(&first, 1..4, &mut SoftwareCrypto).unwrap();
        let second = images.stage(b"second", &[], &mut SoftwareCrypto).unwrap();
        assert_ne!(first.slot, second.slot);
        assert_eq!(
            images.stage(b"third", &[second], &mut SoftwareCrypto),
            Err(Error::Quota)
        );
        pin.with_bytes(&mut SoftwareCrypto, |bytes, provider| {
            assert_eq!(bytes, b"irs");
            assert_eq!(images.stage(b"third", &[], provider), Err(Error::Busy));
            assert_eq!(bytes, b"irs");
            Ok(())
        })
        .unwrap();
        // Model a storage fault outside the authorized writer, not a new activation.
        images.shared.flash.borrow_mut().slots[first.slot as usize][0] ^= 1;
        assert_eq!(
            pin.with_bytes(&mut SoftwareCrypto, |_, _| panic!("damaged code executed")),
            Err::<(), _>(Error::Authentication)
        );
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
        self.images
            .with_verified_image(&self.descriptor, provider, |bytes, provider| {
                read(
                    bytes.get(self.range.clone()).ok_or(Error::Bounds)?,
                    provider,
                )
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

    /// Authenticate before retaining a range. The range normally excludes the package
    /// envelope; every subsequent read still authenticates the complete descriptor.
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
        self.validate(descriptor)?;
        self.with_flash(|flash| {
            flash.with_range(
                usize::from(descriptor.slot),
                0..descriptor.length as usize,
                |bytes| {
                    if provider.sha256(bytes)? != descriptor.digest {
                        return Err(Error::Authentication);
                    }
                    read(bytes, provider)
                },
            )
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
        if usize::from(descriptor.slot) >= self.slot_count
            || descriptor.length == 0
            || descriptor.length as usize > self.slot_size
        {
            return Err(Error::Bounds);
        }
        Ok(())
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

impl<F: ImageFlash> ImageFlash for &mut F {
    fn slot_count(&self) -> usize {
        F::slot_count(self)
    }
    fn slot_size(&self) -> usize {
        F::slot_size(self)
    }
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        F::with_slot(self, index, read)
    }
    fn with_range<T>(
        &self,
        index: usize,
        range: Range<usize>,
        read: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        F::with_range(self, index, range, read)
    }
    fn erase(&mut self, index: usize) -> Result<()> {
        F::erase(self, index)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        F::program(self, index, offset, bytes)
    }
}
