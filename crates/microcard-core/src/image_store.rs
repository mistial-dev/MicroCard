//! Immutable image slots. Only an authenticated metadata commit activates a descriptor.
use crate::{crypto::CryptoProvider, Error, Result};

/// A stable set of independently erasable, memory-mapped slots owned by the image store.
/// Reads must reflect completed writes; programming only clears bits and reports failure.
pub trait ImageFlash {
    fn slot_count(&self) -> usize;
    fn slot_size(&self) -> usize;
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T>;
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
        let baseline = images.into_flash();
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
            let mut flash = images.into_flash();
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
        let baseline = images.into_flash();
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
            assert_eq!(images.into_flash().slots, baseline.slots);
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
                assert_eq!(images.into_flash().slots, baseline.slots);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub slot: u8,
    pub length: u32,
    pub digest: [u8; 32],
}

pub struct Images<F> {
    flash: F,
}

impl<F: ImageFlash> Images<F> {
    pub fn new(flash: F) -> Result<Self> {
        if !(2..=64).contains(&flash.slot_count()) {
            return Err(Error::Storage);
        }
        Ok(Self { flash })
    }

    /// Borrow verified image bytes for the duration of `read`, without allocating.
    pub fn with_image<T>(
        &self,
        descriptor: &Descriptor,
        provider: &mut impl CryptoProvider,
        read: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        self.validate(descriptor)?;
        self.flash.with_slot(usize::from(descriptor.slot), |slot| {
            let bytes = slot
                .get(..descriptor.length as usize)
                .ok_or(Error::Bounds)?;
            if provider.sha256(bytes)? != descriptor.digest {
                return Err(Error::Authentication);
            }
            read(bytes)
        })
    }

    fn validate(&self, descriptor: &Descriptor) -> Result<()> {
        if usize::from(descriptor.slot) >= self.flash.slot_count()
            || descriptor.length == 0
            || descriptor.length as usize > self.flash.slot_size()
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
        let length = u32::try_from(image.len()).map_err(|_| Error::Quota)?;
        if image.is_empty() {
            return Err(Error::Format);
        }
        let mut occupied = 0u64;
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
                return Ok(*descriptor);
            }
        }
        let mut candidate = None;
        for slot in 0..self.flash.slot_count() {
            if occupied & (1u64 << slot) == 0 && self.flash.slot_size() >= image.len() {
                candidate = Some(slot);
                break;
            }
        }
        let slot = candidate.ok_or(Error::Quota)?;
        self.flash.erase(slot)?;
        for (chunk, bytes) in image.chunks(256).enumerate() {
            self.flash.program(slot, chunk * 256, bytes)?;
        }
        let descriptor = Descriptor {
            slot: slot as u8,
            length,
            digest,
        };
        self.with_image(&descriptor, provider, |_| Ok(()))?;
        Ok(descriptor)
    }

    pub fn into_flash(self) -> F {
        self.flash
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
    fn erase(&mut self, index: usize) -> Result<()> {
        F::erase(self, index)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        F::program(self, index, offset, bytes)
    }
}
