//! Shared real-applet fixtures for registry and transport lifecycle tests.
use crate::{
    crypto::{self, CryptoProvider},
    envelope,
    hal::Entropy,
    jcvm_package,
    jcvm_storage::HeapBanks,
    journal::{Flash, MemoryFlash},
    Error, Result,
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use microcard_engine_jcvm::{applet::Sizes, cap::LoadFile};

pub(crate) struct Provider;
impl CryptoProvider for Provider {}
impl Entropy for Provider {
    fn fill_entropy(&mut self, bytes: &mut [u8]) -> Result<()> {
        bytes.fill(7);
        Ok(())
    }
}

pub(crate) struct Bank(Rc<RefCell<MemoryFlash>>);
impl Flash for Bank {
    fn slot_size(&self) -> usize {
        self.0.borrow().slot_size()
    }
    fn monotonic_capacity(&self) -> u64 {
        self.0.borrow().monotonic_capacity()
    }
    fn monotonic_generation(&self) -> Result<u64> {
        self.0.borrow().monotonic_generation()
    }
    fn advance_monotonic(&mut self, value: u64) -> Result<()> {
        self.0.borrow_mut().advance_monotonic(value)
    }
    fn nonce_generation(&self) -> Result<u64> {
        self.0.borrow().nonce_generation()
    }
    fn reserve_nonce(&mut self) -> Result<u64> {
        self.0.borrow_mut().reserve_nonce()
    }
    fn is_erased(&self, slot: usize) -> Result<bool> {
        self.0.borrow().is_erased(slot)
    }
    fn read(&self, slot: usize, offset: usize, bytes: &mut [u8]) -> Result<()> {
        self.0.borrow().read(slot, offset, bytes)
    }
    fn erase(&mut self, slot: usize) -> Result<()> {
        self.0.borrow_mut().erase(slot)
    }
    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        self.0.borrow_mut().program(slot, offset, bytes)
    }
}
pub(crate) struct Heaps {
    pub(crate) banks: [Rc<RefCell<MemoryFlash>>; 2],
    pub(crate) preparations: [usize; 2],
    pub(crate) fail_write: Option<usize>,
}
impl HeapBanks for Heaps {
    type Bank = Bank;
    fn bank_count(&self) -> usize {
        self.banks.len()
    }
    fn open(&mut self, bank: u8) -> Result<Bank> {
        Ok(Bank(Rc::clone(
            self.banks.get(usize::from(bank)).ok_or(Error::Bounds)?,
        )))
    }
    fn prepare(&mut self, bank: u8) -> Result<Bank> {
        let cell = self.banks.get(usize::from(bank)).ok_or(Error::Bounds)?;
        self.preparations[usize::from(bank)] += 1;
        let mut flash = MemoryFlash::new(65536);
        flash.fail_after = self.fail_write;
        *cell.borrow_mut() = flash;
        self.open(bank)
    }
}

pub(crate) fn signed(version: u32, incarnation: u8, private: u8) -> Vec<u8> {
    let image =
        include_bytes!("../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb");
    let header = LoadFile::parse(image).unwrap().header().unwrap();
    let manifest = jcvm_package::Manifest {
        domain: &crate::globalplatform::ISD_AID,
        incarnation: [incarnation; 16],
        package: header.package_aid,
        package_version: [header.package_major, header.package_minor],
        version,
        sizes: Sizes {
            heap_bytes: 65536,
            frame_words: 8192,
            ..Sizes::default()
        },
    }
    .encode()
    .unwrap();
    let key = crypto::p256_public_key(&[private; 32]).unwrap();
    let mut raw = envelope::signing_prefix_bounded(
        &manifest,
        image.len(),
        &crypto::sha256(image),
        &key,
        jcvm_package::MAX_PACKAGE_BYTES,
    )
    .unwrap();
    raw.extend(crypto::p256_ecdsa_sign_package(&[private; 32], &raw).unwrap());
    raw.extend(image);
    raw
}
