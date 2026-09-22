//! Shared real-applet fixtures for registry and transport lifecycle tests.
use crate::{
    crypto::CryptoProvider,
    hal::Entropy,
    jcvm_storage::HeapBanks,
    journal::{Flash, MemoryFlash},
    Error, Result,
};
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

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
    fn slot_size(&self, bank: u8) -> Result<usize> {
        Ok(self.banks.get(bank as usize).ok_or(Error::Bounds)?.borrow().slot_size())
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

pub(crate) fn load_file() -> Vec<u8> {
    include_bytes!("../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb")
        .to_vec()
}

pub(crate) struct Scratch(pub Vec<u8>);
impl crate::hal::StagingFlash for Scratch {
    fn mapped(&self, at: usize, length: usize) -> Result<Option<&[u8]>> {
        Ok(Some(self.0.get(at..at.checked_add(length).ok_or(Error::Bounds)?).ok_or(Error::Bounds)?))
    }
    fn capacity(&self) -> usize { self.0.len() }
    fn read(&self, at: usize, out: &mut [u8]) -> Result<()> {
        out.copy_from_slice(self.0.get(at..at.checked_add(out.len()).ok_or(Error::Bounds)?).ok_or(Error::Bounds)?); Ok(())
    }
    fn erase(&mut self) -> Result<()> { self.0.fill(0xff); Ok(()) }
    fn program(&mut self, at: usize, bytes: &[u8]) -> Result<()> {
        let out = self.0.get_mut(at..at.checked_add(bytes.len()).ok_or(Error::Bounds)?).ok_or(Error::Bounds)?;
        if out.iter().zip(bytes).any(|(old, new)| old & new != *new) { return Err(Error::Storage); }
        out.copy_from_slice(bytes); Ok(())
    }
}
