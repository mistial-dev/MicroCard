//! JCVM storage ownership. Only unreferenced heap banks may be reclaimed.
use super::{layout, Hardware, Nvm, StagingNvm};
use microcard_core::{
    hal::Entropy,
    image_store::Images,
    jcvm_card::{JcvmEngine, Storage},
    jcvm_registry::{Registry, Store},
    jcvm_storage::{heap_root, HeapBanks},
    journal::JournalKey,
    staging::BoundedFlashStaging,
    Error, Result,
};

pub(super) struct Heaps;
impl Heaps {
    pub(super) fn region(bank: u8) -> Result<Nvm> {
        let base = match bank {
            0 => layout::HEAP0_BASE,
            1 => layout::HEAP1_BASE,
            _ => return Err(Error::Bounds),
        };
        Ok(Nvm {
            slots: [base, base + 65536, 0],
            count: 2,
            size: 65536,
            monotonic: base + 2 * 65536,
            nonces: base + 2 * 65536 + 4096,
        })
    }
}
impl HeapBanks for Heaps {
    type Bank = Nvm;
    fn bank_count(&self) -> usize {
        2
    }
    fn slot_size(&self, bank: u8) -> Result<usize> { Ok(Self::region(bank)?.size) }
    fn open(&mut self, bank: u8) -> Result<Nvm> {
        Self::region(bank)
    }
    fn prepare(&mut self, bank: u8) -> Result<Nvm> {
        let region = Self::region(bank)?;
        Nvm::erase_region(region.slots[0], 2 * 65536 + 2 * 4096)?;
        Ok(region)
    }
}

type Staging = BoundedFlashStaging<StagingNvm, { microcard_core::jcvm_package::MAX_PACKAGE_BYTES }>;
pub(super) type BoardCard = JcvmEngine<Nvm, Nvm, Heaps, Hardware, Staging>;

pub(super) fn open(mut hardware: Hardware, key: JournalKey) -> Result<BoardCard> {
    let heap_key = heap_root(&mut hardware, &key)?;
    let mut incarnation = [0; 16];
    hardware.fill_entropy(&mut incarnation)?;
    let storage = Storage {
        registry: Store::open(
            Nvm::new(),
            key,
            Registry::new(incarnation, None),
            &mut hardware,
        )?,
        images: Images::new(Nvm::new())?,
        heaps: Heaps,
        heap_key,
    };
    JcvmEngine::open(
        storage,
        hardware,
        Staging::new(StagingNvm::new()),
        alloc::vec![0; 16384],
    )
}
