use super::*;
use core::cell::{Cell, RefCell};
extern crate std;
mod vm {
    pub(super) use super::super::{BufferResult, NativeArgument};
}
use crate::{
    apdu::Command,
    crypto::CryptoProvider,
    journal::MemoryFlash,
    package::{
        AssemblyEntry, CONTEXT, Dependency, DependencyExport, Limits, Manifest, VersionRange,
    },
};
const STORAGE_KEY: [u8; 16] = [0x5a; 16];
struct TestPlatform(u8);
impl crate::crypto::CryptoProvider for TestPlatform {}
impl crate::hal::Entropy for TestPlatform {
    fn fill_entropy(&mut self, b: &mut [u8]) -> Result<()> {
        self.0 += 1;
        b.fill(self.0);
        Ok(())
    }
}
impl crate::hal::LogicalGpio for TestPlatform {
    fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
        Err(Error::Native)
    }
}
struct AcceptCredentialCheckpoint;
impl CredentialCheckpoint<TestPlatform> for AcceptCredentialCheckpoint {
    fn checkpoint(
        &mut self,
        _: &mut TestPlatform,
        _: &CredentialRetryFloors,
    ) -> Result<()> {
        Ok(())
    }
}
struct FailingEntropy;
impl crate::crypto::CryptoProvider for FailingEntropy {}
impl crate::hal::Entropy for FailingEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
        output.fill(0xa5);
        Err(Error::Native)
    }
}
impl crate::hal::LogicalGpio for FailingEntropy {
    fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
        Err(Error::Native)
    }
}

#[derive(Clone)]
struct TestStagingFlash {
    bytes: Rc<RefCell<[u8; MAX_PACKAGE_BYTES]>>,
    erases: Rc<Cell<usize>>,
}

impl TestStagingFlash {
    fn new() -> Self {
        Self {
            bytes: Rc::new(RefCell::new([0xff; MAX_PACKAGE_BYTES])),
            erases: Rc::new(Cell::new(0)),
        }
    }
}

impl crate::hal::StagingFlash for TestStagingFlash {
    fn capacity(&self) -> usize {
        MAX_PACKAGE_BYTES
    }
    fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(output.len()).ok_or(Error::Bounds)?;
        let bytes = self.bytes.borrow();
        let source = bytes.get(offset..end).ok_or(Error::Bounds)?;
        output.copy_from_slice(source);
        Ok(())
    }
    fn erase(&mut self) -> Result<()> {
        self.bytes.borrow_mut().fill(0xff);
        self.erases.set(self.erases.get() + 1);
        Ok(())
    }
    fn program(&mut self, offset: usize, input: &[u8]) -> Result<()> {
        let end = offset.checked_add(input.len()).ok_or(Error::Bounds)?;
        let mut bytes = self.bytes.borrow_mut();
        let destination = bytes.get_mut(offset..end).ok_or(Error::Bounds)?;
        if destination.iter().zip(input).any(|(old, new)| old & new != *new) {
            return Err(Error::Storage);
        }
        for (old, new) in destination.iter_mut().zip(input) {
            *old = *new;
        }
        Ok(())
    }
}
#[derive(Clone)]
struct SharedJournalFlash(Rc<RefCell<MemoryFlash>>);
impl crate::image_store::ImageReader for SharedJournalFlash {
    fn slot_count(&self) -> usize { crate::image_store::ImageReader::slot_count(&*self.0.borrow()) }
    fn slot_size(&self) -> usize { crate::image_store::ImageReader::slot_size(&*self.0.borrow()) }
    type Image<'a> = core::cell::Ref<'a, [u8]>;
    fn read_range(&self, index: usize, range: core::ops::Range<usize>) -> Result<Self::Image<'_>> {
        let flash = self.0.try_borrow().map_err(|_| Error::Busy)?;
        flash.read_range(index, range.clone())?;
        Ok(core::cell::Ref::map(flash, |flash| flash.read_range(index, range).expect("validated image range")))
    }
}
impl crate::image_store::ImageFlash for SharedJournalFlash {
    type Reader = crate::journal::MemoryImageReader;
    fn image_reader(&self) -> Result<Self::Reader> {
        crate::image_store::ImageFlash::image_reader(&*self.0.borrow())
    }
    fn erase(&mut self, index: usize) -> Result<()> {
        crate::image_store::ImageFlash::erase(&mut *self.0.borrow_mut(), index)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        crate::image_store::ImageFlash::program(&mut *self.0.borrow_mut(), index, offset, bytes)
    }
}
impl Flash for SharedJournalFlash {
    fn slot_size(&self) -> usize {
        self.0.borrow().slot_size()
    }
    fn monotonic_capacity(&self) -> u64 {
        self.0.borrow().monotonic_capacity()
    }
    fn monotonic_generation(&self) -> Result<u64> {
        self.0.borrow().monotonic_generation()
    }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        self.0.borrow_mut().advance_monotonic(generation)
    }
    fn nonce_generation(&self) -> Result<u64> { self.0.borrow().nonce_generation() }
    fn reserve_nonce(&mut self) -> Result<u64> { self.0.borrow_mut().reserve_nonce() }
    fn is_erased(&self, slot: usize) -> Result<bool> {
        self.0.borrow().is_erased(slot)
    }
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()> {
        self.0.borrow().read(slot, offset, output)
    }
    fn erase(&mut self, slot: usize) -> Result<()> {
        self.0.borrow_mut().erase(slot)
    }
    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        self.0.borrow_mut().program(slot, offset, bytes)
    }
}
fn fresh_card() -> Mc04Engine<MemoryFlash, TestPlatform> {
    Mc04Engine::open(MemoryFlash::new(16384), TestPlatform(0), STORAGE_KEY).unwrap()
}
fn card() -> Mc04Engine<MemoryFlash, TestPlatform> {
    let mut card = fresh_card();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    load(&mut card, &package).unwrap();
    card
}

fn command(ins: u8, data: &[u8]) -> Verified<'_> {
    Verified {
        level: 0x13,
        command: Command {
            cla: 0x80,
            ins,
            p1: 0,
            p2: 0,
            data: data.to_vec().into(),
            le: None,
        },
    }
}
fn create(c: &mut Mc04Engine<MemoryFlash, TestPlatform>, id: &str) -> [u8; 16] {
    c.manage(command(0xe0, id.as_bytes()))
        .unwrap()
        .try_into()
        .unwrap()
}

fn package(
    id: &str,
    inc: [u8; 16],
    name: &str,
    version: u32,
    seed: u8,
    code: &[u8],
) -> Vec<u8> {
    signed_package(id, inc, name, version, seed, code, true)
}
fn library_package(id: &str, inc: [u8; 16], name: &str, version: u32, seed: u8) -> Vec<u8> {
    signed_package(id, inc, name, version, seed, &[0x2a], false)
}

fn multi_entry_package(
    id: &str,
    inc: [u8; 16],
    name: &str,
    seed: u8,
    first_aid: u16,
    count: usize,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: name.into(),
        assembly_version: [1, 0, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: (0..count)
            .map(|offset| AssemblyEntry {
                aid: alloc::format!("F04D43{:04X}", first_aid + offset as u16),
                process: 0,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            })
            .collect(),
        dependencies: Vec::new(),
        capabilities: alloc::vec![7, 8],
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(&manifest, &test_assembly(name, &[0x2a]), seed)
}

fn test_assembly(name: &str, body: &[u8]) -> Vec<u8> {
    let valid = (1u64 << crate::mc04_schema::TABLE_MODULE)
        | (1u64 << crate::mc04_schema::TABLE_TYPEDEF)
        | (1u64 << crate::mc04_schema::TABLE_METHODDEF)
        | (1u64 << crate::mc04_schema::TABLE_ASSEMBLY);
    let mut tables = alloc::vec![2, 0, 0, 0];
    tables.extend(valid.to_le_bytes());
    for _ in 0..4 {
        tables.extend(1u16.to_le_bytes());
    }
    tables.push(1); // Module.Name
    tables.extend([0, 1, 0, 0, 3, 0, 0, 0, 1, 1]); // sealed TypeDef
    tables.extend([0, 0, 0, 0, 0, 0, 0x10, 0, 5, 1]); // static MethodDef
    tables.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]); // Assembly
    let mut strings = Vec::from(b"\0M\0T\0Run\0" as &[u8]);
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    let blobs = [0, 3, 0, 0, 1]; // static parameterless void
    let mut code = alloc::vec![0, 0];
    code.extend(1u16.to_le_bytes());
    code.extend((body.len() as u32).to_le_bytes());
    code.extend([0, 0, 0, 0]);
    code.extend_from_slice(body);
    let sections: [&[u8]; 4] = [&tables, &strings, &blobs, &code];
    let header_size = 56usize;
    let file_size = header_size + sections.iter().map(|section| section.len()).sum::<usize>();
    let mut bytes = Vec::from(b"MC04" as &[u8]);
    bytes.extend([4, 0, 0, 0, 4, 2]);
    bytes.extend((header_size as u16).to_le_bytes());
    bytes.extend((file_size as u32).to_le_bytes());
    let mut offset = header_size;
    for (index, section) in sections.iter().enumerate() {
        bytes.extend([index as u8 + 1, 0]);
        bytes.extend((offset as u32).to_le_bytes());
        bytes.extend((section.len() as u32).to_le_bytes());
        offset += section.len();
    }
    for section in sections {
        bytes.extend(section);
    }
    bytes
}
fn signed_package(
    id: &str,
    inc: [u8; 16],
    name: &str,
    version: u32,
    seed: u8,
    code: &[u8],
    has_entry: bool,
) -> Vec<u8> {
    signed_package_with_storage(
        id,
        inc,
        name,
        version,
        seed,
        code,
        has_entry,
        alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_package_with_storage(
    id: &str,
    inc: [u8; 16],
    name: &str,
    version: u32,
    seed: u8,
    code: &[u8],
    has_entry: bool,
    storage: Vec<StorageDeclaration>,
) -> Vec<u8> {
    let m = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: name.into(),
        assembly_version: [1, 0, 0, 0],
        version,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: if has_entry {
            alloc::vec![AssemblyEntry {
                aid: "F04D430001".into(),
                process: 0,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            }]
        } else {
            Vec::new()
        },
        dependencies: Vec::new(),
        capabilities: alloc::vec![7, 8],
        storage,
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(&m, &test_assembly(name, code), seed)
}

fn counter_package(id: &str, inc: [u8; 16], version: u32, seed: u8) -> Vec<u8> {
    counter_package_with_storage(
        id,
        inc,
        version,
        seed,
        alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
    )
}

fn counter_package_with_storage(
    id: &str,
    inc: [u8; 16],
    version: u32,
    seed: u8,
    storage: Vec<StorageDeclaration>,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: "Counter".into(),
        assembly_version: [1, 0, 0, 0],
        version,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![
            AssemblyEntry {
                aid: "F04D430001".into(),
                process: 1,
                install: Some(0),
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430002".into(),
                process: 28,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
        dependencies: Vec::new(),
        capabilities: alloc::vec![2, 7, 8, 9, 11, 12, 13, 20],
        storage,
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(
        &manifest,
        include_bytes!("../../../../fuzz/fixtures/counter.mca"),
        seed,
    )
}

fn transaction_records_package(
    id: &str,
    inc: [u8; 16],
    version: u32,
    seed: u8,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: "TransactionRecords".into(),
        assembly_version: [1, 0, 0, 0],
        version,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![AssemblyEntry {
            aid: "F04D430020".into(),
            process: 0,
            install: None,
            uninstall: None,
            select: None,
            deselect: None,
        }],
        dependencies: Vec::new(),
        capabilities: alloc::vec![2, 7, 8, 11, 12, 13, 31, 32, 34, 46, 47, 48],
        storage: alloc::vec![
            StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 2, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 3, kind: 2, max_bytes: 1 },
        ],
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(
        &manifest,
        include_bytes!("../../../../tests/fixtures/transaction_records.mca"),
        seed,
    )
}

fn transaction_negative_package(
    id: &str,
    inc: [u8; 16],
    version: u32,
    seed: u8,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: "TransactionRuntimeNegative".into(),
        assembly_version: [1, 0, 0, 0],
        version,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![AssemblyEntry {
            aid: "F04D430022".into(),
            process: 0,
            install: None,
            uninstall: None,
            select: None,
            deselect: None,
        }],
        dependencies: Vec::new(),
        capabilities: alloc::vec![6, 7, 8, 11, 12, 46, 47, 48],
        storage: alloc::vec![StorageDeclaration {
            key: 1,
            kind: 1,
            max_bytes: 0,
        }],
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(
        &manifest,
        include_bytes!("../../../../tests/fixtures/transaction_runtime_negative.mca"),
        seed,
    )
}

fn stage_pending_transaction(
    card: &mut Mc04Engine<MemoryFlash, TestPlatform>,
    value: i32,
    commands_left: u8,
) {
    let (registry_aid, incarnation, state) = {
        let domain = card.state.domains.get_mut("transaction").unwrap();
        let mut state = StagedApplication::new(domain).unwrap();
        state.view(domain).store.insert(1, value).unwrap();
        (domain.registry_aid, domain.incarnation, state)
    };
    card.transaction = Some(PendingTransaction {
        owner: (registry_aid, incarnation, "F04D430020".into()),
        state,
        commands_left,
    });
}

fn key_operations_package(id: &str, inc: [u8; 16], version: u32, seed: u8) -> Vec<u8> {
    key_operations_package_with_storage(
        id,
        inc,
        version,
        seed,
        alloc::vec![
            StorageDeclaration { key: 10, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 20, kind: 2, max_bytes: 3 },
            StorageDeclaration { key: 21, kind: 2, max_bytes: 1 },
            StorageDeclaration { key: 30, kind: 1, max_bytes: 0 },
        ],
    )
}

fn key_operations_package_with_storage(
    id: &str,
    inc: [u8; 16],
    version: u32,
    seed: u8,
    storage: Vec<StorageDeclaration>,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: id.into(),
        incarnation: inc,
        assembly: "KeyOperations".into(),
        assembly_version: [1, 0, 0, 0],
        version,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![
            AssemblyEntry {
                aid: "F04D430010".into(),
                process: 1,
                install: Some(0),
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430011".into(),
                process: 3,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430012".into(),
                process: 4,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430013".into(),
                process: 5,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
        dependencies: Vec::new(),
        capabilities: alloc::vec![
            2, 5, 7, 8, 11, 12, 13, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
            34,
        ],
        storage,
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(
        &manifest,
        include_bytes!("../../../../fuzz/fixtures/key_operations.mca"),
        seed,
    )
}

fn signed_compiled_package(manifest: &Manifest, image: &[u8], seed: u8) -> Vec<u8> {
    let meta = manifest.encode_cbor_unchecked().unwrap();
    let private = [seed; 32];
    let key = crate::crypto::p256_public_key(&private).unwrap();
    let mut raw = crate::package::envelope::signing_prefix(&meta, image.len(), &crate::crypto::sha256(image), &key).unwrap();
    let signature = crate::crypto::p256_ecdsa_sign_package(&private, &raw).unwrap();
    raw.extend(signature); raw.extend(image);
    raw
}
fn load<P: Platform>(c: &mut Mc04Engine<MemoryFlash, P>, p: &[u8]) -> Result<Vec<u8>> {
    c.manage(command(0xe6, &[]))?;
    for (i, chunk) in p.chunks(200).enumerate() {
        let mut data = (i as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        c.manage(command(0xe8, &data))?;
    }
    c.manage(command(0xea, &[]))
}
fn run_loaded(
    card: &mut Mc04Engine<MemoryFlash, TestPlatform>,
    domain: &str,
    assembly: &str,
    entry: u16,
    data: &[u8],
) -> Result<Vec<u8>> {
    let descriptor = card.state.domain(domain).unwrap().image_refs[assembly];
    let raw = descriptor.read_verified(card.journal.flash(), &mut card.platform)?;
    let bindings = card.state.domain(domain).unwrap().bindings[assembly].clone();
    let calls = card.state.domain(domain).unwrap().imports[assembly].clone();
    let package = PackageView::verify(raw)?;
    let units = [ExecutionUnit {
        package: (&package).into(),
        bindings: &bindings,
        calls: &calls,
    }];
    run_context(
        card.state.domain_mut(domain).unwrap(),
        &units[0].package,
        Some(&units),
        entry,
        data,
        &mut card.platform,
        0,
    )
}
mod signing_tests;
mod budget_tests;
mod snapshot_tests;
mod management_tests;
mod registry_tests;
mod verifier_tests;
mod execution_tests;
mod storage_tests;
mod activation_tests;
mod native_api_tests;

// Fixture-only publication for deliberately constructed recovery states.
impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Mc04Engine<F, P, S> {
    fn commit(&mut self, next: State) -> Result<()> {
        if self.state == next {
            return Ok(());
        }
        let mut protected = Vec::new();
        let current_count: usize = core::iter::once(&self.state.isd)
            .chain(self.state.domains.0.iter().map(|(_, domain)| domain))
            .map(|domain| domain.image_refs.len()).sum();
        let next_count: usize = core::iter::once(&next.isd)
            .chain(next.domains.0.iter().map(|(_, domain)| domain))
            .map(|domain| domain.image_refs.len()).sum();
        protected.try_reserve_exact((self.uncommitted_images.len() + current_count + next_count).min(64))
            .map_err(|_| Error::Quota)?;
        protected.extend_from_slice(&self.uncommitted_images);
        for domain in core::iter::once(&self.state.isd).chain(self.state.domains.0.iter().map(|(_, domain)| domain)) {
            for (_, descriptor) in domain.image_refs.iter() {
                if !protected.contains(descriptor) { protected.push(*descriptor); }
            }
        }
        for domain in core::iter::once(&next.isd).chain(next.domains.values()) {
            for descriptor in domain.image_refs.values() {
                if !protected.contains(descriptor) {
                    if protected.len() == 64 { return Err(Error::Quota); }
                    protected.push(*descriptor);
                }
            }
        }
        let data = next.encode_snapshot()?;
        if data.len() > 49152 {
            return Err(Error::Quota);
        }
        self.uncommitted_images = protected;
        self.journal
            .commit_owned_with(data, &mut self.platform)?;
        self.uncommitted_images.clear();
        self.state = next;
        Ok(())
    }
}

fn commit_cuts(snapshot_bytes: usize, image_bytes: usize) -> Vec<usize> {
    let image_end = if image_bytes == 0 { 0 } else { 16384 + image_bytes };
    let journal_header = image_end + 4 + 1 + 16384;
    let ciphertext_end = journal_header + 40 + snapshot_bytes;
    let mut cuts = alloc::vec![0, 1];
    for boundary in [16384.min(image_end), image_end, image_end + 1, image_end + 4, journal_header,
        ciphertext_end, ciphertext_end + 1, ciphertext_end + 2, ciphertext_end + 6] {
        cuts.extend([boundary.saturating_sub(1), boundary, boundary + 1]);
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}
