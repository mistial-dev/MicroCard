use super::*;
use core::cell::{Cell, RefCell};
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
impl crate::image_store::ImageFlash for SharedJournalFlash {
    fn slot_count(&self) -> usize { crate::image_store::ImageFlash::slot_count(&*self.0.borrow()) }
    fn slot_size(&self) -> usize { crate::image_store::ImageFlash::slot_size(&*self.0.borrow()) }
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        crate::image_store::ImageFlash::with_slot(&*self.0.borrow(), index, read)
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
fn fresh_card() -> Card<MemoryFlash, TestPlatform> {
    Card::open(MemoryFlash::new(16384), TestPlatform(0), STORAGE_KEY).unwrap()
}
fn card() -> Card<MemoryFlash, TestPlatform> {
    let mut card = fresh_card();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    load(&mut card, &package).unwrap();
    card
}

#[test]
fn assembly_name_maps_are_compact_sorted_bounded_and_unique() {
    let mut values = NameMap::new();
    for index in (0..MAX_ASSEMBLIES_PER_DOMAIN).rev() {
        values
            .insert(Rc::from(alloc::format!("a{index}")), i32::from(index))
            .unwrap();
    }
    let pointer = values.0.as_ptr();
    assert_eq!(
        values.insert(Rc::from("overflow"), 9),
        Err(Error::Quota)
    );
    values.insert(Rc::from("a0"), 99).unwrap();
    assert_eq!(values.0.as_ptr(), pointer);
    assert_eq!(values.get("a0"), Some(&99));

    assert!(values.0.windows(2).all(|pair| pair[0].0 < pair[1].0));
}

#[test]
fn domain_creation_rejects_noncanonical_identifiers() {
    let mut card = card();
    for identifier in [
        ".hidden",
        "bad/name",
        "bad\\name",
        "bad\"name",
        "bad name",
        "é",
    ] {
        assert_eq!(
            card.manage(command(0xe0, identifier.as_bytes())),
            Err(Error::Domain)
        );
    }
    assert!(card.state.domains.is_empty());
}

#[test]
fn credential_invocation_state_uses_fixed_capacity() {
    let mut authorizations = CredentialAuthorizations::default();
    for slot in 0..crate::credential_store::MAX_SLOTS as i32 {
        authorizations.insert(slot).unwrap();
    }
    authorizations.insert(0).unwrap();
    assert_eq!(authorizations.insert(99), Err(Error::Quota));
    authorizations.remove(3);
    authorizations.insert(99).unwrap();
    assert!(!authorizations.contains(3));
    assert!(authorizations.contains(99));

    let mut floors = CredentialRetryFloors::default();
    assert!(floors.is_empty());
    for slot in 0..crate::credential_store::MAX_SLOTS as i32 {
        floors.record(slot, (3, 2)).unwrap();
    }
    floors.record(0, (2, 1)).unwrap();
    assert_eq!(floors.record(99, (1, 1)), Err(Error::Quota));
    assert!(floors.iter().any(|entry| entry == (0, (2, 1))));
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
fn create(c: &mut Card<MemoryFlash, TestPlatform>, id: &str) -> [u8; 16] {
    c.manage(command(0xe0, id.as_bytes()))
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn globalplatform_registry_reports_isd_domains_and_loads_in_bounded_records() {
    let unowned = fresh_card();
    let (isd, more) = unowned.get_status_record(0x80, 0, &[0xff, 0xff]).unwrap();
    assert!(!more);
    assert_eq!(
        &isd[..12],
        &[0xe3, 0x13, 0x4f, 8, 0xa0, 0, 0, 1, 0x51, 0, 0, 0]
    );
    assert!(isd.windows(4).any(|value| value == [0x9f, 0x70, 1, 1]));

    let mut owned = card();
    let incarnation = create(&mut owned, "payments");
    let (ssd, more) = owned
        .get_status_record(0x40, 0, &[0xa0, 0, 0, 1, 0x51])
        .unwrap();
    assert!(!more);
    let expected = crate::globalplatform::synthetic_aid(0x53, &incarnation);
    assert!(ssd.windows(16).any(|value| value == expected));
    assert!(ssd.windows(4).any(|value| value == [0x9f, 0x70, 1, 7]));

    let (load_record, more) = owned.get_status_record(0x20, 0, &[]).unwrap();
    assert!(!more);
    assert_eq!(load_record[0], 0xe3);
    assert!(
        load_record
            .windows(4)
            .any(|value| value == [0x9f, 0x70, 1, 1])
    );
    assert!(load_record.windows(2).any(|value| value == [0xce, 8]));

    let managed = package("payments", incarnation, "Wallet", 1, 7, &[0x2a]);
    load(&mut owned, &managed).unwrap();
    owned
        .manage(command(
            0xec,
            &management_names_wire("payments", "F04D430001").unwrap(),
        ))
        .unwrap();
    let (application, more) = owned.get_status_record(0x40, 1, &[]).unwrap();
    assert!(!more);
    assert!(
        application
            .windows(5)
            .any(|value| value == [0x4f, 5, 0xf0, 0x4d, 0x43])
    );
    assert!(application.windows(2).any(|value| value == [0xc4, 16]));
    let (load_with_module, more) = owned.get_status_record(0x10, 1, &[]).unwrap();
    assert!(!more);
    assert!(
        load_with_module
            .windows(7)
            .any(|value| value == [0x84, 5, 0xf0, 0x4d, 0x43, 0x00, 0x01])
    );

    let delete = |aid: &[u8]| Verified {
        level: 0x13,
        command: Command {
            cla: 0x80,
            ins: 0xe4,
            p1: 0,
            p2: 0x80,
            data: core::iter::once(0x4f)
                .chain(core::iter::once(aid.len() as u8))
                .chain(aid.iter().copied())
                .collect(),
            le: None,
        },
    };
    owned
        .manage_globalplatform(delete(&[0xf0, 0x4d, 0x43, 0x00, 0x01]))
        .unwrap();
    assert!(owned.state.domains["payments"].instances.is_empty());
    let digest = owned.state.domains["payments"].versions["Wallet"].1;
    owned
        .manage_globalplatform(delete(&crate::globalplatform::synthetic_aid(0x4c, &digest)))
        .unwrap();
    assert!(
        !owned.state.domains["payments"]
            .assemblies
            .contains_key("Wallet")
    );
}

#[test]
fn globalplatform_ssd_creation_and_deletion_are_durable_and_aid_addressed() {
    let requested = [0xf0, 0x4d, 0x43, 0x53, 0x44];
    let mut install_data = Vec::new();
    for value in [
        &[0xa0, 0, 0, 1, 0x51, 0x53, 0x50][..],
        &[0xa0, 0, 0, 1, 0x51, 0x53, 0x50, 0x41],
        &requested,
        &[0x80],
        &[0xc9, 4, 0x81, 2, 3, crate::scp03::SCP03_I],
    ] {
        install_data.push(value.len() as u8);
        install_data.extend_from_slice(value);
    }
    install_data.push(0); // No install token in this profile.
    let install = || Verified {
        level: 0x13,
        command: Command {
            cla: 0x80,
            ins: 0xe6,
            p1: 0x0c,
            p2: 0,
            data: install_data.clone().into(),
            le: None,
        },
    };
    assert_eq!(
        fresh_card().manage_globalplatform(install()),
        Err(Error::Unauthorized)
    );

    let mut owned = card();
    owned.manage_globalplatform(install()).unwrap();
    assert_eq!(
        owned.state.domains["F04D435344"].registry_aid.as_slice(),
        requested
    );
    let (record, more) = owned.get_status_record(0x40, 0, &requested).unwrap();
    assert!(!more);
    assert!(
        record
            .windows(7)
            .any(|value| value == [0x4f, 5, 0xf0, 0x4d, 0x43, 0x53, 0x44])
    );

    let mut reopened = Card::open(owned.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
    reopened.globalplatform_load = Some(GlobalPlatformLoad {
        domain_aid: RegistryAid::new(&requested).unwrap(),
        load_aid: RegistryAid::synthetic(0x4c, &[7; 32]),
        hash: Some([7; 32]),
        receiver: crate::globalplatform::LoadReceiver::new(
            crate::globalplatform::Payload::SignedPackage, MAX_PACKAGE_BYTES,
        ),
    });
    reopened.staging.bytes.push(0xaa);
    let delete = Verified {
        level: 0x13,
        command: Command {
            cla: 0x80,
            ins: 0xe4,
            p1: 0,
            p2: 0x80,
            data: [0x4f, 5, 0xf0, 0x4d, 0x43, 0x53, 0x44].to_vec().into(),
            le: None,
        },
    };
    reopened.manage_globalplatform(delete).unwrap();
    assert!(!reopened.state.domains.contains_key("F04D435344"));
    assert!(reopened.globalplatform_load.is_none());
    assert!(reopened.staging.bytes.is_empty());
    let final_state = Card::open(reopened.into_flash(), TestPlatform(30), STORAGE_KEY).unwrap();
    assert!(!final_state.state.domains.contains_key("F04D435344"));
}

#[test]
fn globalplatform_load_stream_activates_only_a_complete_matching_package() {
    let mut owned = card();
    let incarnation = create(&mut owned, "payments");
    let package = package("payments", incarnation, "Wallet", 1, 7, &[0x2a]);
    let hash = owned.platform.sha256(&package).unwrap();
    let mut wrong_hash = hash;
    wrong_hash[0] ^= 1;
    assert!(matches!(
        PackageView::verify_with_expected_digest(
            &package,
            &mut owned.platform,
            Some(&wrong_hash)
        ),
        Err(Error::Signature)
    ));
    let load_aid = RegistryAid::synthetic(0x4c, &hash);
    let domain_aid = owned.state.domains["payments"].registry_aid;
    let mut request = Vec::new();
    for value in [
        load_aid.as_slice(),
        domain_aid.as_slice(),
        &hash[..],
        &[] as &[u8],
        &[],
    ] {
        request.push(value.len() as u8);
        request.extend_from_slice(value);
    }
    assert_eq!(
        owned
            .manage_globalplatform(Verified {
                level: 0x13,
                command: Command {
                    cla: 0x80,
                    ins: 0xe6,
                    p1: 0x02,
                    p2: 0,
                    data: request.into(),
                    le: None,
                },
            })
            .unwrap(),
        [0]
    );
    assert_eq!(
        owned.globalplatform_load.as_ref().unwrap().domain_aid,
        domain_aid
    );

    let mut load_file =
        alloc::vec![0xc4, 0x82, (package.len() >> 8) as u8, package.len() as u8,];
    load_file.extend_from_slice(&package);
    let blocks = load_file.len().div_ceil(180);
    for (block, chunk) in load_file.chunks(180).enumerate() {
        let last = block + 1 == blocks;
        assert_eq!(
            owned
                .manage_globalplatform(Verified {
                    level: 0x13,
                    command: Command {
                        cla: 0x80,
                        ins: 0xe8,
                        p1: if last { 0x80 } else { 0 },
                        p2: block as u8,
                        data: chunk.to_vec().into(),
                        le: None,
                    },
                })
                .unwrap(),
            [0]
        );
        if !last {
            assert!(
                !owned.state.domains["payments"]
                    .assemblies
                    .contains_key("Wallet")
            );
        }
    }
    assert!(
        owned.state.domains["payments"]
            .assemblies
            .contains_key("Wallet")
    );
    assert!(owned.staging.bytes.is_empty());
    assert!(!owned.globalplatform_load_active());

    let instance_aid = [0xf0, 0x4d, 0x43, 0x00, 0x01];
    let mut install = Vec::new();
    for value in [
        load_aid.as_slice(),
        &instance_aid,
        &instance_aid,
        &[0][..],
        &[0xc9, 0],
        &[],
    ] {
        install.push(value.len() as u8);
        install.extend_from_slice(value);
    }
    assert_eq!(
        owned
            .manage_globalplatform(Verified {
                level: 0x13,
                command: Command {
                    cla: 0x80,
                    ins: 0xe6,
                    p1: 0x0c,
                    p2: 0,
                    data: install.into(),
                    le: None,
                },
            })
            .unwrap(),
        [0]
    );
    assert_eq!(
        owned.state.domains["payments"].instances["F04D430001"].as_ref(),
        "Wallet"
    );
}

#[test]
fn one_load_file_backs_several_instances_under_their_own_aids() {
    let mut owned = card();
    let incarnation = create(&mut owned, "payments");
    // A package offering two entry points, so it can be instantiated twice.
    let package = multi_entry_package("payments", incarnation, "Twice", 1, 0x0301, 2);
    let hash = owned.platform.sha256(&package).unwrap();
    let load_aid = RegistryAid::synthetic(0x4c, &hash);
    let domain_aid = owned.state.domains["payments"].registry_aid;
    let mut request = Vec::new();
    for value in [
        load_aid.as_slice(),
        domain_aid.as_slice(),
        &hash[..],
        &[] as &[u8],
        &[],
    ] {
        request.push(value.len() as u8);
        request.extend_from_slice(value);
    }
    let gp = |owned: &mut Card<MemoryFlash, TestPlatform>, p1: u8, p2: u8, ins: u8, data: Vec<u8>| {
        owned.manage_globalplatform(Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins,
                p1,
                p2,
                data: data.into(),
                le: None,
            },
        })
    };
    gp(&mut owned, 0x02, 0, 0xe6, request).unwrap();
    let mut load_file =
        alloc::vec![0xc4, 0x82, (package.len() >> 8) as u8, package.len() as u8,];
    load_file.extend_from_slice(&package);
    let blocks = load_file.len().div_ceil(180);
    for (block, chunk) in load_file.chunks(180).enumerate() {
        let last = block + 1 == blocks;
        gp(
            &mut owned,
            if last { 0x80 } else { 0 },
            block as u8,
            0xe8,
            chunk.to_vec(),
        )
        .unwrap();
    }

    // Each instance is installed under its own AID, with the module AID left alone.
    let module_aid = [0xf0, 0x4d, 0x43, 0x03, 0x01];
    for instance in [
        [0xf0, 0x4d, 0x43, 0x03, 0x01],
        [0xf0, 0x4d, 0x43, 0x03, 0x02],
    ] {
        let mut install = Vec::new();
        for value in [
            load_aid.as_slice(),
            &module_aid,
            &instance,
            &[0][..],
            &[0xc9, 0],
            &[],
        ] {
            install.push(value.len() as u8);
            install.extend_from_slice(value);
        }
        assert_eq!(gp(&mut owned, 0x0c, 0, 0xe6, install).unwrap(), [0]);
    }
    // Both live at once, backed by the one load file.
    let instances = &owned.state.domains["payments"].instances;
    assert_eq!(instances["F04D430301"].as_ref(), "Twice");
    assert_eq!(instances["F04D430302"].as_ref(), "Twice");

    // A third AID the package never offered is refused, because the package says which
    // AIDs it can answer to.
    let mut absent = Vec::new();
    for value in [
        load_aid.as_slice(),
        &module_aid,
        &[0xf0, 0x4d, 0x43, 0x03, 0x09],
        &[0][..],
        &[0xc9, 0],
        &[],
    ] {
        absent.push(value.len() as u8);
        absent.extend_from_slice(value);
    }
    assert_eq!(gp(&mut owned, 0x0c, 0, 0xe6, absent), Err(Error::Missing));
}

#[test]
fn a_java_card_load_file_is_recognised_and_refused_before_anything_is_staged() {
    let mut owned = card();
    create(&mut owned, "payments");
    // The first bytes of a Java Card load file, JCVM §6.3. The Header component leads,
    // carrying the magic that tells the two payload formats apart.
    let mut package = alloc::vec![0x01, 0x00, 0x13, 0xde, 0xca, 0xff, 0xed];
    package.extend_from_slice(&[0x01, 0x02, 0x04, 0x0a, 0x01, 0x09]);
    let hash = owned.platform.sha256(&package).unwrap();
    let load_aid = RegistryAid::synthetic(0x4c, &hash);
    let domain_aid = owned.state.domains["payments"].registry_aid;
    let mut request = Vec::new();
    for value in [
        load_aid.as_slice(),
        domain_aid.as_slice(),
        &hash[..],
        &[] as &[u8],
        &[],
    ] {
        request.push(value.len() as u8);
        request.extend_from_slice(value);
    }
    owned
        .manage_globalplatform(Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins: 0xe6,
                p1: 0x02,
                p2: 0,
                data: request.into(),
                le: None,
            },
        })
        .unwrap();

    // A short definite length, because this block is the whole load file.
    let mut load_file = alloc::vec![0xc4, package.len() as u8];
    load_file.extend_from_slice(&package);
    assert_eq!(
        owned.manage_globalplatform(Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins: 0xe8,
                p1: 0x80,
                p2: 0,
                data: load_file.into(),
                le: None,
            },
        }),
        Err(Error::Unsupported)
    );
    // The card refused before keeping any of it, so a later load starts clean.
    assert!(owned.staging.is_empty());
    assert!(owned.globalplatform_load.is_none());
}
// Explicit test-only signing seeds; never deployment keys.
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
        capabilities: alloc::vec![3, 4],
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
        capabilities: alloc::vec![3, 4],
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
        entry_points: alloc::vec![
            AssemblyEntry {
                aid: "F04D430020".into(),
                process: 0,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430021".into(),
                process: 2,
                install: Some(1),
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
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
fn load<P: Platform>(c: &mut Card<MemoryFlash, P>, p: &[u8]) -> Result<Vec<u8>> {
    c.manage(command(0xe6, &[]))?;
    for (i, chunk) in p.chunks(200).enumerate() {
        let mut data = (i as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        c.manage(command(0xe8, &data))?;
    }
    c.manage(command(0xea, &[]))
}
fn run_loaded(
    card: &mut Card<MemoryFlash, TestPlatform>,
    domain: &str,
    assembly: &str,
    entry: u16,
    data: &[u8],
) -> Result<Vec<u8>> {
    let raw = card.state.domain(domain).unwrap().assemblies[assembly].clone();
    let bindings = card.state.domain(domain).unwrap().bindings[assembly].clone();
    let calls = card.state.domain(domain).unwrap().imports[assembly].clone();
    let package = PackageView::verify(&raw)?;
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

#[test]
fn linked_frame_graph_rejects_cycles_and_paths_over_runtime_limit() {
    let within_limit = (0..31).map(|index| (index, index + 1)).collect::<Vec<_>>();
    validate_program_graph(32, &within_limit, &[false; 32], &[false; 32]).unwrap();

    let over_limit = (0..32).map(|index| (index, index + 1)).collect::<Vec<_>>();
    assert_eq!(
        validate_program_graph(33, &over_limit, &[false; 33], &[false; 33]),
        Err(Error::Quota)
    );
    assert_eq!(
        validate_program_graph(2, &[(0, 1), (1, 0)], &[false; 2], &[false; 2]),
        Err(Error::Quota)
    );
}

#[test]
fn linked_transaction_graph_rejects_indirect_irreversible_output() {
    let edges = [(0, 1), (1, 2)];
    assert_eq!(
        validate_program_graph(3, &edges, &[false, false, true], &[true, false, false]),
        Err(Error::Unsupported)
    );
    validate_program_graph(3, &edges, &[false, false, true], &[false, false, false]).unwrap();
    validate_program_graph(3, &edges, &[false, false, false], &[true, false, false]).unwrap();
}

#[test]
fn signed_mc04_transaction_bits_drive_linked_effect_validation() {
    let mut card = card();
    let incarnation = create(&mut card, "effects");
    load(&mut card, &counter_package("effects", incarnation, 1, 7)).unwrap();
    let calls = card
        .state
        .domains
        .get_mut("effects")
        .unwrap()
        .imports
        .get_mut("Counter")
        .unwrap();
    calls
        .iter_mut()
        .find(|binding| binding.target == CallTarget::Native(11))
        .unwrap()
        .target = CallTarget::Native(6);
    execution_units(&card.state, "effects", "Counter").unwrap();

    let calls = card
        .state
        .domains
        .get_mut("effects")
        .unwrap()
        .imports
        .get_mut("Counter")
        .unwrap();
    calls
        .iter_mut()
        .find(|binding| binding.target == CallTarget::Native(8))
        .unwrap()
        .target = CallTarget::Native(6);
    assert!(matches!(
        execution_units(&card.state, "effects", "Counter"),
        Err(Error::Unsupported)
    ));
}

#[test]
fn signed_forged_platform_identity_is_rejected_before_binding() {
    let mut card = card();
    for (identifier, identity, seed) in [
        ("framework-forgery", crate::mc04_imports::FRAMEWORK_HASH, 7),
        ("runtime-forgery", crate::mc04_imports::SYSTEM_RUNTIME_TOKEN, 8),
    ] {
        let incarnation = create(&mut card, identifier);
        let mut package = counter_package(identifier, incarnation, 1, seed);
        let positions = package
            .windows(identity.len())
            .enumerate()
            .filter_map(|(index, value)| (value == identity).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        package[positions[0]] ^= 1;
        let manifest_length = u32::from_le_bytes(package[32..36].try_into().unwrap()) as usize;
        let image_start = crate::package::envelope::OVERHEAD_BYTES + manifest_length;
        let digest = crate::crypto::sha256(&package[image_start..]);
        let digest_start = crate::package::HEADER_BYTES + manifest_length;
        package[digest_start..digest_start + 32].copy_from_slice(&digest);
        let signed_length = image_start - 64;
        let signature = crate::crypto::p256_ecdsa_sign_package(&[seed; 32], &package[..signed_length]).unwrap();
        package[signed_length..image_start].copy_from_slice(&signature);

        assert_eq!(load(&mut card, &package), Err(Error::Unauthorized));
        let domain = &card.state.domains[identifier];
        assert!(domain.key.is_none());
        assert!(domain.assemblies.is_empty());
        assert!(domain.imports.is_empty());
    }
}

#[test]
fn execution_unit_queue_is_deduplicated_and_bounded() {
    let mut card = card();
    let incarnation = create(&mut card, "queue");
    load(&mut card, &counter_package("queue", incarnation, 1, 7)).unwrap();

    let mut units = Vec::new();
    units.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
    push_execution_unit(&card.state, &mut units, "queue", "Counter", None).unwrap();
    let digest = units[0].package.digest;
    push_execution_unit(&card.state, &mut units, "queue", "Counter", Some(digest)).unwrap();
    assert_eq!(units.len(), 1);
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert_eq!(
        push_execution_unit(
            &card.state,
            &mut units,
            "queue",
            "Counter",
            Some(wrong_digest),
        ),
        Err(Error::Storage)
    );

    let isd = &card.state.isd;
    let bindings = isd.bindings.get("mscorlib").unwrap();
    let calls = isd.imports.get("mscorlib").unwrap();
    let mut full = Vec::new();
    full.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
    for _ in 0..MAX_EXECUTION_UNITS {
        full.push(ExecutionUnit {
            package: isd.package("mscorlib").unwrap(),
            bindings,
            calls,
        });
    }
    assert_eq!(
        push_execution_unit(&card.state, &mut full, "queue", "Counter", None),
        Err(Error::Quota)
    );
}

#[test]
fn linked_verifier_rejects_working_sets_before_unbounded_growth() {
    let raw = counter_package("a", [0; 16], 1, 7);
    let package = PackageView::verify(&raw).unwrap();
    let mut units = Vec::new();
    for _ in 0..=MAX_EXECUTION_UNITS {
        units.push(ExecutionUnit {
            package: (&package).into(),
            bindings: &[],
            calls: &[],
        });
    }
    assert_eq!(validate_linked_program(&units), Err(Error::Quota));
    assert_eq!(MAX_LINKED_METHODS, 4352);

    let mut edges = Vec::new();
    for edge in 0..MAX_LINKED_CALL_EDGES {
        push_link_edge(&mut edges, (edge, edge)).unwrap();
    }
    assert_eq!(
        push_link_edge(&mut edges, (MAX_LINKED_CALL_EDGES, 0)),
        Err(Error::Quota)
    );
}

#[test]
fn mscorlib_takes_permanent_isd_ownership_before_ssd_creation() {
    let mut c = fresh_card();
    let inc = c.state.isd.incarnation;
    assert_eq!(c.manage(command(0xe0, b"a")), Err(Error::Unauthorized));
    assert_eq!(
        load(&mut c, &library_package("ISD", inc, "Kdf108", 1, 42)),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        load(&mut c, &package("ISD", inc, "mscorlib", 1, 42, &[0x2a])),
        Err(Error::Unauthorized)
    );
    load(&mut c, &library_package("ISD", inc, "mscorlib", 1, 42)).unwrap();
    assert_eq!(
        c.manage(command(0xf0, &management_names_wire("ISD", "mscorlib").unwrap())),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        load(&mut c, &library_package("ISD", inc, "Kdf108", 1, 7)),
        Err(Error::KeyMismatch)
    );
    create(&mut c, "a");
    let c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(c.state.is_owned());
    assert_eq!(
        c.state.isd.key,
        Some(crate::crypto::signer_identity(&crate::crypto::p256_public_key(&[42; 32]).unwrap()))
    );
}

#[test]
fn domain_capacity_is_bounded_and_survives_reboot() {
    let mut card = card();
    for index in (0..MAX_SSDS).rev() {
        create(&mut card, &alloc::format!("d{index}"));
    }
    assert_eq!(card.manage(command(0xe0, b"overflow")), Err(Error::Quota));

    let inventory = card.manage(command(0xe2, &[MAX_SSDS as u8])).unwrap();
    assert_eq!(inventory[0], 1);
    assert_eq!(inventory[1] as usize, MAX_SSDS + 1);
    assert_eq!(inventory[2] as usize, MAX_SSDS);

    let mut reopened = Card::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
    assert_eq!(reopened.state.domains.len(), MAX_SSDS);
    assert_eq!(
        reopened.manage(command(0xe0, b"overflow")),
        Err(Error::Quota)
    );

    let invalid = DomainPolicy {
        max_assemblies: MAX_ASSEMBLIES_PER_DOMAIN + 1,
        ..DomainPolicy::standard().unwrap()
    };
    assert!(!invalid.valid());
    let invalid = DomainPolicy {
        max_instances: MAX_INSTANCES_PER_DOMAIN + 1,
        ..DomainPolicy::standard().unwrap()
    };
    assert!(!invalid.valid());
}

#[test]
fn domain_registry_orders_insertions() {
    let policy = DomainPolicy::standard().unwrap();
    let mut domains = Domains::new();
    for id in ["z", "a", "m"] {
        let stable = [id.as_bytes()[0]; 16];
        domains
            .insert(
                String::from(id),
                Domain::new(
                    [id.as_bytes()[0]; 16],
                    RegistryAid::synthetic(0x53, &stable),
                    policy.clone(),
                ),
            )
            .unwrap();
    }
    assert_eq!(domains.0.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["a", "m", "z"]);
}

#[test]
fn integer_store_is_compact_sorted_bounded_and_unique() {
    let mut store = IntStore::new();
    for key in (0..MAX_INT_RECORDS as i32).rev() {
        store.insert(key, key).unwrap();
    }
    let pointer = store.0.as_ptr();
    assert_eq!(store.insert(MAX_INT_RECORDS as i32, 1), Err(Error::Quota));
    assert_eq!(store.len(), MAX_INT_RECORDS);
    assert_eq!(store.0.as_ptr(), pointer);
    store.insert(0, -1).unwrap();
    assert_eq!(store.get(&0), Some(&-1));

    let mut small = IntStore::new();
    small.insert(2, 20).unwrap();
    small.insert(-1, -10).unwrap();
    small.insert(1, 10).unwrap();
    assert_eq!(small.0, [(-1, -10), (1, 10), (2, 20)]);
}

#[test]
fn byte_store_is_compact_sorted_bounded_and_unique() {
    let mut store = BlobStore::new();
    for key in (0..MAX_BLOB_RECORDS as i32).rev() {
        store.insert(key, alloc::vec![key as u8]).unwrap();
    }
    let entries_pointer = store.0.as_ptr();
    let first_value_pointer = store.get(&0).unwrap().as_ptr();
    assert_eq!(
        store.insert(MAX_BLOB_RECORDS as i32, alloc::vec![0xaa]),
        Err(Error::Quota)
    );
    assert_eq!(store.len(), MAX_BLOB_RECORDS);
    assert_eq!(store.0.as_ptr(), entries_pointer);
    assert_eq!(store.get(&0).unwrap().as_ptr(), first_value_pointer);

    let replacement = alloc::vec![0x55; 3];
    let replacement_pointer = replacement.as_ptr();
    store.insert(0, replacement).unwrap();
    assert_eq!(store.get(&0).unwrap().as_ptr(), replacement_pointer);

    let mut small = BlobStore::new();
    small.insert(2, alloc::vec![2]).unwrap();
    small.insert(-1, alloc::vec![1]).unwrap();
    assert_eq!(small.0, [(-1, alloc::vec![1]), (2, alloc::vec![2])]);
}

#[test]
fn installed_instances_are_compact_sorted_bounded_and_unique() {
    let mut instances = Instances::new();
    for index in (0..MAX_INSTANCES_PER_DOMAIN).rev() {
        instances
            .insert(
                alloc::format!("F04D4301{index:02}"),
                Rc::from("Counter"),
            )
            .unwrap();
    }
    let pointer = instances.0.as_ptr();
    assert_eq!(
        instances.insert(String::from("F04D4301FF"), Rc::from("Counter")),
        Err(Error::Quota)
    );
    assert_eq!(
        instances.insert(String::from("F04D430100"), Rc::from("Other")),
        Err(Error::Busy)
    );
    assert_eq!(instances.0.as_ptr(), pointer);
    assert_eq!(instances.get("F04D430100").unwrap().as_ref(), "Counter");

    assert!(instances.0.windows(2).all(|pair| pair[0].0 < pair[1].0));
}

#[test]
fn installed_instance_capacity_is_enforced_per_domain_and_card() {
    let mut card = card();
    let a = create(&mut card, "a");
    let b = create(&mut card, "b");
    let c = create(&mut card, "c");
    load(
        &mut card,
        &multi_entry_package("a", a, "ManyA1", 7, 0x100, 4),
    )
    .unwrap();
    load(
        &mut card,
        &multi_entry_package("a", a, "ManyA2", 7, 0x104, 4),
    )
    .unwrap();
    load(
        &mut card,
        &multi_entry_package("a", a, "ExtraA", 7, 0x108, 1),
    )
    .unwrap();
    load(
        &mut card,
        &multi_entry_package("b", b, "ManyB1", 8, 0x200, 4),
    )
    .unwrap();
    load(
        &mut card,
        &multi_entry_package("b", b, "ManyB2", 8, 0x204, 4),
    )
    .unwrap();
    load(
        &mut card,
        &multi_entry_package("c", c, "ManyC", 9, 0x300, 1),
    )
    .unwrap();

    let install = |card: &mut Card<MemoryFlash, TestPlatform>, domain: &str, aid: u16| {
        let request = management_names_wire(domain, &alloc::format!("F04D43{aid:04X}")).unwrap();
        card.manage(command(0xec, &request))
    };
    for aid in 0x100..0x108 {
        install(&mut card, "a", aid).unwrap();
    }
    assert_eq!(install(&mut card, "a", 0x108), Err(Error::Quota));
    for aid in 0x200..0x208 {
        install(&mut card, "b", aid).unwrap();
    }
    assert_eq!(install(&mut card, "c", 0x300), Err(Error::Quota));

    let reopened = Card::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
    assert_eq!(
        reopened
            .state
            .domains
            .values()
            .map(|domain| domain.instances.len())
            .sum::<usize>(),
        MAX_TOTAL_INSTANCES
    );
}

#[test]
fn pin_survives_unload_and_reboot() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let p = package("a", inc, "one", 1, 7, &[0x2a]);
    load(&mut c, &p).unwrap();
    c.manage(command(0xf0, &management_names_wire("a", "one").unwrap())).unwrap();
    let mut c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(
        load(&mut c, &package("a", inc, "two", 1, 8, &[0x2a])),
        Err(Error::KeyMismatch)
    );
    load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])).unwrap();
}
#[test]
fn signature_covers_every_byte() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let p = package("a", inc, "one", 1, 7, &[0x2a]);
    let mut previous_format = p.clone();
    previous_format[..4].copy_from_slice(b"MP02");
    assert!(matches!(
        Package::verify(&previous_format),
        Err(Error::Format)
    ));
    for i in 0..p.len() {
        let mut b = p.clone();
        b[i] ^= 1;
        assert!(Package::verify(&b).is_err(), "byte {}", i);
    }
    assert!(c.state.domains["a"].key.is_none());
}
#[test]
fn versions_and_incarnations() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let p = package("a", inc, "one", 2, 7, &[0x2a]);
    load(&mut c, &p).unwrap();
    load(&mut c, &p).unwrap();
    assert_eq!(
        load(&mut c, &package("a", inc, "one", 1, 7, &[0x2a])),
        Err(Error::Rollback)
    );
    assert_eq!(
        load(&mut c, &package("a", inc, "one", 2, 7, &[0x00, 0x2a])),
        Err(Error::Rollback)
    );
    c.manage(command(0xe4, b"a")).unwrap();
    let new = create(&mut c, "a");
    assert_ne!(new, inc);
    assert_eq!(load(&mut c, &p), Err(Error::Domain));
    load(&mut c, &package("a", new, "one", 1, 8, &[0x2a])).unwrap();
}
#[test]
fn management_level_and_isd() {
    let mut c = card();
    // Command integrity is the floor. A session without C-MAC carries no proof of
    // origin, so management is refused whatever else it negotiated.
    let mut plain = command(0xe0, b"a");
    plain.level = 0;
    assert_eq!(c.manage(plain), Err(Error::Unauthorized));
    // Every level that carries C-MAC is served, so a host may choose how much
    // confidentiality it wants without losing management access.
    for level in [0x01, 0x03, 0x11, 0x13] {
        let mut cmd = command(0xe0, b"ISD");
        cmd.level = level;
        assert_eq!(c.manage(cmd), Err(Error::Domain), "level {level:#04x}");
    }
}

#[test]
fn domain_policy_is_immutable_and_enforced() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let mut policy = DomainPolicy {
        capabilities: alloc::vec![3],
        max_assemblies: 1,
        max_instances: 1,
        max_int_records: 1,
        max_blob_records: 1,
        max_blob_bytes: 3,
        max_key_slots: 1,
        max_package_bytes: 8192,
    };
    let request = |policy: DomainPolicy| {
        let mut data = alloc::vec![1, 1, b'a'];
        data.extend(&policy.wire().unwrap()[1..]);
        data
    };
    c.manage(command(0xe1, &request(policy.clone()))).unwrap();
    assert_eq!(
        c.manage(command(0xe3, b"a")).unwrap(),
        policy.wire().unwrap()
    );
    let mut empty_policy = policy.clone();
    empty_policy.capabilities.clear();
    c.manage(command(0xe1, &request(empty_policy.clone())))
        .unwrap();
    assert_eq!(
        c.manage(command(0xe3, b"a")).unwrap(),
        empty_policy.wire().unwrap()
    );
    c.manage(command(0xe1, &request(policy.clone()))).unwrap();
    assert_eq!(
        load(&mut c, &package("a", inc, "one", 1, 7, &[0x2a])),
        Err(Error::Unauthorized)
    );
    assert!(c.state.domains["a"].key.is_none());

    policy.capabilities = alloc::vec![2, 3, 4, 7, 8, 9, 11, 12, 13, 20];
    c.manage(command(0xe1, &request(policy.clone()))).unwrap();
    load(&mut c, &counter_package("a", inc, 1, 7)).unwrap();
    assert_eq!(
        load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])),
        Err(Error::Quota)
    );
    c.state
        .domains
        .get_mut("a")
        .unwrap()
        .store
        .insert(2, 99)
        .unwrap();
    assert_eq!(
        c.manage(command(0xec, &management_names_wire("a", "F04D430001").unwrap())),
        Err(Error::Quota)
    );
    assert_eq!(c.state.domains["a"].store.get(&2), Some(&99));
    assert!(c.state.domains["a"].instances.is_empty());
    let store = &mut c.state.domains.get_mut("a").unwrap().store;
    let index = store.position(2).unwrap();
    store.0[index].1.zeroize();
    store.0.remove(index);
    c.manage(command(0xf0, &management_names_wire("a", "Counter").unwrap())).unwrap();
    assert_eq!(
        load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])),
        Err(Error::Quota)
    );
    assert_eq!(
        c.manage(command(0xe1, &request(policy.clone()))),
        Err(Error::Busy)
    );
    let mut invalid = request(policy);
    invalid[3] = 1;
    assert_eq!(c.manage(command(0xe1, &invalid)), Err(Error::Format));
    let reopened = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(reopened.state.domains["a"].policy.max_int_records, 1);
}
#[test]
fn failed_invocation_rolls_back_store() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let p = counter_package("a", inc, 1, 7);
    load(&mut c, &p).unwrap();
    c.manage(command(0xec, &management_names_wire("a", "F04D430001").unwrap())).unwrap();
    c.state
        .domains
        .get_mut("a")
        .unwrap()
        .store
        .insert(1, i32::MAX)
        .unwrap();
    assert_eq!(c.invoke("F04D430001", &[]), Err(Error::Arithmetic));
    assert_eq!(c.state.domains["a"].store.get(&1), Some(&i32::MAX));
    assert_eq!(
        c.manage(command(0xf0, &management_names_wire("a", "Counter").unwrap())),
        Err(Error::Busy)
    );
}

#[test]
fn selected_identity_buffers_are_reused_across_processing() {
    let mut card = card();
    let incarnation = create(&mut card, "selected-buffer");
    load(
        &mut card,
        &counter_package("selected-buffer", incarnation, 1, 7),
    )
    .unwrap();
    card.manage(command(
        0xec,
        &management_names_wire("selected-buffer", "F04D430001").unwrap(),
    ))
    .unwrap();
    card.select("F04D430001").unwrap();
    let pointers = {
        let (domain, _, aid) = card.selected.as_ref().unwrap();
        (domain.as_ptr(), aid.as_ptr())
    };

    card.process(&[]).unwrap();
    card.process_verified(Verified {
        command: Command {
            cla: 0x80,
            ins: 0x10,
            p1: 0,
            p2: 0,
            data: Vec::new().into(),
            le: None,
        },
        level: 0x13,
    })
    .unwrap();

    let (domain, _, aid) = card.selected.as_ref().unwrap();
    assert_eq!((domain.as_ptr(), aid.as_ptr()), pointers);

    card.select_isd_with_cancel(&mut || false).unwrap();
    assert!(card.selected.is_none());
    card.select("F04D430001").unwrap();
    *card
        .state
        .domains
        .get_mut("selected-buffer")
        .unwrap()
        .instances
        .get_mut("F04D430001")
        .unwrap() = Rc::from("Missing");
    let pointers = {
        let (domain, _, aid) = card.selected.as_ref().unwrap();
        (domain.as_ptr(), aid.as_ptr())
    };
    assert_eq!(
        card.select_isd_with_cancel(&mut || false),
        Err(Error::Missing)
    );
    let (domain, _, aid) = card.selected.as_ref().unwrap();
    assert_eq!((domain.as_ptr(), aid.as_ptr()), pointers);
}

#[test]
fn signed_multi_command_transactions_commit_abort_and_expire() {
    let mut card = card();
    let incarnation = create(&mut card, "transaction");
    load(
        &mut card,
        &transaction_records_package("transaction", incarnation, 1, 7),
    )
    .unwrap();
    load(
        &mut card,
        &transaction_negative_package("transaction", incarnation, 1, 7),
    )
    .unwrap();
    card.manage(command(0xec, &management_names_wire("transaction", "F04D430020").unwrap()))
        .unwrap();
    card.manage(command(0xec, &management_names_wire("transaction", "F04D430022").unwrap()))
        .unwrap();
    assert_eq!(
        card.manage(command(0xec, &management_names_wire("transaction", "F04D430021").unwrap())),
        Err(Error::Unauthorized)
    );
    assert!(!card.state.domains["transaction"]
        .instances
        .contains_key("F04D430021"));
    assert!(card.transaction.is_none());
    for command in [0, 1, 2] {
        assert_eq!(
            card.invoke("F04D430022", &[command]),
            Err(Error::Unauthorized)
        );
        assert!(card.transaction.is_none());
        assert!(card.state.domains["transaction"].store.is_empty());
    }

    assert_eq!(card.invoke("F04D430020", &[6]).unwrap(), [0, 0, 0, 0x90, 0]);
    assert_eq!(card.invoke("F04D430020", &[4]), Err(Error::Missing));
    assert_eq!(card.invoke("F04D430020", &[5]), Err(Error::Missing));
    card.invoke("F04D430020", &[0]).unwrap();
    card.invoke("F04D430020", &[1, 11]).unwrap();
    card.invoke("F04D430020", &[2, 22]).unwrap();
    card.invoke("F04D430020", &[3, 33]).unwrap();
    assert_eq!(
        card.invoke("F04D430020", &[6]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );
    assert!(card.state.domains["transaction"].store.is_empty());
    assert!(card.state.domains["transaction"].blobs.is_empty());

    let mut card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(card.transaction.is_none());
    assert_eq!(card.invoke("F04D430020", &[6]).unwrap(), [0, 0, 0, 0x90, 0]);

    card.invoke("F04D430020", &[0]).unwrap();
    let domain_registry_aid = card.state.domains["transaction"].registry_aid;
    let owner_aid_pointer = card.transaction.as_ref().unwrap().owner.2.as_ptr();
    card.invoke("F04D430020", &[1, 11]).unwrap();
    let owner = &card.transaction.as_ref().unwrap().owner;
    assert_eq!(owner.0, domain_registry_aid);
    assert_eq!(owner.2.as_ptr(), owner_aid_pointer);
    card.invoke("F04D430020", &[2, 22]).unwrap();
    card.invoke("F04D430020", &[3, 33]).unwrap();
    card.invoke("F04D430020", &[4]).unwrap();
    assert!(card.transaction.is_none());
    assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));
    assert_eq!(card.state.domains["transaction"].store.get(&2), Some(&22));
    assert_eq!(card.state.domains["transaction"].blobs.get(&3).unwrap(), &[33]);

    let mut card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(
        card.invoke("F04D430020", &[6]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );
    card.invoke("F04D430020", &[0]).unwrap();
    card.invoke("F04D430020", &[1, 44]).unwrap();
    card.invoke("F04D430020", &[5]).unwrap();
    assert_eq!(
        card.invoke("F04D430020", &[6]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );

    card.invoke("F04D430020", &[0]).unwrap();
    card.invoke("F04D430020", &[1, 55]).unwrap();
    assert_eq!(card.invoke("F04D430020", &[0]), Err(Error::Busy));
    assert!(card.transaction.is_none());
    assert_eq!(
        card.invoke("F04D430020", &[6]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );

    card.invoke("F04D430020", &[0]).unwrap();
    for _ in 0..14 {
        card.invoke("F04D430020", &[6]).unwrap();
    }
    assert_eq!(card.invoke("F04D430020", &[6]), Err(Error::Budget));
    assert!(card.transaction.is_none());

    card.invoke("F04D430020", &[0]).unwrap();
    card.invoke("F04D430020", &[1, 77]).unwrap();
    assert_eq!(card.invoke("F04D430020", &[0; 256]), Err(Error::Bounds));
    assert!(card.transaction.is_none());

    card.invoke("F04D430020", &[7]).unwrap();
    assert!(card.transaction.is_none());
    assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));

    card.invoke("F04D430020", &[0]).unwrap();
    card.invoke("F04D430020", &[1, 66]).unwrap();
    card.select("F04D430020").unwrap();
    assert!(card.transaction.is_none());
    assert_eq!(
        card.invoke("F04D430020", &[6]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );
}

#[test]
fn representative_simulator_runtime_peaks_stay_within_budget() {
    let mut card = card();
    let incarnation = create(&mut card, "metrics");
    load(
        &mut card,
        &key_operations_package("metrics", incarnation, 1, 7),
    )
    .unwrap();
    for aid in ["F04D430010", "F04D430011"] {
        card.manage(command(
            0xec,
            &management_names_wire("metrics", aid).unwrap(),
        ))
        .unwrap();
    }
    let mut peak = crate::mc04_vm::ExecutionMetrics::default();
    for (aid, data) in [
        ("F04D430010", &[0][..]),
        ("F04D430010", &[1][..]),
        ("F04D430010", &[2][..]),
        ("F04D430010", &[3][..]),
        ("F04D430011", &[][..]),
    ] {
        let (_, measured) = card.invoke_context_with_metrics(aid, data, 0).unwrap();
        peak.instructions = peak.instructions.max(measured.instructions);
        peak.peak_evaluation_slots = peak
            .peak_evaluation_slots
            .max(measured.peak_evaluation_slots);
        peak.peak_local_slots = peak.peak_local_slots.max(measured.peak_local_slots);
        peak.peak_frames = peak.peak_frames.max(measured.peak_frames);
        peak.peak_transient_bytes =
            peak.peak_transient_bytes.max(measured.peak_transient_bytes);
        peak.peak_transient_objects = peak
            .peak_transient_objects
            .max(measured.peak_transient_objects);
        peak.native_work_units = peak.native_work_units.max(measured.native_work_units);
    }
    assert_eq!(
        peak,
        crate::mc04_vm::ExecutionMetrics {
            instructions: 256,
            peak_evaluation_slots: 7,
            peak_local_slots: 10,
            peak_frames: 2,
            peak_transient_bytes: 177,
            peak_transient_objects: 7,
            native_work_units: 124,
        }
    );
    assert!(peak.instructions <= 512);
    assert!(peak.peak_evaluation_slots <= 8);
    assert!(peak.peak_local_slots <= 16);
    assert!(peak.peak_frames <= 4);
    assert!(peak.peak_transient_bytes <= 256);
    assert!(peak.peak_transient_objects <= 8);
    assert!(peak.native_work_units <= 128);
}

#[test]
fn native_failure_and_fuel_exhaustion_roll_back_all_writes() {
    let mut card = card();
    let incarnation = create(&mut card, "atomic");
    load(
        &mut card,
        &key_operations_package("atomic", incarnation, 1, 7),
    )
    .unwrap();

    card.manage(command(0xec, &management_names_wire("atomic", "F04D430011").unwrap()))
        .unwrap();
    assert_eq!(card.invoke("F04D430011", &[]), Err(Error::Missing));
    assert!(!card.state.domains["atomic"].store.contains_key(&10));

    card.manage(command(0xec, &management_names_wire("atomic", "F04D430013").unwrap()))
        .unwrap();
    assert_eq!(card.invoke("F04D430013", &[]), Err(Error::Budget));
    assert!(!card.state.domains["atomic"].store.contains_key(&30));

    let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(!reopened.state.domains["atomic"].store.contains_key(&10));
    assert!(!reopened.state.domains["atomic"].store.contains_key(&30));
}

#[test]
fn cooperative_cancellation_rolls_back_all_writes() {
    let mut card = card();
    let incarnation = create(&mut card, "cancel");
    load(
        &mut card,
        &key_operations_package("cancel", incarnation, 1, 7),
    )
    .unwrap();
    card.manage(command(0xec, &management_names_wire("cancel", "F04D430013").unwrap()))
        .unwrap();

    let mut polls = 0;
    let result = card.invoke_context_with_cancel("F04D430013", &[], 0, &mut || {
        polls += 1;
        polls == 2
    });
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(polls, 2);
    assert!(!card.state.domains["cancel"].store.contains_key(&30));

    let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(!reopened.state.domains["cancel"].store.contains_key(&30));
}

// Primitive tests sweep every flash byte. Domain tests exercise both sides of each
// storage phase and the state changes that must commit together.
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

#[test]
fn invocation_commit_boundaries_recover_old_or_new_state() {
    let mut card = card();
    let incarnation = create(&mut card, "atomic");
    load(&mut card, &counter_package("atomic", incarnation, 1, 7)).unwrap();
    card.manage(command(0xec, &management_names_wire("atomic", "F04D430001").unwrap()))
        .unwrap();
    let previous = card.state.encode_snapshot().unwrap().to_vec();
    let base = card.into_flash();

    let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
    complete.invoke("F04D430001", &[]).unwrap();
    let committed = complete.state.encode_snapshot().unwrap().to_vec();
    for cut in commit_cuts(committed.len(), 0) {
        let mut flash = base.clone();
        flash.fail_after = Some(cut);
        let mut interrupted = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let _ = interrupted.invoke("F04D430001", &[]);
        let mut flash = interrupted.into_flash();
        flash.fail_after = None;
        let recovered = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let actual = recovered.state.encode_snapshot().unwrap().to_vec();
        assert!(
            actual == previous || actual == committed,
            "partial invocation commit at cut {cut}"
        );
    }
}
#[test]
fn domain_application_state_is_zeroized_before_release() {
    let mut domain = Domain::new(
        [7; 16],
        RegistryAid::synthetic(1, b"zeroize-test"),
        DomainPolicy::standard().unwrap(),
    );
    domain.store.insert(1, 0x1122_3344).unwrap();
    domain.blobs.insert(2, alloc::vec![0x5a; 32]).unwrap();

    domain.zeroize_application_state();

    assert_eq!(domain.store[&1], 0);
    assert!(domain.blobs[&2].is_empty());
}

#[test]
fn stores_are_domain_scoped() {
    let mut c = card();
    let a = create(&mut c, "a");
    let b = create(&mut c, "b");
    load(&mut c, &counter_package("a", a, 1, 7)).unwrap();
    assert_eq!(
        run_loaded(&mut c, "a", "Counter", 1, &[]).unwrap(),
        [1, 0x90, 0]
    );
    assert_eq!(
        run_loaded(&mut c, "a", "Counter", 28, &[]).unwrap(),
        [1, 0, 0, 0, 0x90, 0]
    );
    c.manage(command(0xf0, &management_names_wire("a", "Counter").unwrap())).unwrap();
    load(&mut c, &counter_package("b", b, 1, 8)).unwrap();
    assert_eq!(
        run_loaded(&mut c, "b", "Counter", 28, &[]).unwrap(),
        [0, 0, 0, 0, 0x90, 0]
    );
}

#[test]
fn persistent_storage_schema_is_pinned_until_domain_deletion() {
    let mut card = card();
    let incarnation = create(&mut card, "schema");
    load(&mut card, &counter_package("schema", incarnation, 1, 7)).unwrap();
    let pinned_schema = Rc::clone(&card.state.domains["schema"].storage_schema);
    load(
        &mut card,
        &library_package("schema", incarnation, "Library", 1, 7),
    )
    .unwrap();
    assert!(Rc::ptr_eq(
        &pinned_schema,
        &card.state.domains["schema"].storage_schema
    ));
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
    );
    card.manage(command(0xf0, &management_names_wire("schema", "Counter").unwrap()))
        .unwrap();
    card.manage(command(0xf0, &management_names_wire("schema", "Library").unwrap()))
        .unwrap();
    let conflicting = signed_package_with_storage(
        "schema",
        incarnation,
        "Conflict",
        1,
        7,
        &[0x2a],
        false,
        alloc::vec![
            StorageDeclaration { key: 0, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 1, kind: 2, max_bytes: 16 },
        ],
    );
    assert_eq!(load(&mut card, &conflicting), Err(Error::KeyMismatch));
    assert!(card.state.domains["schema"].assemblies.is_empty());
    assert!(card.state.domains["schema"].storage_declaration(0).is_none());
    assert!(Rc::ptr_eq(
        &pinned_schema,
        &card.state.domains["schema"].storage_schema
    ));
    let card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
    );
    let mut card = card;
    card.manage(command(0xe4, b"schema")).unwrap();
    let replacement = create(&mut card, "schema");
    let replacement_package = signed_package_with_storage(
        "schema",
        replacement,
        "Replacement",
        1,
        8,
        &[0x2a],
        false,
        alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
    );
    load(&mut card, &replacement_package).unwrap();
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 2, max_bytes: 16 })
    );
}

#[test]
fn recovery_rejects_missing_or_retyped_persistent_schema() {
    let mut card = card();
    let incarnation = create(&mut card, "schema-recovery");
    load(
        &mut card,
        &counter_package("schema-recovery", incarnation, 1, 7),
    )
    .unwrap();
    run_loaded(&mut card, "schema-recovery", "Counter", 1, &[]).unwrap();
    let mut corrupted = card.state.try_clone().unwrap();
    let domain = corrupted.domains.get_mut("schema-recovery").unwrap();
    let mut schema = domain.storage_schema.as_ref().clone();
    schema[0].kind = 2;
    schema[0].max_bytes = 1;
    domain.storage_schema = Rc::new(schema);
    card.commit(corrupted).unwrap();
    assert!(matches!(
        Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY),
        Err(Error::Storage)
    ));
}

#[test]
fn managed_storage_access_requires_the_calling_assembly_declaration() {
    let mut card = card();
    let undeclared_incarnation = create(&mut card, "undeclared");
    let undeclared = counter_package_with_storage(
        "undeclared",
        undeclared_incarnation,
        1,
        7,
        Vec::new(),
    );
    load(&mut card, &undeclared).unwrap();
    assert_eq!(
        run_loaded(&mut card, "undeclared", "Counter", 0, &[]),
        Err(Error::Unauthorized)
    );
    assert!(card.state.domains["undeclared"].store.is_empty());

    let wrong_kind_incarnation = create(&mut card, "wrong-kind");
    let wrong_kind = counter_package_with_storage(
        "wrong-kind",
        wrong_kind_incarnation,
        1,
        8,
        alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
    );
    load(&mut card, &wrong_kind).unwrap();
    assert_eq!(
        run_loaded(&mut card, "wrong-kind", "Counter", 0, &[]),
        Err(Error::Unauthorized)
    );
    assert!(card.state.domains["wrong-kind"].store.is_empty());
}

#[test]
fn persistent_byte_declaration_bounds_each_native_write() {
    let mut card = card();
    let incarnation = create(&mut card, "blob-bound");
    let package = key_operations_package_with_storage(
        "blob-bound",
        incarnation,
        1,
        7,
        alloc::vec![
            StorageDeclaration { key: 10, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 20, kind: 2, max_bytes: 2 },
            StorageDeclaration { key: 21, kind: 2, max_bytes: 1 },
            StorageDeclaration { key: 30, kind: 1, max_bytes: 0 },
        ],
    );
    load(&mut card, &package).unwrap();
    assert_eq!(
        run_loaded(&mut card, "blob-bound", "KeyOperations", 4, &[0]),
        Err(Error::Quota)
    );
    assert!(card.state.domains["blob-bound"].blobs.is_empty());
}

#[test]
fn issuer_dependency_code_cannot_reach_caller_domain_storage() {
    let raw = signed_package_with_storage(
        "ISD",
        [2; 16],
        "Provider",
        1,
        7,
        &[0x2a],
        false,
        alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
    );
    let package = PackageView::verify(&raw).unwrap();
    let calls = [ResolvedCall { member: 1, target: CallTarget::Native(3) }];
    let units = [ExecutionUnit { package: (&package).into(), bindings: &[], calls: &calls }];
    let schema = [StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }];
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let mut transaction = TransactionDisposition::Inactive;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 32,
        capabilities: &[],
        domain_schema: &schema,
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: Some(&units),
        transaction: &mut transaction,
        irreversible_output: false,
    };
    let mut heap = crate::mc04_vm::Heap::new();
    assert_eq!(
        crate::mc04_vm::External::invoke(
            &mut host,
            0,
            1,
            3,
            &[crate::mc04_vm::RuntimeValue::Int(1)],
            &mut heap,
        ),
        Err(Error::Unauthorized)
    );
    assert!(host.store.is_empty());
}

#[test]
fn execution_units_borrow_persisted_packages_and_link_tables() {
    let mut card = card();
    let incarnation = create(&mut card, "borrowed");
    load(
        &mut card,
        &package("borrowed", incarnation, "library", 1, 7, &[0x2a]),
    )
    .unwrap();
    let domain = &card.state.domains["borrowed"];
    let raw = &domain.assemblies["library"];
    let calls = &domain.imports["library"];
    let units = execution_units(&card.state, "borrowed", "library").unwrap();
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].package.raw.as_ptr(), raw.as_ptr());
    assert_eq!(units[0].calls.as_ptr(), calls.as_ptr());
    let image_offset = units[0].package.image.as_ptr() as usize - raw.as_ptr() as usize;
    assert!(image_offset >= 12 && image_offset < raw.len());
}

#[test]
fn owned_package_indexes_image_inside_its_signed_envelope() {
    let raw = counter_package("owned", [7; 16], 1, 7);
    let package = Package::verify(&raw).unwrap();
    let raw_start = package.raw.as_ptr() as usize;
    let raw_end = raw_start + package.raw.len();
    let image_start = package.image().as_ptr() as usize;
    assert!(image_start >= raw_start && image_start + package.image().len() <= raw_end);
    assert_eq!(
        package.image(),
        include_bytes!("../../../../fuzz/fixtures/counter.mca")
    );
}

#[test]
fn state_snapshots_share_signed_packages_and_preserve_wire_state() {
    fn assert_shared_names(domain: &Domain, name: &str) {
        let package_name = domain.assemblies.get_key_value(name).unwrap().0;
        let version_name = domain.versions.get_key_value(name).unwrap().0;
        let binding_name = domain.bindings.get_key_value(name).unwrap().0;
        let import_name = domain.imports.get_key_value(name).unwrap().0;
        assert!(Rc::ptr_eq(package_name, version_name));
        assert!(Rc::ptr_eq(package_name, binding_name));
        assert!(Rc::ptr_eq(package_name, import_name));
        for instance_name in domain
            .instances
            .values()
            .filter(|instance_name| instance_name.as_ref() == name)
        {
            assert!(Rc::ptr_eq(package_name, instance_name));
        }
    }

    let mut card = card();
    let incarnation = create(&mut card, "shared");
    let counter = counter_package("shared", incarnation, 1, 7);
    let keys = key_operations_package("shared", incarnation, 1, 7);
    load(&mut card, &counter).unwrap();
    load(&mut card, &keys).unwrap();
    card.manage(command(0xec, &management_names_wire("shared", "F04D430001").unwrap()))
        .unwrap();
    let shared = card.state.domains.get_mut("shared").unwrap();
    shared.store.insert(7, 11).unwrap();
    shared.blobs.insert(8, alloc::vec![1, 2, 3, 4]).unwrap();
    shared
        .keys
        .generate(shared.incarnation, 0, 1, |bytes| {
            bytes.fill(0x5a);
            Ok(())
        })
        .unwrap();
    shared
        .credentials
        .create(
            shared.incarnation,
            0,
            b"1234",
            b"12345678",
            (3, 3),
            &mut TestPlatform(0xa4),
        )
        .unwrap();
    assert!(card.state.encode_snapshot().unwrap().to_vec().len() <= 49152);
    assert_shared_names(&card.state.isd, "mscorlib");
    assert_shared_names(&card.state.domains["shared"], "Counter");
    assert_shared_names(&card.state.domains["shared"], "KeyOperations");
    let wire_state = card.state.encode_snapshot().unwrap().to_vec();
    let mut clone_context = crate::fallible_clone::CloneContext::new();
    let snapshot = card.state.try_clone_with(&mut clone_context).unwrap();
    let allocation_count = clone_context.allocations();
    assert!(allocation_count > 16);
    for fail_at in 0..allocation_count {
        let mut context = crate::fallible_clone::CloneContext::failing_at(fail_at);
        assert!(matches!(
            card.state.try_clone_with(&mut context),
            Err(Error::Quota)
        ));
        assert_eq!(card.state.encode_snapshot().unwrap().to_vec(), wire_state);
    }
    assert!(Rc::ptr_eq(
        &card.state.isd.assemblies["mscorlib"],
        &snapshot.isd.assemblies["mscorlib"]
    ));
    assert!(Rc::ptr_eq(
        &card.state.domains["shared"].storage_schema,
        &snapshot.domains["shared"].storage_schema
    ));
    for name in ["Counter", "KeyOperations"] {
        assert!(Rc::ptr_eq(
            &card.state.domains["shared"].assemblies[name],
            &snapshot.domains["shared"].assemblies[name]
        ));
        assert_shared_names(&snapshot.domains["shared"], name);
    }
    assert_eq!(
        card.state.encode_snapshot().unwrap().to_vec(),
        snapshot.encode_snapshot().unwrap().to_vec()
    );
    let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_shared_names(&reopened.state.isd, "mscorlib");
    assert_shared_names(&reopened.state.domains["shared"], "Counter");
    assert_shared_names(&reopened.state.domains["shared"], "KeyOperations");
}

#[test]
fn maximum_container_state_clone_is_fallible_and_atomic() {
    let mut card = card();
    let incarnation = create(&mut card, "maximum-clone");
    let domain = card.state.domains.get_mut("maximum-clone").unwrap();
    domain.key = Some([0x44; 32]);
    for index in 0..MAX_ASSEMBLIES_PER_DOMAIN {
        let name: Rc<str> = Rc::from(alloc::format!("Assembly{index}"));
        domain
            .assemblies
            .insert(Rc::clone(&name), Rc::new(alloc::vec![index]))
            .unwrap();
        domain.image_refs.insert(Rc::clone(&name), crate::image_store::Descriptor {
            slot: index, length: 1, digest: [index; 32],
        }).unwrap();
        domain
            .bindings
            .insert(Rc::clone(&name), Vec::new())
            .unwrap();
        domain
            .imports
            .insert(Rc::clone(&name), Vec::new())
            .unwrap();
        domain
            .versions
            .insert(Rc::clone(&name), (1, [index; 32]))
            .unwrap();
        domain
            .instances
            .insert(alloc::format!("F04D4301{index:02X}"), name)
            .unwrap();
    }
    let mut schema = Vec::new();
    schema
        .try_reserve_exact(MAX_DOMAIN_STORAGE_DECLARATIONS)
        .unwrap();
    for key in 0..MAX_DOMAIN_STORAGE_DECLARATIONS as i32 {
        schema.push(StorageDeclaration { key, kind: 1, max_bytes: 0 });
        domain.store.insert(key, key).unwrap();
    }
    domain.storage_schema = Rc::new(schema);
    for index in 0..MAX_BLOB_RECORDS {
        domain
            .blobs
            .insert(1_000 + index as i32, alloc::vec![index as u8; 128])
            .unwrap();
    }
    for slot in 0..8 {
        domain
            .keys
            .generate(incarnation, slot, 1, |output| { output.fill(slot as u8 + 1); Ok(()) })
            .unwrap();
        domain
            .credentials
            .create(
                incarnation,
                slot,
                b"1234",
                b"12345678",
                (3, 3),
                &mut TestPlatform(slot as u8),
            )
            .unwrap();
    }

    let before = card.state.encode_snapshot().unwrap().to_vec();
    let mut complete_context = crate::fallible_clone::CloneContext::new();
    let complete = card.state.try_clone_with(&mut complete_context).unwrap();
    assert!(Rc::ptr_eq(
        &card.state.domains["maximum-clone"].storage_schema,
        &complete.domains["maximum-clone"].storage_schema
    ));
    let allocations = complete_context.allocations();
    assert!(allocations > 70, "allocations={allocations}");
    for fail_at in 0..allocations {
        let mut context = crate::fallible_clone::CloneContext::failing_at(fail_at);
        assert!(matches!(
            card.state.try_clone_with(&mut context),
            Err(Error::Quota)
        ));
        assert_eq!(card.state.encode_snapshot().unwrap().to_vec(), before);
    }
}

#[test]
fn first_load_power_loss_never_pins_alone() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let p = package("a", inc, "one", 1, 7, &[0x2a]);
    let previous = c.state.encode_snapshot().unwrap().to_vec();
    let base = c.into_flash();
    let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
    load(&mut complete, &p).unwrap();
    let serialized = complete.state.encode_snapshot().unwrap().to_vec(); // Journal mutation behavior is exhaustively tested separately.
    for cut in commit_cuts(serialized.len(), p.len()) {
        let mut f = base.clone();
        f.fail_after = Some(cut);
        let mut c = Card::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
        let _ = load(&mut c, &p);
        let marker_cut = 16384 + p.len() + 16384 + 47 + serialized.len();
        if cut == marker_cut {
            // The candidate is durable even though advancing the anchor failed.
            // A later upload must not recycle its slot before reboot resolves that.
            c.journal.flash_mut().fail_after = None;
            c.abort_staging();
            let replacement = package("a", inc, "one", 2, 7, &[0x2a]);
            assert_eq!(load(&mut c, &replacement), Err(Error::Storage));
        }
        let mut f = c.into_flash();
        f.fail_after = None;
        let mut recovered = Card::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
        let actual = recovered.state.encode_snapshot().unwrap().to_vec();
        assert!(
            actual == previous || actual == serialized,
            "partial activation at cut {cut}"
        );
        load(&mut recovered, &p).unwrap();
        assert_eq!(recovered.state.encode_snapshot().unwrap().to_vec(), serialized);
        let reopened =
            Card::open(recovered.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(reopened.state.encode_snapshot().unwrap().to_vec(), serialized);
    }
}
#[test]
fn activation_moves_staging_and_restores_it_after_commit_failure() {
    let mut card = card();
    let incarnation = create(&mut card, "move");
    let initial = package("move", incarnation, "one", 1, 7, &[0x2a]);
    for (index, chunk) in initial.chunks(200).enumerate() {
        let mut data = (index as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        card.manage(command(0xe8, &data)).unwrap();
    }
    let staged_pointer = card.staging.bytes.as_ptr();
    card.manage(command(0xea, &[])).unwrap();
    assert!(card.staging.bytes.is_empty());
    assert_eq!(
        card.state.domains["move"].assemblies["one"]
            .as_ref()
            .as_ptr(),
        staged_pointer
    );

    let mut flash = card.into_flash();
    flash.fail_after = Some(0);
    let mut card = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
    let replacement = signed_package_with_storage(
        "move",
        incarnation,
        "one",
        2,
        7,
        &[0x2a],
        true,
        alloc::vec![
            StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 2, kind: 2, max_bytes: 8 },
        ],
    );
    for (index, chunk) in replacement.chunks(200).enumerate() {
        let mut data = (index as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        card.manage(command(0xe8, &data)).unwrap();
    }
    let staged_pointer = card.staging.bytes.as_ptr();
    assert_eq!(card.manage(command(0xea, &[])), Err(Error::Storage));
    assert_eq!(card.staging.bytes, replacement);
    assert_eq!(card.staging.bytes.as_ptr(), staged_pointer);
    assert_eq!(card.state.domains["move"].versions["one"].0, 1);
    assert!(card.state.domains["move"].storage_declaration(2).is_none());
}
#[test]
fn flash_staging_streams_and_activates_without_a_ram_upload_buffer() {
    let flash = TestStagingFlash::new();
    let erases = Rc::clone(&flash.erases);
    let mut card = Card::open_with_staging(
        MemoryFlash::new(16384),
        TestPlatform(0),
        STORAGE_KEY,
        crate::staging::FlashStaging::new(flash),
    )
    .unwrap();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    for (index, chunk) in package.chunks(200).enumerate() {
        let mut data = (index as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        card.manage(command(0xe8, &data)).unwrap();
    }
    assert!(card.staging.as_slice().is_none());
    assert_eq!(erases.get(), 1);
    card.manage(command(0xea, &[])).unwrap();
    assert_eq!(card.state.isd.assemblies["mscorlib"].as_slice(), package);
    assert_eq!(card.staging.len(), 0);

    let mut corrupted = package.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    for (index, chunk) in corrupted.chunks(200).enumerate() {
        let mut data = (index as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        card.manage(command(0xe8, &data)).unwrap();
    }
    assert_eq!(erases.get(), 2);
    assert_eq!(card.manage(command(0xea, &[])), Err(Error::Signature));
    assert_eq!(card.staging.len(), corrupted.len());
    let mut retry = 0u32.to_le_bytes().to_vec();
    retry.extend(&corrupted[..200.min(corrupted.len())]);
    card.manage(command(0xe8, &retry)).unwrap();
    assert_eq!(erases.get(), 2);
    card.manage(command(0xe6, &[])).unwrap();
    assert_eq!(card.staging.len(), 0);
}
#[test]
fn flash_staging_survives_journal_failure_for_activation_retry() {
    let journal = Rc::new(RefCell::new(MemoryFlash::new(16384)));
    let flash = TestStagingFlash::new();
    let erases = Rc::clone(&flash.erases);
    let mut card = Card::open_with_staging(
        SharedJournalFlash(Rc::clone(&journal)),
        TestPlatform(0),
        STORAGE_KEY,
        crate::staging::FlashStaging::new(flash),
    )
    .unwrap();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    for (index, chunk) in package.chunks(200).enumerate() {
        let mut data = (index as u32 * 200).to_le_bytes().to_vec();
        data.extend(chunk);
        card.manage(command(0xe8, &data)).unwrap();
    }
    journal.borrow_mut().fail_after = Some(0);
    assert_eq!(card.manage(command(0xea, &[])), Err(Error::Storage));
    assert_eq!(card.staging.len(), package.len());
    assert!(card.state.isd.key.is_none());
    assert_eq!(erases.get(), 1);

    journal.borrow_mut().fail_after = None;
    card.manage(command(0xea, &[])).unwrap();
    assert_eq!(card.state.isd.assemblies["mscorlib"].as_slice(), package);
    assert_eq!(card.staging.len(), 0);
    assert_eq!(erases.get(), 1);
}
#[test]
fn staged_upload_quota_failure_preserves_existing_bytes() {
    let mut card = card();
    card.staging.bytes = alloc::vec![0xa5; MAX_PACKAGE_BYTES];
    let staged_pointer = card.staging.bytes.as_ptr();
    let mut data = (MAX_PACKAGE_BYTES as u32).to_le_bytes().to_vec();
    data.push(0x5a);

    assert_eq!(card.manage(command(0xe8, &data)), Err(Error::Quota));
    assert_eq!(card.staging.len(), MAX_PACKAGE_BYTES);
    assert!(card.staging.bytes.iter().all(|byte| *byte == 0xa5));
    assert_eq!(card.staging.bytes.as_ptr(), staged_pointer);
}
#[test]
fn domain_accepts_packages_above_eight_kib_with_a_sixteen_kib_ceiling() {
    let mut card = card();
    let incarnation = create(&mut card, "large");
    let mut body = alloc::vec![0; 8 * 1024];
    body.push(0x2a);
    let package = package("large", incarnation, "large", 1, 7, &body);
    assert!(package.len() > 8 * 1024);
    assert!(package.len() <= MAX_PACKAGE_BYTES);
    load(&mut card, &package).unwrap();
    assert_eq!(
        card.state.domains["large"].assemblies["large"].len(),
        package.len()
    );

    assert!(matches!(
        PackageView::verify(&alloc::vec![0; MAX_PACKAGE_BYTES + 1]),
        Err(Error::Format)
    ));
}
#[test]
fn failed_install_is_invisible_and_durable() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let mut p = Package::verify(&package("a", inc, "one", 1, 7, &[0x2b, 0xfe])).unwrap();
    p.manifest.entry_points[0].install = Some(0);
    let raw = signed_compiled_package(&p.manifest, p.image(), 7);
    load(&mut c, &raw).unwrap();
    assert_eq!(
        c.manage(command(0xec, &management_names_wire("a", "F04D430001").unwrap())),
        Err(Error::Budget)
    );
    let c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(c.state.domains["a"].instances.is_empty());
    assert!(c.state.domains["a"].key.is_some());
}

#[test]
fn bulk_command_io_validates_before_charging_or_mutating() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let capabilities = [12, 13];
    let mut transaction = TransactionDisposition::Inactive;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: [1; 16],
        data: b"abcdef",
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 32,
        capabilities: &capabilities,
        domain_schema: &[],
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: None,
        transaction: &mut transaction,
        irreversible_output: false,
    };
    let mut heap = crate::mc04_vm::Heap::new();
    let destination = heap.allocate_bytes(alloc::vec![0; 5]).unwrap();

    host.copy_command(&mut heap, destination, 1, 1, 3)
        .unwrap();
    assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
    assert_eq!(host.budget, 28);

    assert_eq!(
        host.copy_command(&mut heap, destination, 4, 0, 2),
        Err(Error::Bounds)
    );
    assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
    assert_eq!(host.budget, 28);

    host.write_response(&heap, destination, 1, 2).unwrap();
    assert_eq!(host.out, b"bc");
    assert_eq!(host.budget, 25);

    let oversized = heap.allocate_bytes(alloc::vec![0; 247]).unwrap();
    assert_eq!(
        host.write_response(&heap, oversized, 0, 247),
        Err(Error::Quota)
    );
    assert_eq!(host.out, b"bc");
    assert_eq!(host.budget, 25);

    host.capabilities = &[];
    assert_eq!(
        host.copy_command(&mut heap, destination, 0, 0, 1),
        Err(Error::Unauthorized)
    );
    assert_eq!(host.budget, 25);
}

#[test]
fn bulk_random_and_fixed_time_comparison_validate_ranges() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = FailingEntropy;
    let capabilities = [39, 50, 51];
    let mut transaction = TransactionDisposition::Inactive;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 32,
        capabilities: &capabilities,
        domain_schema: &[],
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: None,
        transaction: &mut transaction,
        irreversible_output: false,
    };
    let mut heap = crate::mc04_vm::Heap::new();
    let destination = heap.allocate_bytes(alloc::vec![0x7e; 8]).unwrap();
    assert_eq!(
        host.fill_random(&mut heap, destination, 6, 3),
        Err(Error::Bounds)
    );
    assert_eq!(heap.bytes(destination).unwrap(), [0x7e; 8]);
    assert_eq!(host.budget, 32);

    assert_eq!(
        host.fill_random(&mut heap, destination, 2, 4),
        Err(Error::Native)
    );
    assert_eq!(heap.bytes(destination).unwrap(), [0x7e, 0x7e, 0, 0, 0, 0, 0x7e, 0x7e]);
    assert_eq!(host.budget, 27);

    assert_eq!(host.random_bytes(-1), Err(Error::Bounds));
    assert_eq!(host.random_bytes(1025), Err(Error::Bounds));
    assert_eq!(host.budget, 27);
    assert_eq!(host.random_bytes(0), Ok(Vec::new()));
    assert_eq!(host.budget, 26);
    assert_eq!(host.random_bytes(4), Err(Error::Native));
    assert_eq!(host.budget, 21);

    let left = heap.allocate_bytes(alloc::vec![9, 1, 2, 3, 8]).unwrap();
    let right = heap.allocate_bytes(alloc::vec![7, 1, 2, 3, 6]).unwrap();
    host.budget = 16;
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 1, 3), (right, 1, 3)),
        Ok(1)
    );
    assert_eq!(host.budget, 12);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 0, 5), (right, 0, 4)),
        Ok(0)
    );
    assert_eq!(host.budget, 6);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, -1, 1), (right, 0, 1)),
        Err(Error::Bounds)
    );
    assert_eq!(host.budget, 6);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 4, 2), (right, 0, 2)),
        Err(Error::Bounds)
    );
    assert_eq!(host.budget, 6);
}

#[test]
fn credential_native_api_tracks_retries_and_scopes_authorization_to_invocation() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(9);
    let capabilities = [40, 41, 42, 43, 44, 45];
    {
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: &[],
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 4096,
            capabilities: &capabilities,
            domain_schema: &[],
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: None,
            transaction: &mut transaction,
            irreversible_output: false,
        };
        assert_eq!(
            host.credential_call(
                40,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x1234y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                    NativeArgument::Int(3),
                    NativeArgument::Bytes(b"x12345678y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(8),
                    NativeArgument::Int(2),
                ],
            ),
            Ok(BufferResult::Void)
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x9999y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Scalar(0))
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"1234"),
                    NativeArgument::Int(3),
                    NativeArgument::Int(2),
                ],
            ),
            Err(Error::Bounds)
        );
        assert_eq!(
            host.credential_call(
                45,
                &[NativeArgument::Int(2), NativeArgument::Int(0)],
            ),
            Ok(BufferResult::Scalar(2))
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x1234y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Scalar(1))
        );
        assert_eq!(
            host.credential_call(42, &[NativeArgument::Int(2)]),
            Ok(BufferResult::Scalar(1))
        );
        assert_eq!(
            host.credential_call(
                43,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x5678y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Void)
        );
    }
    let mut transaction = TransactionDisposition::Inactive;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 4096,
        capabilities: &capabilities,
        domain_schema: &[],
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: None,
        transaction: &mut transaction,
        irreversible_output: false,
    };
    assert_eq!(
        host.credential_call(42, &[NativeArgument::Int(2)]),
        Ok(BufferResult::Scalar(0))
    );
    assert_eq!(
        host.credential_call(
            41,
            &[
                NativeArgument::Int(2),
                NativeArgument::Bytes(b"x5678y"),
                NativeArgument::Int(1),
                NativeArgument::Int(4),
            ],
        ),
        Ok(BufferResult::Scalar(1))
    );
}

#[test]
fn credential_retry_floor_is_committed_and_recovers_after_invocation_failure() {
    let mut card = card();
    let incarnation = create(&mut card, "credential-floor");
    load(
        &mut card,
        &counter_package("credential-floor", incarnation, 1, 7),
    )
    .unwrap();
    let mut next = card.state.try_clone().unwrap();
    next.domains
        .get_mut("credential-floor")
        .unwrap()
        .credentials
        .create(
            incarnation,
            4,
            b"1234",
            b"12345678",
            (3, 2),
            &mut TestPlatform(0x59),
        )
        .unwrap();
    card.commit(next).unwrap();

    let mut floor = CredentialRetryFloors::default();
    floor.record(4, (2, 1)).unwrap();
    let domain_registry_aid = card.state.domains["credential-floor"].registry_aid;
    card.commit_credential_retry_floor(domain_registry_aid, &floor)
        .unwrap();
    assert_eq!(
        card.state.domains["credential-floor"]
            .credentials
            .retries(incarnation, 4)
            .unwrap(),
        (2, 1)
    );
    let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(
        reopened.state.domains["credential-floor"]
            .credentials
            .retries(incarnation, 4)
            .unwrap(),
        (2, 1)
    );
}

#[test]
fn credential_retry_floor_power_loss_recovers_prior_or_consumed_count() {
    let mut card = card();
    let incarnation = create(&mut card, "credential-cut");
    load(
        &mut card,
        &counter_package("credential-cut", incarnation, 1, 7),
    )
    .unwrap();
    let mut initial = card.state.try_clone().unwrap();
    initial
        .domains
        .get_mut("credential-cut")
        .unwrap()
        .credentials
        .create(
            incarnation,
            4,
            b"1234",
            b"12345678",
            (3, 2),
            &mut TestPlatform(0x59),
        )
        .unwrap();
    card.commit(initial).unwrap();
    let domain_registry_aid = card.state.domains["credential-cut"].registry_aid;
    let base = card.into_flash();
    let mut floor = CredentialRetryFloors::default();
    floor.record(4, (2, 1)).unwrap();
    let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
    complete
        .commit_credential_retry_floor(domain_registry_aid, &floor)
        .unwrap();
    let serialized = complete.state.encode_snapshot().unwrap().to_vec();

    for cut in commit_cuts(serialized.len(), 0) {
        let mut flash = base.clone();
        flash.fail_after = Some(cut);
        let mut interrupted = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let _ = interrupted.commit_credential_retry_floor(domain_registry_aid, &floor);
        let mut flash = interrupted.into_flash();
        flash.fail_after = None;
        let recovered = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let retries = recovered.state.domains["credential-cut"]
            .credentials
            .retries(incarnation, 4)
            .unwrap();
        assert!(retries == (3, 2) || retries == (2, 1), "cut {cut}: {retries:?}");
    }
}

#[test]
fn byte_storage_native_api_enforces_ownership_and_quotas() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let capabilities = [4, 22, 25, 29, 31, 32, 33, 34, 52];
    let mut transaction = TransactionDisposition::Inactive;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 4096,
        capabilities: &capabilities,
        domain_schema: &[],
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: None,
        transaction: &mut transaction,
        irreversible_output: false,
    };
    let oversized = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES + 1];
    assert_eq!(
        host.key_call(
            25,
            &[
                vm::NativeArgument::Bytes(&[]),
                vm::NativeArgument::Bytes(&oversized),
            ]
        ),
        Err(Error::Quota)
    );
    let maximum = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES];
    assert_eq!(
        host.key_call(
            29,
            &[
                vm::NativeArgument::Bytes(&[]),
                vm::NativeArgument::Bytes(&maximum),
                vm::NativeArgument::Bytes(&maximum),
                vm::NativeArgument::Bytes(&maximum),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            52,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"xvaluey"),
                vm::NativeArgument::Int(1),
                vm::NativeArgument::Int(5),
            ],
        ),
        Ok(vm::BufferResult::Void)
    );
    assert!(matches!(
        host.key_call(
            31,
            &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(7)]
        ),
        Ok(vm::BufferResult::Bytes(value)) if value == b"value"
    ));
    assert!(matches!(
        host.key_call(
            34,
            &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(7)]
        ),
        Ok(vm::BufferResult::Scalar(1))
    ));
    assert_eq!(
        host.key_call(
            52,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"value"),
                vm::NativeArgument::Int(4),
                vm::NativeArgument::Int(2),
            ],
        ),
        Err(Error::Bounds)
    );
    host.max_blob_bytes = 4;
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"value"),
            ]
        ),
        Err(Error::Quota)
    );
    host.max_blob_bytes = 8192;
    host.max_blob_records = 1;
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[]),
            ]
        ),
        Err(Error::Quota)
    );
    host.max_blob_records = 64;
    host.max_int_records = 1;
    assert_eq!(host.call(4, &[1, 1]), Ok(None));
    assert_eq!(host.call(4, &[2, 2]), Err(Error::Quota));
    assert!(matches!(
        host.key_call(
            22,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(1),
            ]
        ),
        Ok(vm::BufferResult::Bytes(token)) if token.len() == 32
    ));
    host.max_key_slots = 1;
    assert_eq!(
        host.key_call(
            22,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(1),
                vm::NativeArgument::Int(1),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            31,
            &[vm::NativeArgument::Int(1), vm::NativeArgument::Int(7)]
        ),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[0; MAX_DECLARED_BLOB_BYTES as usize + 1]),
            ]
        ),
        Err(Error::Quota)
    );
    for slot in 0..8 {
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(slot),
                vm::NativeArgument::Bytes(&[slot as u8; 1024]),
            ],
        )
        .unwrap();
    }
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[0]),
            ]
        ),
        Err(Error::Quota)
    );
    for slot in 0..8 {
        assert_eq!(
            host.key_call(
                33,
                &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(slot)]
            ),
            Ok(vm::BufferResult::Void)
        );
    }
    for slot in 0..64 {
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(slot),
                vm::NativeArgument::Bytes(&[]),
            ],
        )
        .unwrap();
    }
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(64),
                vm::NativeArgument::Bytes(&[]),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            33,
            &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(100)]
        ),
        Err(Error::Missing)
    );
}

#[test]
fn package_trust_boundaries_use_the_platform_crypto_provider() {
    use core::cell::Cell;

    struct TrackingPlatform {
        random: u8,
        calls: Rc<Cell<[usize; 2]>>,
    }
    impl crate::crypto::CryptoProvider for TrackingPlatform {
        fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32]> {
            let mut calls = self.calls.get();
            calls[0] += 1;
            self.calls.set(calls);
            Ok(crate::crypto::sha256(data))
        }

        fn p256_ecdsa_verify(
            &mut self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool> {
            let mut calls = self.calls.get();
            calls[1] += 1;
            self.calls.set(calls);
            Ok(crate::crypto::p256_ecdsa_verify(public_key, message, signature))
        }
    }
    impl crate::hal::Entropy for TrackingPlatform {
        fn fill_entropy(&mut self, bytes: &mut [u8]) -> Result<()> {
            self.random = self.random.wrapping_add(1);
            bytes.fill(self.random);
            Ok(())
        }
    }
    impl crate::hal::LogicalGpio for TrackingPlatform {
        fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
            Err(Error::Native)
        }
    }

    let calls = Rc::new(Cell::new([0; 2]));
    let platform = TrackingPlatform {
        random: 0,
        calls: Rc::clone(&calls),
    };
    let mut card = Card::open(MemoryFlash::new(16384), platform, STORAGE_KEY).unwrap();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    load(&mut card, &package).unwrap();
    assert_eq!(calls.get(), [5, 1]);

    let metadata = card.state.isd.packages.get("mscorlib").unwrap();
    let candidate = card.state.try_clone().unwrap();
    assert!(Rc::ptr_eq(metadata, candidate.isd.packages.get("mscorlib").unwrap()));
    let units = execution_units(&card.state, "ISD", "mscorlib").unwrap();
    assert!(core::ptr::eq(units[0].package.manifest, &metadata.manifest));
    visit_registry(&card.state, 0x10, |aid, entry| {
        registry_record(0x10, aid, entry).map(|_| ())
    }).unwrap();
    assert_eq!(calls.get(), [5, 1]);
    drop(units);
    drop(candidate);

    let flash = card.into_flash();
    let platform = TrackingPlatform {
        random: 0,
        calls: Rc::clone(&calls),
    };
    Card::open(flash, platform, STORAGE_KEY).unwrap();
    // Digest and signature again on reopening. A stored identity is the digest of a
    // key rather than a key, so there is nothing left for recovery to revalidate as a
    // curve point. A package whose key is wrong fails its signature instead.
    assert_eq!(calls.get(), [9, 2]);
}

#[test]
fn management_cbor_matches_shared_vectors_and_rejects_other_encodings() {
    assert_eq!(management_names_wire("bad/name", "Wallet"), Err(Error::Format));
    let vectors: serde_json::Value = serde_json::from_str(include_str!("../../../../format/management-names-v1.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let first = vector["first"].as_str().unwrap();
        let second = vector["second"].as_str().unwrap();
        let hex = vector["hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap()).collect();
        assert_eq!(management_names_wire(first, second).unwrap(), bytes);
        assert_eq!(management_names(&bytes), Ok((first, second)));
        let (domain, target) = management_names(&bytes).unwrap();
        for name in [domain, target] {
            let offset = name.as_ptr() as usize - bytes.as_ptr() as usize;
            assert!(offset + name.len() <= bytes.len(), "name was copied out of the command buffer");
        }
        for end in 0..bytes.len() { assert_eq!(management_names(&bytes[..end]), Err(Error::Format)); }
        let mut trailing = bytes.clone(); trailing.push(0);
        assert_eq!(management_names(&trailing), Err(Error::Format));
        let mut version = bytes.clone(); version[1] = 2;
        assert_eq!(management_names(&version), Err(Error::Format));
    }
    for bytes in [&b"[\"ISD\",\"Counter\"]"[..], &b"\x83\x01\x78\x03ISD\x67Counter"[..],
        &b"\x9f\x01\x63ISD\x67Counter\xff"[..], &b"\x83\x01\x60\x67Counter"[..]] {
        assert_eq!(management_names(bytes), Err(Error::Format));
    }
}
