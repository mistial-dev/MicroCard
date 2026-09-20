use super::*;
use crate::{
    crypto::SoftwareCrypto,
    journal::MemoryFlash,
};
use microcard_engine_jcvm::cap::LoadFile;
use crate::{jcvm_test::{signed, Heaps, Provider}, journal::{Flash, JournalKey}};
use alloc::rc::Rc;
use core::cell::RefCell;

#[test]
fn heap_publication_failures_preserve_existing_instances_and_never_reuse_identity() {
    let raw = signed(7, 1, 7);
    let mut provider = Provider;
    let mut scratch = alloc::vec![0; 16384];
    let package = Package::verify(&raw, &mut provider, &mut scratch).unwrap();
    let file = LoadFile::parse(package.envelope.image).unwrap();
    let module = file.applets().unwrap().iter().next().unwrap().aid;
    let mut store = Store::open(MemoryFlash::new(4096), [3; 16], Registry::new([1; 16], None), &mut provider).unwrap();
    let mut images = crate::image_store::Images::new(MemoryFlash::with_images(4096, 2, 65536).unwrap()).unwrap();
    store.load(&mut images, &raw, &mut scratch, &mut provider, &mut || false).unwrap();
    let mut heaps = Heaps { banks: core::array::from_fn(|_| Rc::new(RefCell::new(MemoryFlash::new(65536)))), preparations: [0; 2], fail_write: None };
    let root = JournalKey::from([9; 16]);
    let mut request = crate::globalplatform::ApplicationInstall {
        load_aid: package.manifest.package, module_aid: module,
        instance_aid: &[0xf0, 1, 2, 3, 4], privileges: &[0], parameters: &[],
    };
    let (first, _) = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536).unwrap();
    let select = [0, 0xa4, 4, 0, 0];
    let wrong_pin = [0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 255, 255];
    let mut session = store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
    assert_eq!(session.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
    let before = session.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw;
    assert_eq!(before & 0xfff0, 0x63c0);
    drop(session);

    request.instance_aid = &[0xf0, 1, 2, 3, 5];
    // Insufficient transient RAM must not publish an otherwise valid installation.
    assert!(matches!(store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 0), Err(Error::Quota)));
    assert_eq!(store.state().unwrap().instances().count(), 1);
    heaps.fail_write = Some(128);
    assert!(store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536).is_err());
    assert_eq!(store.state().unwrap().instances().count(), 1);
    heaps.fail_write = None;
    // Let identity reservation finish, then fail publication after the heap commits.
    store.journal.flash_mut().fail_after = Some(4);
    assert!(matches!(store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536), Err(Error::Storage)));
    assert_eq!(store.state().unwrap().instances().count(), 1);
    let consumed = store.journal.flash_mut().nonce_generation().unwrap();
    store.journal.flash_mut().fail_after = None;
    let (second, _) = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536).unwrap();
    assert!(u64::from_le_bytes(second.identity[..8].try_into().unwrap()) > consumed);
    assert_ne!(first.identity, second.identity);
    assert_eq!(heaps.preparations, [1, 4]);
    let mut session = store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
    assert_eq!(session.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
    assert_eq!(session.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw + 1, before);
    drop(session);
    assert!(store.open_session(second.aid, &images, &mut heaps, &JournalKey::from([8; 16]), &mut scratch, &mut provider).is_err());
    assert!(store.open_session(second.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap().installed().unwrap());
    // Referenced erased heaps are errors, not an instruction to rerun install.
    *heaps.banks[0].borrow_mut() = MemoryFlash::new(65536);
    assert!(matches!(store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider), Err(Error::Storage)));
    assert_eq!(heaps.preparations, [1, 4]);
}

#[test]
fn registry_authority_rollback_and_uncertain_activation_survive_recovery() {
    let initial = Registry::new([1; 16], None);
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../../format/jcvm-registry-cbor-v2.json"))
            .unwrap();
    let hex = vector["hex"].as_str().unwrap();
    let expected: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(initial.encode().unwrap(), expected);
    assert_eq!(Registry::decode(&expected).unwrap(), initial);
    assert!(core::mem::size_of::<Registry>() <= MAX_SNAPSHOT_BYTES);
    let mut counters = initial;
    assert_eq!(counters.reserve_sequences(2).unwrap(), 1..=2);
    assert_eq!(
        Registry::decode(&counters.encode().unwrap())
            .unwrap()
            .reserve_sequences(1)
            .unwrap(),
        3..=3
    );
    assert_eq!(counters.reserve_sequences(0), Err(Error::Quota));
    assert_eq!(counters.reserve_sequences(0xffffff), Err(Error::Quota));
    let mut store = Store::open(
        MemoryFlash::new(4096),
        [3; 16],
        initial,
        &mut SoftwareCrypto,
    )
    .unwrap();
    let raw = signed(7, 1, 7);
    let mut scratch = alloc::vec![0; 16384];
    let package = Package::verify(&raw, &mut SoftwareCrypto, &mut scratch).unwrap();
    let image = Descriptor {
        slot: 0,
        length: raw.len() as u32,
        digest: package.envelope.package_digest,
    };
    let mut next = *store.state().unwrap();
    next.activate(&package, image).unwrap();
    let mut images =
        crate::image_store::Images::new(MemoryFlash::with_images(4096, 2, 65536).unwrap())
            .unwrap();
    assert_eq!(
        store
            .load(
                &mut images,
                &raw,
                &mut scratch,
                &mut SoftwareCrypto,
                &mut || false
            )
            .unwrap(),
        image
    );
    assert_eq!(store.state().unwrap(), &next);
    assert_eq!(
        store.state().unwrap().domains[0].unwrap().owner,
        Some(package.envelope.signer)
    );
    for (version, incarnation, private, error) in [
        (6, 1, 7, Error::Rollback),
        (8, 2, 7, Error::Domain),
        (8, 1, 8, Error::KeyMismatch),
    ] {
        let raw = signed(version, incarnation, private);
        let package = Package::verify(&raw, &mut SoftwareCrypto, &mut scratch).unwrap();
        let mut candidate = next;
        assert_eq!(
            candidate.activate(
                &package,
                Descriptor {
                    slot: 1,
                    length: raw.len() as u32,
                    digest: package.envelope.package_digest
                }
            ),
            Err(error.clone())
        );
        assert_eq!(candidate, next);
        let mut flash = images.into_flash().unwrap();
        flash.fail_after = Some(0);
        images = crate::image_store::Images::new(flash).unwrap();
        assert_eq!(
            store.load(
                &mut images,
                &raw,
                &mut scratch,
                &mut SoftwareCrypto,
                &mut || false
            ),
            Err(error)
        );
        let mut flash = images.into_flash().unwrap();
        flash.fail_after = None;
        images = crate::image_store::Images::new(flash).unwrap();
    }

    let raw = signed(8, 1, 7);
    let package = Package::verify(&raw, &mut SoftwareCrypto, &mut scratch).unwrap();
    let mut newer = next;
    newer
        .activate(
            &package,
            Descriptor {
                slot: 1,
                length: raw.len() as u32,
                digest: package.envelope.package_digest,
            },
        )
        .unwrap();
    for cut in [0, 65536 + 257] {
        let mut flash = images.into_flash().unwrap();
        flash.fail_after = Some(cut);
        images = crate::image_store::Images::new(flash).unwrap();
        assert_eq!(
            store.load(
                &mut images,
                &raw,
                &mut scratch,
                &mut SoftwareCrypto,
                &mut || false
            ),
            Err(Error::Storage)
        );
        assert_eq!(store.state().unwrap(), &next);
        images
            .with_image(&image, &mut SoftwareCrypto, |_| Ok(()))
            .unwrap();
        let mut flash = images.into_flash().unwrap();
        flash.fail_after = None;
        images = crate::image_store::Images::new(flash).unwrap();
    }
    for stop in [5, raw.len().div_ceil(256) + 5] {
        let mut polls = 0;
        assert_eq!(
            store.load(
                &mut images,
                &raw,
                &mut scratch,
                &mut SoftwareCrypto,
                &mut || {
                    polls += 1;
                    polls == stop
                }
            ),
            Err(Error::Cancelled)
        );
        assert_eq!(polls, stop);
        assert_eq!(store.state().unwrap(), &next);
        images
            .with_image(&image, &mut SoftwareCrypto, |_| Ok(()))
            .unwrap();
    }
    store.journal.flash_mut().fail_after = Some(0);
    assert_eq!(
        store.load(
            &mut images,
            &raw,
            &mut scratch,
            &mut SoftwareCrypto,
            &mut || false
        ),
        Err(Error::Storage)
    );
    assert_eq!(store.state().unwrap(), &next);
    // Burn nonce, mark reclaim, erase, write authenticated record and markers;
    // fail the anchor update after the new image has become authoritative.
    store.journal.flash_mut().fail_after =
        Some(4 + 1 + 4096 + 24 + newer.encode().unwrap().len() + 16 + 1 + 1);
    assert_eq!(
        store.load(
            &mut images,
            &raw,
            &mut scratch,
            &mut SoftwareCrypto,
            &mut || false
        ),
        Err(Error::Storage)
    );
    assert_eq!(store.state(), Err(Error::Storage));
    assert_eq!(
        store.load(
            &mut images,
            &raw,
            &mut scratch,
            &mut SoftwareCrypto,
            &mut || false
        ),
        Err(Error::Storage)
    );
    store.journal.flash_mut().fail_after = None;
    store.recover(&mut SoftwareCrypto).unwrap();
    assert_eq!(store.state().unwrap(), &newer);
    assert_eq!(
        store
            .state()
            .unwrap()
            .protected_images()
            .next()
            .unwrap()
            .slot,
        1
    );

    // Retrying an already active package verifies flash without consuming writes.
    store.journal.flash_mut().fail_after = Some(0);
    let mut flash = images.into_flash().unwrap();
    flash.fail_after = Some(0);
    images = crate::image_store::Images::new(flash).unwrap();
    assert_eq!(
        store
            .load(
                &mut images,
                &raw,
                &mut scratch,
                &mut SoftwareCrypto,
                &mut || false
            )
            .unwrap()
            .slot,
        1
    );
    store.journal.flash_mut().fail_after = None;
    let mut flash = images.into_flash().unwrap();
    flash.fail_after = None;
    images = crate::image_store::Images::new(flash).unwrap();

    let aid = Aid::new(&[0xf0, 1, 2, 3, 4]).unwrap();
    let file = LoadFile::parse(package.envelope.image).unwrap();
    let module = Aid::new(file.applets().unwrap().iter().next().unwrap().aid).unwrap();
    newer.register(&package, module, aid, [4; 16], 0).unwrap();
    store.commit(newer, &mut SoftwareCrypto).unwrap();
    store.recover(&mut SoftwareCrypto).unwrap();
    assert_eq!(store.state().unwrap().instances().next().unwrap().aid, aid);
    let load = Aid::new(package.manifest.package).unwrap();
    assert_eq!(
        store.with_package(load, &images, &mut scratch, &mut SoftwareCrypto, |p| Ok(p
            .manifest
            .version)),
        Ok(8)
    );
    assert_eq!(newer.remove_load(load), Err(Error::Busy));
    newer.remove_instance(aid).unwrap();
    newer.remove_load(load).unwrap();
    store.commit(newer, &mut SoftwareCrypto).unwrap();
    let mut reopened =
        Store::open(store.into_flash(), [3; 16], initial, &mut SoftwareCrypto).unwrap();
    let mut tombstone = *reopened.state().unwrap();
    assert_eq!(
        tombstone.activate(
            &package,
            Descriptor {
                slot: 1,
                length: raw.len() as u32,
                digest: package.envelope.package_digest
            }
        ),
        Err(Error::Rollback)
    );
    assert_eq!(tombstone.loads().next().unwrap().version, 8);
    assert_eq!(tombstone.protected_images().count(), 0);
    reopened.recover(&mut SoftwareCrypto).unwrap();

    let mut duplicate = initial;
    duplicate.domains[1] = duplicate.domains[0];
    assert_eq!(duplicate.encode(), Err(Error::Format));
    let child = Aid::new(&[0xf0, 5, 6, 7, 8]).unwrap();
    assert_eq!(
        {
            let mut unclaimed = initial;
            unclaimed.add_domain(child, [2; 16])
        },
        Err(Error::Unauthorized)
    );
    tombstone.add_domain(child, [2; 16]).unwrap();
    assert_eq!(
        tombstone.domains().find(|d| d.aid == child).unwrap().owner,
        tombstone.domains[0].unwrap().owner
    );
    assert_eq!(
        tombstone.remove_domain(Aid::isd()),
        Err(Error::Unauthorized)
    );
    tombstone.remove_domain(child).unwrap();
    let mut old = expected.clone();
    old[2] = 0;
    assert_eq!(Registry::decode(&old), Err(Error::IncompatibleState));
    let mut trailing = expected;
    trailing.push(0);
    assert_eq!(Registry::decode(&trailing), Err(Error::Format));
}

#[test]
fn pending_renewal_binds_staging_and_blocks_ordinary_use_after_reboot() {
    let aid = Aid::new(&[0xf0, 1, 2, 3, 4]).unwrap();
    let load = Aid::new(&[0xf0, 1, 2, 3, 5]).unwrap();
    let mut initial = Registry::new([1; 16], Some([2; 32]));
    initial.loads[0] = Some(Load { domain: Aid::isd(), aid: load, version: 1,
        image: Some(Descriptor { slot: 0, length: 512, digest: [3; 32] }) });
    initial.instances[0] = Some(Instance { domain: Aid::isd(), load, module: aid,
        aid, identity: [4; 16], heap_bank: 0 });
    let renewal = Renewal { aid, bank: 0, old_identity: [4; 16], new_identity: [5; 16],
        package_digest: [3; 32], record_length: 1024, record_digest: [6; 32] };
    let mut pending = initial;
    pending.renewal = Some(renewal);
    let encoded = pending.encode().unwrap();
    let vector: serde_json::Value = serde_json::from_str(include_str!("../../../../format/jcvm-registry-cbor-v2.json")).unwrap();
    let hex = vector["pending_hex"].as_str().unwrap();
    let expected: Vec<_> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    assert_eq!(encoded, expected);
    assert_eq!(Registry::decode(&encoded), Ok(pending));
    for case in 0..7 {
        let mut broken = pending;
        let descriptor = broken.renewal.as_mut().unwrap();
        match case {
            0 => descriptor.aid = load,
            1 => descriptor.bank = 1,
            2 => descriptor.old_identity = [7; 16],
            3 => descriptor.new_identity = descriptor.old_identity,
            4 => descriptor.package_digest = [7; 32],
            5 => descriptor.record_length = 40,
            _ => descriptor.record_length = 65534,
        }
        assert_eq!(broken.encode(), Err(Error::Format), "case {case}");
    }
    for end in 0..encoded.len() { assert!(Registry::decode(&encoded[..end]).is_err()); }
    let mut trailing = encoded.clone(); trailing.push(0);
    assert!(Registry::decode(&trailing).is_err());
    let mut legacy = initial.encode().unwrap();
    legacy[0] = 0x86; legacy[1] = 1; legacy.pop();
    assert_eq!(Registry::decode(&legacy), Err(Error::IncompatibleState));

    let mut store = Store::open(MemoryFlash::new(4096), [3; 16], initial, &mut SoftwareCrypto).unwrap();
    let base = store.journal.flash_mut().clone();
    store.journal.flash_mut().fail_after = Some(usize::MAX);
    store.commit(pending, &mut SoftwareCrypto).unwrap();
    let mutations = usize::MAX - store.journal.flash_mut().fail_after.unwrap();
    for cut in [0, 4, 5, mutations / 2, mutations - 5, mutations - 4, mutations - 1, mutations] {
        let mut store = Store::open(base.clone(), [3; 16], initial, &mut SoftwareCrypto).unwrap();
        store.journal.flash_mut().fail_after = Some(cut);
        let published = store.commit(pending, &mut SoftwareCrypto).is_ok();
        let mut flash = store.into_flash(); flash.fail_after = None;
        let mut rebooted = Store::open(flash, [3; 16], initial, &mut SoftwareCrypto).unwrap();
        if rebooted.pending_renewal().unwrap().is_some() {
            assert_eq!(rebooted.pending_renewal().unwrap(), Some(&renewal));
            assert_eq!(rebooted.state(), Err(Error::Busy));
            assert_eq!(rebooted.commit(initial, &mut SoftwareCrypto), Err(Error::Busy));
            assert_eq!(rebooted.pending_renewal().unwrap(), Some(&renewal));
        } else {
            assert!(!published, "published ownership lost at cut {cut}");
            assert_eq!(rebooted.state(), Ok(&initial));
        }
    }
}

#[test]
fn renewal_recovery_authenticates_before_reclaim_and_never_reencrypts_the_heap() {
    use crate::{crypto::CryptoProvider, hal::StagingFlash, staging::{BoundedFlashStaging, PackageStaging}};
    struct Scratch(Vec<u8>);
    impl StagingFlash for Scratch {
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
    struct RecoveryProvider([u8; 16]);
    impl CryptoProvider for RecoveryProvider {
        fn aes_ccm_encrypt_in_place(&mut self, key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], output: &mut [u8]) -> Result<usize> {
            assert_ne!(key, &self.0, "recovery encrypted under the renewed heap key");
            SoftwareCrypto.aes_ccm_encrypt_in_place(key, nonce, aad, output)
        }
    }
    let raw = signed(7, 1, 7);
    let mut provider = Provider;
    let mut scratch = alloc::vec![0; 16384];
    let package = Package::verify(&raw, &mut provider, &mut scratch).unwrap();
    let module = LoadFile::parse(package.envelope.image).unwrap().applets().unwrap().iter().next().unwrap().aid;
    let mut store = Store::open(MemoryFlash::new(4096), [3; 16], Registry::new([1; 16], None), &mut provider).unwrap();
    let mut images = crate::image_store::Images::new(MemoryFlash::with_images(4096, 2, 65536).unwrap()).unwrap();
    store.load(&mut images, &raw, &mut scratch, &mut provider, &mut || false).unwrap();
    let mut heaps = Heaps { banks: core::array::from_fn(|_| Rc::new(RefCell::new(MemoryFlash::new(65536)))), preparations: [0; 2], fail_write: None };
    let root = JournalKey::from([9; 16]);
    let mut request = crate::globalplatform::ApplicationInstall {
        load_aid: package.manifest.package, module_aid: module, instance_aid: &[0xf0, 1, 2, 3, 4], privileges: &[0], parameters: &[],
    };
    let (first, _) = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536).unwrap();
    request.instance_aid = &[0xf0, 1, 2, 3, 5];
    let (second, _) = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false, 65536).unwrap();
    let mut live = store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
    let select = [0, 0xa4, 4, 0, 0];
    let wrong_pin = [0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 255, 255];
    assert_eq!(live.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
    let pin_status = live.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw;
    assert_eq!(pin_status & 0xfff0, 0x63c0);
    let mut staging = BoundedFlashStaging::<_, 65536>::new(Scratch(alloc::vec![0xff; 65536]));
    struct FailedEncryption;
    impl CryptoProvider for FailedEncryption {
        fn aes_ccm_encrypt_in_place(&mut self, _: &[u8; 16], _: &[u8; 13], _: &[u8], _: &mut [u8]) -> Result<usize> { Err(Error::Native) }
    }
    let preparations = heaps.preparations;
    let generation = heaps.banks[first.heap_bank as usize].borrow().monotonic_generation().unwrap();
    let nonce = store.journal.flash_mut().nonce_generation().unwrap();
    assert_eq!(store.begin_renewal(first.aid, &live, &images, &heaps, &root, &mut staging, &mut scratch, &mut FailedEncryption), Err(Error::Native));
    let consumed = store.journal.flash_mut().nonce_generation().unwrap();
    assert_eq!(consumed, nonce + 1);
    assert!(staging.is_empty());
    assert!(store.pending_renewal().unwrap().is_none());
    let before_publication = store.journal.flash_mut().clone();
    let initial = *store.state().unwrap();
    let renewal = store.begin_renewal(first.aid, &live, &images, &heaps, &root, &mut staging, &mut scratch, &mut provider).unwrap();
    let identity = renewal.new_identity;
    assert!(u64::from_le_bytes(identity[..8].try_into().unwrap()) > consumed);
    assert!(live.selected().unwrap(), "staging does not deselect the running applet");
    assert_eq!(heaps.preparations, preparations);
    assert_eq!(heaps.banks[first.heap_bank as usize].borrow().monotonic_generation(), Ok(generation));
    // A separate interruption starts from the same pre-publication state. The pending
    // marker reaches flash, but its anchor cannot advance until reboot.
    let mut interrupted = Store::open(before_publication, [3; 16], initial, &mut provider).unwrap();
    let before_anchor = 4 + 4 + 1 + 4096 + 40 + store.state.encode().unwrap().len() + 1 + 1;
    interrupted.journal.flash_mut().fail_after = Some(before_anchor);
    let mut protected = BoundedFlashStaging::<_, 65536>::new(Scratch(alloc::vec![0xff; 65536]));
    assert_eq!(interrupted.begin_renewal(first.aid, &live, &images, &heaps, &root, &mut protected, &mut scratch, &mut provider), Err(Error::Storage));
    assert!(!protected.is_empty(), "uncertain publication must retain staging ownership");
    let mut flash = interrupted.into_flash(); flash.fail_after = None;
    let interrupted = Store::open(flash, [3; 16], initial, &mut provider).unwrap();
    let owner = interrupted.pending_renewal().unwrap().unwrap();
    let bytes = protected.read_all().unwrap();
    let mut staged_hash = [0; 32]; provider.sha256_into(&bytes, &mut staged_hash).unwrap();
    assert_eq!(owner.record_digest, staged_hash);
    assert_eq!(heaps.preparations, preparations);
    drop(live);
    let key = crate::jcvm_storage::heap_key(&mut provider, &root, first.heap_bank, &identity, &package.envelope.image_digest).unwrap();
    let forbidden = *key.as_ref();
    let length = renewal.record_length as usize;
    let pending = store.state;
    let base = store.into_flash();
    let mut corrupt = alloc::vec![0; 65536]; staging.read_persistent(0, &mut corrupt).unwrap(); corrupt[24] ^= 1;
    let bad_staging = BoundedFlashStaging::<_, 65536>::new(Scratch(corrupt));
    let mut store = Store::open(base.clone(), [3; 16], pending, &mut provider).unwrap();
    let preparations = heaps.preparations;
    assert_eq!(store.recover_renewal(&images, &mut heaps, &root, &bad_staging, &mut scratch, &mut provider), Err(Error::Authentication));
    assert_eq!(heaps.preparations, preparations);
    assert!(store.recover_renewal(&images, &mut heaps, &JournalKey::from([8; 16]), &staging, &mut scratch, &mut provider).is_err());
    assert_eq!(heaps.preparations, preparations);
    assert_eq!(store.pending_renewal().unwrap(), Some(&renewal));

    // Both banks remain occupied. Only the named bank can be prepared.
    let untouched_generation = heaps.banks[second.heap_bank as usize].borrow().monotonic_generation().unwrap();
    let mut final_state = pending;
    final_state.renewal = None;
    final_state.instances.iter_mut().flatten().find(|i| i.aid == first.aid).unwrap().identity = identity;
    // Registry nonce, reclaim intent, erase, header/tag/payload, markers, anchor.
    let publication_bytes = 4 + 1 + 4096 + 40 + final_state.encode().unwrap().len() + 1 + 1 + 4;
    for (bank_cut, registry_cut) in [(Some(0), None), (Some(length / 2), None),
            (None, Some(0)), (None, Some(4)), (None, Some(publication_bytes - 5)),
            (None, Some(publication_bytes - 1)), (None, None)] {
        let mut store = Store::open(base.clone(), [3; 16], pending, &mut provider).unwrap();
        heaps.fail_write = bank_cut;
        store.journal.flash_mut().fail_after = registry_cut;
        let mut recovery_provider = RecoveryProvider(forbidden);
        let result = store.recover_renewal(&images, &mut heaps, &root, &staging, &mut scratch, &mut recovery_provider);
        if bank_cut.is_some() || registry_cut.is_some() { assert_eq!(result, Err(Error::Storage)); }
        else { result.unwrap(); }
        let mut flash = store.into_flash(); flash.fail_after = None;
        heaps.fail_write = None;
        let mut rebooted = Store::open(flash, [3; 16], pending, &mut provider).unwrap();
        rebooted.recover_renewal(&images, &mut heaps, &root, &staging, &mut scratch, &mut recovery_provider).unwrap();
        assert!(rebooted.pending_renewal().unwrap().is_none());
        assert_eq!(rebooted.state().unwrap().instances().count(), 2);
        assert_eq!(rebooted.state().unwrap().instances().find(|i| i.aid == first.aid).unwrap().identity, identity);
        let bank = heaps.banks[first.heap_bank as usize].borrow();
        assert_eq!(bank.monotonic_generation(), Ok(1)); assert_eq!(bank.nonce_generation(), Ok(1)); drop(bank);
        let preparations = heaps.preparations;
        rebooted.recover_renewal(&images, &mut heaps, &root, &bad_staging, &mut scratch, &mut recovery_provider).unwrap();
        assert_eq!(heaps.preparations, preparations, "completed renewal must not repeat preparation");
        let mut session = rebooted.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
        assert_eq!(session.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
        assert_eq!(session.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw + 1, pin_status,
            "renewal must preserve consumed PIN attempts");
    }
    assert_eq!(heaps.preparations[second.heap_bank as usize], 1);
    assert_eq!(heaps.banks[second.heap_bank as usize].borrow().monotonic_generation(), Ok(untouched_generation));
}
