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
    let first = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false).unwrap();
    let select = [0, 0xa4, 4, 0, 0];
    let wrong_pin = [0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 255, 255];
    let mut session = store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
    assert_eq!(session.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
    let before = session.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw;
    assert_eq!(before & 0xfff0, 0x63c0);
    drop(session);

    request.instance_aid = &[0xf0, 1, 2, 3, 5];
    heaps.fail_write = Some(128);
    assert!(store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false).is_err());
    assert_eq!(store.state().unwrap().instances().count(), 1);
    heaps.fail_write = None;
    // Let identity reservation finish, then fail publication after the heap commits.
    store.journal.flash_mut().fail_after = Some(4);
    assert_eq!(store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false), Err(Error::Storage));
    assert_eq!(store.state().unwrap().instances().count(), 1);
    let consumed = store.journal.flash_mut().nonce_generation().unwrap();
    store.journal.flash_mut().fail_after = None;
    let second = store.install(&request, &images, &mut heaps, &root, &mut scratch, &mut provider, &mut || false).unwrap();
    assert!(u64::from_le_bytes(second.identity[..8].try_into().unwrap()) > consumed);
    assert_ne!(first.identity, second.identity);
    assert_eq!(heaps.preparations, [1, 3]);
    let mut session = store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap();
    assert_eq!(session.process(&select, true, &mut provider, &mut || false).unwrap().sw, 0x9000);
    assert_eq!(session.process(&wrong_pin, false, &mut provider, &mut || false).unwrap().sw + 1, before);
    drop(session);
    assert!(store.open_session(second.aid, &images, &mut heaps, &JournalKey::from([8; 16]), &mut scratch, &mut provider).is_err());
    assert!(store.open_session(second.aid, &images, &mut heaps, &root, &mut scratch, &mut provider).unwrap().installed().unwrap());
    // Referenced erased heaps are errors, not an instruction to rerun install.
    *heaps.banks[0].borrow_mut() = MemoryFlash::new(65536);
    assert!(matches!(store.open_session(first.aid, &images, &mut heaps, &root, &mut scratch, &mut provider), Err(Error::Storage)));
    assert_eq!(heaps.preparations, [1, 3]);
}

#[test]
fn registry_authority_rollback_and_uncertain_activation_survive_recovery() {
    let initial = Registry::new([1; 16], None);
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../../format/jcvm-registry-cbor-v1.json"))
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
