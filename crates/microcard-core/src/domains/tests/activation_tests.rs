use super::*;

#[test]
fn maximum_application_staging_is_fallible_and_atomic() {
    let mut card = card();
    let incarnation = create(&mut card, "maximum-staging");
    let domain = card.state.domains.get_mut("maximum-staging").unwrap();
    domain.key = Some([0x44; 32]);
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
    let mut complete = StagedApplication::new_with(&card.state.domains["maximum-staging"], &mut complete_context).unwrap();
    let domain = &card.state.domains["maximum-staging"];
    let staged = complete.view(domain);
    assert!(*staged.store == domain.store);
    assert!(*staged.blobs == domain.blobs);
    assert!(*staged.keys == domain.keys);
    assert!(*staged.credentials == domain.credentials);
    let allocations = complete_context.allocations();
    assert!(allocations > 0);
    for fail_at in 0..allocations {
        let mut context = crate::fallible_clone::CloneContext::failing_at(fail_at);
        assert!(matches!(
            StagedApplication::new_with(&card.state.domains["maximum-staging"], &mut context),
            Err(Error::Quota)
        ));
        assert_eq!(card.state.encode_snapshot().unwrap().to_vec(), before);
    }

}

#[test]
fn package_activation_power_loss_preserves_complete_generations() {
    for version in [1, 2] {
        let mut c = card();
        let inc = create(&mut c, "a");
        if version == 2 {
            load(&mut c, &package("a", inc, "one", 1, 7, &[0x2a])).unwrap();
        }
        let p = package("a", inc, "one", version, 7, &[0x2a]);
        let previous = c.state.encode_snapshot().unwrap().to_vec();
        let base = c.into_flash();
        let mut complete = Mc04Engine::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        load(&mut complete, &p).unwrap();
        let serialized = complete.state.encode_snapshot().unwrap().to_vec(); // Journal mutation behavior is exhaustively tested separately.
        for cut in commit_cuts(serialized.len(), p.len()) {
            let mut f = base.clone();
            f.fail_after = Some(cut);
            let mut c = Mc04Engine::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
            if load(&mut c, &p).is_err() {
                assert_eq!(c.state.encode_snapshot().unwrap().as_slice(), previous);
                assert_eq!(c.staging.as_slice(), Some(p.as_slice()));
            }
            let marker_cut = 16384 + p.len() + 16384 + 47 + serialized.len();
            if cut == marker_cut {
                // The candidate is durable even though advancing the anchor failed.
                // A later upload must not recycle its slot before reboot resolves that.
                c.journal.flash_mut().fail_after = None;
                c.abort_staging();
                let replacement = package("a", inc, "one", version + 1, 7, &[0x2a]);
                assert_eq!(load(&mut c, &replacement), Err(Error::Storage));
            }
            let mut f = c.into_flash();
            f.fail_after = None;
            let mut recovered = Mc04Engine::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
            let actual = recovered.state.encode_snapshot().unwrap().to_vec();
            assert!(
                actual == previous || actual == serialized,
                "partial activation at cut {cut}"
            );
            load(&mut recovered, &p).unwrap();
            assert_eq!(recovered.state.encode_snapshot().unwrap().to_vec(), serialized);
            let reopened =
                Mc04Engine::open(recovered.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
            assert_eq!(reopened.state.encode_snapshot().unwrap().to_vec(), serialized);
        }
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
    card.manage(command(0xea, &[])).unwrap();
    assert!(card.staging.bytes.is_empty());
    let descriptor = card.state.domains["move"].image_refs["one"];
    assert_eq!(descriptor.read_verified(card.journal.flash(), &mut card.platform).unwrap(), initial);

    let mut flash = card.into_flash();
    flash.fail_after = Some(0);
    let mut card = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
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
    assert_eq!(card.manage_with_cancel(command(0xea, &[]), &mut || true), Err(Error::Cancelled));
    assert_eq!(card.staging.bytes.as_ptr(), staged_pointer);
    assert_eq!(card.state.domains["move"].versions["one"].0, 1);
    assert!(card.state.domains["move"].storage_declaration(2).is_none());
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
    let mut card = Mc04Engine::open_with_staging(
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
    assert_eq!(card.state.isd.image_refs["mscorlib"].read_verified(card.journal.flash(), &mut card.platform).unwrap(), package.as_slice());
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
    let mut card = Mc04Engine::open_with_staging(
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
    assert_eq!(card.state.isd.image_refs["mscorlib"].read_verified(card.journal.flash(), &mut card.platform).unwrap().as_ref(), package.as_slice());
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
        card.state.domains["large"].image_refs["large"].length as usize,
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
    let c = Mc04Engine::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(c.state.domains["a"].instances.is_empty());
    assert!(c.state.domains["a"].key.is_some());
}
