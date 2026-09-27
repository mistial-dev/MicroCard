use super::*;

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
fn lifecycle_callbacks_share_staging_and_roll_back_registry_and_data() {
    let mut card = card();
    for (name, aid) in [("first", "F04D431001"), ("second", "F04D431002")] {
        let incarnation = create(&mut card, name);
        let raw = counter_package(name, incarnation, 1, 7);
        let view = PackageView::verify(&raw).unwrap();
        let mut manifest = view.manifest.clone();
        manifest.entry_points[0].aid = aid.into();
        manifest.entry_points[0].select = Some(1);
        manifest.entry_points[0].deselect = Some(1);
        manifest.entry_points[0].uninstall = Some(1);
        load(&mut card, &signed_compiled_package(&manifest, view.image, 7)).unwrap();
        card.manage(command(0xec, &management_names_wire(name, aid).unwrap())).unwrap();
    }
    card.select("F04D431001").unwrap();
    card.select("F04D431001").unwrap();
    assert_eq!(card.state.domains["first"].store.get(&1), Some(&3));

    // The old callback succeeds before the target overflows. Neither write publishes.
    let mut next = ApplicationChanges::new();
    next.view(&card.state.domains["second"]).unwrap().store.insert(1, i32::MAX).unwrap();
    card.commit_application_changes(next).unwrap();
    let before = card.state.encode_snapshot().unwrap().to_vec();
    assert!(card.select("F04D431002").is_err());
    assert_eq!(card.state.encode_snapshot().unwrap().as_slice(), before);
    assert_eq!(card.selected.as_ref().unwrap().2, "F04D431001");

    let mut next = ApplicationChanges::new();
    next.view(&card.state.domains["second"]).unwrap().store.insert(1, 0).unwrap();
    card.commit_application_changes(next).unwrap();
    let before = card.state.encode_snapshot().unwrap().to_vec();
    card.journal.flash_mut().fail_after = Some(0);
    assert_eq!(card.select("F04D431002"), Err(Error::Storage));
    card.journal.flash_mut().fail_after = None;
    assert_eq!(card.state.encode_snapshot().unwrap().as_slice(), before);
    assert_eq!(card.selected.as_ref().unwrap().2, "F04D431001");
    assert_eq!(card.select_with_cancel("F04D431002", &mut || true), Err(Error::Cancelled));
    assert_eq!(card.state.encode_snapshot().unwrap().as_slice(), before);

    card.select("F04D431002").unwrap();
    assert_eq!(card.state.domains["first"].store.get(&1), Some(&4));
    assert_eq!(card.state.domains["second"].store.get(&1), Some(&1));
    card.select_isd_with_cancel(&mut || false).unwrap();
    assert!(card.selected.is_none());
    // Registry publication and callback writes must roll back as one change.
    for instruction in [0xee, 0xec] {
        let before = card.state.encode_snapshot().unwrap().to_vec();
        let request = management_names_wire("first", "F04D431001").unwrap();
        card.journal.flash_mut().fail_after = Some(0);
        assert_eq!(card.manage(command(instruction, &request)), Err(Error::Storage));
        card.journal.flash_mut().fail_after = None;
        assert_eq!(card.state.encode_snapshot().unwrap().as_slice(), before);
        card.manage(command(instruction, &request)).unwrap();
    }
    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(reopened.state.domains["first"].instances.contains_key("F04D431001"));
    assert_eq!(reopened.state.domains["first"].store.get(&1), Some(&0));
    assert_eq!(reopened.state.domains["second"].store.get(&1), Some(&2));
}

#[test]
fn explicit_transaction_lifecycle_is_bounded_and_owner_scoped() {
    let mut card = card();
    let incarnation = create(&mut card, "transaction");
    load(
        &mut card,
        &transaction_records_package("transaction", incarnation, 1, 7),
    )
    .unwrap();
    assert_eq!(
        load(
            &mut card,
            &transaction_negative_package("transaction", incarnation, 1, 7),
        ),
        Err(Error::Unsupported)
    );
    load(&mut card, &counter_package("transaction", incarnation, 1, 7)).unwrap();
    card.manage(command(0xec, &management_names_wire("transaction", "F04D430020").unwrap()))
        .unwrap();
    card.manage(command(0xec, &management_names_wire("transaction", "F04D430001").unwrap()))
        .unwrap();
    let generation = card.journal.generation();
    let (_, abort_metrics) = card
        .invoke_context_with_metrics("F04D430020", &[1, 11, 22, 33], 0)
        .unwrap();
    assert_eq!(abort_metrics.transaction_snapshots, 1);
    assert!(card.transaction.is_none());
    assert_eq!(card.journal.generation(), generation);
    assert_eq!(card.invoke("F04D430020", &[2]).unwrap(), [0, 0, 0, 0x90, 0]);

    let (_, commit_metrics) = card
        .invoke_context_with_metrics("F04D430020", &[0, 11, 22, 33], 0)
        .unwrap();
    assert_eq!(commit_metrics.transaction_snapshots, 1);
    assert!(card.transaction.is_none());
    assert_eq!(card.journal.generation(), generation + 1);
    assert_eq!(
        card.invoke("F04D430020", &[2]).unwrap(),
        [11, 22, 33, 0x90, 0]
    );

    let generation = card.journal.generation();
    stage_pending_transaction(&mut card, 44, 2);
    assert_eq!(card.invoke("F04D430020", &[2]).unwrap(), [44, 22, 33, 0x90, 0]);
    assert_eq!(card.invoke("F04D430020", &[2]), Err(Error::Budget));
    assert!(card.transaction.is_none(), "expired transaction remained active");
    assert_eq!(card.journal.generation(), generation);
    assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));

    stage_pending_transaction(&mut card, 55, MAX_TRANSACTION_COMMANDS);
    card.select("F04D430001").unwrap();
    assert!(card.transaction.is_none(), "selection retained another applet's transaction");
    assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));

    stage_pending_transaction(&mut card, 66, MAX_TRANSACTION_COMMANDS);
    assert_eq!(card.invoke("F04D430001", &[0]).unwrap(), [12, 0x90, 0]);
    assert!(card.transaction.is_none(), "another applet controlled the transaction");
    assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&12));

    stage_pending_transaction(&mut card, 77, MAX_TRANSACTION_COMMANDS);
    let mut card = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(card.transaction.is_none(), "reset recovered an in-memory transaction");
    assert_eq!(card.invoke("F04D430020", &[2]).unwrap(), [12, 22, 33, 0x90, 0]);
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
            instructions: 294,
            peak_evaluation_slots: 7,
            peak_local_slots: 10,
            peak_frames: 2,
            peak_transient_bytes: 126,
            peak_transient_objects: 7,
            native_work_units: 124,
            transaction_snapshots: 0,
            transaction_clone_allocations: 0,
        }
    );
    assert!(peak.instructions <= 512);
    assert!(peak.peak_evaluation_slots <= 8);
    assert!(peak.peak_local_slots <= 16);
    assert!(peak.peak_frames <= 4);
    assert!(peak.peak_transient_bytes <= 128);
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

    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
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

    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(!reopened.state.domains["cancel"].store.contains_key(&30));
}

#[test]
fn ordinary_commands_avoid_rollback_state_and_commit_only_changes() {
    let mut card = card();
    let incarnation = create(&mut card, "ordinary");
    load(
        &mut card,
        &counter_package("ordinary", incarnation, 1, 7),
    )
    .unwrap();
    load(
        &mut card,
        &key_operations_package("ordinary", incarnation, 1, 7),
    )
    .unwrap();
    for aid in ["F04D430001", "F04D430012"] {
        card.manage(command(
            0xec,
            &management_names_wire("ordinary", aid).unwrap(),
        ))
        .unwrap();
    }

    for (name, aid, data, expected_commits) in [
        ("no-op", "F04D430012", &[2][..], 0),
        ("integer-write", "F04D430001", &[][..], 1),
        ("blob-write", "F04D430012", &[0][..], 1),
    ] {
        card.journal.flash_mut().reset_metrics();
        let generation = card.journal.generation();
        let started = std::time::Instant::now();
        let (_, execution) = card.invoke_context_with_metrics(aid, data, 0).unwrap();
        let elapsed = started.elapsed();
        let flash = card.journal.flash_mut().metrics();
        let commits = card.journal.generation() - generation;

        std::eprintln!(
            "{name}: commits={commits} program_calls={} programmed_bytes={} erase_calls={} erased_bytes={} elapsed_us={}",
            flash.program_calls,
            flash.programmed_bytes,
            flash.erase_calls,
            flash.erased_bytes,
            elapsed.as_micros()
        );
        assert_eq!(commits, expected_commits);
        assert_eq!(execution.transaction_snapshots, 0);
        assert_eq!(execution.transaction_clone_allocations, 0);
        assert_eq!(flash.programmed_bytes == 0, expected_commits == 0);
        if expected_commits == 0 {
            assert_eq!(flash.erase_calls, 0);
            assert_eq!(flash.erased_bytes, 0);
        }
    }
}

// Primitive tests sweep every flash byte. Domain tests exercise both sides of each
// storage phase and the state changes that must commit together.
#[test]
fn invocation_and_package_removal_boundaries_recover_old_or_new_state() {
    let mut card = card();
    let incarnation = create(&mut card, "atomic");
    load(&mut card, &counter_package("atomic", incarnation, 1, 7)).unwrap();
    card.manage(command(0xec, &management_names_wire("atomic", "F04D430001").unwrap()))
        .unwrap();
    let unrelated = create(&mut card, "untouched");
    load(&mut card, &counter_package("untouched", unrelated, 1, 8)).unwrap();
    let mut next = card.state.clone();
    next.domains.get_mut("untouched").unwrap().store.insert(1, 123).unwrap();
    card.commit(next).unwrap();
    let previous = card.state.encode_snapshot().unwrap().to_vec();
    let base = card.into_flash();

    for remove in [false, true] {
        let mutate = |card: &mut Mc04Engine<MemoryFlash, TestPlatform>| {
            if remove {
                card.manage(command(0xf0, &management_names_wire("untouched", "Counter").unwrap()))
            } else {
                card.invoke("F04D430001", &[])
            }
        };
        let mut complete = Mc04Engine::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        mutate(&mut complete).unwrap();
        assert_eq!(complete.state.domains["untouched"].store.get(&1), Some(&123));
        let committed = complete.state.encode_snapshot().unwrap().to_vec();
        for cut in commit_cuts(committed.len(), 0) {
            let mut flash = base.clone();
            flash.fail_after = Some(cut);
            let mut interrupted = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let result = mutate(&mut interrupted);
            assert_eq!(interrupted.state.domains["untouched"].store.get(&1), Some(&123));
            let mut flash = interrupted.into_flash();
            flash.fail_after = None;
            let recovered = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let actual = recovered.state.encode_snapshot().unwrap().to_vec();
            if remove {
                assert!(
                    actual == previous || actual == committed,
                    "partial package removal at cut {cut}"
                );
            } else {
                assert_eq!(
                    actual.as_slice(),
                    if result.is_ok() { committed.as_slice() } else { previous.as_slice() },
                    "invocation result must identify the authoritative state at cut {cut}"
                );
            }
        }
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
