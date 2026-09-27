use super::*;

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
    load(
        &mut card,
        &transaction_records_package("effects", incarnation, 1, 7),
    )
    .unwrap();
    let calls = card
        .state
        .domains
        .get_mut("effects")
        .unwrap()
        .imports
        .get_mut("TransactionRecords")
        .unwrap();
    calls
        .iter_mut()
        .find(|binding| binding.target == CallTarget::Native(8))
        .unwrap()
        .target = CallTarget::Native(6);
    assert!(matches!(
        linking::BorrowedExecution::new(&card.state, card.journal.flash(), &mut card.platform, "effects", "TransactionRecords").and_then(|images| images.units().map(|_| ())),
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
        assert!(domain.image_refs.is_empty());
        assert!(domain.imports.is_empty());
    }
}

#[test]
fn execution_source_queue_is_deduplicated_and_bounded() {
    let mut card = card();
    let incarnation = create(&mut card, "queue");
    load(&mut card, &counter_package("queue", incarnation, 1, 7)).unwrap();

    let mut units = Vec::new();
    units.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
    push_execution_source(&card.state, &mut units, "queue", "Counter", None).unwrap();
    let digest = units[0].2.package_metadata("Counter").unwrap().digest;
    push_execution_source(&card.state, &mut units, "queue", "Counter", Some(digest)).unwrap();
    assert_eq!(units.len(), 1);
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert_eq!(
        push_execution_source(
            &card.state,
            &mut units,
            "queue",
            "Counter",
            Some(wrong_digest),
        ),
        Err(Error::Storage)
    );

    let isd = &card.state.isd;
    let mut full = Vec::new();
    full.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
    for _ in 0..MAX_EXECUTION_UNITS {
        full.push(("ISD", "mscorlib", isd));
    }
    assert_eq!(
        push_execution_source(&card.state, &mut full, "queue", "Counter", None),
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
