use super::*;

fn provider_package(
    incarnation: [u8; 16],
    name: &str,
    image: &[u8],
    capabilities: Vec<u8>,
) -> Vec<u8> {
    let manifest = Manifest {
        domain: "ISD".into(),
        incarnation,
        assembly: name.into(),
        assembly_version: [0, 1, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 1,
            key: None,
        },
        entry_points: Vec::new(),
        dependencies: Vec::new(),
        capabilities,
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(&manifest, image, 42)
}

fn credential_package(incarnation: [u8; 16]) -> Vec<u8> {
    let signer =
        crate::crypto::signer_identity(&crate::crypto::p256_public_key(&[42; 32]).unwrap());
    let exact = |assembly: &str| Dependency {
        assembly: assembly.into(),
        ranges: alloc::vec![VersionRange {
            min: Some([0, 1, 0, 0]),
            min_inclusive: true,
            max: Some([0, 1, 0, 0]),
            max_inclusive: true,
        }],
        package_version: 1,
        signer: Some(signer),
        digest: None,
        scope: 1,
    };
    let manifest = Manifest {
        domain: "credential-budget".into(),
        incarnation,
        assembly: "Credential".into(),
        assembly_version: [0, 1, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![AssemblyEntry {
            aid: "F04D4308C0".into(),
            process: 1,
            install: Some(0),
            uninstall: None,
            select: None,
            deselect: None,
        }],
        dependencies: alloc::vec![
            exact("MicroCard.Cryptography"),
            exact("MicroCard.Security"),
        ],
        capabilities: alloc::vec![2, 11, 12, 13, 31, 52],
        storage: alloc::vec![StorageDeclaration {
            key: 1,
            kind: 2,
            max_bytes: 248,
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
        include_bytes!("../../../../../fuzz/fixtures/credential.mca"),
        7,
    )
}

fn cryptography_consumer_package(incarnation: [u8; 16]) -> Vec<u8> {
    let signer =
        crate::crypto::signer_identity(&crate::crypto::p256_public_key(&[42; 32]).unwrap());
    let manifest = Manifest {
        domain: "crypto-offset".into(),
        incarnation,
        assembly: "CryptographyConsumer".into(),
        assembly_version: [0, 1, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: alloc::vec![AssemblyEntry {
            aid: "F04D4306C0".into(),
            process: 2,
            install: Some(0),
            uninstall: Some(1),
            select: None,
            deselect: None,
        }],
        dependencies: alloc::vec![Dependency {
            assembly: "MicroCard.Cryptography".into(),
            ranges: alloc::vec![VersionRange {
                min: Some([0, 1, 0, 0]),
                min_inclusive: true,
                max: Some([0, 1, 0, 0]),
                max_inclusive: true,
            }],
            package_version: 0,
            signer: Some(signer),
            digest: None,
            scope: 1,
        }],
        capabilities: alloc::vec![2, 11, 12, 13, 20, 50],
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    signed_compiled_package(
        &manifest,
        include_bytes!("../../../../../fuzz/fixtures/cryptography_consumer.mca"),
        7,
    )
}

#[test]
fn sha256_offset_api_writes_a_caller_owned_destination() {
    let mut card = card();
    let isd_incarnation = card.state.isd.incarnation;
    load(
        &mut card,
        &provider_package(
            isd_incarnation,
            "MicroCard.Cryptography",
            include_bytes!("../../../../../fuzz/fixtures/cryptography.mca"),
            alloc::vec![
                20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38, 39, 49,
                50, 51,
            ],
        ),
    )
    .unwrap();
    let incarnation = create(&mut card, "crypto-offset");
    load(&mut card, &cryptography_consumer_package(incarnation)).unwrap();
    card.manage(command(0xec, &management_names_wire("crypto-offset", "F04D4306C0").unwrap()))
        .unwrap();

    let payload = b"offset input";
    let mut command = alloc::vec![0];
    command.extend_from_slice(payload);
    let response = card.invoke("F04D4306C0", &command).unwrap();
    let mut expected = crate::crypto::sha256(payload).to_vec();
    expected.extend_from_slice(&[0x90, 0]);
    assert_eq!(response, expected);
    assert_eq!(card.invoke("F04D4306C0", &[12, 1]), Err(Error::Bounds));
    assert_eq!(card.invoke("F04D4306C0", &[13, 1]), Err(Error::Bounds));
    let alias_payload = [0x5a; 40];
    let mut alias_command = alloc::vec![14];
    alias_command.extend_from_slice(&alias_payload);
    let mut alias_expected = crate::crypto::sha256(&alias_payload).to_vec();
    alias_expected.extend_from_slice(&[0x90, 0]);
    assert_eq!(card.invoke("F04D4306C0", &alias_command).unwrap(), alias_expected);
    let random = card.invoke("F04D4306C0", &[16]).unwrap();
    assert_eq!(random.len(), 34);
    assert_ne!(&random[..32], &[0; 32]);
    assert_eq!(card.invoke("F04D4306C0", &[17]), Err(Error::Bounds));
}

fn observe(
    peak: &mut crate::mc04_vm::ExecutionMetrics,
    measured: crate::mc04_vm::ExecutionMetrics,
) {
    peak.instructions = peak.instructions.max(measured.instructions);
    peak.peak_evaluation_slots = peak
        .peak_evaluation_slots
        .max(measured.peak_evaluation_slots);
    peak.peak_local_slots = peak.peak_local_slots.max(measured.peak_local_slots);
    peak.peak_frames = peak.peak_frames.max(measured.peak_frames);
    peak.peak_transient_bytes = peak.peak_transient_bytes.max(measured.peak_transient_bytes);
    peak.peak_transient_objects = peak
        .peak_transient_objects
        .max(measured.peak_transient_objects);
    peak.native_work_units = peak.native_work_units.max(measured.native_work_units);
}

#[test]
fn credential_profile_has_measured_runtime_and_journal_budgets() {
    let mut card = card();
    let isd_incarnation = card.state.isd.incarnation;
    let cryptography = provider_package(
        isd_incarnation,
        "MicroCard.Cryptography",
        include_bytes!("../../../../../fuzz/fixtures/cryptography.mca"),
        alloc::vec![
            20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38, 39, 49, 50, 51,
        ],
    );
    let security = provider_package(
        isd_incarnation,
        "MicroCard.Security",
        include_bytes!("../../../../../fuzz/fixtures/security.mca"),
        alloc::vec![40, 41, 42, 43, 44, 45],
    );
    load(&mut card, &cryptography).unwrap();
    load(&mut card, &security).unwrap();
    let incarnation = create(&mut card, "credential-budget");
    let credential = credential_package(incarnation);
    load(&mut card, &credential).unwrap();
    card.manage(command(
        0xec,
        &management_names_wire("credential-budget", "F04D4308C0").unwrap(),
    ))
    .unwrap();

    let mut peak = crate::mc04_vm::ExecutionMetrics::default();
    let mut provision = Vec::from([0]);
    provision.extend_from_slice(b"1234");
    provision.extend_from_slice(b"12345678");
    provision.extend_from_slice(b"credential-public-data");
    let sign = [
        alloc::vec![3],
        b"1234".to_vec(),
        b"signed credential challenge".to_vec(),
    ]
    .concat();
    for command_data in [
        provision,
        alloc::vec![1],
        alloc::vec![2],
        sign,
        alloc::vec![4],
    ] {
        let (_, measured) = card
            .invoke_context_with_metrics("F04D4308C0", &command_data, 0x13)
            .unwrap();
        observe(&mut peak, measured);
    }
    let wrong = [
        alloc::vec![3],
        b"0000".to_vec(),
        b"signed credential challenge".to_vec(),
    ]
    .concat();
    for _ in 0..3 {
        let (response, measured) = card
            .invoke_context_with_metrics("F04D4308C0", &wrong, 0x13)
            .unwrap();
        assert_eq!(response, [0x69, 0x82]);
        observe(&mut peak, measured);
    }
    let unblock = [alloc::vec![5], b"12345678".to_vec(), b"2468".to_vec()].concat();
    let (_, measured) = card
        .invoke_context_with_metrics("F04D4308C0", &unblock, 0x13)
        .unwrap();
    observe(&mut peak, measured);

    let active_package_bytes = card
        .state
        .isd
        .assemblies
        .values()
        .chain(card.state.domains["credential-budget"].assemblies.values())
        .map(|package| package.len())
        .sum::<usize>();
    let serialized_state_bytes = card.state.encode_snapshot().unwrap().len();
    assert_eq!(
        (active_package_bytes, serialized_state_bytes, peak),
        (
            5792,
            1406,
            crate::mc04_vm::ExecutionMetrics {
                instructions: 78,
                peak_evaluation_slots: 19,
                peak_local_slots: 3,
                peak_frames: 3,
                peak_transient_bytes: 152,
                peak_transient_objects: 3,
                native_work_units: 714,
            },
        )
    );
    assert!(peak.instructions <= 128);
    assert!(peak.peak_evaluation_slots <= 24);
    assert!(peak.peak_local_slots <= 8);
    assert!(peak.peak_frames <= 4);
    assert!(peak.peak_transient_bytes <= 160);
    assert!(peak.peak_transient_objects <= 8);
    assert!(peak.native_work_units <= 768);
}
