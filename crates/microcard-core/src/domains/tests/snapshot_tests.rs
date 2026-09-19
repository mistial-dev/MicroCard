use super::*;

#[test]
fn snapshot_matches_python_golden_vector() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../format/snapshot-cbor-v2.json")).unwrap();
    let hex = vector["hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut state = State {
        isd: Domain::new(
            [1; 16],
            RegistryAid::isd(),
            DomainPolicy::standard().unwrap(),
        ),
        domains: Domains(Vec::new()),
        scp03_sequence: 0,
    };
    state.isd.key = Some([2; 32]);
    state.isd.assemblies.insert(Rc::from("mscorlib"), Rc::new(Vec::new())).unwrap();
    state.isd.image_refs.insert(Rc::from("mscorlib"), crate::image_store::Descriptor {
        slot: 7, length: 123, digest: [3; 32],
    }).unwrap();
    assert_eq!(*state.encode_snapshot().unwrap(), bytes);
    let decoded = State::decode_snapshot(&bytes).unwrap();
    assert!(decoded == state);
}

#[test]
fn snapshot_rejects_every_truncation_and_noncanonical_header() {
    let mut card = card();
    let incarnation = create(&mut card, "a");
    load(&mut card, &counter_package("a", incarnation, 1, 7)).unwrap();
    let raw = card.state.encode_snapshot().unwrap();
    let recovered = State::decode_snapshot(&raw).unwrap();
    assert_eq!(*recovered.encode_snapshot().unwrap(), *raw);
    for end in 0..raw.len() {
        assert!(
            State::decode_snapshot(&raw[..end]).is_err(),
            "accepted length {end}"
        );
    }
    let mut trailing = raw.to_vec();
    trailing.push(0);
    assert!(State::decode_snapshot(&trailing).is_err());
    let mut overlong = raw.to_vec();
    overlong.splice(1..2, [0x18, 2]);
    assert!(State::decode_snapshot(&overlong).is_err());
    for index in [1, 2] {
        let mut unsupported = raw.to_vec();
        unsupported[index] = 3;
        assert!(matches!(
            State::decode_snapshot(&unsupported),
            Err(Error::IncompatibleState)
        ));
    }
}

#[test]
fn old_snapshot_fails_explicitly_without_mutating_flash() {
    let old = br#"{"isd":{},"domains":{}}"#.to_vec();
    let shared = SharedJournalFlash(Rc::new(RefCell::new(MemoryFlash::new(16384))));
    let (mut journal, _) = Journal::open(shared.clone(), STORAGE_KEY).unwrap();
    journal.commit(&old).unwrap();
    let generation = shared.monotonic_generation().unwrap();
    // Any attempted write consumes this budget, including an erase or sequence reservation.
    shared.0.borrow_mut().fail_after = Some(1);
    assert!(matches!(
        Card::open(shared.clone(), TestPlatform(10), STORAGE_KEY),
        Err(Error::IncompatibleState)
    ));
    assert_eq!(shared.0.borrow().fail_after, Some(1));
    assert_eq!(shared.monotonic_generation().unwrap(), generation);
    let (_, recovered) = Journal::open(shared, STORAGE_KEY).unwrap();
    assert_eq!(*recovered.unwrap(), old);
}

#[test]
fn snapshot_rejects_duplicate_and_unsorted_records() {
    let mut card = fresh_card();
    for records in [alloc::vec![(1, 10), (1, 20)], alloc::vec![(2, 10), (1, 20)]] {
        card.state.isd.store.0 = records;
        let raw = card.state.encode_snapshot().unwrap();
        assert!(State::decode_snapshot(&raw).is_err());
    }
    card.state.isd.store.0.clear();
    card.state.isd.blobs.0 = alloc::vec![(1, alloc::vec![1]), (1, alloc::vec![2])];
    assert!(State::decode_snapshot(&card.state.encode_snapshot().unwrap()).is_err());

    // Each collection has its own decoder bound. Test the current binary path once.
    for collection in [
        "domains",
        "assemblies",
        "instances",
        "integers",
        "blobs",
        "schema",
        "duplicate names",
        "duplicate instances",
        "duplicate schema",
    ] {
        let mut state = fresh_card().state.try_clone().unwrap();
        let domain = &mut state.isd;
        match collection {
            "duplicate names" => {
                domain.assemblies.0 = alloc::vec![(Rc::from("a"), Rc::new(Vec::new())); 2];
                domain.image_refs.insert(Rc::from("a"), crate::image_store::Descriptor {
                    slot: 0, length: 1, digest: [0; 32],
                }).unwrap();
            }
            "duplicate instances" => {
                domain.instances.0 =
                    alloc::vec![(String::from("F04D430100"), Rc::from("Counter")); 2]
            }
            "duplicate schema" => {
                domain.storage_schema =
                    Rc::new(alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }; 2])
            }
            "domains" => {
                state.domains.0 = (0..=MAX_SSDS)
                    .map(|i| {
                        (
                            alloc::format!("d{i:02}"),
                            Domain::new(
                                [i as u8; 16],
                                RegistryAid::isd(),
                                DomainPolicy::standard().unwrap(),
                            ),
                        )
                    })
                    .collect()
            }
            "assemblies" => {
                domain.assemblies.0 = (0..=MAX_ASSEMBLIES_PER_DOMAIN)
                    .map(|i| (Rc::from(alloc::format!("a{i:02}")), Rc::new(Vec::new())))
                    .collect();
                domain.image_refs.0 = domain.assemblies.iter().map(|(name, _)| (Rc::clone(name), crate::image_store::Descriptor {
                    slot: 0, length: 1, digest: [0; 32],
                })).collect();
            }
            "instances" => {
                domain.instances.0 = (0..=MAX_INSTANCES_PER_DOMAIN)
                    .map(|i| (alloc::format!("F04D4301{i:02}"), Rc::from("Counter")))
                    .collect()
            }
            "integers" => domain.store.0 = (0..=MAX_INT_RECORDS as i32).map(|i| (i, i)).collect(),
            "blobs" => {
                domain.blobs.0 = (0..=MAX_BLOB_RECORDS as i32)
                    .map(|i| (i, Vec::new()))
                    .collect()
            }
            "schema" => {
                domain.storage_schema = Rc::new(
                    (0..=MAX_DOMAIN_STORAGE_DECLARATIONS)
                        .map(|i| StorageDeclaration {
                            key: i as i32,
                            kind: 1,
                            max_bytes: 0,
                        })
                        .collect(),
                )
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(State::decode_snapshot(&state.encode_snapshot().unwrap()), Err(Error::Format)),
            "accepted invalid {collection}"
        );
    }
}
