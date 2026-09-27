use super::*;

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
    let c = Mc04Engine::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
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

    let mut reopened = Mc04Engine::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
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
fn metadata_commit_failures_restore_live_state_without_reboot() {
    fn rejected(card: &mut Mc04Engine<MemoryFlash, TestPlatform>, change: impl FnOnce(&mut Mc04Engine<MemoryFlash, TestPlatform>) -> Result<()>) {
        let before = card.state.encode_snapshot().unwrap().to_vec();
        card.journal.flash_mut().fail_after = Some(0);
        assert_eq!(change(card), Err(Error::Storage));
        card.journal.flash_mut().fail_after = None;
        assert_eq!(card.state.encode_snapshot().unwrap().as_slice(), before);
    }
    let mut card = card();
    rejected(&mut card, |card| card.manage(command(0xe0, b"new")).map(|_| ()));
    create(&mut card, "new");
    rejected(&mut card, |card| card.manage(command(0xe4, b"new")).map(|_| ()));
    let policy = DomainPolicy { max_int_records: 1, ..DomainPolicy::standard().unwrap() };
    let mut request = alloc::vec![1, 3, b'n', b'e', b'w'];
    request.extend_from_slice(&policy.wire().unwrap()[1..]);
    rejected(&mut card, |card| card.manage(command(0xe1, &request)).map(|_| ()));
    card.manage(command(0xe1, &request)).unwrap();
    assert_eq!(card.state.domains["new"].policy.max_int_records, 1);
    #[cfg(feature = "scp03-pseudo-random")]
    {
        let next = card.state.scp03_sequence;
        rejected(&mut card, |card| card.next_secure_channel_sequence().map(|_| ()));
        assert_eq!(card.next_secure_channel_sequence().unwrap(), next);
    }
    card.manage(command(0xe4, b"new")).unwrap();
    let recovered = Mc04Engine::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
    assert!(!recovered.state.domains.contains_key("new"));
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

    let install = |card: &mut Mc04Engine<MemoryFlash, TestPlatform>, domain: &str, aid: u16| {
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

    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
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
    let mut c = Mc04Engine::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
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
        capabilities: alloc::vec![7],
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

    policy.capabilities = alloc::vec![2, 7, 8, 9, 11, 12, 13, 20];
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
    let reopened = Mc04Engine::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(reopened.state.domains["a"].policy.max_int_records, 1);
}
