use super::*;

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
            .image_refs
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

    let mut reopened = Mc04Engine::open(owned.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
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
    let final_state = Mc04Engine::open(reopened.into_flash(), TestPlatform(30), STORAGE_KEY).unwrap();
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
                    .image_refs
                    .contains_key("Wallet")
            );
        }
    }
    assert!(
        owned.state.domains["payments"]
            .image_refs
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
    let gp = |owned: &mut Mc04Engine<MemoryFlash, TestPlatform>, p1: u8, p2: u8, ins: u8, data: Vec<u8>| {
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
#[test]
fn management_cbor_matches_shared_vectors_and_rejects_other_encodings() {
    assert_eq!(management_names_wire("bad/name", "Wallet"), Err(Error::Format));
    let vectors: serde_json::Value = serde_json::from_str(include_str!("../../../../../format/management-names-v1.json")).unwrap();
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
