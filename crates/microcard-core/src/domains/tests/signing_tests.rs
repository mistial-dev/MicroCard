//! Loader rejection must preserve durable state, not merely return an error.
use super::*;
use alloc::collections::BTreeMap;

fn snapshot(c: &Card<MemoryFlash, TestPlatform>) -> Vec<u8> {
    serde_json::to_vec(&c.state).unwrap()
}

fn rejected(c: &mut Card<MemoryFlash, TestPlatform>, raw: &[u8], expected: Option<Error>) {
    let before = snapshot(c);
    let result = load(c, raw);
    if let Some(error) = expected {
        assert_eq!(result, Err(error));
    } else {
        assert!(result.is_err());
    }
    assert_eq!(snapshot(c), before, "rejected load changed live state");
    let flash = core::mem::replace(c, card()).into_flash();
    *c = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(snapshot(c), before, "rejected load changed durable state");
}

fn signed(meta: &[u8], image: &[u8], seed: u8, context: &[u8]) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut raw = b"MP03".to_vec();
    raw.extend(context);
    raw.extend((meta.len() as u32).to_le_bytes());
    raw.extend((image.len() as u32).to_le_bytes());
    raw.extend(meta);
    raw.extend(image);
    raw.extend(key.verifying_key().to_bytes());
    let signature = key.sign(&raw).to_bytes();
    raw.extend(signature);
    raw
}

fn set_table_row_count(image: &mut [u8], table: u8, count: u16) {
    let tables = u32::from_le_bytes(image[18..22].try_into().unwrap()) as usize;
    let valid = u64::from_le_bytes(image[tables + 4..tables + 12].try_into().unwrap());
    assert_ne!(valid & (1u64 << table), 0);
    let preceding = (0..table)
        .filter(|candidate| valid & (1u64 << candidate) != 0)
        .count();
    let offset = tables + 12 + preceding * 2;
    image[offset..offset + 2].copy_from_slice(&count.to_le_bytes());
}

fn insert_table_row_count(image: &mut Vec<u8>, table: u8, count: u16) {
    let tables = u32::from_le_bytes(image[18..22].try_into().unwrap()) as usize;
    let mut valid = u64::from_le_bytes(image[tables + 4..tables + 12].try_into().unwrap());
    assert_eq!(valid & (1u64 << table), 0);
    let preceding = (0..table)
        .filter(|candidate| valid & (1u64 << candidate) != 0)
        .count();
    image.splice(
        tables + 12 + preceding * 2..tables + 12 + preceding * 2,
        count.to_le_bytes(),
    );
    valid |= 1u64 << table;
    image[tables + 4..tables + 12].copy_from_slice(&valid.to_le_bytes());

    let file_size = u32::from_le_bytes(image[12..16].try_into().unwrap()) + 2;
    image[12..16].copy_from_slice(&file_size.to_le_bytes());
    let tables_length = u32::from_le_bytes(image[22..26].try_into().unwrap()) + 2;
    image[22..26].copy_from_slice(&tables_length.to_le_bytes());
    for directory in 1..4 {
        let at = 16 + directory * 10 + 2;
        let offset = u32::from_le_bytes(image[at..at + 4].try_into().unwrap()) + 2;
        image[at..at + 4].copy_from_slice(&offset.to_le_bytes());
    }
}

fn fixture(bound: bool) -> (Card<MemoryFlash, TestPlatform>, [u8; 16]) {
    let mut c = card();
    let inc = create(&mut c, "a");
    if bound {
        load(&mut c, &counter_package("a", inc, 1, 7)).unwrap();
        c.manage(command(0xec, br#"["a","F04D430001"]"#)).unwrap();
        c.invoke("F04D430001", &[]).unwrap();
        assert_eq!(c.state.domains["a"].store[&1], 1);
    }
    (c, inc)
}

fn dependency(name: &str) -> Dependency {
    Dependency {
        assembly: name.into(),
        ranges: alloc::vec![VersionRange {
            min: Some([1, 0, 0, 0]),
            min_inclusive: true,
            max: Some([1, 0, 0, 0]),
            max_inclusive: true,
        }],
        package_version: 0,
        signer: None,
        digest: None,
        scope: 0,
    }
}

fn rewritten(raw: &[u8], seed: u8, change: impl FnOnce(&mut Manifest)) -> Vec<u8> {
    let mut package = Package::verify(raw).unwrap();
    change(&mut package.manifest);
    let mut image = package.image().to_vec();
    let tables = u32::from_le_bytes(image[18..22].try_into().unwrap()) as usize;
    let assembly = tables + 41;
    let assembly_version = package.manifest.assembly_version;
    for (index, part) in assembly_version.iter().enumerate() {
        image[assembly + index * 2..assembly + index * 2 + 2]
            .copy_from_slice(&part.to_le_bytes());
    }
    signed(
        &serde_json::to_vec(&package.manifest).unwrap(),
        &image,
        seed,
        CONTEXT,
    )
}

#[test]
fn signed_dependency_predicates_and_export_policy_are_enforced() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let provider = rewritten(
        &package("a", inc, "provider", 7, 7, &[0x2a]),
        7,
        |manifest| {
            manifest.assembly_version = [1, 2, 3, 4];
            manifest.export = DependencyExport {
                access: 1,
                key: None,
            };
        },
    );
    let parsed_provider = Package::verify(&provider).unwrap();
    load(&mut c, &provider).unwrap();

    let consumer = |change: fn(&mut Dependency)| {
        rewritten(
            &package("a", inc, "consumer", 1, 7, &[0x2a]),
            7,
            |manifest| {
                let mut requirement = Dependency {
                    assembly: "provider".into(),
                    ranges: alloc::vec![VersionRange {
                        min: Some([1, 2, 0, 0]),
                        min_inclusive: true,
                        max: Some([1, 3, 0, 0]),
                        max_inclusive: false,
                    }],
                    package_version: 0,
                    signer: None,
                    digest: None,
                    scope: 0,
                };
                change(&mut requirement);
                manifest.dependencies = alloc::vec![requirement];
            },
        )
    };
    fn unchanged(_: &mut Dependency) {}
    fn wrong_range(requirement: &mut Dependency) {
        requirement.ranges[0].min = Some([2, 0, 0, 0]);
        requirement.ranges[0].max = Some([3, 0, 0, 0]);
    }
    fn wrong_package_version(requirement: &mut Dependency) {
        requirement.package_version = 8;
    }
    fn wrong_signer(requirement: &mut Dependency) {
        requirement.signer = Some(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
    }
    fn wrong_digest(requirement: &mut Dependency) {
        requirement.digest = Some([0x66; 32]);
    }
    for invalid in [
        wrong_range,
        wrong_package_version,
        wrong_signer,
        wrong_digest,
    ] {
        rejected(&mut c, &consumer(invalid), Some(Error::Missing));
    }

    let accepted = consumer(unchanged);
    load(&mut c, &accepted).unwrap();
    assert_eq!(
        c.manage(command(0xf0, br#"["a","provider"]"#)),
        Err(Error::Busy)
    );
    c.manage(command(0xf0, br#"["a","consumer"]"#)).unwrap();

    let pinned = rewritten(
        &package("a", inc, "consumer", 2, 7, &[0x2a]),
        7,
        |manifest| {
            let mut requirement = dependency("provider");
            requirement.ranges[0] = VersionRange {
                min: Some([1, 2, 3, 4]),
                min_inclusive: true,
                max: Some([1, 2, 3, 4]),
                max_inclusive: true,
            };
            requirement.package_version = 7;
            requirement.signer = Some(parsed_provider.key);
            requirement.digest = Some(parsed_provider.digest);
            manifest.dependencies = alloc::vec![requirement];
        },
    );
    load(&mut c, &pinned).unwrap();

    let mut private_card = card();
    let private_inc = create(&mut private_card, "private");
    load(
        &mut private_card,
        &package("private", private_inc, "provider", 1, 7, &[0x2a]),
    )
    .unwrap();
    let private_consumer = rewritten(
        &package("private", private_inc, "consumer", 1, 7, &[0x2a]),
        7,
        |manifest| manifest.dependencies = alloc::vec![dependency("provider")],
    );
    rejected(&mut private_card, &private_consumer, Some(Error::Missing));
}

#[test]
fn ssd_dependency_resolves_pinned_isd_provider_with_distinct_signer() {
    let mut c = card();
    let isd_inc = c.state.isd.incarnation;
    let provider = rewritten(
        &library_package("ISD", isd_inc, "Kdf108", 1, 42),
        42,
        |manifest| {
            manifest.assembly_version = [0, 1, 0, 0];
            manifest.export = DependencyExport {
                access: 1,
                key: None,
            };
        },
    );
    let parsed_provider = Package::verify(&provider).unwrap();
    load(&mut c, &provider).unwrap();

    let ssd_inc = create(&mut c, "consumer");
    let consumer = rewritten(
        &package("consumer", ssd_inc, "KdfConsumer", 1, 7, &[0x2a]),
        7,
        |manifest| {
            manifest.dependencies = alloc::vec![Dependency {
                assembly: "Kdf108".into(),
                ranges: alloc::vec![VersionRange {
                    min: Some([0, 1, 0, 0]),
                    min_inclusive: true,
                    max: Some([0, 1, 0, 0]),
                    max_inclusive: true,
                }],
                package_version: 1,
                signer: Some(parsed_provider.key),
                digest: Some(parsed_provider.digest),
                scope: 1,
            }];
        },
    );
    let parsed_consumer = Package::verify(&consumer).unwrap();
    assert_ne!(parsed_provider.key, parsed_consumer.key);
    load(&mut c, &consumer).unwrap();
    assert_eq!(
        c.state.domains["consumer"].bindings["KdfConsumer"],
        [ResolvedDependency {
            digest: parsed_provider.digest,
        }]
    );
    assert_eq!(
        serde_json::to_vec(&c.state.domains["consumer"].bindings["KdfConsumer"])
            .unwrap()
            .len(),
        59
    );
    let mut noncanonical =
        serde_json::to_value(&c.state.domains["consumer"].bindings["KdfConsumer"][0]).unwrap();
    noncanonical["digest"] = alloc::format!("{}=", noncanonical["digest"].as_str().unwrap()).into();
    assert!(serde_json::from_value::<ResolvedDependency>(noncanonical).is_err());
    let mut obsolete_binding =
        serde_json::to_value(&c.state.domains["consumer"].bindings["KdfConsumer"][0]).unwrap();
    obsolete_binding["domain"] = "ISD".into();
    assert!(serde_json::from_value::<ResolvedDependency>(obsolete_binding).is_err());
    let managed_call = ResolvedCall {
        member: 1,
        target: CallTarget::Managed {
            dependency: 0,
            method: 0,
        },
    };
    assert_eq!(serde_json::to_vec(&managed_call).unwrap().len(), 61);
    let mut obsolete_call = serde_json::to_value(&managed_call).unwrap();
    obsolete_call["target"]["Managed"]["assembly"] = "Kdf108".into();
    assert!(serde_json::from_value::<ResolvedCall>(obsolete_call).is_err());
    assert_eq!(
        c.manage(command(0xf0, br#"["ISD","Kdf108"]"#)),
        Err(Error::Busy)
    );
    let upgraded_provider = rewritten(&provider, 42, |manifest| manifest.version = 2);
    assert_eq!(load(&mut c, &upgraded_provider), Err(Error::Busy));

    let wrong_pin = rewritten(&consumer, 7, |manifest| {
        manifest.version = 2;
        manifest.dependencies[0].signer = Some(parsed_consumer.key);
    });
    rejected(&mut c, &wrong_pin, Some(Error::Missing));
    c.manage(command(0xf0, br#"["consumer","KdfConsumer"]"#))
        .unwrap();
    c.manage(command(0xf0, br#"["ISD","Kdf108"]"#)).unwrap();
}

#[test]
fn rejected_mutations_preserve_live_and_durable_state() {
    for bound in [false, true] {
        let (mut c, inc) = fixture(bound);
        let raw = package("a", inc, "candidate", 1, 7, &[0x2a]);
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 1;
            rejected(&mut c, &bad, None);
        }
        for n in 0..raw.len() {
            rejected(&mut c, &raw[..n], None);
        }
        let mut extra = raw.clone();
        extra.push(0);
        rejected(&mut c, &extra, None);
        load(&mut c, &raw).unwrap();
    }
}

#[test]
fn signed_invalid_content_never_activates_or_binds() {
    for bound in [false, true] {
        let (mut c, inc) = fixture(bound);
        let p = Package::verify(&package("a", inc, "candidate", 1, 7, &[0x2a])).unwrap();
        let meta = serde_json::to_vec(&p.manifest).unwrap();
        let mut maximum_entries = p.manifest.clone();
        maximum_entries.entry_points = (0..4)
            .map(|index| {
                let mut entry = p.manifest.entry_points[0].clone();
                entry.aid = alloc::format!("F04D43{index:04}");
                entry
            })
            .collect();
        assert!(Package::verify(&signed(
            &serde_json::to_vec(&maximum_entries).unwrap(),
            p.image(),
            7,
            CONTEXT,
        ))
        .is_ok());
        let mut too_many_methods = p.image().to_vec();
        set_table_row_count(
            &mut too_many_methods,
            crate::mc04_schema::TABLE_METHODDEF,
            crate::mc04_schema::MAX_METHODDEF_ROWS + 1,
        );
        rejected(
            &mut c,
            &signed(&meta, &too_many_methods, 7, CONTEXT),
            Some(Error::Quota),
        );
        let mut too_many_types = p.image().to_vec();
        set_table_row_count(
            &mut too_many_types,
            crate::mc04_schema::TABLE_TYPEDEF,
            crate::mc04_schema::MAX_TYPEDEF_ROWS + 1,
        );
        rejected(
            &mut c,
            &signed(&meta, &too_many_types, 7, CONTEXT),
            Some(Error::Quota),
        );
        let mut too_many_fields = p.image().to_vec();
        insert_table_row_count(
            &mut too_many_fields,
            crate::mc04_schema::TABLE_FIELD,
            crate::mc04_schema::MAX_FIELD_ROWS + 1,
        );
        rejected(
            &mut c,
            &signed(&meta, &too_many_fields, 7, CONTEXT),
            Some(Error::Quota),
        );
        let mut too_many_attributes = p.image().to_vec();
        insert_table_row_count(
            &mut too_many_attributes,
            crate::mc04_schema::TABLE_CUSTOMATTRIBUTE,
            crate::mc04_schema::MAX_CUSTOMATTRIBUTE_ROWS + 1,
        );
        rejected(
            &mut c,
            &signed(&meta, &too_many_attributes, 7, CONTEXT),
            Some(Error::Quota),
        );
        let mut noncanonical = meta.clone();
        noncanonical.push(b' ');
        let mut unknown = meta.clone();
        unknown.pop();
        unknown.extend(br#","extra":0}"#);
        let mut duplicate = meta.clone();
        duplicate.pop();
        duplicate.extend(br#","version":1}"#);
        for bad in [b"{".to_vec(), noncanonical, unknown, duplicate] {
            rejected(
                &mut c,
                &signed(&bad, p.image(), 7, CONTEXT),
                Some(Error::Format),
            );
        }
        let legacy = b"MC01\x01\0\0\0\0\x01\0\0\0\x14";
        let scalar_as_buffer =
            b"MC03\x01\0\0\0\0\xff\0\x0c\0\0\0\x01\0\0\0\0\x1e\x14\0\0\0\x13\x14";
        let forged_layout = b"MC03\x02\0\x01\x01\0\0\0\xff\0\x07\0\0\0\x27\x01\0\x02\0\x13\x14\x01\0\xff\0\x03\x01\0\0\0\x14";
        for bad_image in [
            legacy.as_slice(),
            scalar_as_buffer.as_slice(),
            forged_layout.as_slice(),
        ] {
            rejected(
                &mut c,
                &signed(&meta, bad_image, 7, CONTEXT),
                Some(Error::Format),
            );
        }
        let forged_field = b"MC03\x01\0\x01\x01\0\x01\0\0\0\x03\x07\0\0\0\x02\0\x28\x03\x01\0\x14";
        rejected(
            &mut c,
            &signed(&meta, forged_field, 7, CONTEXT),
            Some(Error::Format),
        );
        let transactional_hardware = b"MC03\x02\0\0\0\0\xff\x01\x04\0\0\0\x17\x01\0\x14\0\0\xff\0\x10\0\0\0\x01\0\0\0\0\x01\0\0\0\0\x1e\x06\0\0\0\x14";
        rejected(
            &mut c,
            &signed(&meta, transactional_hardware, 7, CONTEXT),
            Some(Error::Format),
        );
        for case in 0..12 {
            let mut m = p.manifest.clone();
            let expected = match case {
                0 => {
                    m.entry_points[0].process = 99;
                    Error::Bounds
                }
                1 => {
                    m.dependencies.push(dependency("missing"));
                    Error::Missing
                }
                2 => {
                    m.limits.arena += 1;
                    Error::Quota
                }
                3 => {
                    m.version = 0;
                    Error::Format
                }
                4 => {
                    m.entry_points.push(m.entry_points[0].clone());
                    Error::Format
                }
                5 => {
                    m.domain = "missing".into();
                    Error::Domain
                }
                6 => {
                    m.incarnation[0] ^= 1;
                    Error::Domain
                }
                7 => {
                    m.domain = "bad\"domain".into();
                    Error::Format
                }
                8 => {
                    m.assembly = "bad/name".into();
                    Error::Format
                }
                9 => {
                    m.dependencies.push(dependency("bad name"));
                    Error::Format
                }
                10 => {
                    m.dependencies = (0..17)
                        .map(|index| dependency(&alloc::format!("d{index:02}")))
                        .collect();
                    Error::Format
                }
                _ => {
                    m.entry_points = (0..5)
                        .map(|index| {
                            let mut entry = p.manifest.entry_points[0].clone();
                            entry.aid = alloc::format!("F04D43{index:04}");
                            entry
                        })
                        .collect();
                    Error::Format
                }
            };
            rejected(
                &mut c,
                &signed(&serde_json::to_vec(&m).unwrap(), p.image(), 7, CONTEXT),
                Some(expected),
            );
        }
        let mut m = p.manifest.clone();
        m.capabilities.push(255);
        rejected(
            &mut c,
            &signed(&serde_json::to_vec(&m).unwrap(), p.image(), 7, CONTEXT),
            None,
        );
        rejected(&mut c, &signed(&meta, b"bad-image", 7, CONTEXT), None);
        let mut semantic = p.manifest.clone();
        semantic.dependencies = alloc::vec![dependency("z"), dependency("a")];
        rejected(
            &mut c,
            &signed(
                &serde_json::to_vec(&semantic).unwrap(),
                p.image(),
                7,
                CONTEXT,
            ),
            Some(Error::Format),
        );
        for capabilities in [alloc::vec![3, 1], alloc::vec![1, 1]] {
            semantic.dependencies.clear();
            semantic.capabilities = capabilities;
            rejected(
                &mut c,
                &signed(
                    &serde_json::to_vec(&semantic).unwrap(),
                    p.image(),
                    7,
                    CONTEXT,
                ),
                Some(Error::Format),
            );
        }
        rejected(
            &mut c,
            &signed(&meta, p.image(), 7, b"Wrong context"),
            Some(Error::Format),
        );
        let mut substituted = package("a", inc, "candidate", 1, 7, &[0x2a]);
        let offset = substituted.len() - 96;
        substituted[offset..offset + 32]
            .copy_from_slice(&SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        rejected(&mut c, &substituted, Some(Error::Signature));
        if bound {
            rejected(
                &mut c,
                &package("a", inc, "candidate", 1, 8, &[0x2a]),
                Some(Error::KeyMismatch),
            );
        }
        load(&mut c, &package("a", inc, "candidate", 1, 7, &[0x2a])).unwrap();
    }
}

#[test]
fn empty_domain_retains_versions_and_key_after_reboot() {
    let mut c = card();
    let inc = create(&mut c, "a");
    let raw = package("a", inc, "one", 2, 7, &[0x2a]);
    load(&mut c, &raw).unwrap();
    c.manage(command(0xec, br#"["a","F04D430001"]"#)).unwrap();
    c.manage(command(0xee, br#"["a","F04D430001"]"#)).unwrap();
    c.manage(command(0xf0, br#"["a","one"]"#)).unwrap();
    let mut c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert!(c.state.domains["a"].assemblies.is_empty());
    assert!(c.state.domains["a"].instances.is_empty());
    rejected(
        &mut c,
        &package("a", inc, "one", 1, 7, &[0x2a]),
        Some(Error::Rollback),
    );
    rejected(
        &mut c,
        &package("a", inc, "one", 2, 7, &[0x00, 0x2a]),
        Some(Error::Rollback),
    );
    rejected(
        &mut c,
        &package("a", inc, "two", 1, 8, &[0x2a]),
        Some(Error::KeyMismatch),
    );
    load(&mut c, &raw).unwrap();
    let before = snapshot(&c);
    load(&mut c, &raw).unwrap();
    assert_eq!(snapshot(&c), before);
}

#[test]
fn recovery_rejects_authenticated_but_inconsistent_snapshots() {
    let (c, _) = fixture(true);
    let good = snapshot(&c);
    let base: serde_json::Value = serde_json::from_slice(&good).unwrap();
    for case in 0..17 {
        let mut bad = base.clone();
        let d = &mut bad["domains"]["a"];
        match case {
            0 => {
                let mut encoded = d["assemblies"]["Counter"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec();
                encoded[20] = if encoded[20] == b'A' { b'B' } else { b'A' };
                d["assemblies"]["Counter"] =
                    serde_json::Value::String(String::from_utf8(encoded).unwrap());
            }
            1 => d["key"] = serde_json::json!(null),
            2 => d["incarnation"][0] = serde_json::json!(99),
            3 => d["versions"]["Counter"][0] = serde_json::json!(999),
            4 => d["instances"]["F04D430001"] = serde_json::json!("missing"),
            5 => {
                d["instances"].as_object_mut().unwrap().clear();
                d["instances"]["F04D430099"] = serde_json::json!("Counter");
            }
            6 => d["unknown"] = serde_json::json!(true),
            7 => d["versions"]["Counter"][1][0] = serde_json::json!(99),
            8 => {
                d["store"] =
                    serde_json::to_value((0..513).map(|i| (i, i)).collect::<BTreeMap<_, _>>())
                        .unwrap()
            }
            9 => {
                d["assemblies"].as_object_mut().unwrap().clear();
                d["key"] = serde_json::json!(null);
            }
            10 => d["key"] = serde_json::to_value([0u8; 32]).unwrap(),
            11 => {
                d["keys"]["entries"]["8"] = serde_json::json!({"algorithm":"HmacSha256", "nonce": alloc::vec![0u8;16], "key": alloc::vec![0u8;32]})
            }
            12 => {
                d["policy"] = serde_json::to_value(DomainPolicy {
                    max_int_records: 0,
                    ..DomainPolicy::standard().unwrap()
                })
                .unwrap()
            }
            13 => {
                d["policy"] = serde_json::to_value(DomainPolicy {
                    capabilities: alloc::vec![1, 1],
                    ..DomainPolicy::standard().unwrap()
                })
                .unwrap()
            }
            14 => {
                d["policy"] = serde_json::to_value(DomainPolicy {
                    capabilities: alloc::vec![1],
                    ..DomainPolicy::standard().unwrap()
                })
                .unwrap()
            }
            15 => {
                d["bindings"]["Counter"] = serde_json::json!([{
                    "domain": "ISD",
                    "assembly": "mscorlib",
                    "digest": alloc::vec![0u8; 32]
                }])
            }
            _ => {
                d["imports"]["Counter"] = serde_json::json!([{
                    "member": 1,
                    "target": {"Native": 1}
                }])
            }
        }
        // Serialize via State when possible to ensure semantic checks, not JSON ordering, reject it.
        let raw = match serde_json::from_value::<State>(bad.clone()) {
            Ok(state) => serde_json::to_vec(&state).unwrap(),
            Err(_) => serde_json::to_vec(&bad).unwrap(),
        };
        let (mut journal, _) = Journal::open(MemoryFlash::new(65536), STORAGE_KEY).unwrap();
        journal.commit(&good).unwrap();
        journal.commit(&raw).unwrap(); // Writes a validly authenticated newer generation.
        assert!(
            Card::open(journal.into_flash(), TestPlatform(10), STORAGE_KEY).is_err(),
            "accepted corruption {case}"
        );
    }
    let (mut journal, _) = Journal::open(MemoryFlash::new(16384), STORAGE_KEY).unwrap();
    journal.commit(&good).unwrap();
    Card::open(journal.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
}

#[test]
fn inventory_is_bounded_authenticated_and_read_only() {
    let mut c = card();
    let isd = c.manage(command(0xe2, &[0])).unwrap();
    assert_eq!(&isd[..7], &[1, 1, 0, 3, b'I', b'S', b'D']);
    assert_eq!(isd[23], 1);
    let z = create(&mut c, "z");
    let a = create(&mut c, "a");
    load(&mut c, &package("z", z, "one", 1, 7, &[0x2a])).unwrap();
    let before = snapshot(&c);
    let first = c.manage(command(0xe2, &[1])).unwrap();
    assert_eq!(&first[..5], &[1, 3, 1, 1, b'a']);
    assert_eq!(&first[5..21], &a);
    assert_eq!(first[21], 0);
    assert_eq!(&first[22..54], &[0; 32]);
    let second = c.manage(command(0xe2, &[2])).unwrap();
    assert_eq!(&second[..5], &[1, 3, 2, 1, b'z']);
    assert_eq!(second[21], 1);
    assert_eq!(
        &second[22..54],
        &SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    );
    assert_eq!(&second[54..], &[1, 0, 0, 0]);
    for data in [
        alloc::vec![],
        alloc::vec![0, 0],
        alloc::vec![3],
        alloc::vec![255],
    ] {
        assert!(c.manage(command(0xe2, &data)).is_err());
    }
    for level in [0, 1, 3, 0x11] {
        let mut cmd = command(0xe2, &[0]);
        cmd.level = level;
        assert_eq!(c.manage(cmd), Err(Error::Unauthorized));
    }
    assert_eq!(snapshot(&c), before);
    let c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(snapshot(&c), before);
}
