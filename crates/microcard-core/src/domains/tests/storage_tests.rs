use super::*;

#[test]
fn stores_are_domain_scoped() {
    let mut c = card();
    let a = create(&mut c, "a");
    let b = create(&mut c, "b");
    load(&mut c, &counter_package("a", a, 1, 7)).unwrap();
    assert_eq!(
        run_loaded(&mut c, "a", "Counter", 1, &[]).unwrap(),
        [1, 0x90, 0]
    );
    assert_eq!(
        run_loaded(&mut c, "a", "Counter", 28, &[]).unwrap(),
        [1, 0, 0, 0, 0x90, 0]
    );
    c.manage(command(0xf0, &management_names_wire("a", "Counter").unwrap())).unwrap();
    load(&mut c, &counter_package("b", b, 1, 8)).unwrap();
    assert_eq!(
        run_loaded(&mut c, "b", "Counter", 28, &[]).unwrap(),
        [0, 0, 0, 0, 0x90, 0]
    );
}

#[test]
fn persistent_storage_schema_is_pinned_until_domain_deletion() {
    let mut card = card();
    let incarnation = create(&mut card, "schema");
    load(&mut card, &counter_package("schema", incarnation, 1, 7)).unwrap();
    let pinned_schema = Rc::clone(&card.state.domains["schema"].storage_schema);
    load(
        &mut card,
        &library_package("schema", incarnation, "Library", 1, 7),
    )
    .unwrap();
    assert!(Rc::ptr_eq(
        &pinned_schema,
        &card.state.domains["schema"].storage_schema
    ));
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
    );
    card.manage(command(0xf0, &management_names_wire("schema", "Counter").unwrap()))
        .unwrap();
    card.manage(command(0xf0, &management_names_wire("schema", "Library").unwrap()))
        .unwrap();
    let conflicting = signed_package_with_storage(
        "schema",
        incarnation,
        "Conflict",
        1,
        7,
        &[0x2a],
        false,
        alloc::vec![
            StorageDeclaration { key: 0, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 1, kind: 2, max_bytes: 16 },
        ],
    );
    assert_eq!(load(&mut card, &conflicting), Err(Error::KeyMismatch));
    assert!(card.state.domains["schema"].image_refs.is_empty());
    assert!(card.state.domains["schema"].storage_declaration(0).is_none());
    assert!(Rc::ptr_eq(
        &pinned_schema,
        &card.state.domains["schema"].storage_schema
    ));
    let card = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
    );
    let mut card = card;
    card.manage(command(0xe4, b"schema")).unwrap();
    let replacement = create(&mut card, "schema");
    let replacement_package = signed_package_with_storage(
        "schema",
        replacement,
        "Replacement",
        1,
        8,
        &[0x2a],
        false,
        alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
    );
    load(&mut card, &replacement_package).unwrap();
    assert_eq!(
        card.state.domains["schema"].storage_declaration(1),
        Some(&StorageDeclaration { key: 1, kind: 2, max_bytes: 16 })
    );
}

#[test]
fn recovery_rejects_missing_or_retyped_persistent_schema() {
    let mut card = card();
    let incarnation = create(&mut card, "schema-recovery");
    load(
        &mut card,
        &counter_package("schema-recovery", incarnation, 1, 7),
    )
    .unwrap();
    run_loaded(&mut card, "schema-recovery", "Counter", 1, &[]).unwrap();
    let mut corrupted = card.state.clone();
    let domain = corrupted.domains.get_mut("schema-recovery").unwrap();
    let mut schema = domain.storage_schema.as_ref().clone();
    schema[0].kind = 2;
    schema[0].max_bytes = 1;
    domain.storage_schema = Rc::new(schema);
    card.commit(corrupted).unwrap();
    assert!(matches!(
        Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY),
        Err(Error::Storage)
    ));
}

#[test]
fn managed_storage_access_requires_the_calling_assembly_declaration() {
    let mut card = card();
    let undeclared_incarnation = create(&mut card, "undeclared");
    let undeclared = counter_package_with_storage(
        "undeclared",
        undeclared_incarnation,
        1,
        7,
        Vec::new(),
    );
    load(&mut card, &undeclared).unwrap();
    assert_eq!(
        run_loaded(&mut card, "undeclared", "Counter", 0, &[]),
        Err(Error::Unauthorized)
    );
    assert!(card.state.domains["undeclared"].store.is_empty());

    let wrong_kind_incarnation = create(&mut card, "wrong-kind");
    let wrong_kind = counter_package_with_storage(
        "wrong-kind",
        wrong_kind_incarnation,
        1,
        8,
        alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
    );
    load(&mut card, &wrong_kind).unwrap();
    assert_eq!(
        run_loaded(&mut card, "wrong-kind", "Counter", 0, &[]),
        Err(Error::Unauthorized)
    );
    assert!(card.state.domains["wrong-kind"].store.is_empty());
}

#[test]
fn persistent_byte_declaration_bounds_each_native_write() {
    let mut card = card();
    let incarnation = create(&mut card, "blob-bound");
    let package = key_operations_package_with_storage(
        "blob-bound",
        incarnation,
        1,
        7,
        alloc::vec![
            StorageDeclaration { key: 10, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 20, kind: 2, max_bytes: 2 },
            StorageDeclaration { key: 21, kind: 2, max_bytes: 1 },
            StorageDeclaration { key: 30, kind: 1, max_bytes: 0 },
        ],
    );
    load(&mut card, &package).unwrap();
    assert_eq!(
        run_loaded(&mut card, "blob-bound", "KeyOperations", 4, &[0]),
        Err(Error::Quota)
    );
    assert!(card.state.domains["blob-bound"].blobs.is_empty());
}

#[test]
fn issuer_dependency_code_cannot_reach_caller_domain_storage() {
    let raw = signed_package_with_storage(
        "ISD",
        [2; 16],
        "Provider",
        1,
        7,
        &[0x2a],
        false,
        alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
    );
    let package = PackageView::verify(&raw).unwrap();
    let calls = [ResolvedCall { member: 1, target: CallTarget::Native(3) }];
    let units = [ExecutionUnit { package: (&package).into(), bindings: &[], calls: &calls }];
    let schema = [StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }];
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let mut transaction = TransactionDisposition::Inactive;
    let mut transaction_snapshot = None;
    let mut persistent_dirty = false;
    let mut transaction_snapshots = 0;
    let mut transaction_clone_allocations = 0;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        credential_checkpoint: None,
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 32,
        capabilities: &[],
        domain_schema: &schema,
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: Some(&units),
        transaction: &mut transaction,
        transaction_snapshot: &mut transaction_snapshot,
        persistent_dirty: &mut persistent_dirty,
        transaction_snapshots: &mut transaction_snapshots,
        transaction_clone_allocations: &mut transaction_clone_allocations,
        irreversible_output: false,
    };
    let mut heap = crate::mc04_vm::Heap::new();
    assert_eq!(
        crate::mc04_vm::External::invoke(
            &mut host,
            0,
            1,
            3,
            &[crate::mc04_vm::RuntimeValue::Int(1)],
            &mut heap,
        ),
        Err(Error::Unauthorized)
    );
    assert!(host.store.is_empty());
}

#[test]
fn execution_units_borrow_persisted_packages_and_link_tables() {
    let mut card = card();
    let incarnation = create(&mut card, "borrowed");
    let raw = package("borrowed", incarnation, "library", 1, 7, &[0x2a]);
    load(&mut card, &raw).unwrap();
    let domain = &card.state.domains["borrowed"];
    let calls = &domain.imports["library"];
    let descriptor = domain.image_refs["library"];
    {
        let flash = &*card.journal.flash_mut();
        let images = linking::BorrowedExecution::new(&card.state, flash, &mut card.platform,
            "borrowed", "library").unwrap();
        let units = images.units().unwrap();
        let bytes = descriptor.read_verified(flash, &mut card.platform).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].package.raw.as_ptr(), bytes.as_ptr());
        let image_offset = units[0].package.image.as_ptr() as usize - bytes.as_ptr() as usize;
        assert!(image_offset >= 12 && image_offset < bytes.len());
        assert_eq!(units[0].calls.as_ptr(), calls.as_ptr());
    }
    card.manage(command(0xec, &management_names_wire("borrowed", "F04D430001").unwrap())).unwrap();
    assert_eq!(card.invoke("F04D430001", &[]).unwrap(), [0x90, 0x00]);
    crate::image_store::ImageFlash::program(card.journal.flash_mut(), usize::from(descriptor.slot), 0, &[0]).unwrap();
    assert_eq!(card.invoke("F04D430001", &[]), Err(Error::Authentication));
    // Activation validates its verified candidate before staging, independent of
    // the old root slot. Dependency slots still use authenticated reads.
    let images = linking::BorrowedExecution::with_candidate(&card.state, card.journal.flash(),
        &mut card.platform, "borrowed", "library", &raw).unwrap();
    let units = images.units().unwrap();
    assert_eq!(units[0].package.raw.as_ptr(), raw.as_ptr());
}

#[test]
fn owned_package_indexes_image_inside_its_signed_envelope() {
    let raw = counter_package("owned", [7; 16], 1, 7);
    let package = Package::verify(&raw).unwrap();
    let raw_start = package.raw.as_ptr() as usize;
    let raw_end = raw_start + package.raw.len();
    let image_start = package.image().as_ptr() as usize;
    assert!(image_start >= raw_start && image_start + package.image().len() <= raw_end);
    assert_eq!(
        package.image(),
        include_bytes!("../../../../../fuzz/fixtures/counter.mca")
    );
}

#[test]
fn package_names_are_shared_after_installation_and_recovery() {
    fn assert_shared_names(domain: &Domain, name: &str) {
        let package_name = domain.image_refs.get_key_value(name).unwrap().0;
        let version_name = domain.versions.get_key_value(name).unwrap().0;
        let binding_name = domain.bindings.get_key_value(name).unwrap().0;
        let import_name = domain.imports.get_key_value(name).unwrap().0;
        assert!(Rc::ptr_eq(package_name, version_name));
        assert!(Rc::ptr_eq(package_name, binding_name));
        assert!(Rc::ptr_eq(package_name, import_name));
        for instance_name in domain
            .instances
            .values()
            .filter(|instance_name| instance_name.as_ref() == name)
        {
            assert!(Rc::ptr_eq(package_name, instance_name));
        }
    }

    let mut card = card();
    let incarnation = create(&mut card, "shared");
    let counter = counter_package("shared", incarnation, 1, 7);
    let keys = key_operations_package("shared", incarnation, 1, 7);
    load(&mut card, &counter).unwrap();
    load(&mut card, &keys).unwrap();
    card.manage(command(0xec, &management_names_wire("shared", "F04D430001").unwrap()))
        .unwrap();
    assert_shared_names(&card.state.isd, "mscorlib");
    assert_shared_names(&card.state.domains["shared"], "Counter");
    assert_shared_names(&card.state.domains["shared"], "KeyOperations");
    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_shared_names(&reopened.state.isd, "mscorlib");
    assert_shared_names(&reopened.state.domains["shared"], "Counter");
    assert_shared_names(&reopened.state.domains["shared"], "KeyOperations");
}

#[test]
fn byte_storage_native_api_enforces_ownership_and_quotas() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let capabilities = [8, 22, 25, 29, 31, 32, 33, 34, 52];
    let mut transaction = TransactionDisposition::Inactive;
    let mut transaction_snapshot = None;
    let mut persistent_dirty = false;
    let mut transaction_snapshots = 0;
    let mut transaction_clone_allocations = 0;
    let mut host = Host {
        store: &mut store,
        blobs: &mut blobs,
        keys: &mut keys,
        credentials: &mut credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        credential_checkpoint: None,
        owner: [1; 16],
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 4096,
        capabilities: &capabilities,
        domain_schema: &[],
        max_int_records: 512,
        max_blob_records: 64,
        max_blob_bytes: 8192,
        max_key_slots: 8,
        level: 0,
        units: None,
        transaction: &mut transaction,
        transaction_snapshot: &mut transaction_snapshot,
        persistent_dirty: &mut persistent_dirty,
        transaction_snapshots: &mut transaction_snapshots,
        transaction_clone_allocations: &mut transaction_clone_allocations,
        irreversible_output: false,
    };
    let oversized = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES + 1];
    assert_eq!(
        host.key_call(
            25,
            &[
                vm::NativeArgument::Bytes(&[]),
                vm::NativeArgument::Bytes(&oversized),
            ]
        ),
        Err(Error::Quota)
    );
    let maximum = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES];
    assert_eq!(
        host.key_call(
            29,
            &[
                vm::NativeArgument::Bytes(&[]),
                vm::NativeArgument::Bytes(&maximum),
                vm::NativeArgument::Bytes(&maximum),
                vm::NativeArgument::Bytes(&maximum),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            52,
            &[
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"xvaluey"),
                vm::NativeArgument::Int(1),
                vm::NativeArgument::Int(5),
            ],
        ),
        Ok(vm::BufferResult::Void)
    );
    assert!(matches!(
        host.key_call(
            31,
            &[vm::NativeArgument::Int(7)]
        ),
        Ok(vm::BufferResult::Bytes(value)) if value == b"value"
    ));
    assert!(matches!(
        host.key_call(
            34,
            &[vm::NativeArgument::Int(7)]
        ),
        Ok(vm::BufferResult::Scalar(1))
    ));
    *host.persistent_dirty = false;
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"value"),
            ]
        ),
        Ok(vm::BufferResult::Void)
    );
    assert!(!*host.persistent_dirty);
    host.begin_transaction().unwrap();
    host.transaction.abort().unwrap();
    assert_eq!(
        host.key_call(
            52,
            &[
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"value"),
                vm::NativeArgument::Int(4),
                vm::NativeArgument::Int(2),
            ],
        ),
        Err(Error::Bounds)
    );
    host.max_blob_bytes = 4;
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(7),
                vm::NativeArgument::Bytes(b"value"),
            ]
        ),
        Err(Error::Quota)
    );
    host.max_blob_bytes = 8192;
    host.max_blob_records = 1;
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[]),
            ]
        ),
        Err(Error::Quota)
    );
    host.max_blob_records = 64;
    host.max_int_records = 1;
    assert_eq!(host.call(8, &[1, 1]), Ok(None));
    assert_eq!(host.call(8, &[2, 2]), Err(Error::Quota));
    assert!(matches!(
        host.key_call(
            22,
            &[
                vm::NativeArgument::Int(0),
                vm::NativeArgument::Int(1),
            ]
        ),
        Ok(vm::BufferResult::Bytes(token)) if token.len() == 32
    ));
    host.max_key_slots = 1;
    assert_eq!(
        host.key_call(
            22,
            &[
                vm::NativeArgument::Int(1),
                vm::NativeArgument::Int(1),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[0; MAX_DECLARED_BLOB_BYTES as usize + 1]),
            ]
        ),
        Err(Error::Quota)
    );
    for slot in 0..8 {
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(slot),
                vm::NativeArgument::Bytes(&[slot as u8; 1024]),
            ],
        )
        .unwrap();
    }
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(8),
                vm::NativeArgument::Bytes(&[0]),
            ]
        ),
        Err(Error::Quota)
    );
    for slot in 0..8 {
        assert_eq!(
            host.key_call(
                33,
                &[vm::NativeArgument::Int(slot)]
            ),
            Ok(vm::BufferResult::Void)
        );
    }
    for slot in 0..64 {
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(slot),
                vm::NativeArgument::Bytes(&[]),
            ],
        )
        .unwrap();
    }
    assert_eq!(
        host.key_call(
            32,
            &[
                vm::NativeArgument::Int(64),
                vm::NativeArgument::Bytes(&[]),
            ]
        ),
        Err(Error::Quota)
    );
    assert_eq!(
        host.key_call(
            33,
            &[vm::NativeArgument::Int(100)]
        ),
        Err(Error::Missing)
    );
}
