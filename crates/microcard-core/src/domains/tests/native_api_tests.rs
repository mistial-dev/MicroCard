use super::*;

#[test]
fn bulk_command_io_validates_before_charging_or_mutating() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(0);
    let capabilities = [12, 13, 53, 54];
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
        data: b"abcdef",
        out: Vec::new(),
        sw: 0x9000,
        platform: &mut platform,
        budget: 32,
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
    let mut heap = crate::mc04_vm::Heap::new();
    let destination = heap.allocate_bytes(alloc::vec![0; 5]).unwrap();

    host.copy_command(&mut heap, destination, 1, 1, 3)
        .unwrap();
    assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
    assert_eq!(host.budget, 28);

    assert_eq!(
        host.copy_command(&mut heap, destination, 4, 0, 2),
        Err(Error::Bounds)
    );
    assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
    assert_eq!(host.budget, 28);

    host.write_response(&heap, destination, 1, 2).unwrap();
    assert_eq!(host.out, b"bc");
    assert_eq!(host.budget, 25);

    let oversized = heap.allocate_bytes(alloc::vec![0; 247]).unwrap();
    assert_eq!(
        host.write_response(&heap, oversized, 0, 247),
        Err(Error::Quota)
    );
    assert_eq!(host.out, b"bc");
    assert_eq!(host.budget, 25);

    assert!(host.copy_bytes(&mut heap, destination, 0, destination, 1, 4).unwrap());
    assert_eq!(heap.bytes(destination).unwrap(), b"\0\0bcd");
    assert_eq!(host.budget, 20);
    assert!(!host.copy_bytes(&mut heap, destination, -1, destination, 0, 1).unwrap());
    assert!(!host.copy_bytes(&mut heap, destination, 0, destination, 4, 2).unwrap());
    assert_eq!(heap.bytes(destination).unwrap(), b"\0\0bcd");
    host.budget = 2;
    assert_eq!(host.copy_bytes(&mut heap, destination, 0, destination, 0, 3), Err(Error::Budget));
    assert_eq!(heap.bytes(destination).unwrap(), b"\0\0bcd");
    host.budget = 25;
    let input = heap.allocate_bytes(alloc::vec![0, 2, 2, 0, 1]).unwrap();
    let parsed = heap.allocate(false, 7).unwrap();
    heap.write_ints(parsed, 0, &[99; 7]).unwrap();
    assert!(!host.read_tlv(&mut heap, input, 1, 4, parsed, 1, true).unwrap());
    assert_eq!(host.budget, 20);
    assert_eq!((0..7).map(|i| heap.array_get(parsed, i, false).unwrap()).collect::<Vec<_>>(), [99; 7]);
    assert!(host.read_tlv(&mut heap, input, 1, 4, parsed, 1, false).unwrap());
    assert_eq!(host.budget, 15);
    // No partial publication on malformed input or an undersized result window.
    assert!(!host.read_tlv(&mut heap, input, 1, 4, parsed, 3, false).unwrap());
    assert!(!host.read_tlv(&mut heap, input, 0, 5, parsed, 1, false).unwrap());
    host.budget = 2;
    assert_eq!(host.read_tlv(&mut heap, input, 1, 4, parsed, 1, false), Err(Error::Budget));
    assert_eq!((0..7).map(|i| heap.array_get(parsed, i, false).unwrap()).collect::<Vec<_>>(), [99, 2, 2, 3, 2, 5, 99]);
    host.budget = 25;
    host.capabilities = &[];
    assert_eq!(host.copy_bytes(&mut heap, destination, 0, destination, 0, 1), Err(Error::Unauthorized));
    assert_eq!(
        host.copy_command(&mut heap, destination, 0, 0, 1),
        Err(Error::Unauthorized)
    );
    assert_eq!(host.budget, 25);
}

#[test]
fn bulk_random_and_fixed_time_comparison_validate_ranges() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = FailingEntropy;
    let capabilities = [39, 50, 51];
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
    let mut heap = crate::mc04_vm::Heap::new();
    let destination = heap.allocate_bytes(alloc::vec![0x7e; 8]).unwrap();
    assert_eq!(
        host.fill_random(&mut heap, destination, 6, 3),
        Err(Error::Bounds)
    );
    assert_eq!(heap.bytes(destination).unwrap(), [0x7e; 8]);
    assert_eq!(host.budget, 32);

    assert_eq!(
        host.fill_random(&mut heap, destination, 2, 4),
        Err(Error::Native)
    );
    assert_eq!(heap.bytes(destination).unwrap(), [0x7e, 0x7e, 0, 0, 0, 0, 0x7e, 0x7e]);
    assert_eq!(host.budget, 27);

    assert_eq!(host.random_bytes(-1), Err(Error::Bounds));
    assert_eq!(host.random_bytes(1025), Err(Error::Bounds));
    assert_eq!(host.budget, 27);
    assert_eq!(host.random_bytes(0), Ok(Vec::new()));
    assert_eq!(host.budget, 26);
    assert_eq!(host.random_bytes(4), Err(Error::Native));
    assert_eq!(host.budget, 21);

    let left = heap.allocate_bytes(alloc::vec![9, 1, 2, 3, 8]).unwrap();
    let right = heap.allocate_bytes(alloc::vec![7, 1, 2, 3, 6]).unwrap();
    host.budget = 16;
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 1, 3), (right, 1, 3)),
        Ok(1)
    );
    assert_eq!(host.budget, 12);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 0, 5), (right, 0, 4)),
        Ok(0)
    );
    assert_eq!(host.budget, 6);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, -1, 1), (right, 0, 1)),
        Err(Error::Bounds)
    );
    assert_eq!(host.budget, 6);
    assert_eq!(
        host.fixed_time_equals(&heap, (left, 4, 2), (right, 0, 2)),
        Err(Error::Bounds)
    );
    assert_eq!(host.budget, 6);
}

#[test]
fn credential_native_api_tracks_retries_and_scopes_authorization_to_invocation() {
    let mut store = IntStore::new();
    let mut blobs = BlobStore::new();
    let mut keys = crate::key_store::KeyStore::default();
    let mut credentials = crate::credential_store::CredentialStore::default();
    let mut platform = TestPlatform(9);
    let capabilities = [40, 41, 42, 43, 44, 45];
    {
        let mut checkpoint = AcceptCredentialCheckpoint;
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
            credential_checkpoint: Some(&mut checkpoint),
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
        assert_eq!(
            host.credential_call(
                40,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x1234y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                    NativeArgument::Int(3),
                    NativeArgument::Bytes(b"x12345678y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(8),
                    NativeArgument::Int(2),
                ],
            ),
            Ok(BufferResult::Void)
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x9999y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Scalar(0))
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"1234"),
                    NativeArgument::Int(3),
                    NativeArgument::Int(2),
                ],
            ),
            Err(Error::Bounds)
        );
        assert_eq!(
            host.credential_call(
                45,
                &[NativeArgument::Int(2), NativeArgument::Int(0)],
            ),
            Ok(BufferResult::Scalar(2))
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x1234y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Scalar(1))
        );
        assert_eq!(
            host.credential_call(42, &[NativeArgument::Int(2)]),
            Ok(BufferResult::Scalar(1))
        );
        assert_eq!(
            host.credential_call(
                43,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x5678y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Void)
        );
    }
    let mut transaction = TransactionDisposition::Inactive;
    let mut checkpoint = AcceptCredentialCheckpoint;
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
        credential_checkpoint: Some(&mut checkpoint),
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
    assert_eq!(
        host.credential_call(42, &[NativeArgument::Int(2)]),
        Ok(BufferResult::Scalar(0))
    );
    assert_eq!(
        host.credential_call(
            41,
            &[
                NativeArgument::Int(2),
                NativeArgument::Bytes(b"x5678y"),
                NativeArgument::Int(1),
                NativeArgument::Int(4),
            ],
        ),
        Ok(BufferResult::Scalar(1))
    );
}

#[test]
fn lifecycle_retry_floors_accumulate_without_restoring_consumed_attempts() {
    let mut card = card();
    let incarnation = create(&mut card, "credential-floor");
    load(
        &mut card,
        &counter_package("credential-floor", incarnation, 1, 7),
    )
    .unwrap();
    let mut next = card.state.clone();
    next.domains
        .get_mut("credential-floor")
        .unwrap()
        .credentials
        .create(
            incarnation,
            4,
            b"1234",
            b"12345678",
            (3, 2),
            &mut TestPlatform(0x59),
        )
        .unwrap();
    let isd_incarnation = next.isd.incarnation;
    next.isd.credentials.create(isd_incarnation, 4, b"1234", b"12345678", (3, 2), &mut TestPlatform(0x61)).unwrap();
    let isd_aid = next.isd.registry_aid;
    card.commit(next).unwrap();

    let domain_registry_aid = card.state.domains["credential-floor"].registry_aid;
    let result: Result<()> = card.with_lifecycle_retry_floors(|_, retries| {
        retries.control(domain_registry_aid, &mut || false)?.retry_floor.record(4, (2, 2))?;
        retries.control(domain_registry_aid, &mut || false)?.retry_floor.record(4, (3, 1))?;
        retries.control(isd_aid, &mut || false)?.retry_floor.record(4, (1, 2))?;
        Err(Error::Cancelled)
    });
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(
        card.state.domains["credential-floor"]
            .credentials
            .retries(incarnation, 4)
            .unwrap(),
        (2, 1)
    );
    let reopened = Mc04Engine::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
    assert_eq!(reopened.state.isd.credentials.retries(isd_incarnation, 4).unwrap(), (1, 2));
    assert_eq!(
        reopened.state.domains["credential-floor"]
            .credentials
            .retries(incarnation, 4)
            .unwrap(),
        (2, 1)
    );
}

#[test]
fn credential_retry_floor_power_loss_recovers_prior_or_consumed_count() {
    let mut card = card();
    let incarnation = create(&mut card, "credential-cut");
    load(
        &mut card,
        &counter_package("credential-cut", incarnation, 1, 7),
    )
    .unwrap();
    let mut initial = card.state.clone();
    initial
        .domains
        .get_mut("credential-cut")
        .unwrap()
        .credentials
        .create(
            incarnation,
            4,
            b"1234",
            b"12345678",
            (3, 2),
            &mut TestPlatform(0x59),
        )
        .unwrap();
    card.commit(initial).unwrap();
    let domain_registry_aid = card.state.domains["credential-cut"].registry_aid;
    let base = card.into_flash();
    let mut floor = CredentialRetryFloors::default();
    floor.record(4, (2, 1)).unwrap();
    let mut complete = Mc04Engine::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
    complete
        .commit_credential_retry_floor(domain_registry_aid, &floor)
        .unwrap();
    let serialized = complete.state.encode_snapshot().unwrap().to_vec();

    for cut in commit_cuts(serialized.len(), 0) {
        let mut flash = base.clone();
        flash.fail_after = Some(cut);
        let mut interrupted = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let _ = interrupted.commit_credential_retry_floor(domain_registry_aid, &floor);
        let mut flash = interrupted.into_flash();
        flash.fail_after = None;
        let recovered = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let retries = recovered.state.domains["credential-cut"]
            .credentials
            .retries(incarnation, 4)
            .unwrap();
        assert!(retries == (3, 2) || retries == (2, 1), "cut {cut}: {retries:?}");
    }
}

fn failed_pin_native_checkpoint(
    card: &mut Mc04Engine<MemoryFlash, TestPlatform>,
    domain_name: &str,
    slot: i32,
) -> (Result<BufferResult>, bool) {
    let registry_aid = card.state.domains[domain_name].registry_aid;
    let incarnation = card.state.domains[domain_name].incarnation;
    let (journal, state, platform) = (&mut card.journal, &mut card.state, &mut card.platform);
    let domain = state.domains.get_mut(domain_name).unwrap();
    let mut checkpoint = JournalCredentialCheckpoint::new(journal, registry_aid);
    let mut transaction = TransactionDisposition::Inactive;
    let mut transaction_snapshot = None;
    let mut persistent_dirty = false;
    let mut transaction_snapshots = 0;
    let mut transaction_clone_allocations = 0;
    let mut host = Host {
        store: &mut domain.store,
        blobs: &mut domain.blobs,
        keys: &mut domain.keys,
        credentials: &mut domain.credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        credential_checkpoint: Some(&mut checkpoint),
        owner: incarnation,
        data: &[],
        out: Vec::new(),
        sw: 0x9000,
        platform,
        budget: 1024,
        capabilities: &[41],
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
    let result = host.credential_call(
        41,
        &[
            NativeArgument::Int(slot),
            NativeArgument::Bytes(b"9999"),
            NativeArgument::Int(0),
            NativeArgument::Int(4),
        ],
    );
    drop(host);
    (result, persistent_dirty)
}

#[test]
fn failed_pin_native_returns_only_after_its_retry_floor_is_durable() {
    let mut card = card();
    let incarnation = create(&mut card, "native-retry");
    load(
        &mut card,
        &counter_package("native-retry", incarnation, 1, 7),
    )
    .unwrap();
    let mut initial = card.state.clone();
    initial.domains.get_mut("native-retry").unwrap().credentials
        .create(
            incarnation,
            4,
            b"1234",
            b"12345678",
            (3, 2),
            &mut card.platform,
        )
        .unwrap();
    card.commit(initial).unwrap();
    let base = card.into_flash();
    let snapshot_bytes = Mc04Engine::open(base.clone(), TestPlatform(10), STORAGE_KEY)
        .unwrap()
        .state
        .encode_snapshot()
        .unwrap()
        .len();

    for cut in commit_cuts(snapshot_bytes, 0) {
        let mut interrupted =
            Mc04Engine::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        interrupted.journal.flash_mut().fail_after = Some(cut);
        let (result, dirty) = failed_pin_native_checkpoint(&mut interrupted, "native-retry", 4);
        let mut flash = interrupted.into_flash();
        flash.fail_after = None;
        let recovered = Mc04Engine::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let retries = recovered.state.domains["native-retry"]
            .credentials
            .retries(incarnation, 4)
            .unwrap();
        match result {
            Ok(BufferResult::Scalar(0)) => {
                assert_eq!(retries.0, 2, "successful native checkpoint at cut {cut}");
                assert!(!dirty, "successful checkpoint must restore ordinary dirty state");
            }
            Err(Error::Storage) => {
                assert_eq!(retries.0, 3, "failed native checkpoint at cut {cut}");
                assert!(dirty, "failed checkpoint must force unsafe-exit recovery");
            }
            other => panic!("unexpected native result at cut {cut}: {other:?}"),
        }
    }
}

#[test]
fn package_trust_boundaries_use_the_platform_crypto_provider() {
    use core::cell::Cell;

    struct TrackingPlatform {
        random: u8,
        calls: Rc<Cell<[usize; 2]>>,
    }
    impl crate::crypto::CryptoProvider for TrackingPlatform {
        fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32]> {
            let mut calls = self.calls.get();
            calls[0] += 1;
            self.calls.set(calls);
            Ok(crate::crypto::sha256(data))
        }

        fn p256_ecdsa_verify(
            &mut self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool> {
            let mut calls = self.calls.get();
            calls[1] += 1;
            self.calls.set(calls);
            Ok(crate::crypto::p256_ecdsa_verify(public_key, message, signature))
        }
    }
    impl crate::hal::Entropy for TrackingPlatform {
        fn fill_entropy(&mut self, bytes: &mut [u8]) -> Result<()> {
            self.random = self.random.wrapping_add(1);
            bytes.fill(self.random);
            Ok(())
        }
    }
    impl crate::hal::LogicalGpio for TrackingPlatform {
        fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
            Err(Error::Native)
        }
    }

    let calls = Rc::new(Cell::new([0; 2]));
    let platform = TrackingPlatform {
        random: 0,
        calls: Rc::clone(&calls),
    };
    let mut card = Mc04Engine::open(MemoryFlash::new(16384), platform, STORAGE_KEY).unwrap();
    let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
    load(&mut card, &package).unwrap();
    assert_eq!(calls.get(), [5, 1]);

    let metadata = card.state.isd.packages.get("mscorlib").unwrap();
    let candidate = card.state.clone();
    assert!(Rc::ptr_eq(metadata, candidate.isd.packages.get("mscorlib").unwrap()));
    let images = linking::BorrowedExecution::new(&card.state, card.journal.flash(), &mut card.platform, "ISD", "mscorlib").unwrap();
    let units = images.units().unwrap();
    assert!(core::ptr::eq(units[0].package.manifest, &metadata.manifest));
    visit_registry(&card.state, 0x10, |aid, entry| {
        registry_record(0x10, aid, entry).map(|_| ())
    }).unwrap();
    assert_eq!(calls.get(), [6, 1]);
    drop(units);
    drop(images);
    drop(candidate);

    let flash = card.into_flash();
    let platform = TrackingPlatform {
        random: 0,
        calls: Rc::clone(&calls),
    };
    Mc04Engine::open(flash, platform, STORAGE_KEY).unwrap();
    // Digest and signature again on reopening. A stored identity is the digest of a
    // key rather than a key, so there is nothing left for recovery to revalidate as a
    // curve point. A package whose key is wrong fails its signature instead.
    assert_eq!(calls.get(), [12, 2]);
}
