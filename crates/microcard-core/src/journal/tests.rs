use super::*;
use core::cell::Cell;
const KEY: [u8; 16] = [0x33; 16];

    #[cfg(all(feature = "jcvm", feature = "software-crypto"))]
    #[test]
    fn reserved_identity_nonce_is_the_same_nonce_used_for_publication() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(4096), KEY).unwrap();
        let nonce = journal.reserve_identity_nonce().unwrap();
        assert_eq!(nonce.value(), 1);
        journal.commit_owned_with_reserved(Zeroizing::new(b"installed".to_vec()), nonce,
            &mut SoftwareCrypto).unwrap();
        let flash = journal.into_flash();
        assert_eq!(flash.nonce_generation(), Ok(1));
        let (_, recovered) = Journal::open(flash, KEY).unwrap();
        assert_eq!(recovered.as_deref().map(Vec::as_slice), Some(b"installed".as_slice()));
    }

    struct MeasuredFlash {
        inner: MemoryFlash,
        largest_read: Cell<usize>,
    }

    impl Flash for MeasuredFlash {
        fn slot_size(&self) -> usize {
            self.inner.slot_size()
        }

        fn monotonic_capacity(&self) -> u64 {
            self.inner.monotonic_capacity()
        }

        fn monotonic_generation(&self) -> Result<u64> {
            self.inner.monotonic_generation()
        }

        fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
            self.inner.advance_monotonic(generation)
        }

        fn nonce_generation(&self) -> Result<u64> { self.inner.nonce_generation() }
        fn reserve_nonce(&mut self) -> Result<u64> { self.inner.reserve_nonce() }

        fn is_erased(&self, slot: usize) -> Result<bool> {
            self.inner.is_erased(slot)
        }

        fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()> {
            self.largest_read
                .set(self.largest_read.get().max(output.len()));
            self.inner.read(slot, offset, output)
        }

        fn erase(&mut self, slot: usize) -> Result<()> {
            self.inner.erase(slot)
        }

        fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
            self.inner.program(slot, offset, bytes)
        }
    }

    #[test]
    fn factory_empty_is_distinct_from_damaged_storage() {
        let (_, data) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        assert!(data.is_none());

        let mut incomplete = MemoryFlash::new(128);
        incomplete.program(0, 0, b"MJ01").unwrap();
        assert!(matches!(Journal::open(incomplete, KEY), Err(Error::IncompatibleState)));
    }

    #[test]
    fn flash_word_limit_counts_unaligned_writes_and_resets_on_erase() {
        let mut flash = MemoryFlash::new(128);
        flash.program(0, 0, &[0xfe]).unwrap();
        flash.program(0, 1, &[0xfe]).unwrap();
        assert_eq!(flash.program(0, 2, &[0xfe]), Err(Error::Storage));
        assert_eq!(flash.slot_word_writes[0][0], 2);
        flash.erase(0).unwrap();
        flash.program(0, 2, &[0xfe]).unwrap();
        assert_eq!(flash.slot_word_writes[0][0], 1);
    }

    #[test]
    fn previous_committed_formats_require_explicit_reset() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"state").unwrap();
        let current = journal.into_flash();
        for magic in [b"MJ03", b"MJ07"] {
            let mut old = current.clone();
            old.slots[0][..4].copy_from_slice(magic);
            assert!(matches!(Journal::open(old, KEY), Err(Error::IncompatibleState)));
        }
    }

    #[test]
    fn journal_rejects_an_invalid_slot_count_before_slot_access() {
        for count in [0, 1, 9] {
            assert!(matches!(
                Journal::open(MemoryFlash::with_slots(128, count), KEY),
                Err(Error::Storage)
            ));
        }
    }

    #[test]
    fn committed_old_formats_have_no_upgrade_route() {
        for magic in [b"MJ01", b"MJ02"] {
            let mut old = MemoryFlash::new(128);
            old.program(0, 0, magic).unwrap();
            old.program(0, 127, &[0]).unwrap();
            assert!(matches!(Journal::open(old, KEY), Err(Error::IncompatibleState)));
        }
    }

    #[test]
    fn payload_is_confidential_and_requires_the_correct_key() {
        let secret = b"private-key-material-and-application-record";
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(secret).unwrap();
        let flash = journal.into_flash();
        assert!(!flash
            .slots
            .iter()
            .any(|slot| { slot.windows(secret.len()).any(|window| window == secret) }));
        assert!(matches!(
            Journal::open(flash.clone(), [0x44; 16]),
            Err(Error::Storage)
        ));
        let (_, recovered) = Journal::open(flash, KEY).unwrap();
        assert_eq!(
            recovered.as_ref().map(|d| d.as_slice()),
            Some(secret.as_slice())
        );
    }

    #[test]
    fn recovery_reads_only_the_committed_record() {
        let secret = b"small authenticated state";
        let (mut journal, _) = Journal::open(MemoryFlash::new(65536), KEY).unwrap();
        journal.commit(secret).unwrap();
        let flash = MeasuredFlash {
            inner: journal.into_flash(),
            largest_read: Cell::new(0),
        };

        let (journal, recovered) = Journal::open(flash, KEY).unwrap();

        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(secret.as_slice()));
        let flash = journal.into_flash();
        assert_eq!(flash.largest_read.get(), secret.len() + 16);
        assert!(flash.largest_read.get() < flash.slot_size());
    }

    #[test]
    fn every_authenticated_record_byte_is_covered() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"authenticated state").unwrap();
        let base = journal.into_flash();
        let record_len = HEADER_BYTES + 19 + 16;
        for offset in 0..record_len {
            let Some(bit) = (0..8).find(|bit| base.slots[0][offset] & (1 << bit) != 0) else {
                continue;
            };
            let mut tampered = base.clone();
            tampered.slots[0][offset] &= !(1 << bit);
            assert!(Journal::open(tampered, KEY).is_err());
        }
    }

    #[test]
    fn corrupt_committed_record_never_rolls_back() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"old").unwrap();
        journal.commit(b"new").unwrap();
        let mut flash = journal.into_flash();

        // The second commit is in slot 1. Clear one programmed payload bit while
        // retaining its commit marker, simulating post-commit corruption.
        let bit = (0..8)
            .find(|bit| flash.slots[1][HEADER_BYTES + 1] & (1 << bit) != 0)
            .unwrap();
        flash.slots[1][HEADER_BYTES + 1] &= !(1 << bit);
        assert!(matches!(Journal::open(flash, KEY), Err(Error::Storage)));
    }

    #[test]
    fn monotonic_anchor_rejects_an_older_authenticated_snapshot() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"old").unwrap();
        let old_slots = journal.flash.slots.clone();
        journal.commit(b"new").unwrap();
        let mut flash = journal.into_flash();
        flash.slots = old_slots;

        assert_eq!(flash.monotonic_generation().unwrap(), 2);
        assert!(matches!(Journal::open(flash, KEY), Err(Error::Storage)));
    }

    #[test]
    fn monotonic_anchor_rejects_erased_journal_slots() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"owned").unwrap();
        let mut flash = journal.into_flash();
        flash.slots[0].fill(0xff);
        flash.slots[1].fill(0xff);

        assert_eq!(flash.monotonic_generation().unwrap(), 1);
        assert!(matches!(Journal::open(flash, KEY), Err(Error::Storage)));
    }

    #[test]
    fn recovery_finishes_anchor_advance_after_journal_commit() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"old").unwrap();
        let old_anchor = journal.flash.monotonic.clone();
        journal.commit(b"new").unwrap();
        let mut flash = journal.into_flash();
        flash.monotonic = old_anchor;

        let mut torn = flash.clone();
        torn.monotonic[4] = 0;
        let (_, recovered) = Journal::open(torn, KEY).unwrap();
        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(b"new".as_slice()));

        let (journal, recovered) = Journal::open(flash, KEY).unwrap();
        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(b"new".as_slice()));
        assert_eq!(journal.flash.monotonic_generation().unwrap(), 2);
    }

    #[test]
    fn torn_anchor_word_is_consumed_and_out_of_order_words_are_rejected() {
        let mut torn = MemoryFlash::new(128);
        torn.monotonic[0] = 0;
        assert_eq!(torn.monotonic_generation().unwrap(), 1);

        let mut out_of_order = MemoryFlash::new(128);
        out_of_order.monotonic[4] = 0;
        assert_eq!(out_of_order.monotonic_generation(), Err(Error::Storage));
    }

    #[test]
    fn bit_anchor_is_compact_and_rejects_out_of_order_programming() {
        assert_eq!(decode_monotonic_bits(&[0xff, 0xff]).unwrap(), 0);
        assert_eq!(decode_monotonic_bits(&[0xfe, 0xff]).unwrap(), 1);
        assert_eq!(decode_monotonic_bits(&[0xf8, 0xff]).unwrap(), 3);
        assert_eq!(decode_monotonic_bits(&[0x00, 0xfe]).unwrap(), 9);
        assert_eq!(decode_monotonic_bits(&[0xfa, 0xff]), Err(Error::Storage));
        assert_eq!(decode_monotonic_bits(&[0xff, 0xfe]), Err(Error::Storage));
    }

    #[test]
    fn programmed_once_counter_exhausts_without_reusing_or_skipping_words() {
        let erased = [0xff; 12];
        assert_eq!(decode_program_once_words(&erased), Ok(0));

        let mut full = erased;
        for generation in 1..=3 {
            let offset = next_program_once_word(&full, generation).unwrap();
            assert_eq!(offset, (generation as usize - 1) * 4);
            full[offset..offset + 4].fill(0);
        }
        assert_eq!(decode_program_once_words(&full), Ok(3));
        assert_eq!(next_program_once_word(&full, 3), Err(Error::Storage));
        assert_eq!(next_program_once_word(&full, 4), Err(Error::Quota));

        let mut hole = erased;
        hole[..4].fill(0);
        hole[8..].fill(0);
        assert_eq!(decode_program_once_words(&hole), Err(Error::Storage));

        let mut malformed = erased;
        malformed[0] = 0;
        assert_eq!(decode_program_once_words(&malformed), Err(Error::Storage));
        assert_eq!(decode_program_once_words(&erased[..11]), Err(Error::Storage));
    }

    #[test]
    fn failed_anchor_advance_poisoned_journal_requires_successful_recovery() {
        let mut flash = MemoryFlash::new(128);
        // Stop after the marker but before the four-byte security anchor.
        flash.fail_after = Some(4 + 128 + 44 + 4);
        let (mut journal, _) = Journal::open(flash, KEY).unwrap();
        assert_eq!(journal.commit(b"one"), Err(Error::Storage));
        assert_eq!(journal.commit(b"two"), Err(Error::Storage));

        assert_eq!(journal.recover_with(&mut SoftwareCrypto), Err(Error::Storage));
        assert_eq!(journal.commit(b"two"), Err(Error::Storage));
        journal.flash.fail_after = None;
        let recovered = journal.recover_with(&mut SoftwareCrypto).unwrap();
        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(b"one".as_slice()));
        assert_eq!(journal.flash.monotonic_generation().unwrap(), 1);
        journal.commit(b"two").unwrap();
        let (_, reopened) = Journal::open(journal.into_flash(), KEY).unwrap();
        assert_eq!(reopened.as_deref().map(|data| data.as_slice()), Some(b"two".as_slice()));
    }

    #[test]
    fn exhausted_anchor_rejects_before_mutating_the_journal() {
        for nonce_only in [false, true] {
        let (mut journal, _) = Journal::open(MemoryFlash::new(64), KEY).unwrap();
        for _ in 0..journal.flash.monotonic_capacity() {
            if nonce_only { journal.flash.reserve_nonce().unwrap(); }
            else { journal.commit(b"x").unwrap(); }
        }
        let slots = journal.flash.slots.clone();
        let monotonic = journal.flash.monotonic.clone();

        assert_eq!(journal.commit(b"y"), Err(Error::Quota));
        assert_eq!(journal.flash.slots, slots);
        assert_eq!(journal.flash.monotonic, monotonic);
        }
    }

    #[test]
    fn incomplete_new_record_falls_back_to_committed_old_record() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"old").unwrap();
        let mut flash = journal.into_flash();
        flash.program(1, 0, b"MJ08partial").unwrap();
        let (_, data) = Journal::open(flash, KEY).unwrap();
        assert_eq!(data.as_ref().map(|d| d.as_slice()), Some(b"old".as_slice()));
    }

    #[test]
    fn interrupted_reuse_always_recovers_old_or_new_state() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"one").unwrap();
        journal.commit(b"two").unwrap();
        let base = journal.into_flash();
        for cut in 0..=190 {
            let mut flash = base.clone();
            flash.fail_after = Some(cut);
            let (mut journal, _) = Journal::open(flash, KEY).unwrap();
            let committed = journal.commit(b"three");
            if committed.is_err() && cut >= 4 {
                // Removing the I/O fault must not make an uncertain commit retryable.
                journal.flash.fail_after = None;
                let nonce = journal.flash.nonce_generation().unwrap();
                assert_eq!(journal.commit(b"retry"), Err(Error::Storage));
                assert_eq!(journal.flash.nonce_generation().unwrap(), nonce);
            }
            let mut flash = journal.into_flash();
            flash.fail_after = None;
            let (_, recovered) = Journal::open(flash, KEY).unwrap();
            assert!(
                recovered.as_ref().map(|d| d.as_slice()) == Some(b"two".as_slice())
                    || recovered.as_ref().map(|d| d.as_slice()) == Some(b"three".as_slice()),
                "partial reuse at cut {cut}: {recovered:?}"
            );
        }
    }

    #[test]
    fn three_slot_ring_rotates_and_recovers_the_latest_generation() {
        let (mut journal, _) = Journal::open(MemoryFlash::with_slots(128, 3), KEY).unwrap();
        for state in [b"one".as_slice(), b"two", b"three", b"four"] {
            journal.commit(state).unwrap();
        }
        let flash = journal.into_flash();
        assert_eq!(&flash.slots[0][4..12], &4u64.to_le_bytes());
        assert_eq!(&flash.slots[1][4..12], &2u64.to_le_bytes());
        assert_eq!(&flash.slots[2][4..12], &3u64.to_le_bytes());
        let (_, recovered) = Journal::open(flash, KEY).unwrap();
        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(b"four".as_slice()));
    }

    #[test]
    fn three_slot_reuse_recovers_old_or_new_at_every_mutation() {
        let (mut journal, _) = Journal::open(MemoryFlash::with_slots(128, 3), KEY).unwrap();
        let mut initial = RecordingProvider::default();
        for state in [b"one".as_slice(), b"two", b"three"] {
            journal.commit_with(state, &mut initial).unwrap();
        }
        let base = journal.into_flash();

        let (mut measured, _) = Journal::open(base.clone(), KEY).unwrap();
        measured.flash.fail_after = Some(usize::MAX);
        measured.commit(b"four").unwrap();
        let remaining = measured.flash.fail_after.unwrap();
        let mutations = usize::MAX - remaining;

        for cut in 0..=mutations {
            let (mut interrupted, _) = Journal::open(base.clone(), KEY).unwrap();
            interrupted.flash.fail_after = Some(cut);
            let mut provider = RecordingProvider { nonces: initial.nonces.clone(), ..Default::default() };
            let _ = interrupted.commit_with(b"four", &mut provider);
            let mut flash = interrupted.into_flash();
            flash.fail_after = None;
            let (mut resumed, recovered) = Journal::open(flash, KEY).unwrap();
            assert!(
                recovered.as_deref().map(|data| data.as_slice()) == Some(b"three".as_slice())
                    || recovered.as_deref().map(|data| data.as_slice())
                        == Some(b"four".as_slice()),
                "partial three-slot reuse at cut {cut}: {recovered:?}"
            );
            resumed.commit_with(b"different retry", &mut provider).unwrap();
            let (_, recovered) = Journal::open(resumed.into_flash(), KEY).unwrap();
            assert_eq!(recovered.unwrap().as_slice(), b"different retry");
        }
    }

    #[derive(Default)]
    struct RecordingProvider {
        encrypts: usize,
        decrypts: usize,
        nonces: Vec<[u8; 13]>,
        fail_encrypt: bool,
        encryption_buffer: usize,
    }
    impl CryptoProvider for RecordingProvider {
        fn aes_ccm_encrypt_in_place(
            &mut self,
            key: &[u8; 16],
            nonce: &[u8; 13],
            aad: &[u8],
            output: &mut [u8],
        ) -> Result<usize> {
            assert!(!self.nonces.contains(nonce), "encryption nonce reused");
            self.nonces.push(*nonce);
            self.encrypts += 1;
            self.encryption_buffer = output.as_ptr() as usize;
            if self.fail_encrypt { return Err(Error::Native); }
            crate::crypto::ccm_encrypt_in_place(key, nonce, aad, output)
        }

        fn aes_ccm_decrypt_in_place(
            &mut self,
            key: &[u8; 16],
            nonce: &[u8; 13],
            aad: &[u8],
            ciphertext: &mut [u8],
        ) -> Result<usize> {
            self.decrypts += 1;
            crate::crypto::ccm_decrypt_in_place(key, nonce, aad, ciphertext)
        }
    }

    #[test]
    fn journal_uses_provider_and_preserves_provider_failures() {

        let mut provider = RecordingProvider::default();
        let (mut journal, _) =
            Journal::open_with(MemoryFlash::new(128), KEY, &mut provider).unwrap();
        let mut snapshot = Zeroizing::new(Vec::with_capacity(128));
        snapshot.extend_from_slice(b"provider-backed journal");
        let payload_address = snapshot.as_ptr() as usize + HEADER_BYTES;
        journal.commit_owned_with(snapshot, &mut provider).unwrap();
        assert_eq!(provider.encryption_buffer, payload_address,
            "owned snapshots must reach encryption without another allocation");
        assert_eq!((provider.encrypts, provider.decrypts), (1, 0));
        let flash = journal.into_flash();
        let (_, recovered) = Journal::open_with(flash.clone(), KEY, &mut provider).unwrap();
        assert_eq!(
            recovered.as_ref().map(|bytes| bytes.as_slice()),
            Some(b"provider-backed journal".as_slice())
        );
        // Candidate authentication drops its scratch buffer before the
        // selected record is loaded into the returned snapshot.
        assert_eq!((provider.encrypts, provider.decrypts), (1, 2));

        struct FailingProvider;
        impl CryptoProvider for FailingProvider {
            fn aes_ccm_encrypt_in_place(
                &mut self,
                _: &[u8; 16],
                _: &[u8; 13],
                _: &[u8],
                _: &mut [u8],
            ) -> Result<usize> {
                Err(Error::Native)
            }

            fn aes_ccm_decrypt_in_place(
                &mut self,
                _: &[u8; 16],
                _: &[u8; 13],
                _: &[u8],
                _: &mut [u8],
            ) -> Result<usize> {
                Err(Error::Native)
            }
        }

        assert!(matches!(
            Journal::open_with(flash, KEY, &mut FailingProvider),
            Err(Error::Native)
        ));
        let (mut blank, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        let mut failed = RecordingProvider { fail_encrypt: true, ..Default::default() };
        assert!(matches!(
            blank.commit_with(b"must not commit", &mut failed),
            Err(Error::Native)
        ));
        assert!(blank
            .flash
            .slots
            .iter()
            .all(|slot| slot.iter().all(|byte| *byte == 0xff)));
        failed.fail_encrypt = false;
        blank.commit_with(b"different live retry", &mut failed).unwrap();
        assert_eq!(failed.nonces.len(), 2);
        let mut flash = blank.into_flash();
        flash.nonces.fill(0xff);
        assert!(matches!(Journal::open(flash, KEY), Err(Error::Storage)));
    }
