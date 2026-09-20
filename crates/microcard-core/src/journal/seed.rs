//! Copy an authenticated initial record without repeating encryption after renewal.
use super::*;

/// Ciphertext borrowed immutably after authentication and application validation.
/// The registry must reserve a fresh key identity before producing this record and
/// own its recovery copy before authorizing bank preparation or counter erasure.
pub struct SeedRecord<'a> { bytes: &'a [u8] }
impl<'a> SeedRecord<'a> {
    pub const MIN_BYTES: usize = HEADER_BYTES + 16 + 1;
    pub const MAX_BYTES: usize = 65536 - 3;
    pub fn authenticate(bytes: &'a [u8], key: &JournalKey, provider: &mut impl CryptoProvider,
            validate: impl FnOnce(&[u8]) -> Result<()>) -> Result<Self> {
        if !(Self::MIN_BYTES..=Self::MAX_BYTES).contains(&bytes.len()) { return Err(Error::Format); }
        let header: &[u8; HEADER_BYTES] = bytes.get(..HEADER_BYTES)
            .ok_or(Error::Format)?.try_into().map_err(|_| Error::Format)?;
        let fields = RecordHeader::decode(header, bytes.len() - HEADER_BYTES, 1)?;
        if !fields.append_enabled { return Err(Error::IncompatibleState); }
        if fields.generation != 1 || fields.attempt != 1
            || fields.payload_length as usize != bytes.len() - HEADER_BYTES {
            return Err(Error::Format);
        }
        let mut plaintext = crate::crypto::zeroizing_buffer(fields.payload_length as usize)?;
        plaintext.copy_from_slice(&bytes[HEADER_BYTES..]);
        let length = provider.aes_ccm_decrypt_in_place(key.as_ref(), &nonce(1), header, &mut plaintext)?;
        if length != plaintext.len() - 16 { return Err(Error::Storage); }
        plaintext.truncate(length);
        validate(&plaintext)?;
        Ok(Self { bytes })
    }

    /// Only accepts a completely prepared bank. Partial attempts require registry-
    /// authorized preparation again; callers must not resume from guessed offsets.
    /// There is deliberately no crypto provider or encryption call in this path.
    pub fn install_empty_bank(&self, flash: &mut impl Flash) -> Result<()> {
        let size = flash.slot_size();
        if !(2..=8).contains(&flash.slot_count()) || size < OVERHEAD
            || self.bytes.len() > size - 3 { return Err(Error::Bounds); }
        if flash.monotonic_capacity() == 0 || flash.nonce_capacity() == 0 { return Err(Error::Quota); }
        if flash.monotonic_generation()? != 0 || flash.nonce_generation()? != 0 {
            return Err(Error::Storage);
        }
        for slot in 0..flash.slot_count() {
            if !flash.is_erased(slot)? { return Err(Error::Storage); }
        }
        if flash.reserve_nonce()? != 1 || flash.nonce_generation()? != 1 { return Err(Error::Storage); }
        flash.program(0, 0, self.bytes)?;
        let mut scratch = [0; 64];
        for (index, expected) in self.bytes.chunks(scratch.len()).enumerate() {
            let output = &mut scratch[..expected.len()];
            flash.read(0, index * 64, output)?;
            if output != expected { return Err(Error::Storage); }
        }
        flash.program(0, size - 1, &[0])?;
        flash.read(0, size - 1, &mut scratch[..1])?;
        if scratch[0] != 0 { return Err(Error::Storage); }
        flash.advance_monotonic(1)?;
        if flash.monotonic_generation()? != 1 { return Err(Error::Storage); }
        Ok(())
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;

    #[test]
    fn seed_authenticates_before_copy_and_recovers_each_publication_cut() {
        let key = JournalKey::from([3; 16]);
        let (mut journal, _) = Journal::open_with_replay(MemoryFlash::new(1024), [3; 16],
            &mut SoftwareCrypto, |_, _, _| Err(Error::Format)).unwrap();
        journal.commit(b"committed state").unwrap();
        let source = journal.into_flash();
        let length = HEADER_BYTES + b"committed state".len() + 16;
        let record = &source.slots[0][..length];
        let validate = |bytes: &[u8]| if bytes == b"committed state" { Ok(()) } else { Err(Error::Format) };
        let seed = SeedRecord::authenticate(record, &key, &mut SoftwareCrypto, validate).unwrap();
        assert!(SeedRecord::authenticate(record, &JournalKey::from([4; 16]), &mut SoftwareCrypto, validate).is_err());
        assert!(SeedRecord::authenticate(record, &key, &mut SoftwareCrypto, |_| Err(Error::KeyMismatch)).is_err());
        for end in 0..record.len() {
            assert!(SeedRecord::authenticate(&record[..end], &key, &mut SoftwareCrypto, validate).is_err());
        }
        let mut trailing = record.to_vec(); trailing.push(0);
        assert!(SeedRecord::authenticate(&trailing, &key, &mut SoftwareCrypto, validate).is_err());
        for at in [0, 4, 12, 20, HEADER_BYTES, record.len() - 1] {
            let mut changed = record.to_vec(); changed[at] ^= 1;
            assert!(SeedRecord::authenticate(&changed, &key, &mut SoftwareCrypto, validate).is_err());
        }
        let mut used = source.clone();
        assert_eq!(seed.install_empty_bank(&mut used), Err(Error::Storage));
        assert_eq!(used.slots, source.slots);
        assert_eq!(used.nonce_generation(), Ok(1));

        // Nonce bytes, exact ciphertext, marker, then generation bytes.
        let mutations = 4 + record.len() + 1 + 4;
        for cut in 0..=mutations {
            let mut flash = MemoryFlash::new(1024);
            flash.fail_after = Some(cut);
            let complete = seed.install_empty_bank(&mut flash).is_ok();
            flash.fail_after = None;
            if cut > 4 + record.len() {
                let (_, state) = Journal::open_with_replay(flash, [3; 16], &mut SoftwareCrypto,
                    |_, _, _| Err(Error::Format)).unwrap();
                assert_eq!(state.unwrap().as_slice(), b"committed state");
            } else { assert!(!complete); }
            // Recovery owns a fresh preparation; it copies the same verified bytes.
            let mut prepared = MemoryFlash::new(1024);
            seed.install_empty_bank(&mut prepared).unwrap();
            assert_eq!(&prepared.slots[0][..record.len()], record);
            assert_eq!(prepared.nonce_generation(), Ok(1));
            assert_eq!(prepared.monotonic_generation(), Ok(1));
        }
    }
}
