//! Authenticated rotating journal. Commit marker is programmed last; the old slot survives.
use crate::{
    crypto::{CryptoProvider, SoftwareCrypto},
    Error, Result,
};
use alloc::{vec, vec::Vec};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct JournalKey([u8; 16]);

impl JournalKey {
    pub(crate) fn zeroed() -> Self {
        Self([0; 16])
    }
}

impl From<[u8; 16]> for JournalKey {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 16]> for JournalKey {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for JournalKey {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}
pub trait Flash {
    /// Stable number of independently erasable snapshot slots.
    fn slot_count(&self) -> usize {
        2
    }
    fn slot_size(&self) -> usize;
    fn monotonic_capacity(&self) -> u64;
    fn monotonic_generation(&self) -> Result<u64>;
    fn advance_monotonic(&mut self, generation: u64) -> Result<()>;
    fn is_erased(&self, slot: usize) -> Result<bool>;
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()>;
    fn erase(&mut self, slot: usize) -> Result<()>;
    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()>;
}
pub struct Journal<F: Flash> {
    flash: F,
    generation: u64,
    active: Option<usize>,
    slot_count: usize,
    poisoned: bool,
    key: JournalKey,
}
impl<F: Flash> Journal<F> {
    pub fn open(
        flash: F,
        key: impl Into<JournalKey>,
    ) -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        Self::open_with(flash, key, &mut SoftwareCrypto)
    }

    pub fn open_with(
        mut flash: F,
        key: impl Into<JournalKey>,
        provider: &mut impl CryptoProvider,
    ) -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        let key = key.into();
        let slot_count = flash.slot_count();
        if !(2..=8).contains(&slot_count) {
            return Err(Error::Storage);
        }
        let size = flash.slot_size();
        if size < 35 {
            return Err(Error::Storage);
        }
        let mut selected = None;
        let mut saw_non_erased = false;
        let mut saw_corrupt_committed = false;
        for slot in 0..slot_count {
            if !flash.is_erased(slot)? {
                saw_non_erased = true;
            }
            let mut tail = [0; 3];
            flash.read(slot, size - tail.len(), &mut tail)?;
            if tail[2] != 0 {
                continue;
            }
            let mut header = [0; 16];
            flash.read(slot, 0, &mut header)?;
            if &header[..4] != b"MJ02" {
                saw_corrupt_committed = true;
                continue;
            }
            let generation = u64::from_le_bytes(header[4..12].try_into().unwrap());
            let n = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
            if n < 16 || n > size - 19 {
                saw_corrupt_committed = true;
                continue;
            }
            let mut plaintext = crate::crypto::zeroizing_buffer(n)?;
            flash.read(slot, header.len(), &mut plaintext)?;
            let nonce = nonce(generation);
            match provider.aes_ccm_decrypt_in_place(key.as_ref(), &nonce, &header, &mut plaintext) {
                Ok(written) if written == n - 16 => plaintext.truncate(written),
                Ok(_) => {
                    plaintext.zeroize();
                    return Err(Error::Storage);
                }
                Err(Error::Authentication) => {
                    plaintext.zeroize();
                    saw_corrupt_committed = true;
                    continue;
                }
                Err(error) => {
                    plaintext.zeroize();
                    return Err(error);
                }
            }
            let reclaim_started = tail[0] == 0;
            let reclaim_complete = tail[1] == 0;
            if reclaim_complete && !reclaim_started {
                saw_corrupt_committed = true;
                continue;
            }
            if selected
                .as_ref()
                .is_none_or(|(_, g, _, _, _)| generation > *g)
            {
                selected = Some((
                    slot,
                    generation,
                    plaintext,
                    reclaim_started,
                    reclaim_complete,
                ));
            }
        }
        // A reclaim intent on the surviving record authorizes fallback only while
        // a target slot is being replaced. Completion closes that narrow recovery window.
        let interrupted_reclaim = selected
            .as_ref()
            .is_some_and(|(_, _, _, started, complete)| *started && !*complete);
        if (saw_corrupt_committed && !interrupted_reclaim) || (saw_non_erased && selected.is_none())
        {
            return Err(Error::Storage);
        }
        let (active, generation, data) = match selected {
            Some((s, g, d, _, _)) => (Some(s), g, Some(d)),
            None => (None, 0, None),
        };
        let anchored = flash.monotonic_generation()?;
        if anchored > flash.monotonic_capacity() {
            return Err(Error::Storage);
        }
        let next_anchored = anchored.checked_add(1).ok_or(Error::Storage)?;
        if anchored > generation || generation > next_anchored {
            return Err(Error::Storage);
        }
        if generation == next_anchored {
            flash.advance_monotonic(generation)?;
        }
        Ok((
            Self {
                flash,
                generation,
                active,
                slot_count,
                poisoned: false,
                key,
            },
            data,
        ))
    }
    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        self.commit_with(data, &mut SoftwareCrypto)
    }

    pub fn commit_with(&mut self, data: &[u8], provider: &mut impl CryptoProvider) -> Result<()> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        let size = self.flash.slot_size();
        if size < 35 || data.len() > size - 35 {
            return Err(Error::Quota);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Storage)?;
        if generation > self.flash.monotonic_capacity() {
            return Err(Error::Quota);
        }
        let slot = self
            .active
            .map_or(0, |active| (active + 1) % self.slot_count);
        let payload_length = data.len().checked_add(16).ok_or(Error::Quota)?;
        let encoded_payload_length = u32::try_from(payload_length).map_err(|_| Error::Quota)?;
        let record_length = 16usize
            .checked_add(payload_length)
            .ok_or(Error::Quota)?;
        let mut record = Vec::new();
        record
            .try_reserve_exact(record_length)
            .map_err(|_| Error::Quota)?;
        record.extend_from_slice(b"MJ02");
        record.extend_from_slice(&generation.to_le_bytes());
        record.extend_from_slice(&encoded_payload_length.to_le_bytes());
        let header = record.len();
        record.resize(record_length, 0);
        let (aad, ciphertext) = record.split_at_mut(header);
        let written =
            match provider.aes_ccm_encrypt(
                self.key.as_ref(),
                &nonce(generation),
                aad,
                data,
                ciphertext,
            ) {
                Ok(written) => written,
                Err(error) => {
                    ciphertext.zeroize();
                    return Err(error);
                }
            };
        if written != ciphertext.len() {
            ciphertext.zeroize();
            return Err(Error::Storage);
        }
        if let Some(active) = self.active {
            self.flash.program(active, size - 3, &[0])?;
        }
        self.flash.erase(slot)?;
        self.flash.program(slot, 0, &record)?;
        self.flash.program(slot, size - 1, &[0])?;
        if let Some(active) = self.active {
            self.flash.program(active, size - 2, &[0])?;
        }
        self.generation = generation;
        self.active = Some(slot);
        if let Err(error) = self.flash.advance_monotonic(generation) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    pub fn into_flash(self) -> F {
        let Self { flash, .. } = self;
        flash
    }
}

fn nonce(generation: u64) -> [u8; 13] {
    let mut nonce = *b"MCJNL\0\0\0\0\0\0\0\0";
    nonce[5..].copy_from_slice(&generation.to_le_bytes());
    nonce
}

/// Decode an append-only sequence where each non-erased word consumes one generation.
/// A torn word is consumed, so power loss cannot move the anchor backwards.
pub fn decode_monotonic_words(bytes: &[u8]) -> Result<u64> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::Storage);
    }
    let mut generation = 0u64;
    let mut saw_erased = false;
    for word in bytes.chunks_exact(4) {
        let consumed = word.iter().any(|byte| *byte != 0xff);
        if consumed {
            if saw_erased {
                return Err(Error::Storage);
            }
            generation = generation.checked_add(1).ok_or(Error::Storage)?;
        } else {
            saw_erased = true;
        }
    }
    Ok(generation)
}

/// Decode a one-way bit anchor. Bits are consumed least-significant first and
/// every consumed bit must precede every erased bit.
pub fn decode_monotonic_bits(bytes: &[u8]) -> Result<u64> {
    let mut generation = 0u64;
    let mut saw_erased = false;
    for byte in bytes {
        for bit in 0..8 {
            let consumed = byte & (1 << bit) == 0;
            if consumed {
                if saw_erased {
                    return Err(Error::Storage);
                }
                generation = generation.checked_add(1).ok_or(Error::Storage)?;
            } else {
                saw_erased = true;
            }
        }
    }
    Ok(generation)
}
/// Host fault model. Every erased/programmed byte is a separately interruptible mutation.
#[derive(Clone)]
pub struct MemoryFlash {
    slots: Vec<Vec<u8>>,
    monotonic: Vec<u8>,
    pub fail_after: Option<usize>,
}
impl MemoryFlash {
    pub fn new(size: usize) -> Self {
        Self::with_slots(size, 2)
    }
    fn with_slots(size: usize, slot_count: usize) -> Self {
        Self {
            slots: (0..slot_count).map(|_| vec![255; size]).collect(),
            monotonic: vec![255; size],
            fail_after: None,
        }
    }
    fn tick(&mut self) -> Result<()> {
        if let Some(n) = self.fail_after.as_mut() {
            if *n == 0 {
                return Err(Error::Storage);
            }
            *n -= 1;
        }
        Ok(())
    }
}
impl Flash for MemoryFlash {
    fn slot_count(&self) -> usize {
        self.slots.len()
    }
    fn slot_size(&self) -> usize {
        self.slots[0].len()
    }
    fn monotonic_capacity(&self) -> u64 {
        (self.monotonic.len() / 4) as u64
    }
    fn monotonic_generation(&self) -> Result<u64> {
        decode_monotonic_words(&self.monotonic)
    }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        let index = usize::try_from(generation.checked_sub(1).ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        let offset = index.checked_mul(4).ok_or(Error::Storage)?;
        let word = self
            .monotonic
            .get(offset..offset + 4)
            .ok_or(Error::Quota)?;
        if word.iter().any(|byte| *byte != 0xff) {
            return Err(Error::Storage);
        }
        for byte in offset..offset + 4 {
            self.tick()?;
            self.monotonic[byte] = 0;
        }
        Ok(())
    }
    fn is_erased(&self, s: usize) -> Result<bool> {
        Ok(self
            .slots
            .get(s)
            .ok_or(Error::Bounds)?
            .iter()
            .all(|byte| *byte == 0xff))
    }
    fn read(&self, s: usize, o: usize, output: &mut [u8]) -> Result<()> {
        let slot = self.slots.get(s).ok_or(Error::Bounds)?;
        let end = o.checked_add(output.len()).ok_or(Error::Bounds)?;
        output.copy_from_slice(slot.get(o..end).ok_or(Error::Bounds)?);
        Ok(())
    }
    fn erase(&mut self, s: usize) -> Result<()> {
        for i in 0..self.slot_size() {
            self.tick()?;
            self.slots[s][i] = 255;
        }
        Ok(())
    }
    fn program(&mut self, s: usize, o: usize, b: &[u8]) -> Result<()> {
        if o.checked_add(b.len()).is_none_or(|n| n > self.slot_size()) {
            return Err(Error::Bounds);
        }
        for (i, v) in b.iter().enumerate() {
            self.tick()?;
            if self.slots[s][o + i] & v != *v {
                return Err(Error::Storage);
            }
            self.slots[s][o + i] = *v;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    const KEY: [u8; 16] = [0x33; 16];

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
        assert!(matches!(
            Journal::open(incomplete, KEY),
            Err(Error::Storage)
        ));
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
    fn committed_mj01_state_has_no_upgrade_route() {
        let mut old = MemoryFlash::new(128);
        old.program(0, 0, b"MJ01").unwrap();
        old.program(0, 127, &[0]).unwrap();
        assert!(matches!(Journal::open(old, KEY), Err(Error::Storage)));
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
        let record_len = 16 + 19 + 16;
        for offset in 0..record_len {
            let Some(bit) = (0..8).find(|bit| base.slots[0][offset] & (1 << bit) != 0) else {
                continue;
            };
            let mut tampered = base.clone();
            tampered.slots[0][offset] &= !(1 << bit);
            assert!(matches!(Journal::open(tampered, KEY), Err(Error::Storage)));
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
            .find(|bit| flash.slots[1][17] & (1 << bit) != 0)
            .unwrap();
        flash.slots[1][17] &= !(1 << bit);
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
    fn failed_anchor_advance_poisoned_journal_recovers_on_reopen() {
        let mut flash = MemoryFlash::new(128);
        // erase(128) + record(35) + commit marker(1), then fail before the anchor word.
        flash.fail_after = Some(164);
        let (mut journal, _) = Journal::open(flash, KEY).unwrap();
        assert_eq!(journal.commit(b"one"), Err(Error::Storage));
        assert_eq!(journal.commit(b"two"), Err(Error::Storage));

        let mut flash = journal.into_flash();
        flash.fail_after = None;
        let (journal, recovered) = Journal::open(flash, KEY).unwrap();
        assert_eq!(recovered.as_deref().map(|data| data.as_slice()), Some(b"one".as_slice()));
        assert_eq!(journal.flash.monotonic_generation().unwrap(), 1);
    }

    #[test]
    fn exhausted_anchor_rejects_before_mutating_the_journal() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(64), KEY).unwrap();
        for _ in 0..journal.flash.monotonic_capacity() {
            journal.commit(b"x").unwrap();
        }
        let slots = journal.flash.slots.clone();
        let monotonic = journal.flash.monotonic.clone();

        assert_eq!(journal.commit(b"y"), Err(Error::Quota));
        assert_eq!(journal.flash.slots, slots);
        assert_eq!(journal.flash.monotonic, monotonic);
    }

    #[test]
    fn incomplete_new_record_falls_back_to_committed_old_record() {
        let (mut journal, _) = Journal::open(MemoryFlash::new(128), KEY).unwrap();
        journal.commit(b"old").unwrap();
        let mut flash = journal.into_flash();
        flash.program(1, 0, b"MJ02partial").unwrap();
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
            let _ = journal.commit(b"three");
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
        journal.commit(b"one").unwrap();
        journal.commit(b"two").unwrap();
        journal.commit(b"three").unwrap();
        let base = journal.into_flash();

        let (mut measured, _) = Journal::open(base.clone(), KEY).unwrap();
        measured.flash.fail_after = Some(usize::MAX);
        measured.commit(b"four").unwrap();
        let remaining = measured.flash.fail_after.unwrap();
        let mutations = usize::MAX - remaining;

        for cut in 0..=mutations {
            let (mut interrupted, _) = Journal::open(base.clone(), KEY).unwrap();
            interrupted.flash.fail_after = Some(cut);
            let _ = interrupted.commit(b"four");
            let mut flash = interrupted.into_flash();
            flash.fail_after = None;
            let (_, recovered) = Journal::open(flash, KEY).unwrap();
            assert!(
                recovered.as_deref().map(|data| data.as_slice()) == Some(b"three".as_slice())
                    || recovered.as_deref().map(|data| data.as_slice())
                        == Some(b"four".as_slice()),
                "partial three-slot reuse at cut {cut}: {recovered:?}"
            );
        }
    }

    #[test]
    fn journal_uses_provider_and_preserves_provider_failures() {
        #[derive(Default)]
        struct RecordingProvider {
            encrypts: usize,
            decrypts: usize,
        }
        impl CryptoProvider for RecordingProvider {
            fn aes_ccm_encrypt(
                &mut self,
                key: &[u8; 16],
                nonce: &[u8; 13],
                aad: &[u8],
                plaintext: &[u8],
                output: &mut [u8],
            ) -> Result<usize> {
                self.encrypts += 1;
                crate::crypto::ccm_encrypt_into(key, nonce, aad, plaintext, output)
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

        let mut provider = RecordingProvider::default();
        let (mut journal, _) =
            Journal::open_with(MemoryFlash::new(128), KEY, &mut provider).unwrap();
        journal
            .commit_with(b"provider-backed journal", &mut provider)
            .unwrap();
        assert_eq!((provider.encrypts, provider.decrypts), (1, 0));
        let flash = journal.into_flash();
        let (_, recovered) = Journal::open_with(flash.clone(), KEY, &mut provider).unwrap();
        assert_eq!(
            recovered.as_ref().map(|bytes| bytes.as_slice()),
            Some(b"provider-backed journal".as_slice())
        );
        assert_eq!((provider.encrypts, provider.decrypts), (1, 1));

        struct FailingProvider;
        impl CryptoProvider for FailingProvider {
            fn aes_ccm_encrypt(
                &mut self,
                _: &[u8; 16],
                _: &[u8; 13],
                _: &[u8],
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
        assert!(matches!(
            blank.commit_with(b"must not commit", &mut FailingProvider),
            Err(Error::Native)
        ));
        assert!(blank
            .into_flash()
            .slots
            .iter()
            .all(|slot| slot.iter().all(|byte| *byte == 0xff)));
    }
}
