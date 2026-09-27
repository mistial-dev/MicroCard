//! Authenticated rotating journal. Commit marker is programmed last; the old slot survives.
#[cfg(feature = "software-crypto")]
use crate::crypto::SoftwareCrypto;
use crate::{
    crypto::CryptoProvider,
    Error, Result,
};
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[cfg(any(test, feature = "jcvm"))]
mod append;
#[cfg(any(test, feature = "jcvm"))]
mod seed;
#[cfg(any(test, feature = "jcvm"))]
pub use seed::SeedRecord;

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
const TAIL_BYTES: usize = 12;
const RECLAIM_STARTED: usize = TAIL_BYTES;
const RECLAIM_COMPLETE: usize = TAIL_BYTES - 4;
const COMMITTED: usize = TAIL_BYTES - 8;
pub(crate) const RECORD_OVERHEAD: usize = HEADER_BYTES + 16;
pub const OVERHEAD: usize = RECORD_OVERHEAD + TAIL_BYTES;
const HEADER_BYTES: usize = 24;

/// JCVM records carry an append sequence and a separately advanced security anchor.
/// The low word changes for every authenticated record; the high word changes only
/// when the card's security policy protects PIN retry state from rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability { Ordinary, Anchored }

#[cfg(feature = "jcvm")]
impl From<microcard_engine_jcvm::host::CheckpointReason> for Durability {
    fn from(reason: microcard_engine_jcvm::host::CheckpointReason) -> Self {
        use microcard_engine_jcvm::host::CheckpointReason;
        match reason {
            CheckpointReason::ApduEnd | CheckpointReason::TransactionCommit => Self::Ordinary,
            CheckpointReason::Installation | CheckpointReason::OwnerPin => Self::Anchored,
        }
    }
}

fn anchor(generation: u64, append_enabled: bool) -> u64 {
    if append_enabled { generation >> 32 } else { generation }
}

fn next_generation(generation: u64, append_enabled: bool, durability: Durability) -> Result<u64> {
    if !append_enabled { return generation.checked_add(1).ok_or(Error::Quota); }
    let sequence = (generation as u32).checked_add(1).ok_or(Error::Quota)?;
    let anchored = anchor(generation, true)
        .checked_add(u64::from(durability == Durability::Anchored)).ok_or(Error::Quota)?;
    if anchored == 0 || anchored > u32::MAX as u64 { return Err(Error::Quota); }
    Ok((anchored << 32) | u64::from(sequence))
}

struct RecordHeader {
    append_enabled: bool,
    generation: u64,
    attempt: u64,
    payload_length: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CandidateMeta {
    slot: usize,
    base_generation: u64,
    attempt: u64,
    payload_length: usize,
    generation: u64,
    append_offset: Option<usize>,
    reclaim_started: bool,
    reclaim_complete: bool,
}

enum CandidateRead {
    Absent,
    Corrupt,
    Valid(CandidateMeta, Zeroizing<Vec<u8>>),
}

impl RecordHeader {
    fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..4].copy_from_slice(if self.append_enabled { b"MJ09" } else { b"MJ08" });
        bytes[4..12].copy_from_slice(&self.generation.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.attempt.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.payload_length.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8; HEADER_BYTES], capacity: usize, reserved_nonce: u64) -> Result<Self> {
        if matches!(&bytes[..4], b"MJ01" | b"MJ02" | b"MJ03" | b"MJ04" | b"MJ05" | b"MJ06" | b"MJ07") {
            return Err(Error::IncompatibleState);
        }
        let append_enabled = match &bytes[..4] { b"MJ08" => false, b"MJ09" => true, _ => return Err(Error::Storage) };
        let header = Self {
            append_enabled,
            generation: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            attempt: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            payload_length: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        };
        if header.attempt == 0 || header.attempt > reserved_nonce
            || header.payload_length < 16 || header.payload_length as usize > capacity {
            return Err(Error::Storage);
        }
        if append_enabled && (anchor(header.generation, true) == 0 || header.generation as u32 == 0) {
            return Err(Error::Storage);
        }
        Ok(header)
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
    /// Separate, non-erasable-in-service counter for encryption attempts.
    fn nonce_capacity(&self) -> u64 { self.monotonic_capacity() }
    fn nonce_generation(&self) -> Result<u64>;
    /// Durably consume the next value before returning it. A partial reservation
    /// is consumed on recovery; failures must never return a usable nonce.
    fn reserve_nonce(&mut self) -> Result<u64>;
    fn is_erased(&self, slot: usize) -> Result<bool>;
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()>;
    fn erase(&mut self, slot: usize) -> Result<()>;
    fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()>;
}
pub struct Journal<F: Flash> {
    flash: F,
    generation: u64,
    base_attempt: Option<u64>,
    active: Option<usize>,
    append_offset: Option<usize>,
    append_enabled: bool,
    slot_count: usize,
    poisoned: bool,
    key: JournalKey,
}

#[cfg(feature = "jcvm")]
pub(crate) struct ReservedNonce(u64);

#[cfg(feature = "jcvm")]
impl ReservedNonce {
    pub(crate) fn value(&self) -> u64 { self.0 }
}

impl<F: Flash> Journal<F> {
    /// Domain-separated consumers may burn counter values for fresh identities.
    #[cfg(feature = "jcvm")]
    pub(crate) fn reserve_identity_nonce(&mut self) -> Result<ReservedNonce> {
        if self.poisoned { return Err(Error::Storage); }
        let value = self.flash.reserve_nonce()?;
        if value == 0 || value > self.flash.nonce_capacity() { return Err(Error::Storage); }
        Ok(ReservedNonce(value))
    }
    #[cfg(feature = "software-crypto")]
    pub fn open(
        flash: F,
        key: impl Into<JournalKey>,
    ) -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        Self::open_with(flash, key, &mut SoftwareCrypto)
    }

    pub fn open_with(
        flash: F,
        key: impl Into<JournalKey>,
        provider: &mut impl CryptoProvider,
    ) -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        Self::open_mode(flash, key, provider, false, |_, _, _| Err(Error::IncompatibleState))
    }

    #[cfg(any(test, feature = "jcvm"))]
    pub fn open_with_replay(flash: F, key: impl Into<JournalKey>, provider: &mut impl CryptoProvider,
            apply: impl FnMut(&mut Zeroizing<Vec<u8>>, u64, &[u8]) -> Result<()>)
            -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        Self::open_mode(flash, key, provider, true, apply)
    }

    fn open_mode(flash: F, key: impl Into<JournalKey>, provider: &mut impl CryptoProvider,
            append_enabled: bool, apply: impl FnMut(&mut Zeroizing<Vec<u8>>, u64, &[u8]) -> Result<()>)
            -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        let mut journal = Self {
            flash, generation: 0, base_attempt: None, active: None, append_offset: None, append_enabled, slot_count: 0, poisoned: true, key: key.into(),
        };
        let data = journal.recover_with_replay(provider, apply)?;
        Ok((journal, data))
    }

    /// Reconcile uncertain writes using the same authenticated scan as reboot.
    /// A failed recovery keeps commits disabled until recovery succeeds.
    pub fn recover_with(&mut self, provider: &mut impl CryptoProvider) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.recover_with_replay(provider, |_, _, _| Err(Error::IncompatibleState))
    }

    /// Replay authenticated changes into each candidate snapshot before selecting it.
    /// A callback error discards that candidate's zeroizing scratch state.
    pub fn recover_with_replay(&mut self, provider: &mut impl CryptoProvider,
            apply: impl FnMut(&mut Zeroizing<Vec<u8>>, u64, &[u8]) -> Result<()>)
            -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.recover_with_replay_mode(provider, apply, false)
    }

    /// Return the selected authenticated generation even when repairing its monotonic
    /// anchor fails. The journal stays poisoned, but a caller can still resolve whether
    /// an interrupted publication took effect before it returns an operation result.
    #[cfg(feature = "mc04")]
    pub(crate) fn recover_selected_with(
        &mut self,
        provider: &mut impl CryptoProvider,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.recover_with_replay_mode(
            provider,
            |_, _, _| Err(Error::IncompatibleState),
            true,
        )
    }

    fn recover_with_replay_mode(&mut self, provider: &mut impl CryptoProvider,
            apply: impl FnMut(&mut Zeroizing<Vec<u8>>, u64, &[u8]) -> Result<()>,
            allow_unreconciled: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut apply = apply;
        self.poisoned = true;
        let slot_count = self.flash.slot_count();
        if !(2..=8).contains(&slot_count) {
            return Err(Error::Storage);
        }
        let size = self.flash.slot_size();
        if size < OVERHEAD {
            return Err(Error::Storage);
        }
        let reserved_nonce = self.flash.nonce_generation()?;
        if reserved_nonce > self.flash.nonce_capacity() { return Err(Error::Storage); }
        let mut selected: Option<CandidateMeta> = None;
        let mut saw_non_erased = false;
        let mut saw_corrupt_committed = false;
        for slot in 0..slot_count {
            if !self.flash.is_erased(slot)? {
                saw_non_erased = true;
            }
            match self.read_candidate(slot, size, reserved_nonce, provider, &mut apply)? {
                CandidateRead::Absent => {}
                CandidateRead::Corrupt => saw_corrupt_committed = true,
                CandidateRead::Valid(meta, _plaintext) => {
                    if selected.is_none_or(|current| meta.generation > current.generation) {
                        selected = Some(meta);
                    }
                }
            }
        }
        // A reclaim intent on the surviving record authorizes fallback only while
        // a target slot is being replaced. Completion closes that narrow recovery window.
        let interrupted_reclaim = selected
            .is_some_and(|candidate| candidate.reclaim_started && !candidate.reclaim_complete);
        if (saw_corrupt_committed && !interrupted_reclaim) || (saw_non_erased && selected.is_none())
        {
            return Err(Error::Storage);
        }
        // Do not retain one full snapshot while authenticating another. Re-read
        // only the selected record after every committed slot has been checked.
        let (active, generation, data, append_offset) = match selected {
            Some(meta) => {
                let data = match self.read_candidate(meta.slot, size, reserved_nonce, provider, &mut apply)? {
                    CandidateRead::Valid(reloaded, data) if reloaded == meta => data,
                    _ => return Err(Error::Storage),
                };
                (Some(meta.slot), meta.generation, Some(data), meta.append_offset)
            }
            None => (None, 0, None, None),
        };
        let reconciled = reconcile_generation(&mut self.flash, anchor(generation, self.append_enabled));
        self.generation = generation;
        self.base_attempt = selected.map(|meta| meta.attempt);
        self.active = active;
        self.append_offset = append_offset;
        self.slot_count = slot_count;
        self.poisoned = reconciled.is_err();
        if !allow_unreconciled {
            reconciled?;
        }
        Ok(data)
    }

    fn read_candidate(
        &mut self,
        slot: usize,
        size: usize,
        reserved_nonce: u64,
        provider: &mut impl CryptoProvider,
        apply: &mut impl FnMut(&mut Zeroizing<Vec<u8>>, u64, &[u8]) -> Result<()>,
    ) -> Result<CandidateRead> {
        #[cfg(not(any(test, feature = "jcvm")))]
        let _ = apply;
        #[cfg(all(feature = "latency-trace", feature = "jcvm"))]
        crate::jcvm_storage::renewal_phase(50 + slot as u32);
        let mut header = [0; HEADER_BYTES];
        self.flash.read(slot, 0, &mut header)?;
        if matches!(&header[..4], b"MJ01" | b"MJ02" | b"MJ03" | b"MJ04" | b"MJ05" | b"MJ06" | b"MJ07") {
            return Err(Error::IncompatibleState);
        }
        let mut tail = [0; TAIL_BYTES];
        self.flash.read(slot, size - tail.len(), &mut tail)?;
        if tail[TAIL_BYTES - COMMITTED..] != [0; 4] {
            return Ok(CandidateRead::Absent);
        }
        let decoded = match RecordHeader::decode(&header, size - HEADER_BYTES - TAIL_BYTES, reserved_nonce) {
            Ok(decoded) => decoded,
            Err(Error::IncompatibleState) => return Err(Error::IncompatibleState),
            Err(_) => return Ok(CandidateRead::Corrupt),
        };
        if decoded.append_enabled != self.append_enabled {
            return Err(Error::IncompatibleState);
        }
        let n = decoded.payload_length as usize;
        let capacity = if self.append_enabled { size - OVERHEAD + 16 } else { n };
        let mut plaintext = crate::crypto::zeroizing_buffer(capacity)?;
        plaintext.truncate(n);
        #[cfg(all(feature = "latency-trace", feature = "jcvm"))]
        crate::jcvm_storage::renewal_phase(60 + slot as u32);
        self.flash.read(slot, header.len(), &mut plaintext)?;
        let nonce = nonce(decoded.attempt);
        match provider.aes_ccm_decrypt_in_place(self.key.as_ref(), &nonce, &header, &mut plaintext) {
            Ok(written) if written == n - 16 => plaintext.truncate(written),
            Ok(_) => {
                plaintext.zeroize();
                return Err(Error::Storage);
            }
            Err(Error::Authentication) => {
                plaintext.zeroize();
                return Ok(CandidateRead::Corrupt);
            }
            Err(error) => {
                plaintext.zeroize();
                return Err(error);
            }
        }
        #[cfg(all(feature = "latency-trace", feature = "jcvm"))]
        crate::jcvm_storage::renewal_phase(70 + slot as u32);
        #[cfg(any(test, feature = "jcvm"))]
        let (generation, append_offset) = if self.append_enabled {
            let append_start = (HEADER_BYTES + n).next_multiple_of(4);
            match append::replay(&self.flash, &self.key, slot, append_start,
                    append::Epoch { generation: decoded.generation, attempt: decoded.attempt }, provider,
                    |base, delta| apply(&mut plaintext, base, delta)) {
                Ok(result) => result,
                Err(Error::Format | Error::Authentication) => return Ok(CandidateRead::Corrupt),
                Err(error) => return Err(error),
            }
        } else {
            (decoded.generation, None)
        };
        #[cfg(not(any(test, feature = "jcvm")))]
        let (generation, append_offset) = (decoded.generation, None);
        #[cfg(all(feature = "latency-trace", feature = "jcvm"))]
        crate::jcvm_storage::renewal_phase(80 + slot as u32);
        let reclaim_started = tail[..4] == [0; 4];
        let reclaim_complete = tail[TAIL_BYTES - RECLAIM_COMPLETE..TAIL_BYTES - COMMITTED] == [0; 4];
        if tail[..4] != [0; 4] && tail[..4] != [0xff; 4]
            || tail[TAIL_BYTES - RECLAIM_COMPLETE..TAIL_BYTES - COMMITTED] != [0; 4]
                && tail[TAIL_BYTES - RECLAIM_COMPLETE..TAIL_BYTES - COMMITTED] != [0xff; 4] {
            return Ok(CandidateRead::Corrupt);
        }
        if reclaim_complete && !reclaim_started {
            return Ok(CandidateRead::Corrupt);
        }
        Ok(CandidateRead::Valid(CandidateMeta {
            slot,
            base_generation: decoded.generation,
            attempt: decoded.attempt,
            payload_length: n,
            generation,
            append_offset: if reclaim_started { None } else { append_offset },
            reclaim_started,
            reclaim_complete,
        }, plaintext))
    }

    #[cfg(feature = "software-crypto")]
    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        self.commit_with(data, &mut SoftwareCrypto)
    }

    pub fn commit_with(&mut self, data: &[u8], provider: &mut impl CryptoProvider) -> Result<()> {
        if self.poisoned { return Err(Error::Storage); }
        let size = self.flash.slot_size();
        if size < OVERHEAD || data.len() > size - OVERHEAD { return Err(Error::Quota); }
        let mut owned = Zeroizing::new(Vec::new());
        owned.try_reserve_exact(data.len() + HEADER_BYTES + 16).map_err(|_| Error::Quota)?;
        owned.extend_from_slice(data);
        self.commit_owned_with(owned, provider)
    }

    pub fn generation(&self) -> u64 { self.generation }

    /// Remaining successful commits, bounded by both independent counters.
    pub fn remaining_commits(&self) -> Result<u64> {
        let anchored = anchor(self.generation, self.append_enabled);
        if self.poisoned || self.flash.monotonic_generation()? != anchored { return Err(Error::Storage); }
        let generations = self.flash.monotonic_capacity().checked_sub(anchored).ok_or(Error::Storage)?;
        let attempts = self.flash.nonce_capacity().checked_sub(self.flash.nonce_generation()?).ok_or(Error::Storage)?;
        Ok(generations.min(attempts))
    }

    #[cfg(any(test, feature = "jcvm"))]
    pub fn append_capacity(&self) -> Result<usize> {
        if self.poisoned { return Err(Error::Storage); }
        let at = self.append_offset.ok_or(Error::Quota)?;
        if !self.append_enabled { return Err(Error::IncompatibleState); }
        let available = self.flash.slot_size().saturating_sub(TAIL_BYTES).saturating_sub(at) / 4 * 4;
        let capacity = available.saturating_sub(append::MIN_FRAME_BYTES);
        if capacity == 0 { return Err(Error::Quota); }
        Ok(capacity.min(append::MAX_PAYLOAD))
    }

    /// Estimate append room after a full snapshot of this payload in the idle slot.
    /// This avoids rotating slots when the same snapshot would still leave no room.
    #[cfg(feature = "jcvm")]
    pub(crate) fn append_capacity_after_snapshot(&self, payload_length: usize) -> Result<usize> {
        let record_end = payload_length.checked_add(RECORD_OVERHEAD)
            .ok_or(Error::Quota)?.next_multiple_of(4);
        let available = self.flash.slot_size().saturating_sub(TAIL_BYTES)
            .saturating_sub(record_end);
        Ok(available.saturating_sub(append::MIN_FRAME_BYTES).min(append::MAX_PAYLOAD))
    }

    /// Conservative count of maximum-sized append records left in this epoch.
    #[cfg(any(test, feature = "jcvm"))]
    pub fn remaining_append_frames(&self) -> Result<usize> {
        if self.poisoned || !self.append_enabled { return Err(Error::Storage); }
        // A full slot reopens with no append offset. That is a renewal trigger,
        // not a corrupt journal.
        let Some(at) = self.append_offset else { return Ok(0); };
        let available = self.flash.slot_size().saturating_sub(TAIL_BYTES).saturating_sub(at);
        Ok(available / append::MAX_FRAME_BYTES)
    }

    /// Append one bounded authenticated change without erasing a snapshot slot.
    /// Quota requires a new full snapshot; uncertain writes require recovery.
    #[cfg(any(test, feature = "jcvm"))]
    pub fn append_owned_with(&mut self, data: Zeroizing<Vec<u8>>, provider: &mut impl CryptoProvider) -> Result<()> {
        if self.poisoned { return Err(Error::Storage); }
        let at = self.append_offset.ok_or(Error::Quota)?;
        let length = data.len();
        append::append(self, at, data, Durability::Anchored, provider)?;
        self.append_offset = append::frame_end(&self.flash, at, length).ok();
        Ok(())
    }

    /// Encode a bounded change directly into the authenticated append frame.
    #[cfg(any(test, feature = "jcvm"))]
    pub fn append_encoded_with(&mut self, length: usize, durability: Durability, provider: &mut impl CryptoProvider,
            encode: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<()> {
        if self.poisoned { return Err(Error::Storage); }
        let at = self.append_offset.ok_or(Error::Quota)?;
        append::append_encoded(self, at, length, durability, provider, encode)?;
        self.append_offset = append::frame_end(&self.flash, at, length).ok();
        Ok(())
    }

    /// Consume a zeroizing snapshot, reusing its allocation for the encrypted record.
    pub fn commit_owned_with(&mut self, data: Zeroizing<Vec<u8>>, provider: &mut impl CryptoProvider) -> Result<()> {
        self.commit_owned_with_nonce(data, Durability::Anchored, provider, None).map(|_| ())
    }

    #[cfg(feature = "jcvm")]
    pub(crate) fn commit_reusing_with_reason(&mut self, data: Zeroizing<Vec<u8>>,
            reason: microcard_engine_jcvm::host::CheckpointReason,
            provider: &mut impl CryptoProvider) -> Result<Zeroizing<Vec<u8>>> {
        self.commit_owned_with_nonce(data, reason.into(), provider, None)
    }

    #[cfg(feature = "jcvm")]
    pub(crate) fn commit_owned_with_reserved(&mut self, data: Zeroizing<Vec<u8>>,
            nonce: ReservedNonce, provider: &mut impl CryptoProvider) -> Result<()> {
        self.commit_owned_with_nonce(data, Durability::Anchored, provider, Some(nonce.0)).map(|_| ())
    }

    fn commit_owned_with_nonce(&mut self, data: Zeroizing<Vec<u8>>, durability: Durability,
            provider: &mut impl CryptoProvider, reserved: Option<u64>) -> Result<Zeroizing<Vec<u8>>> {
        if self.poisoned {
            return Err(Error::Storage);
        }
        let size = self.flash.slot_size();
        if size < OVERHEAD || data.len() > size - OVERHEAD {
            return Err(Error::Quota);
        }
        let generation = next_generation(self.generation, self.append_enabled, durability)?;
        if anchor(generation, self.append_enabled) > self.flash.monotonic_capacity() {
            return Err(Error::Quota);
        }
        let slot = self
            .active
            .map_or(0, |active| (active + 1) % self.slot_count);
        let (record, attempt) = self.seal_record(data, generation, provider, reserved)?;
        // Any flash error from here may leave a published record or reclaim intent.
        // Only recovery can determine which generation is safe to extend.
        self.poisoned = true;
        if let Some(active) = self.active {
            self.flash.program(active, size - RECLAIM_STARTED, &[0; 4])?;
        }
        self.flash.erase(slot)?;
        self.flash.program(slot, 0, &record)?;
        self.flash.program(slot, size - COMMITTED, &[0; 4])?;
        if let Some(active) = self.active {
            self.flash.program(active, size - RECLAIM_COMPLETE, &[0; 4])?;
        }
        self.generation = generation;
        self.base_attempt = Some(attempt);
        self.active = Some(slot);
        self.append_offset = Some(record.len().next_multiple_of(4));
        if durability == Durability::Anchored {
            self.flash.advance_monotonic(anchor(generation, self.append_enabled))?;
        }
        self.poisoned = false;
        Ok(record)
    }
    /// Reserve the nonce only after staging succeeds, then authenticate the exact header.
    fn seal_record(&mut self, data: Zeroizing<Vec<u8>>, generation: u64,
            provider: &mut impl CryptoProvider, reserved: Option<u64>) -> Result<(Zeroizing<Vec<u8>>, u64)> {
        let (record, payload_length) = prepare_record(data)?;
        let attempt = match reserved {
            Some(value) if value != 0 && self.flash.nonce_generation()? == value => value,
            Some(_) => return Err(Error::Storage),
            None => self.flash.reserve_nonce()?,
        };
        let record = encrypt_record(record, &self.key, RecordHeader {
            append_enabled: self.append_enabled, generation, attempt, payload_length,
        }, &nonce(attempt), provider)?;
        Ok((record, attempt))
    }

    pub fn into_flash(self) -> F {
        let Self { flash, .. } = self;
        flash
    }
    #[cfg(any(feature = "mc04", all(test, feature = "jcvm", feature = "software-crypto")))]
    pub(crate) fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }
    #[cfg(feature = "mc04")]
    pub(crate) fn flash(&self) -> &F { &self.flash }
    #[cfg(all(test, feature = "mc04"))]
    pub(crate) fn flash_for_test(&self) -> &F { &self.flash }
}

fn prepare_record(mut data: Zeroizing<Vec<u8>>) -> Result<(Zeroizing<Vec<u8>>, u32)> {
    let payload_length = data.len().checked_add(16).ok_or(Error::Quota)?;
    let encoded_payload_length = u32::try_from(payload_length).map_err(|_| Error::Quota)?;
    let record_length = HEADER_BYTES
        .checked_add(payload_length)
        .ok_or(Error::Quota)?;
    // Never realloc a buffer holding plaintext: an allocator could retain the
    // freed secret copy. Undersized callers get a new buffer and the old one wipes.
    if data.capacity() < record_length {
        let mut replacement = Zeroizing::new(Vec::new());
        replacement.try_reserve_exact(record_length).map_err(|_| Error::Quota)?;
        replacement.extend_from_slice(&data);
        data = replacement;
    }
    let plaintext_length = data.len();
    data.resize(record_length, 0);
    data.copy_within(..plaintext_length, HEADER_BYTES);
    Ok((data, encoded_payload_length))
}

fn encrypt_record(mut record: Zeroizing<Vec<u8>>, key: &JournalKey, header: RecordHeader,
    nonce: &[u8; 13],
    provider: &mut impl CryptoProvider) -> Result<Zeroizing<Vec<u8>>> {
    record[..HEADER_BYTES].copy_from_slice(&header.encode());
    let (aad, ciphertext) = record.split_at_mut(HEADER_BYTES);
    let written =
        match provider.aes_ccm_encrypt_in_place(
            key.as_ref(),
            nonce,
            aad,
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
    Ok(record)
}

/// Apply only after selecting and validating the complete recoverable state.
fn reconcile_generation(flash: &mut impl Flash, generation: u64) -> Result<()> {
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
    Ok(())
}

fn nonce(attempt: u64) -> [u8; 13] {
    let mut nonce = *b"MCJN3\0\0\0\0\0\0\0\0";
    nonce[5..].copy_from_slice(&attempt.to_le_bytes());
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

/// Decode a programmed-once word counter. Every consumed word must be fully
/// programmed, and all consumed words must precede all erased words.
pub fn decode_program_once_words(bytes: &[u8]) -> Result<u64> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::Storage);
    }
    let mut generation = 0u64;
    let mut saw_erased = false;
    for bytes in bytes.chunks_exact(4) {
        let word = u32::from_le_bytes(bytes.try_into().map_err(|_| Error::Storage)?);
        match word {
            0 => {
                if saw_erased {
                    return Err(Error::Storage);
                }
                generation = generation.checked_add(1).ok_or(Error::Storage)?;
            }
            u32::MAX => saw_erased = true,
            _ => return Err(Error::Storage),
        }
    }
    Ok(generation)
}

/// Select the erased word that advances a programmed-once counter by exactly one.
pub fn next_program_once_word(bytes: &[u8], generation: u64) -> Result<usize> {
    let current = decode_program_once_words(bytes)?;
    if current.checked_add(1) != Some(generation) {
        return Err(Error::Storage);
    }
    let index = usize::try_from(generation.checked_sub(1).ok_or(Error::Storage)?)
        .map_err(|_| Error::Storage)?;
    let offset = index.checked_mul(4).ok_or(Error::Storage)?;
    if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return Err(Error::Quota);
    }
    Ok(offset)
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
mod memory_flash;
pub use memory_flash::{MemoryFlash, MemoryImageReader};
#[cfg(test)]
mod tests;
