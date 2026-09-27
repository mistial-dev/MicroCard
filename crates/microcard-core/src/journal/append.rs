//! A torn append closes this epoch; the next snapshot starts in the other slot.
use super::*;
#[cfg(test)]
use alloc::vec;
pub(super) const MAX_FRAME_BYTES: usize = 1024;
const MARKER_BYTES: usize = 4;
pub(super) const MIN_FRAME_BYTES: usize = HEADER_BYTES + 16 + MARKER_BYTES;
pub(super) const MAX_PAYLOAD: usize = MAX_FRAME_BYTES - MIN_FRAME_BYTES;

pub(super) struct Epoch {
    pub generation: u64,
    pub attempt: u64,
}

struct DecodedAppend {
    payload: Zeroizing<Vec<u8>>,
    end: usize,
    generation: u64,
}

pub(super) fn frame_end(flash: &impl Flash, at: usize, length: usize) -> Result<usize> {
    if !at.is_multiple_of(4) { return Err(Error::Bounds); }
    if length > MAX_PAYLOAD { return Err(Error::Quota); }
    at.checked_add(MIN_FRAME_BYTES).and_then(|end| end.checked_add(length))
        .and_then(|end| end.checked_add(3)).map(|end| end & !3)
        .filter(|end| *end <= flash.slot_size().saturating_sub(TAIL_BYTES))
        .ok_or(Error::Quota)
}

fn erased(flash: &impl Flash, slot: usize, at: usize, end: usize) -> Result<bool> {
    let mut bytes = [0; 64];
    let mut offset = at;
    while offset < end {
        let count = (end - offset).min(bytes.len());
        flash.read(slot, offset, &mut bytes[..count])?;
        if bytes[..count].iter().any(|byte| *byte != 0xff) { return Ok(false); }
        offset += count;
    }
    Ok(true)
}

/// Replay into caller-owned scratch state. Discard that state if any frame fails.
/// The outer journal must compare the final generation with its monotonic anchor.
pub(super) fn replay(flash: &impl Flash, key: &JournalKey, slot: usize, mut at: usize,
        epoch: Epoch, provider: &mut impl CryptoProvider,
        mut apply: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<(u64, Option<usize>)> {
    if !at.is_multiple_of(4) { return Err(Error::Bounds); }
    let mut generation = epoch.generation;
    while frame_end(flash, at, 0).is_ok() {
        let Some(record) = read(flash, key, slot, at, generation, epoch.attempt, provider)? else {
            let available = erased(flash, slot, at, flash.slot_size().saturating_sub(TAIL_BYTES))?;
            return Ok((generation, available.then_some(at)));
        };
        apply(generation, &record.payload)?;
        generation = record.generation;
        at = record.end;
    }
    Ok((generation, None))
}

pub(super) fn append<F: Flash>(journal: &mut Journal<F>, at: usize, data: Zeroizing<Vec<u8>>,
        durability: Durability, provider: &mut impl CryptoProvider) -> Result<()> {
    let (slot, end, generation) = prepare_append(journal, at, data.len(), durability)?;
    let attempt = journal.base_attempt.ok_or(Error::Storage)?;
    let (record, payload_length) = prepare_record(data)?;
    let record = encrypt_record(record, &journal.key, RecordHeader {
        append_enabled: true, generation, attempt, payload_length,
    }, &append_nonce(attempt, at)?, provider)?;
    publish(journal, slot, at, end, generation, durability, &record)
}

/// Fill the plaintext in its final record buffer before encryption.
pub(super) fn append_encoded<F: Flash>(journal: &mut Journal<F>, at: usize, length: usize,
        durability: Durability, provider: &mut impl CryptoProvider, encode: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<()> {
    let (slot, end, generation) = prepare_append(journal, at, length, durability)?;
    let mut record = Zeroizing::new([0u8; MAX_FRAME_BYTES]);
    let record_length = HEADER_BYTES + length + 16;
    encode(&mut record[HEADER_BYTES..HEADER_BYTES + length])?;
    let attempt = journal.base_attempt.ok_or(Error::Storage)?;
    let header = RecordHeader {
        append_enabled: journal.append_enabled,
        generation,
        attempt,
        payload_length: u32::try_from(length + 16).map_err(|_| Error::Quota)?,
    };
    record[..HEADER_BYTES].copy_from_slice(&header.encode());
    let (aad, ciphertext) = record[..record_length].split_at_mut(HEADER_BYTES);
    let written = provider.aes_ccm_encrypt_in_place(
        journal.key.as_ref(), &append_nonce(attempt, at)?, aad, ciphertext,
    )?;
    if written != ciphertext.len() { return Err(Error::Storage); }
    publish(journal, slot, at, end, generation, durability, &record[..record_length])
}

fn prepare_append<F: Flash>(journal: &Journal<F>, at: usize, length: usize, durability: Durability)
        -> Result<(usize, usize, u64)> {
    if journal.poisoned { return Err(Error::Storage); }
    if !journal.append_enabled { return Err(Error::IncompatibleState); }
    let slot = journal.active.ok_or(Error::Storage)?;
    let end = frame_end(&journal.flash, at, length)?;
    let generation = next_generation(journal.generation, true, durability)?;
    if anchor(generation, true) > journal.flash.monotonic_capacity() { return Err(Error::Quota); }
    // Never program over a previous attempt, including an incomplete one.
    if !erased(&journal.flash, slot, at, end)? { return Err(Error::Storage); }
    Ok((slot, end, generation))
}

fn publish<F: Flash>(journal: &mut Journal<F>, slot: usize, at: usize, end: usize,
        generation: u64, durability: Durability, record: &[u8]) -> Result<()> {
    journal.poisoned = true;
    journal.flash.program(slot, at, record)?;
    journal.flash.program(slot, end - MARKER_BYTES, &[0; MARKER_BYTES])?;
    if durability == Durability::Anchored {
        journal.flash.advance_monotonic(anchor(generation, true))?;
    }
    journal.generation = generation;
    journal.poisoned = false;
    Ok(())
}

fn read(flash: &impl Flash, key: &JournalKey, slot: usize, at: usize, generation: u64,
        base_attempt: u64, provider: &mut impl CryptoProvider) -> Result<Option<DecodedAppend>> {
    frame_end(flash, at, 0)?;
    let mut bytes = [0; HEADER_BYTES];
    flash.read(slot, at, &mut bytes)?;
    if bytes.iter().all(|byte| *byte == 0xff) { return Ok(None); }
    let reserved = flash.nonce_generation()?;
    if reserved > flash.nonce_capacity() { return Err(Error::Storage); }
    let header = match RecordHeader::decode(&bytes, MAX_PAYLOAD + 16, reserved) {
        Ok(header) => header,
        Err(Error::IncompatibleState) => return Err(Error::IncompatibleState),
        Err(_) => return Ok(None),
    };
    let end = match frame_end(flash, at, header.payload_length as usize - 16) {
        Ok(end) => end,
        Err(Error::Quota) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut marker = [0; MARKER_BYTES];
    flash.read(slot, end - MARKER_BYTES, &mut marker)?;
    if marker != [0; MARKER_BYTES] { return Ok(None); }
    let next_sequence = (generation as u32).checked_add(1).ok_or(Error::Storage)?;
    let previous_anchor = anchor(generation, true);
    let next_anchor = anchor(header.generation, true);
    if !header.append_enabled || header.generation as u32 != next_sequence
        || !(next_anchor == previous_anchor || next_anchor == previous_anchor + 1)
        || header.attempt != base_attempt {
        return Err(Error::Format);
    }
    let mut payload = crate::crypto::zeroizing_buffer(header.payload_length as usize)?;
    flash.read(slot, at + HEADER_BYTES, &mut payload)?;
    let written = provider.aes_ccm_decrypt_in_place(key.as_ref(),
        &append_nonce(base_attempt, at)?, &bytes, &mut payload)?;
    if written != payload.len() - 16 { return Err(Error::Storage); }
    payload.truncate(written);
    Ok(Some(DecodedAppend { payload, end, generation: header.generation }))
}

fn append_nonce(attempt: u64, offset: usize) -> Result<[u8; 13]> {
    let mut nonce = [0; 13];
    nonce[0] = b'A';
    nonce[1..9].copy_from_slice(&attempt.to_le_bytes());
    nonce[9..].copy_from_slice(&u32::try_from(offset).map_err(|_| Error::Bounds)?.to_le_bytes());
    Ok(nonce)
}

#[cfg(all(test, feature = "software-crypto"))]
fn open(flash: MemoryFlash) -> Result<Journal<MemoryFlash>> {
    Journal::open_with_replay(flash, [3; 16], &mut SoftwareCrypto, |state, _, bytes| {
        state.clear(); state.extend_from_slice(bytes); Ok(())
    }).map(|(journal, _)| journal)
}

#[cfg(all(test, feature = "software-crypto"))]
fn generation(anchor: u64, sequence: u32) -> u64 { (anchor << 32) | u64::from(sequence) }

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn nearly_full_slot_reopens_with_bounded_append_capacity() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let mut appended = 0;
    while journal.remaining_append_frames().unwrap() > 0 {
        journal.append_owned_with(Zeroizing::new(b"next".to_vec()), &mut SoftwareCrypto).unwrap();
        appended += 1;
    }
    assert!(appended >= 50);
    assert_eq!(journal.flash.nonce_generation().unwrap(), 1);
    let recovered = open(journal.into_flash()).unwrap();
    assert_eq!(recovered.remaining_append_frames(), Ok(0));
    assert!(recovered.append_capacity().unwrap() < MAX_PAYLOAD);
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn ordinary_records_do_not_consume_security_anchors() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let initial_anchor = journal.flash.monotonic_generation().unwrap();
    for _ in 0..12 {
        journal.append_encoded_with(1, Durability::Ordinary, &mut SoftwareCrypto,
            |output| { output[0] = 7; Ok(()) }).unwrap();
    }
    assert_eq!(journal.flash.monotonic_generation().unwrap(), initial_anchor);
    assert_eq!(journal.flash.nonce_generation().unwrap(), 1);
    let (mut journal, restored) = Journal::open_with_replay(journal.into_flash(), [3; 16],
        &mut SoftwareCrypto, |state, _, bytes| { state.clear(); state.extend_from_slice(bytes); Ok(()) }).unwrap();
    assert_eq!(restored.unwrap().as_slice(), [7]);
    journal.append_encoded_with(1, Durability::Anchored, &mut SoftwareCrypto,
        |output| { output[0] = 8; Ok(()) }).unwrap();
    assert_eq!(journal.flash.monotonic_generation().unwrap(), initial_anchor + 1);
    let mut missing_security_checkpoint = journal.into_flash();
    let end = (HEADER_BYTES + b"base".len() + 16).next_multiple_of(4);
    let ordinary_end = (0..12).try_fold(end, |at, _| frame_end(&missing_security_checkpoint, at, 1)).unwrap();
    let anchored_end = frame_end(&missing_security_checkpoint, ordinary_end, 1).unwrap();
    missing_security_checkpoint.slots[0][ordinary_end..anchored_end].fill(0xff);
    assert!(matches!(open(missing_security_checkpoint), Err(Error::Storage)));
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn append_frames_authenticate_and_publish_only_after_the_marker() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let base = journal.into_flash();
    assert!(matches!(Journal::open(base.clone(), [3; 16]), Err(Error::IncompatibleState)));
    for magic in [b"MJ04", b"MJ05", b"MJ06"] {
        let mut previous_format = base.clone();
        previous_format.slots[0][..4].copy_from_slice(magic);
        assert!(matches!(open(previous_format), Err(Error::IncompatibleState)));
    }
    let (mut legacy, _) = Journal::open(MemoryFlash::new(4096), [3; 16]).unwrap();
    legacy.commit(b"legacy").unwrap();
    assert!(matches!(open(legacy.into_flash()), Err(Error::IncompatibleState)));
    // The epoch nonce is reused only as input to a distinct position-derived nonce.
    // Publication writes a word-rounded 45-byte record, one marker word, and one anchor word.
    let published_at = 45usize.next_multiple_of(4) + 4;
    for cut in 0..=60 {
        let mut journal = open(base.clone()).unwrap();
        journal.flash.fail_after = Some(cut);
        let result = append(&mut journal, 64, Zeroizing::new(b"patch".to_vec()), Durability::Anchored, &mut SoftwareCrypto);
        journal.flash.fail_after = None;
        let recovered = read(&journal.flash, &journal.key, 0, 64, generation(1, 1), 1, &mut SoftwareCrypto).unwrap();
        assert_eq!(recovered.as_ref().map(|record| record.payload.as_slice()), (cut >= published_at).then_some(b"patch".as_slice()));
        if result.is_ok() { assert!(recovered.is_some()); }
        let mut values = Vec::new();
        let (generation, available) = replay(&journal.flash, &journal.key, 0, 64,
            Epoch { generation: generation(1, 1), attempt: 1 },
            &mut SoftwareCrypto, |base, bytes| { values.push((base, bytes.to_vec())); Ok(()) }).unwrap();
        assert_eq!(generation, if cut >= published_at { self::generation(2, 2) } else { self::generation(1, 1) });
        assert_eq!(values.len(), usize::from(cut >= published_at));
        reconcile_generation(&mut journal.flash, anchor(generation, true)).unwrap();
        assert_eq!(journal.flash.monotonic_generation().unwrap(), anchor(generation, true));
        let next = frame_end(&journal.flash, 64, 5).unwrap();
        assert_eq!(available, if cut < 4 { Some(64) } else if cut < published_at { None } else { Some(next) });
        if cut > 0 {
            assert_eq!(append(&mut journal, 64, Zeroizing::new(b"other".to_vec()), Durability::Anchored, &mut SoftwareCrypto), Err(Error::Storage));
        }
    }
    let mut journal = open(base).unwrap();
    append(&mut journal, 64, Zeroizing::new(b"patch".to_vec()), Durability::Anchored, &mut SoftwareCrypto).unwrap();
    assert!(read(&journal.flash, &JournalKey::from([4; 16]), 0, 64, generation(1, 1), 1, &mut SoftwareCrypto).is_err());
    assert!(read(&journal.flash, &journal.key, 0, 64, generation(1, 2), 1, &mut SoftwareCrypto).is_err());
    let next = frame_end(&journal.flash, 64, 5).unwrap();
    assert_ne!(append_nonce(1, 64).unwrap(), append_nonce(1, next).unwrap());
    assert_ne!(append_nonce(1, 64).unwrap(), append_nonce(2, 64).unwrap());
    assert_ne!(append_nonce(1, 64).unwrap(), nonce(1));
    append(&mut journal, next, Zeroizing::new(b"next".to_vec()), Durability::Anchored, &mut SoftwareCrypto).unwrap();
    assert_eq!(journal.flash.nonce_generation().unwrap(), 1);
    let after_next = frame_end(&journal.flash, next, 4).unwrap();
    let mut values = Vec::new();
    assert_eq!(replay(&journal.flash, &journal.key, 0, 64,
        Epoch { generation: generation(1, 1), attempt: 1 }, &mut SoftwareCrypto,
        |base, bytes| { values.push((base, bytes.to_vec())); Ok(()) }).unwrap(), (generation(3, 3), Some(after_next)));
    assert_eq!(values, vec![(generation(1, 1), b"patch".to_vec()), (generation(2, 2), b"next".to_vec())]);
    for length in [0u32, 15, 17, u32::MAX] {
        let mut malformed = journal.flash.clone();
        malformed.slots[0][64 + 20..64 + 24].copy_from_slice(&length.to_le_bytes());
        assert!(open(malformed).is_err(), "length {length}");
    }
    // Losing a committed suffix must not silently restore the earlier valid prefix.
    let mut missing_tail = journal.flash.clone();
    missing_tail.slots[0][next..after_next].fill(0xff);
    let (generation, _) = replay(&missing_tail, &journal.key, 0, 64,
        Epoch { generation: generation(1, 1), attempt: 1 }, &mut SoftwareCrypto,
        |_, _| Ok(())).unwrap();
    assert_eq!(generation, self::generation(2, 2));
    assert_eq!(reconcile_generation(&mut missing_tail, anchor(generation, true)), Err(Error::Storage));
    assert!(replay(&journal.flash, &journal.key, 0, 64,
        Epoch { generation: self::generation(2, 2), attempt: 1 }, &mut SoftwareCrypto,
        |_, _| Ok(())).is_err());
    assert_eq!(replay(&journal.flash, &journal.key, 0, 64,
        Epoch { generation: self::generation(1, 1), attempt: 1 }, &mut SoftwareCrypto,
        |_, _| Err(Error::Format)), Err(Error::Format));
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn journal_recovery_selects_appended_state_and_rotates_after_a_torn_tail() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let nonce = journal.flash.nonce_generation().unwrap();
    assert_eq!(journal.append_encoded_with(5, Durability::Ordinary, &mut SoftwareCrypto, |_| Err(Error::Format)), Err(Error::Format));
    assert_eq!(journal.flash.nonce_generation().unwrap(), nonce);
    let base = journal.into_flash();
    let published_at = 45usize.next_multiple_of(4) + 4;
    for cut in 0..=60 {
        let mut journal = open(base.clone()).unwrap();
        journal.flash.fail_after = Some(cut);
        let _ = journal.append_encoded_with(5, Durability::Ordinary, &mut SoftwareCrypto, |output| {
            output.copy_from_slice(b"patch");
            Ok(())
        });
        journal.flash.fail_after = None;
        let value = journal.recover_with_replay(&mut SoftwareCrypto, |state, generation, bytes| {
            assert_eq!(generation, self::generation(1, 1));
            state.clear();
            state.extend_from_slice(bytes);
            Ok(())
        }).unwrap().unwrap();
        assert_eq!(value.as_slice(), if cut >= published_at { b"patch".as_slice() } else { b"base".as_slice() });
        if cut >= 4 && cut < published_at {
            assert_eq!(journal.append_encoded_with(5, Durability::Ordinary, &mut SoftwareCrypto, |output| {
                output.copy_from_slice(b"retry");
                Ok(())
            }), Err(Error::Quota));
        }
        // Rotation writes a complete state to the other slot and remains recoverable.
        journal.commit(b"final").unwrap();
        let (_, restored) = Journal::open_with_replay(journal.into_flash(), [3; 16],
            &mut SoftwareCrypto, |state, _, bytes| {
                state.clear(); state.extend_from_slice(bytes); Ok(())
            }).unwrap();
        assert_eq!(restored.unwrap().as_slice(), b"final");
    }
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn interrupted_compaction_preserves_the_latest_chain() {
    fn replace(state: &mut Zeroizing<Vec<u8>>, _: u64, bytes: &[u8]) -> Result<()> {
        state.clear(); state.extend_from_slice(bytes); Ok(())
    }
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    journal.append_owned_with(Zeroizing::new(b"older".to_vec()), &mut SoftwareCrypto).unwrap();
    journal.commit(b"second").unwrap();
    journal.append_owned_with(Zeroizing::new(b"latest".to_vec()), &mut SoftwareCrypto).unwrap();
    let base = journal.into_flash();
    // Distinct boundaries: nonce, intent, erase, record, commit, completion, anchor.
    for cut in [0, 3, 4, 5, 6, 44, 1024, 2048, 4096, 4100, 4101, 4102,
            4145, 4146, 4147, 4148, 4149, 4151, 4152, 4160] {
        let (mut journal, _) = Journal::open_with_replay(base.clone(), [3; 16],
            &mut SoftwareCrypto, replace).unwrap();
        journal.flash.fail_after = Some(cut);
        let committed = journal.commit(b"final");
        let mut flash = journal.into_flash();
        flash.fail_after = None;
        let (_, recovered) = Journal::open_with_replay(flash, [3; 16], &mut SoftwareCrypto, replace).unwrap();
        let recovered = recovered.unwrap();
        assert!(matches!(recovered.as_slice(), b"latest" | b"final"), "cut {cut}");
        if committed.is_ok() { assert_eq!(recovered.as_slice(), b"final"); }
    }
    // Model erase damage away from the slot header, not just a sequential byte prefix.
    let mut damaged = base;
    damaged.slots[0][64 + HEADER_BYTES] ^= 1;
    assert!(Journal::open_with_replay(damaged.clone(), [3; 16], &mut SoftwareCrypto, replace).is_err());
    damaged.slots[1][4096 - RECLAIM_STARTED..4096 - RECLAIM_STARTED + 4].fill(0);
    let (_, recovered) = Journal::open_with_replay(damaged, [3; 16], &mut SoftwareCrypto, replace).unwrap();
    assert_eq!(recovered.unwrap().as_slice(), b"latest");
}
