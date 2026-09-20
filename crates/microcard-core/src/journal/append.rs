//! Fixed append frames keep the commit marker locatable after a torn header.
use super::*;
pub(super) const FRAME_BYTES: usize = 1024;
const MARKER_BYTES: usize = 4;
pub(super) const MAX_PAYLOAD: usize = FRAME_BYTES - HEADER_BYTES - 16 - MARKER_BYTES;

pub(super) fn frame_end(flash: &impl Flash, at: usize) -> Result<usize> {
    if !at.is_multiple_of(4) { return Err(Error::Bounds); }
    at.checked_add(FRAME_BYTES).filter(|end| *end <= flash.slot_size().saturating_sub(3))
        .ok_or(Error::Quota)
}

fn erased(flash: &impl Flash, slot: usize, at: usize) -> Result<bool> {
    let end = frame_end(flash, at)?;
    let mut bytes = [0; 64];
    for offset in (at..end).step_by(bytes.len()) {
        flash.read(slot, offset, &mut bytes)?;
        if bytes.iter().any(|byte| *byte != 0xff) { return Ok(false); }
    }
    Ok(true)
}

/// Replay into caller-owned scratch state. Discard that state if any frame fails.
/// The outer journal must compare the final generation with its monotonic anchor.
pub(super) fn replay(flash: &impl Flash, key: &JournalKey, slot: usize, mut at: usize,
        mut generation: u64, provider: &mut impl CryptoProvider,
        mut apply: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<(u64, Option<usize>)> {
    if !at.is_multiple_of(4) { return Err(Error::Bounds); }
    while frame_end(flash, at).is_ok() {
        let next = generation.checked_add(1).ok_or(Error::Storage)?;
        let Some(payload) = read(flash, key, slot, at, next, provider)? else {
            return Ok((generation, erased(flash, slot, at)?.then_some(at)));
        };
        apply(generation, &payload)?;
        generation = next;
        at = at.checked_add(FRAME_BYTES).ok_or(Error::Storage)?;
    }
    Ok((generation, None))
}

pub(super) fn append<F: Flash>(journal: &mut Journal<F>, at: usize, data: Zeroizing<Vec<u8>>,
        provider: &mut impl CryptoProvider) -> Result<()> {
    if journal.poisoned { return Err(Error::Storage); }
    if !journal.append_enabled { return Err(Error::IncompatibleState); }
    let slot = journal.active.ok_or(Error::Storage)?;
    let end = frame_end(&journal.flash, at)?;
    if data.len() > MAX_PAYLOAD { return Err(Error::Quota); }
    let generation = journal.generation.checked_add(1).ok_or(Error::Quota)?;
    if generation > journal.flash.monotonic_capacity() { return Err(Error::Quota); }
    // Never program over a previous attempt, including an incomplete one.
    if !erased(&journal.flash, slot, at)? { return Err(Error::Storage); }
    let record = journal.seal_record(data, generation, provider)?;
    journal.poisoned = true;
    journal.flash.program(slot, at, &record)?;
    journal.flash.program(slot, end - MARKER_BYTES, &[0; MARKER_BYTES])?;
    journal.flash.advance_monotonic(generation)?;
    journal.generation = generation;
    journal.poisoned = false;
    Ok(())
}

fn read(flash: &impl Flash, key: &JournalKey, slot: usize, at: usize, generation: u64,
        provider: &mut impl CryptoProvider) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let end = frame_end(flash, at)?;
    let mut marker = [0; MARKER_BYTES];
    flash.read(slot, end - MARKER_BYTES, &mut marker)?;
    if marker != [0; MARKER_BYTES] { return Ok(None); }
    let mut bytes = [0; HEADER_BYTES];
    flash.read(slot, at, &mut bytes)?;
    let reserved = flash.nonce_generation()?;
    if reserved > flash.nonce_capacity() { return Err(Error::Storage); }
    let header = RecordHeader::decode(&bytes, MAX_PAYLOAD + 16, reserved)
        .map_err(|error| if error == Error::Storage { Error::Format } else { error })?;
    if !header.append_enabled || header.generation != generation { return Err(Error::Format); }
    let mut payload = crate::crypto::zeroizing_buffer(header.payload_length as usize)?;
    flash.read(slot, at + HEADER_BYTES, &mut payload)?;
    let written = provider.aes_ccm_decrypt_in_place(key.as_ref(), &nonce(header.attempt), &bytes, &mut payload)?;
    if written != payload.len() - 16 { return Err(Error::Storage); }
    payload.truncate(written);
    Ok(Some(payload))
}

#[cfg(all(test, feature = "software-crypto"))]
fn open(flash: MemoryFlash) -> Result<Journal<MemoryFlash>> {
    Journal::open_with_replay(flash, [3; 16], &mut SoftwareCrypto, |state, _, bytes| {
        state.clear(); state.extend_from_slice(bytes); Ok(())
    }).map(|(journal, _)| journal)
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn append_frames_authenticate_and_publish_only_after_the_marker() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let base = journal.into_flash();
    assert!(matches!(Journal::open(base.clone(), [3; 16]), Err(Error::IncompatibleState)));
    let (mut legacy, _) = Journal::open(MemoryFlash::new(4096), [3; 16]).unwrap();
    legacy.commit(b"legacy").unwrap();
    assert!(matches!(open(legacy.into_flash()), Err(Error::IncompatibleState)));
    // Four nonce bytes, a 45-byte encrypted record, four marker bytes, four anchor bytes.
    for cut in 0..=60 {
        let mut journal = open(base.clone()).unwrap();
        journal.flash.fail_after = Some(cut);
        let result = append(&mut journal, 64, Zeroizing::new(b"patch".to_vec()), &mut SoftwareCrypto);
        journal.flash.fail_after = None;
        let recovered = read(&journal.flash, &journal.key, 0, 64, 2, &mut SoftwareCrypto).unwrap();
        assert_eq!(recovered.as_deref().map(Vec::as_slice), (cut >= 53).then_some(b"patch".as_slice()));
        if result.is_ok() { assert!(recovered.is_some()); }
        let mut values = Vec::new();
        let (generation, available) = replay(&journal.flash, &journal.key, 0, 64, 1,
            &mut SoftwareCrypto, |base, bytes| { values.push((base, bytes.to_vec())); Ok(()) }).unwrap();
        assert_eq!(generation, if cut >= 53 { 2 } else { 1 });
        assert_eq!(values.len(), usize::from(cut >= 53));
        reconcile_generation(&mut journal.flash, generation).unwrap();
        assert_eq!(journal.flash.monotonic_generation().unwrap(), generation);
        assert_eq!(available, if cut <= 4 { Some(64) } else if cut < 53 { None } else { Some(64 + FRAME_BYTES) });
        if cut >= 4 {
            assert_eq!(append(&mut journal, 64, Zeroizing::new(b"other".to_vec()), &mut SoftwareCrypto), Err(Error::Storage));
        }
    }
    let mut journal = open(base).unwrap();
    append(&mut journal, 64, Zeroizing::new(b"patch".to_vec()), &mut SoftwareCrypto).unwrap();
    assert!(read(&journal.flash, &JournalKey::from([4; 16]), 0, 64, 2, &mut SoftwareCrypto).is_err());
    assert!(read(&journal.flash, &journal.key, 0, 64, 3, &mut SoftwareCrypto).is_err());
    append(&mut journal, 64 + FRAME_BYTES, Zeroizing::new(b"next".to_vec()), &mut SoftwareCrypto).unwrap();
    let mut values = Vec::new();
    assert_eq!(replay(&journal.flash, &journal.key, 0, 64, 1, &mut SoftwareCrypto,
        |base, bytes| { values.push((base, bytes.to_vec())); Ok(()) }).unwrap(), (3, Some(64 + 2 * FRAME_BYTES)));
    assert_eq!(values, vec![(1, b"patch".to_vec()), (2, b"next".to_vec())]);
    // Losing a committed suffix must not silently restore the earlier valid prefix.
    let mut missing_tail = journal.flash.clone();
    missing_tail.slots[0][64 + FRAME_BYTES..64 + 2 * FRAME_BYTES].fill(0xff);
    let (generation, _) = replay(&missing_tail, &journal.key, 0, 64, 1, &mut SoftwareCrypto,
        |_, _| Ok(())).unwrap();
    assert_eq!(generation, 2);
    assert_eq!(reconcile_generation(&mut missing_tail, generation), Err(Error::Storage));
    assert!(replay(&journal.flash, &journal.key, 0, 64, 2, &mut SoftwareCrypto,
        |_, _| Ok(())).is_err());
    assert_eq!(replay(&journal.flash, &journal.key, 0, 64, 1, &mut SoftwareCrypto,
        |_, _| Err(Error::Format)), Err(Error::Format));
}

#[cfg(all(test, feature = "software-crypto"))]
#[test]
fn journal_recovery_selects_appended_state_and_rotates_after_a_torn_tail() {
    let mut journal = open(MemoryFlash::new(4096)).unwrap();
    journal.commit(b"base").unwrap();
    let base = journal.into_flash();
    for cut in 0..=60 {
        let mut journal = open(base.clone()).unwrap();
        journal.flash.fail_after = Some(cut);
        let _ = journal.append_owned_with(Zeroizing::new(b"patch".to_vec()), &mut SoftwareCrypto);
        journal.flash.fail_after = None;
        let value = journal.recover_with_replay(&mut SoftwareCrypto, |state, generation, bytes| {
            assert_eq!(generation, 1);
            state.clear();
            state.extend_from_slice(bytes);
            Ok(())
        }).unwrap().unwrap();
        assert_eq!(value.as_slice(), if cut >= 53 { b"patch".as_slice() } else { b"base".as_slice() });
        if cut > 4 && cut < 53 {
            assert_eq!(journal.append_owned_with(Zeroizing::new(b"retry".to_vec()), &mut SoftwareCrypto), Err(Error::Quota));
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
    damaged.slots[0][44] ^= 1;
    assert!(Journal::open_with_replay(damaged.clone(), [3; 16], &mut SoftwareCrypto, replace).is_err());
    damaged.slots[1][4093] = 0; // Surviving chain records reclaim intent.
    let (_, recovered) = Journal::open_with_replay(damaged, [3; 16], &mut SoftwareCrypto, replace).unwrap();
    assert_eq!(recovered.unwrap().as_slice(), b"latest");
}
