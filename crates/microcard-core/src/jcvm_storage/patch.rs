//! Bounded state changes carried inside an authenticated journal record.
use crate::{cbor::{Decoder, Encoder}, Error, Result};
use alloc::vec::Vec;
use zeroize::Zeroizing;

const MAX_SPANS: usize = 64;

#[cfg(test)]
fn spans<'a>(before: &'a [u8], after: &'a [u8]) -> impl Iterator<Item = (usize, &'a [u8])> + Clone {
    let mut at = 0;
    core::iter::from_fn(move || {
        while at < after.len() && before.get(at).copied().unwrap_or(0) == after[at] {
            at += 1;
        }
        if at == after.len() { return None; }
        let start = at;
        while at < after.len() && before.get(at).copied().unwrap_or(0) != after[at] {
            at += 1;
        }
        Some((start, &after[start..at]))
    })
}

fn span_end(offset: usize, bytes: &[u8], length: usize, previous_end: usize) -> Result<usize> {
    let end = offset.checked_add(bytes.len()).ok_or(Error::Format)?;
    if bytes.is_empty() || end > length || offset < previous_end { return Err(Error::Format); }
    Ok(end)
}

/// Borrow tracked writes; no previous heap image or allocated span list is required.
/// Too many spans or an oversized encoding asks the caller to use a snapshot.
pub(super) fn encode<'a>(changes: impl Iterator<Item = (usize, &'a [u8])> + Clone,
        before_length: usize, after_length: usize, generation: u64, maximum: usize)
        -> Result<Zeroizing<Vec<u8>>> {
    let mut count = 0;
    let mut previous_end = 0;
    for (offset, bytes) in changes.clone() {
        count += 1;
        if count > MAX_SPANS { return Err(Error::Quota); }
        previous_end = span_end(offset, bytes, after_length, previous_end)?;
    }
    let mut encoder = Encoder::new(maximum);
    encoder.array(5)?;
    encoder.unsigned(1)?;
    encoder.unsigned(generation)?;
    encoder.unsigned(before_length as u64)?;
    encoder.unsigned(after_length as u64)?;
    encoder.array(count)?;
    for (offset, bytes) in changes {
        encoder.array(2)?;
        encoder.unsigned(offset as u64)?;
        encoder.bytes(bytes)?;
    }
    Ok(Zeroizing::new(encoder.finish()))
}

#[cfg(test)]
fn encode_diff(before: &[u8], after: &[u8], generation: u64, maximum: usize)
        -> Result<Zeroizing<Vec<u8>>> {
    encode(spans(before, after), before.len(), after.len(), generation, maximum)
}

/// Stage only the requested sanitized heap window, bounded by the record budget.
pub(super) fn encode_heap_window(view: microcard_engine_jcvm::applet::PersistentView<'_>,
        range: core::ops::Range<usize>, before_length: usize, generation: u64,
        maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    if range.start > range.end || range.end > view.heap_bytes() { return Err(Error::Bounds); }
    if range.len() > maximum { return Err(Error::Quota); }
    let mut bytes = crate::crypto::zeroizing_buffer(range.len())?;
    view.save_range(range.start, &mut bytes).map_err(|_| Error::Format)?;
    let change = (!bytes.is_empty()).then_some((range.start, bytes.as_slice()));
    encode(change.into_iter(), before_length, view.heap_bytes(), generation, maximum)
}

pub(super) fn encode_view(view: microcard_engine_jcvm::applet::PersistentView<'_>,
        before_length: usize, generation: u64, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let writes = view.pending_writes().ok_or(Error::Quota)?;
    if writes.snapshot_required() { return Err(Error::Quota); }
    let heap = encode_heap_window(view, writes.heap_range().unwrap_or(0..0),
        before_length, generation, maximum)?;
    let (instance, statics) = view.metadata();
    let range = writes.static_range().unwrap_or(0..0);
    let bytes = statics.get(range.clone()).ok_or(Error::Bounds)?;
    let change = (!bytes.is_empty()).then_some((range.start, bytes));
    let statics = encode(change.into_iter(), statics.len(), statics.len(), generation, maximum)?;
    let mut encoder = Encoder::new(maximum);
    encoder.array(4)?;
    encoder.unsigned(1)?;
    encoder.unsigned(u64::from(instance))?;
    encoder.bytes(&heap)?;
    encoder.bytes(&statics)?;
    Ok(Zeroizing::new(encoder.finish()))
}

pub(super) fn replay_snapshot(snapshot: &mut Zeroizing<Vec<u8>>, generation: u64,
        delta: &[u8], maximum: usize) -> Result<()> {
    let mut source = Decoder::new(snapshot);
    source.record(7)?;
    if source.unsigned()? != 1 || source.unsigned()? != 1 { return Err(Error::IncompatibleState); }
    let image = source.fixed::<32>()?;
    let installation = source.fixed::<16>()?;
    let instance = source.unsigned()?;
    let heap = source.bytes(maximum)?;
    let statics = source.bytes(maximum)?;
    source.finish()?;
    let mut record = Decoder::new(delta);
    record.record(4)?;
    if record.unsigned()? != 1 { return Err(Error::IncompatibleState); }
    if record.unsigned()? != instance { return Err(Error::KeyMismatch); }
    let heap_patch = record.bytes(maximum)?;
    let static_patch = record.bytes(maximum)?;
    record.finish()?;
    let heap_length = validate(heap_patch, generation, heap.len(), maximum)?;
    let static_length = validate(static_patch, generation, statics.len(), maximum)?;
    if super::snapshot_size(instance, heap_length, static_length)? > maximum { return Err(Error::Quota); }
    let capacity = super::snapshot_size(instance, heap_length, static_length)?;
    let mut encoder = Encoder::with_capacity(maximum, capacity)?;
    encoder.array(7)?;
    encoder.unsigned(1)?;
    encoder.unsigned(1)?;
    encoder.bytes(&image)?;
    encoder.bytes(&installation)?;
    encoder.unsigned(instance)?;
    encoder.bytes_with(heap_length, |output| {
        let common = heap.len().min(output.len());
        output[..common].copy_from_slice(&heap[..common]);
        apply_spans(heap_patch, output)
    })?;
    encoder.bytes_with(static_length, |output| {
        let common = statics.len().min(output.len());
        output[..common].copy_from_slice(&statics[..common]);
        apply_spans(static_patch, output)
    })?;
    *snapshot = Zeroizing::new(encoder.finish());
    Ok(())
}

/// Validate the complete record before copying any replacement bytes.
/// Authentication and installation binding belong to the enclosing journal.
/// The caller supplies the exact existing state; this format does not allocate.
#[cfg(test)]
pub(super) fn apply(encoded: &[u8], generation: u64, state: &mut [u8], used: usize) -> Result<usize> {
    if used > state.len() { return Err(Error::Bounds); }
    let length = validate(encoded, generation, used, state.len())?;
    // The allocation tail starts zeroed; truncated plaintext must not survive reuse.
    state[used.min(length)..used.max(length)].fill(0);
    apply_spans(encoded, state)?;
    Ok(length)
}

// Call only after validate has checked all spans against this output's length.
fn apply_spans(encoded: &[u8], state: &mut [u8]) -> Result<()> {
    let mut decoder = Decoder::new(encoded);
    decoder.record(5)?;
    decoder.unsigned()?;
    decoder.unsigned()?;
    decoder.unsigned()?;
    decoder.unsigned()?;
    let count = decoder.array(MAX_SPANS)?;
    for _ in 0..count {
        decoder.record(2)?;
        let offset: usize = decoder.number()?;
        let bytes = decoder.bytes(state.len())?;
        state[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    decoder.finish()
}

fn validate(encoded: &[u8], generation: u64, used: usize, capacity: usize) -> Result<usize> {
    let mut decoder = Decoder::new(encoded);
    decoder.record(5)?;
    if decoder.unsigned()? != 1 { return Err(Error::IncompatibleState); }
    if decoder.unsigned()? != generation || decoder.number::<usize>()? != used {
        return Err(Error::IncompatibleState);
    }
    let length: usize = decoder.number()?;
    if length > capacity { return Err(Error::Quota); }
    let count = decoder.array(MAX_SPANS)?;
    let mut previous_end = 0;
    for _ in 0..count {
        decoder.record(2)?;
        let offset: usize = decoder.number()?;
        let bytes = decoder.bytes(length)?;
        previous_end = span_end(offset, bytes, length, previous_end)?;
    }
    decoder.finish()?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_checks_base_and_all_spans_before_mutating() {
        // [version, base generation, base length, result length, [[offset, replacement], ...]]
        let golden = [0x85, 1, 7, 6, 6, 0x82, 0x82, 1, 0x42, 9, 8, 0x82, 5, 0x41, 7];
        let initial = [1, 2, 3, 4, 5, 6];
        let mut state = initial;
        apply(&golden, 7, &mut state, 6).unwrap();
        assert_eq!(state, [1, 9, 8, 4, 5, 7]);
        assert_eq!(encode_diff(&initial, &state, 7, golden.len()).unwrap().as_slice(), golden);
        assert!(matches!(encode_diff(&initial, &state, 7, golden.len() - 1), Err(Error::Quota)));
        // Every truncation must leave even the first otherwise-valid span untouched.
        for end in 0..golden.len() {
            let mut state = initial;
            assert!(apply(&golden[..end], 7, &mut state, 6).is_err());
            assert_eq!(state, initial);
        }
        for (at, value) in [(1, 2), (2, 8), (3, 5), (4, 7), (12, 2), (12, 6), (13, 0x40)] {
            let mut malformed = golden;
            malformed[at] = value;
            let mut state = initial;
            assert!(apply(&malformed, 7, &mut state, 6).is_err());
            assert_eq!(state, initial);
        }
        let mut trailing = golden.to_vec();
        trailing.push(0);
        let mut state = initial;
        assert!(apply(&trailing, 7, &mut state, 6).is_err());
        assert_eq!(state, initial);

        let mut storage = [0xa5; 8];
        storage[..2].copy_from_slice(&[3, 4]);
        let grow = [0x85, 1, 8, 2, 6, 0x81, 0x82, 4, 0x42, 7, 8];
        assert_eq!(apply(&grow, 8, &mut storage, 2), Ok(6));
        assert_eq!(storage, [3, 4, 0, 0, 7, 8, 0xa5, 0xa5]);
        let shrink = [0x85, 1, 9, 6, 1, 0x80];
        assert_eq!(apply(&shrink, 9, &mut storage, 6), Ok(1));
        assert_eq!(storage, [3, 0, 0, 0, 0, 0, 0xa5, 0xa5]);

        for before in [&[][..], &[1, 2, 3][..], &[0, 0, 0][..]] {
            for after in [&[][..], &[1][..], &[0, 0, 0, 0][..], &[9, 0, 8, 0, 7][..]] {
                let encoded = encode_diff(before, after, 11, 128).unwrap();
                let mut output = [0xa5; 8];
                output[..before.len()].copy_from_slice(before);
                assert_eq!(apply(&encoded, 11, &mut output, before.len()), Ok(after.len()));
                assert_eq!(&output[..after.len()], after);
                let snapshot = |heap: &[u8], statics: &[u8]| {
                    let mut e = Encoder::new(256);
                    e.array(7).unwrap();
                    e.unsigned(1).unwrap();
                    e.unsigned(1).unwrap();
                    e.bytes(&[2; 32]).unwrap();
                    e.bytes(&[3; 16]).unwrap();
                    e.unsigned(4).unwrap();
                    e.bytes(heap).unwrap();
                    e.bytes(statics).unwrap();
                    Zeroizing::new(e.finish())
                };
                let mut delta = Encoder::new(256);
                delta.array(4).unwrap();
                delta.unsigned(1).unwrap();
                delta.unsigned(4).unwrap();
                delta.bytes(&encoded).unwrap();
                delta.bytes(&encode_diff(&[5, 6], &[7], 11, 128).unwrap()).unwrap();
                let delta = delta.finish();
                let mut saved = snapshot(before, &[5, 6]);
                let original = saved.clone();
                assert!(replay_snapshot(&mut saved, 12, &delta, 256).is_err());
                assert_eq!(saved, original);
                replay_snapshot(&mut saved, 11, &delta, 256).unwrap();
                assert_eq!(saved, snapshot(after, &[7]));
            }
        }
        let before = [0; MAX_SPANS * 2 + 1];
        let mut fragmented = before;
        for at in (0..fragmented.len()).step_by(2) { fragmented[at] = 1; }
        assert!(matches!(encode_diff(&before, &fragmented, 1, 1024), Err(Error::Quota)));
    }
}
