//! Java Card ISO 3309 checksums. Intermediate state is reset-scoped and never journaled.
use super::*;

fn advance(algorithm: u16, mut state: u32, input: &[u8]) -> Result<u32> {
    match algorithm {
        1 => {
            for &byte in input {
                state ^= u32::from(byte) << 8;
                for _ in 0..8 {
                    state = if state & 0x8000 != 0 { (state << 1) ^ 0x1021 } else { state << 1 } & 0xffff;
                }
            }
        }
        2 => {
            for &byte in input {
                state ^= u32::from(byte);
                for _ in 0..8 {
                    state = if state & 1 != 0 { (state >> 1) ^ 0xedb8_8320 } else { state >> 1 };
                }
            }
        }
        _ => return Err(Error::Format),
    }
    Ok(state)
}

fn state(heap: &Heap, this: u16, context: heap::Context) -> Result<(u16, u16, u32)> {
    heap.check_access(this, context)?;
    let algorithm = word_field(heap, this, KIND)?;
    let reference = heap.get_word(this, MATERIAL)?;
    heap.check_access(reference, context)?;
    let bytes: &[u8; 4] = heap.byte_slice(reference, 0, 4)?.try_into().map_err(|_| Error::Format)?;
    Ok((algorithm, reference, u32::from_be_bytes(*bytes)))
}

pub(super) fn call(method: MethodId, heap: &mut Heap, frame: &mut Frame,
    context: heap::Context, budget: &mut u32) -> Result<Option<Native>> {
    match method {
        MethodId::init => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let (algorithm, reference, _) = state(heap, this, context)?;
            let required = if algorithm == 1 { 2 } else { 4 };
            if length != required { return crypto_exception(heap, context, 1).map(Some); }
            heap.check_access(input, context)?;
            if offset < 0 { return Err(Error::Bounds); }
            let seed = heap.byte_slice(input, offset as usize, required as usize)?;
            let mut value = [0; 4];
            value[4 - required as usize..].copy_from_slice(seed);
            heap.byte_slice_mut(reference, 0, 4)?.copy_from_slice(&value);
            Ok(Some(Native::Returned))
        }
        MethodId::update | MethodId::doFinal => {
            let output = if method == MethodId::doFinal {
                Some((frame.pop_short()?, frame.pop_reference()?))
            } else { None };
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let (algorithm, reference, current) = state(heap, this, context)?;
            heap.check_access(input, context)?;
            if offset < 0 || length < 0 { return Err(Error::Bounds); }
            let input_bytes = heap.byte_slice(input, offset as usize, length as usize)?;
            let width = if algorithm == 1 { 2 } else { 4 };
            if let Some((output_offset, destination)) = output {
                heap.check_access(destination, context)?;
                if output_offset < 0 { return Err(Error::Bounds); }
                heap.byte_slice(destination, output_offset as usize, width)?;
            }
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let next = advance(algorithm, current, input_bytes)?;
            if let Some((output_offset, destination)) = output {
                let checksum = (next ^ if algorithm == 1 { 0xffff } else { u32::MAX }).to_be_bytes();
                heap.byte_slice_mut(destination, output_offset as usize, width)?
                    .copy_from_slice(&checksum[4 - width..]);
                heap.byte_slice_mut(reference, 0, 4)?.fill(0);
                frame.push_short(width as i16)?;
            } else {
                heap.byte_slice_mut(reference, 0, 4)?.copy_from_slice(&next.to_be_bytes());
            }
            Ok(Some(Native::Returned))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_vectors_reset_and_transient_state() {
        for (algorithm, default_result, seeded_result) in [
            (1, &[0xce, 0x3c][..], &[0xd6, 0x4e][..]),
            (2, &[0xd2, 0x02, 0xd2, 0x77][..], &[0xcb, 0xf4, 0x39, 0x26][..]),
        ] {
            let mut slab = [0; 1024];
            let mut heap = Heap::new(&mut slab).unwrap();
            let checksum = new_native(&mut heap, ClassId::Checksum, STATE_WORDS, 1).unwrap();
            let state = heap.new_transient_array(heap::KIND_BYTE, 4, 1, heap::CLEAR_ON_RESET).unwrap();
            let buffer = heap.new_transient_array(heap::KIND_BYTE, 16, 1, heap::CLEAR_ON_RESET).unwrap();
            heap.put_word(checksum, KIND, algorithm).unwrap();
            heap.put_word(checksum, MATERIAL, state).unwrap();
            heap.mark_checkpointed();
            heap.byte_slice_mut(buffer, 0, 9).unwrap().copy_from_slice(b"123456789");
            let mut words = [0; 16];
            let mut tags = [0; 8];
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            let mut budget = 100;
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(4).unwrap();
            assert!(matches!(call(MethodId::update, &mut heap, &mut frame, 1, &mut budget),
                Ok(Some(Native::Returned))));
            assert!(!heap.has_uncheckpointed_writes());
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(4).unwrap();
            frame.push_short(5).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(0).unwrap();
            assert!(matches!(call(MethodId::doFinal, &mut heap, &mut frame, 1, &mut budget),
                Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short().unwrap() as usize, default_result.len());
            assert_eq!(heap.byte_slice(buffer, 0, default_result.len()).unwrap(), default_result);
            assert_eq!(heap.byte_slice(state, 0, 4).unwrap(), &[0; 4]);
            assert!(!heap.has_uncheckpointed_writes());

            // A reset clears the intermediate value, including an update inside a transaction.
            heap.byte_slice_mut(buffer, 0, 9).unwrap().copy_from_slice(b"123456789");
            heap.begin_transaction(32).unwrap();
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(4).unwrap();
            call(MethodId::update, &mut heap, &mut frame, 1, &mut budget).unwrap();
            heap.abort_transaction(&mut []).unwrap();
            assert_ne!(heap.byte_slice(state, 0, 4).unwrap(), &[0; 4]);
            heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
            assert_eq!(heap.byte_slice(state, 0, 4).unwrap(), &[0; 4]);
            assert!(!heap.has_uncheckpointed_writes());

            heap.byte_slice_mut(buffer, 0, 9).unwrap().copy_from_slice(b"123456789");
            let width = default_result.len();
            let seed = [0xff; 4];
            heap.byte_slice_mut(buffer, 10, width).unwrap().copy_from_slice(&seed[..width]);
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(10).unwrap();
            frame.push_short(width as i16 - 1).unwrap();
            let Some(Native::Threw(exception)) = call(MethodId::init, &mut heap, &mut frame, 1, &mut budget).unwrap()
                else { panic!("invalid checksum seed length was accepted"); };
            assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(1));
            heap.mark_checkpointed();
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(10).unwrap();
            frame.push_short(width as i16).unwrap();
            call(MethodId::init, &mut heap, &mut frame, 1, &mut budget).unwrap();
            frame.push_reference(checksum).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(9).unwrap();
            frame.push_reference(buffer).unwrap();
            frame.push_short(0).unwrap();
            call(MethodId::doFinal, &mut heap, &mut frame, 1, &mut budget).unwrap();
            assert_eq!(frame.pop_short().unwrap() as usize, width);
            assert_eq!(heap.byte_slice(buffer, 0, width).unwrap(), seeded_result);
            assert!(!heap.has_uncheckpointed_writes());
        }
    }
}
