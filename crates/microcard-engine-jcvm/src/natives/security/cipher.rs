use super::*;

pub(super) fn call(
    method: MethodId,
    signature: Signature,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Native> {
    match method {
        MethodId::init => {
            let vector = if signature.init_vector() {
                let length = frame.pop_short()?;
                let offset = frame.pop_short()?;
                let array = frame.pop_reference()?;
                Some((array, offset, length))
            } else {
                None
            };
            let mode = frame.pop_short()?;
            let key = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let kind = word_field(heap, this, KIND)?;
            let chained = matches!(kind, 13 | 240);
            let mut iv = Zeroizing::new([0u8; 16]);
            if let Some((array, offset, length)) = vector {
                if !chained || length != 16 {
                    return crypto_exception(heap, context, 1);
                }
                if offset < 0 {
                    return Err(Error::Bounds);
                }
                heap.check_access(array, context)?;
                iv.copy_from_slice(heap.byte_slice(array, offset as usize, 16)?);
            }
            heap.check_access(key, context)?;
            if !matches!(mode, 1 | 2)
                || super::super::api_class(heap.info(key)?.class).map(|entry| entry.id)
                    != Some(ClassId::AESKey)
                || word_field(heap, key, SIZE)? != 128
            {
                return crypto_exception(heap, context, 1);
            }
            if !key_initialized(heap, key)? {
                return crypto_exception(heap, context, 2);
            }
            let pending = heap.get_word(this, PENDING)?;
            heap.byte_slice(pending, 0, if chained { 32 } else { 16 })?;
            heap.prepare_payload_writes(&[(this, MATERIAL * 2, (COUNTER + 1 - MATERIAL) * 2)])?;
            heap.byte_slice_mut(pending, 0, 16)?.fill(0);
            if chained {
                heap.byte_slice_mut(pending, 16, 16)?
                    .copy_from_slice(&iv[..]);
            }
            heap.put_word(this, MATERIAL, key)?;
            heap.put_word(this, COUNTER, mode as u16)?;
            heap.put_word(this, READY, 1)?;
        }
        MethodId::update | MethodId::doFinal => {
            let out_offset = frame.pop_short()?;
            let output = frame.pop_reference()?;
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if word_field(heap, this, READY)? == 0 {
                return crypto_exception(heap, context, 4);
            }
            let key = heap.get_word(this, MATERIAL)?;
            heap.check_access(key, context)?;
            if !key_initialized(heap, key)? {
                return crypto_exception(heap, context, 2);
            }
            heap.check_access(input, context)?;
            heap.check_access(output, context)?;
            if length < 0 || offset < 0 || out_offset < 0 {
                return Err(Error::Bounds);
            }
            let pending = heap.get_word(this, PENDING)?;
            let mut prior = Zeroizing::new([0u8; 16]);
            prior.copy_from_slice(heap.byte_slice(pending, 0, 16)?);
            let count = (prior[0] & 0x0f) as usize;
            if prior[0] & 0x70 != 0 {
                return Err(Error::Format);
            }
            let total = count + length as usize;
            let kind = word_field(heap, this, KIND)?;
            let ctr = kind == 240;
            if method == MethodId::doFinal && !ctr
                && (!total.is_multiple_of(16) || (total == 0 && prior[0] & 0x80 == 0))
            {
                return crypto_exception(heap, context, 5);
            }
            let written = if ctr && method == MethodId::doFinal { total } else { total / 16 * 16 };
            if written > i16::MAX as usize {
                return Err(Error::Bounds);
            }
            heap.byte_slice(output, out_offset as usize, written)?;
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            let material = heap.get_word(key, MATERIAL)?;
            let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
            let mut key_bytes = Zeroizing::new([0u8; 16]);
            key_bytes.copy_from_slice(heap.byte_slice(material, prefix, 16)?);
            // Stage output only: input may overlap it at any offset. A provider failure
            // must publish neither partial ciphertext nor updated streaming state.
            *budget = budget.checked_sub(total as u32).ok_or(Error::Quota)?;
            let mut staged = StagedBytes::new(written)?;
            let result = staged.as_mut();
            let byte = |at: usize| {
                if at < count {
                    prior[1 + at]
                } else {
                    message[at - count]
                }
            };
            for (at, output) in result.iter_mut().enumerate() {
                *output = byte(at);
            }
            let cbc = kind == 13;
            let encrypt = word_field(heap, this, COUNTER)? == 2;
            let mut next_iv = Zeroizing::new([0u8; 16]);
            if cbc {
                let mut iv = Zeroizing::new([0u8; 16]);
                iv.copy_from_slice(heap.byte_slice(pending, 16, 16)?);
                *next_iv = *iv;
                if written != 0 {
                    if !encrypt {
                        next_iv.copy_from_slice(&result[written - 16..]);
                    }
                    host.aes128_cbc(&key_bytes, &iv, result, encrypt)?;
                    if encrypt {
                        next_iv.copy_from_slice(&result[written - 16..]);
                    }
                }
                if method == MethodId::doFinal {
                    next_iv.fill(0);
                }
            } else if ctr {
                let mut counter = Zeroizing::new([0u8; 16]);
                counter.copy_from_slice(heap.byte_slice(pending, 16, 16)?);
                *next_iv = *counter;
                if written != 0 {
                    let blocks = written.div_ceil(16) as u128;
                    let next = u128::from_be_bytes(*counter)
                        .checked_add(blocks).ok_or(Error::Bounds)?;
                    host.aes128_ctr(&key_bytes, &counter, result)?;
                    if method == MethodId::update {
                        *next_iv = next.to_be_bytes();
                    }
                }
                if method == MethodId::doFinal {
                    next_iv.fill(0);
                }
            } else {
                for block in result.chunks_exact_mut(16) {
                    host.aes128_block(
                        &key_bytes,
                        block.try_into().map_err(|_| Error::Bounds)?,
                        encrypt,
                    )?;
                }
            }
            let mut tail = Zeroizing::new([0u8; 16]);
            tail[0] = (total - written) as u8;
            if method == MethodId::update && (total != 0 || prior[0] & 0x80 != 0) {
                tail[0] |= 0x80;
            }
            for at in written..total {
                tail[1 + at - written] = byte(at);
            }
            heap.byte_slice_mut(output, out_offset as usize, written)?
                .copy_from_slice(result);
            heap.byte_slice_mut(pending, 0, 16)?
                .copy_from_slice(&tail[..]);
            if cbc || ctr {
                heap.byte_slice_mut(pending, 16, 16)?
                    .copy_from_slice(&next_iv[..]);
            }
            frame.push_short(written as i16)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
