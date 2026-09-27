use super::*;

pub(super) fn is_des(kind: u16) -> bool { matches!(kind, 1..=8) }

pub(super) fn is_chained(kind: u16) -> bool { matches!(kind, 1..=4 | 13 | 22..=24 | 240) }

pub(super) fn padding(kind: u16) -> u8 {
    match kind {
        2 | 6 | 22 | 25 => 1, // ISO 9797 method 1
        3 | 7 | 23 | 26 => 2, // ISO 9797 method 2
        4 | 8 | 24 | 27 => 3, // PKCS5
        _ => 0,
    }
}

pub(super) fn state_bytes(kind: u16) -> usize {
    let head = if padding(kind) == 0 { 16 } else { 17 };
    head + if is_chained(kind) { 16 } else { 0 }
}

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
            let des = is_des(kind);
            let chained = is_chained(kind);
            let head = state_bytes(kind) - if chained { 16 } else { 0 };
            let iv_len = if des { 8 } else { 16 };
            let mut iv = Zeroizing::new([0u8; 16]);
            if let Some((array, offset, length)) = vector {
                if !chained || length != iv_len {
                    return crypto_exception(heap, context, 1);
                }
                if offset < 0 {
                    return Err(Error::Bounds);
                }
                heap.check_access(array, context)?;
                iv[..iv_len as usize].copy_from_slice(heap.byte_slice(array, offset as usize, iv_len as usize)?);
            }
            heap.check_access(key, context)?;
            let key_class = if des { ClassId::DESKey } else { ClassId::AESKey };
            let key_bits = word_field(heap, key, SIZE)?;
            if !matches!(mode, 1 | 2)
                || super::super::api_class(heap.info(key)?.class).map(|entry| entry.id)
                    != Some(key_class)
                || if des { !matches!(key_bits, 64 | 128 | 192) } else { key_bits != 128 }
            {
                return crypto_exception(heap, context, 1);
            }
            if !key_initialized(heap, key)? {
                return crypto_exception(heap, context, 2);
            }
            let pending = heap.get_word(this, PENDING)?;
            heap.byte_slice(pending, 0, state_bytes(kind))?;
            heap.prepare_payload_writes(&[(this, MATERIAL * 2, (COUNTER + 1 - MATERIAL) * 2)])?;
            heap.byte_slice_mut(pending, 0, head)?.fill(0);
            if chained {
                heap.byte_slice_mut(pending, head, 16)?
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
            let kind = word_field(heap, this, KIND)?;
            let pad = padding(kind);
            let chained = is_chained(kind);
            let head = state_bytes(kind) - if chained { 16 } else { 0 };
            let mut prior = Zeroizing::new([0u8; 17]);
            prior[..head].copy_from_slice(heap.byte_slice(pending, 0, head)?);
            let count = (prior[0] & 0x1f) as usize;
            if prior[0] & 0x60 != 0 || count >= head {
                return Err(Error::Format);
            }
            let total = count + length as usize;
            let des = is_des(kind);
            let block_size = if des { 8 } else { 16 };
            let ctr = kind == 240;
            let encrypt = word_field(heap, this, COUNTER)? == 2;
            if method == MethodId::doFinal && pad != 0 && !encrypt
                && (!total.is_multiple_of(block_size) || total == 0)
            {
                return crypto_exception(heap, context, 5);
            }
            if method == MethodId::doFinal && pad == 0 && !ctr
                && (!total.is_multiple_of(block_size) || (total == 0 && prior[0] & 0x80 == 0))
            {
                return crypto_exception(heap, context, 5);
            }
            let mut processed = if ctr && method == MethodId::doFinal { total } else { total / block_size * block_size };
            if method == MethodId::update && !encrypt && pad >= 2 && processed == total {
                processed = processed.saturating_sub(block_size);
            }
            if method == MethodId::update && !encrypt && pad >= 2 && total < block_size {
                processed = 0;
            }
            if method == MethodId::doFinal && encrypt && pad != 0 {
                let remainder = total % block_size;
                if pad != 1 || remainder != 0 {
                    processed = total + block_size - remainder;
                }
            }
            if processed > i16::MAX as usize {
                return Err(Error::Bounds);
            }
            if method == MethodId::update || encrypt || pad <= 1 {
                heap.byte_slice(output, out_offset as usize, processed)?;
            }
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            let material = heap.get_word(key, MATERIAL)?;
            let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
            let mut key_bytes = Zeroizing::new([0u8; 24]);
            let key_len = if des { word_field(heap, key, SIZE)? as usize / 8 } else { 16 };
            key_bytes[..key_len].copy_from_slice(heap.byte_slice(material, prefix, key_len)?);
            // Stage output only: input may overlap it at any offset. A provider failure
            // must publish neither partial ciphertext nor updated streaming state.
            *budget = budget.checked_sub(total as u32).ok_or(Error::Quota)?;
            let mut staged = StagedBytes::new(processed)?;
            let result = staged.as_mut();
            let byte = |at: usize| {
                if at < count {
                    prior[1 + at]
                } else {
                    message[at - count]
                }
            };
            for (at, output) in result.iter_mut().take(total).enumerate() {
                *output = byte(at);
            }
            if method == MethodId::doFinal && encrypt && pad != 0 && processed > total {
                if pad == 2 { result[total] = 0x80; }
                if pad == 3 { result[total..].fill((processed - total) as u8); }
            }
            let cbc = chained && !ctr;
            let mut next_iv = Zeroizing::new([0u8; 16]);
            if cbc {
                let mut iv = Zeroizing::new([0u8; 16]);
                iv.copy_from_slice(heap.byte_slice(pending, head, 16)?);
                *next_iv = *iv;
                if processed != 0 {
                    if !encrypt {
                        next_iv[..block_size].copy_from_slice(&result[processed - block_size..]);
                    }
                    if des {
                        let des_iv: &[u8; 8] = iv[..8].try_into().map_err(|_| Error::Bounds)?;
                        host.des_crypt(&key_bytes[..key_len], Some(des_iv), result, encrypt)?;
                    } else {
                        host.aes128_cbc((&key_bytes[..16]).try_into().map_err(|_| Error::Bounds)?, &iv, result, encrypt)?;
                    }
                    if encrypt {
                        next_iv[..block_size].copy_from_slice(&result[processed - block_size..]);
                    }
                }
                if method == MethodId::doFinal {
                    next_iv.fill(0);
                }
            } else if ctr {
                let mut counter = Zeroizing::new([0u8; 16]);
                counter.copy_from_slice(heap.byte_slice(pending, head, 16)?);
                *next_iv = *counter;
                if processed != 0 {
                    let blocks = processed.div_ceil(16) as u128;
                    let next = u128::from_be_bytes(*counter)
                        .checked_add(blocks).ok_or(Error::Bounds)?;
                    host.aes128_ctr((&key_bytes[..16]).try_into().map_err(|_| Error::Bounds)?, &counter, result)?;
                    if method == MethodId::update {
                        *next_iv = next.to_be_bytes();
                    }
                }
                if method == MethodId::doFinal {
                    next_iv.fill(0);
                }
            } else if des {
                if processed != 0 { host.des_crypt(&key_bytes[..key_len], None, result, encrypt)?; }
            } else {
                for block in result.chunks_exact_mut(16) {
                    host.aes128_block(
                        (&key_bytes[..16]).try_into().map_err(|_| Error::Bounds)?,
                        block.try_into().map_err(|_| Error::Bounds)?, encrypt,
                    )?;
                }
            }
            let mut written = processed;
            if method == MethodId::doFinal && !encrypt && pad >= 2 {
                let last = &result[processed - block_size..];
                let trim = if pad == 2 {
                    let zeros = last.iter().rev().take_while(|byte| **byte == 0).count();
                    if zeros == block_size || last[block_size - zeros - 1] != 0x80 {
                        return crypto_exception(heap, context, 5);
                    }
                    zeros + 1
                } else {
                    let count = last[block_size - 1] as usize;
                    if count == 0 || count > block_size || last[block_size - count..].iter().any(|byte| *byte as usize != count) {
                        return crypto_exception(heap, context, 5);
                    }
                    count
                };
                written -= trim;
                heap.byte_slice(output, out_offset as usize, written)?;
            }
            let mut tail = Zeroizing::new([0u8; 17]);
            tail[0] = if method == MethodId::update { (total - processed) as u8 } else { 0 };
            if method == MethodId::update && (total != 0 || prior[0] & 0x80 != 0) {
                tail[0] |= 0x80;
            }
            for at in processed..total {
                if method == MethodId::update { tail[1 + at - processed] = byte(at); }
            }
            heap.byte_slice_mut(output, out_offset as usize, written)?
                .copy_from_slice(&result[..written]);
            heap.byte_slice_mut(pending, 0, head)?
                .copy_from_slice(&tail[..head]);
            if cbc || ctr {
                heap.byte_slice_mut(pending, head, 16)?
                    .copy_from_slice(&next_iv[..]);
            }
            frame.push_short(written as i16)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
