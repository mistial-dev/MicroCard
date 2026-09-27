//! Signature operations retain only reset-scoped streaming state between updates.
use super::*;
use crate::host::SHA256_STATE_BYTES;
#[cfg(feature = "des-legacy")]
use microcard_tiny_crypto::des::{Iso9797Mac, MacAlgorithm, MacPadding, ISO9797_CONTEXT_BYTES};

const AES_MAC_STATE_BYTES: usize = 34;

#[cfg(feature = "des-legacy")]
fn des_mac_params(kind: u16) -> Option<(MacAlgorithm, MacPadding, usize, bool)> {
    let (algorithm, padding, length, pkcs5) = match kind {
        2 => (MacAlgorithm::Cbc, MacPadding::None, 8, false),
        3 => (MacAlgorithm::Cbc, MacPadding::Iso9797M1, 4, false),
        4 => (MacAlgorithm::Cbc, MacPadding::Iso9797M1, 8, false),
        5 => (MacAlgorithm::Cbc, MacPadding::Iso9797M2, 4, false),
        6 => (MacAlgorithm::Cbc, MacPadding::Iso9797M2, 8, false),
        7 => (MacAlgorithm::Cbc, MacPadding::None, 4, true),
        8 => (MacAlgorithm::Cbc, MacPadding::None, 8, true),
        19 => (MacAlgorithm::Retail, MacPadding::Iso9797M2, 4, false),
        20 => (MacAlgorithm::Retail, MacPadding::Iso9797M2, 8, false),
        47 => (MacAlgorithm::Retail, MacPadding::Iso9797M1, 4, false),
        48 => (MacAlgorithm::Retail, MacPadding::Iso9797M1, 8, false),
        _ => return None,
    };
    Some((algorithm, padding, length, pkcs5))
}

#[cfg(feature = "des-legacy")]
fn des_mac_metadata(kind: u16) -> (i16, i16) {
    let cipher = if matches!(kind, 3 | 5 | 7 | 19 | 47) {
        1
    } else {
        2
    };
    let padding = match kind {
        2 => 1,
        3 | 4 => 2,
        5 | 6 => 3,
        19 | 20 => 5,
        47 | 48 => 4,
        7 | 8 => 6,
        _ => unreachable!(),
    };
    (cipher, padding)
}

#[cfg(feature = "des-legacy")]
pub(super) fn combined_des_mac(cipher: i16, padding: i16) -> Option<u16> {
    Some(match (cipher, padding) {
        (1, 2) => 3,
        (2, 1) => 2,
        (2, 2) => 4,
        (1, 3) => 5,
        (2, 3) => 6,
        (1, 6) => 7,
        (2, 6) => 8,
        (1, 5) => 19,
        (2, 5) => 20,
        (1, 4) => 47,
        (2, 4) => 48,
        _ => return None,
    })
}

fn aes_mac_advance(
    host: &mut dyn crate::host::Host,
    key: &[u8; 16],
    state: &mut [u8; AES_MAC_STATE_BYTES],
    input: &[u8],
) -> Result<()> {
    for &byte in input {
        let used = state[32] as usize;
        if used >= 16 {
            return Err(Error::Format);
        }
        state[16 + used] = byte;
        state[32] += 1;
        if state[32] == 16 {
            let mut block = [0u8; 16];
            for (index, value) in block.iter_mut().enumerate() {
                *value = state[index] ^ state[16 + index];
            }
            host.aes128_block(key, &mut block, true)?;
            state[..16].copy_from_slice(&block);
            state[16..32].fill(0);
            state[32] = 0;
            state[33] = 1;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn aes_mac_call(
    method: MethodId,
    signature: Signature,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Option<Native>> {
    if method == MethodId::setInitialDigest {
        for _ in 0..6 {
            frame.pop_raw()?;
        }
        frame.pop_reference()?;
        return crypto_exception(heap, context, 5).map(Some);
    }
    if matches!(
        method,
        MethodId::getAlgorithm
            | MethodId::getMessageDigestAlgorithm
            | MethodId::getCipherAlgorithm
            | MethodId::getPaddingAlgorithm
    ) {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        frame.push_short(match method {
            MethodId::getAlgorithm => 18,
            MethodId::getMessageDigestAlgorithm => 0,
            MethodId::getCipherAlgorithm => 6,
            MethodId::getPaddingAlgorithm => 1,
            _ => unreachable!(),
        })?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::init {
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
        heap.check_access(this, context)?;
        heap.check_access(key, context)?;
        if !matches!(mode, 1 | 2)
            || super::super::api_class(heap.info(key)?.class).map(|entry| entry.id)
                != Some(ClassId::AESKey)
            || word_field(heap, key, SIZE)? != 128
        {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        let mut iv = [0u8; 16];
        if let Some((array, offset, length)) = vector {
            if length != 16 {
                return crypto_exception(heap, context, 1).map(Some);
            }
            if offset < 0 {
                return Err(Error::Bounds);
            }
            heap.check_access(array, context)?;
            iv.copy_from_slice(heap.byte_slice(array, offset as usize, 16)?);
        }
        let state = heap.get_word(this, PENDING)?;
        if state == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, AES_MAC_STATE_BYTES as u16)])?;
        } else {
            heap.byte_slice(state, 0, AES_MAC_STATE_BYTES)?;
        }
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (PENDING + 1 - MATERIAL) * 2)])?;
        let state = if state == NULL {
            heap.new_transient_array(
                heap::KIND_BYTE,
                AES_MAC_STATE_BYTES as u16,
                context,
                heap::CLEAR_ON_RESET,
            )?
        } else {
            state
        };
        let pending = heap.byte_slice_mut(state, 0, AES_MAC_STATE_BYTES)?;
        pending.fill(0);
        pending[..16].copy_from_slice(&iv);
        heap.put_word(this, PENDING, state)?;
        heap.put_word(this, MATERIAL, key)?;
        heap.put_word(this, COUNTER, mode as u16)?;
        heap.put_word(this, READY, 1)?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::getLength {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        if word_field(heap, this, READY)? != 1 {
            return crypto_exception(heap, context, 4).map(Some);
        }
        if !key_initialized(heap, heap.get_word(this, MATERIAL)?)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        frame.push_short(16)?;
        return Ok(Some(Native::Returned));
    }
    let update = method == MethodId::update;
    let verify = method == MethodId::verify;
    if !update && !verify && method != MethodId::sign {
        return Ok(None);
    }
    let signature_length = if verify { frame.pop_short()? } else { 0 };
    let (signature_array, signature_offset) = if update {
        (NULL, 0)
    } else {
        let offset = frame.pop_short()?;
        (frame.pop_reference()?, offset)
    };
    let length = frame.pop_short()?;
    let offset = frame.pop_short()?;
    let input = frame.pop_reference()?;
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    heap.check_access(input, context)?;
    if word_field(heap, this, READY)? != 1
        || (!update && word_field(heap, this, COUNTER)? != if verify { 2 } else { 1 })
    {
        return crypto_exception(heap, context, 4).map(Some);
    }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? {
        return crypto_exception(heap, context, 2).map(Some);
    }
    if length < 0 || offset < 0 || signature_offset < 0 || signature_length < 0 {
        return Err(Error::Bounds);
    }
    if !update {
        heap.check_access(signature_array, context)?;
        heap.byte_slice(
            signature_array,
            signature_offset as usize,
            if verify {
                signature_length as usize
            } else {
                16
            },
        )?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut state = Zeroizing::new([0u8; AES_MAC_STATE_BYTES]);
    state.copy_from_slice(heap.byte_slice(pending, 0, AES_MAC_STATE_BYTES)?);
    let material = heap.get_word(key, MATERIAL)?;
    let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
    let mut secret = Zeroizing::new([0u8; 16]);
    secret.copy_from_slice(heap.byte_slice(material, prefix, 16)?);
    aes_mac_advance(host, &secret, &mut state, input)?;
    if update {
        heap.byte_slice_mut(pending, 0, AES_MAC_STATE_BYTES)?
            .copy_from_slice(&state[..]);
        return Ok(Some(Native::Returned));
    }
    if state[32] != 0 || state[33] == 0 {
        return crypto_exception(heap, context, 5).map(Some);
    }
    if verify {
        let expected = heap.byte_slice(
            signature_array,
            signature_offset as usize,
            signature_length as usize,
        )?;
        let valid = signature_length == 16
            && state[..16]
                .iter()
                .zip(expected)
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0;
        heap.byte_slice_mut(pending, 0, AES_MAC_STATE_BYTES)?
            .fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        heap.byte_slice_mut(signature_array, signature_offset as usize, 16)?
            .copy_from_slice(&state[..16]);
        heap.byte_slice_mut(pending, 0, AES_MAC_STATE_BYTES)?
            .fill(0);
        frame.push_short(16)?;
    }
    Ok(Some(Native::Returned))
}

#[cfg(feature = "des-legacy")]
#[allow(clippy::too_many_arguments)]
fn des_mac_call(
    method: MethodId,
    signature: Signature,
    heap: &mut Heap,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
    kind: u16,
) -> Result<Option<Native>> {
    let (algorithm, padding, tag_len, pkcs5) = des_mac_params(kind).ok_or(Error::Format)?;
    if method == MethodId::setInitialDigest {
        for _ in 0..6 {
            frame.pop_raw()?;
        }
        frame.pop_reference()?;
        return crypto_exception(heap, context, 5).map(Some);
    }
    if matches!(
        method,
        MethodId::getAlgorithm
            | MethodId::getMessageDigestAlgorithm
            | MethodId::getCipherAlgorithm
            | MethodId::getPaddingAlgorithm
    ) {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        let (cipher, pad) = des_mac_metadata(kind);
        frame.push_short(match method {
            MethodId::getAlgorithm => kind as i16,
            MethodId::getMessageDigestAlgorithm => 0,
            MethodId::getCipherAlgorithm => cipher,
            MethodId::getPaddingAlgorithm => pad,
            _ => unreachable!(),
        })?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::init {
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
        heap.check_access(this, context)?;
        heap.check_access(key, context)?;
        let bits = word_field(heap, key, SIZE)?;
        if !matches!(mode, 1 | 2)
            || !matches!(bits, 64 | 128 | 192)
            || (algorithm == MacAlgorithm::Retail && bits == 64)
            || super::super::api_class(heap.info(key)?.class).map(|entry| entry.id)
                != Some(ClassId::DESKey)
        {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        let mut iv = [0u8; 8];
        if let Some((array, offset, length)) = vector {
            if length != 8 {
                return crypto_exception(heap, context, 1).map(Some);
            }
            if offset < 0 {
                return Err(Error::Bounds);
            }
            heap.check_access(array, context)?;
            iv.copy_from_slice(heap.byte_slice(array, offset as usize, 8)?);
        }
        let material = heap.get_word(key, MATERIAL)?;
        let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
        let key_len = bits as usize / 8;
        let mut secret = Zeroizing::new([0u8; 24]);
        secret[..key_len].copy_from_slice(heap.byte_slice(material, prefix, key_len)?);
        let mac =
            Iso9797Mac::new_with_iv(algorithm, padding, &secret[..key_len], vector.map(|_| &iv))
                .map_err(|_| Error::Format)?;
        let mut snapshot = Zeroizing::new([0u8; ISO9797_CONTEXT_BYTES]);
        mac.write_snapshot(&mut snapshot)
            .map_err(|_| Error::Format)?;
        let state = heap.get_word(this, PENDING)?;
        if state == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, ISO9797_CONTEXT_BYTES as u16)])?;
        } else {
            heap.byte_slice(state, 0, ISO9797_CONTEXT_BYTES)?;
        }
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (PENDING + 1 - MATERIAL) * 2)])?;
        let state = if state == NULL {
            heap.new_transient_array(
                heap::KIND_BYTE,
                ISO9797_CONTEXT_BYTES as u16,
                context,
                heap::CLEAR_ON_RESET,
            )?
        } else {
            state
        };
        heap.byte_slice_mut(state, 0, ISO9797_CONTEXT_BYTES)?
            .copy_from_slice(&snapshot[..]);
        heap.put_word(this, PENDING, state)?;
        heap.put_word(this, MATERIAL, key)?;
        heap.put_word(this, COUNTER, mode as u16)?;
        heap.put_word(this, READY, 1)?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::getLength {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        if word_field(heap, this, READY)? != 1 {
            return crypto_exception(heap, context, 4).map(Some);
        }
        let key = heap.get_word(this, MATERIAL)?;
        if !key_initialized(heap, key)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        frame.push_short(tag_len as i16)?;
        return Ok(Some(Native::Returned));
    }
    if matches!(
        method,
        MethodId::signPreComputedHash | MethodId::verifyPreComputedHash
    ) {
        return crypto_exception(heap, context, 5).map(Some);
    }
    let update = method == MethodId::update;
    let verify = method == MethodId::verify;
    if !update && !verify && method != MethodId::sign {
        return Ok(None);
    }
    let signature_length = if verify { frame.pop_short()? } else { 0 };
    let (signature_array, signature_offset) = if update {
        (NULL, 0)
    } else {
        let offset = frame.pop_short()?;
        (frame.pop_reference()?, offset)
    };
    let length = frame.pop_short()?;
    let offset = frame.pop_short()?;
    let input = frame.pop_reference()?;
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    heap.check_access(input, context)?;
    if word_field(heap, this, READY)? != 1
        || (!update && word_field(heap, this, COUNTER)? != if verify { 2 } else { 1 })
    {
        return crypto_exception(heap, context, 4).map(Some);
    }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? {
        return crypto_exception(heap, context, 2).map(Some);
    }
    if length < 0 || offset < 0 || signature_offset < 0 || signature_length < 0 {
        return Err(Error::Bounds);
    }
    if !update {
        heap.check_access(signature_array, context)?;
        heap.byte_slice(
            signature_array,
            signature_offset as usize,
            if verify {
                signature_length as usize
            } else {
                tag_len
            },
        )?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut snapshot = Zeroizing::new([0u8; ISO9797_CONTEXT_BYTES]);
    snapshot.copy_from_slice(heap.byte_slice(pending, 0, ISO9797_CONTEXT_BYTES)?);
    let material = heap.get_word(key, MATERIAL)?;
    let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
    let key_len = word_field(heap, key, SIZE)? as usize / 8;
    let mut secret = Zeroizing::new([0u8; 24]);
    secret[..key_len].copy_from_slice(heap.byte_slice(material, prefix, key_len)?);
    let Ok(mut mac) = Iso9797Mac::resume(algorithm, padding, &secret[..key_len], &snapshot) else {
        return crypto_exception(heap, context, 4).map(Some);
    };
    mac.update(input).map_err(|_| Error::Format)?;
    if update {
        mac.write_snapshot(&mut snapshot)
            .map_err(|_| Error::Format)?;
        heap.byte_slice_mut(pending, 0, ISO9797_CONTEXT_BYTES)?
            .copy_from_slice(&snapshot[..]);
        return Ok(Some(Native::Returned));
    }
    if pkcs5 {
        let pad_len = 8 - (mac.total_len() % 8);
        let pad = [pad_len as u8; 8];
        mac.update(&pad[..pad_len]).map_err(|_| Error::Format)?;
    }
    let mut tag = Zeroizing::new([0u8; 8]);
    if mac.finalize(&mut tag).is_err() {
        return crypto_exception(heap, context, 5).map(Some);
    }
    if verify {
        let expected = heap.byte_slice(
            signature_array,
            signature_offset as usize,
            signature_length as usize,
        )?;
        let valid = signature_length as usize == tag_len
            && tag[..tag_len]
                .iter()
                .zip(expected)
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0;
        heap.byte_slice_mut(pending, 0, ISO9797_CONTEXT_BYTES)?
            .fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        heap.byte_slice_mut(signature_array, signature_offset as usize, tag_len)?
            .copy_from_slice(&tag[..tag_len]);
        heap.byte_slice_mut(pending, 0, ISO9797_CONTEXT_BYTES)?
            .fill(0);
        frame.push_short(tag_len as i16)?;
    }
    Ok(Some(Native::Returned))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call(
    method: MethodId,
    signature: Signature,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Option<Native>> {
    let receiver_depth = match method {
        MethodId::init => {
            if signature.init_vector() {
                5
            } else {
                2
            }
        }
        MethodId::getAlgorithm
        | MethodId::getMessageDigestAlgorithm
        | MethodId::getCipherAlgorithm
        | MethodId::getPaddingAlgorithm
        | MethodId::getLength => 0,
        MethodId::update => 3,
        MethodId::sign | MethodId::signPreComputedHash => 5,
        MethodId::verify | MethodId::verifyPreComputedHash | MethodId::setInitialDigest => 6,
        _ => return Ok(None),
    };
    let receiver = frame.peek_reference(receiver_depth)?;
    heap.check_access(receiver, context)?;
    #[cfg(feature = "des-legacy")]
    {
        let kind = word_field(heap, receiver, KIND)?;
        if des_mac_params(kind).is_some() {
            return des_mac_call(method, signature, heap, frame, context, budget, kind);
        }
    }
    if word_field(heap, receiver, KIND)? == 18 {
        if matches!(
            method,
            MethodId::signPreComputedHash | MethodId::verifyPreComputedHash
        ) {
            return crypto_exception(heap, context, 5).map(Some);
        }
        return aes_mac_call(method, signature, heap, host, frame, context, budget);
    }
    let algorithm = word_field(heap, receiver, KIND)?;
    if !matches!(algorithm, 33 | 34) { return Ok(None); }
    let wide = algorithm == 34;
    if method == MethodId::init {
        if signature.init_vector() {
            frame.pop_short()?;
            frame.pop_short()?;
            frame.pop_reference()?;
        }
        let mode = frame.pop_short()?;
        let key = frame.pop_reference()?;
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        heap.check_access(key, context)?;
        let kind = word_field(heap, key, KIND)?;
        if signature.init_vector()
            || word_field(heap, this, KIND)? != algorithm
            || word_field(heap, key, SIZE)? != if wide { 384 } else { 256 }
            || !((mode == 1 && matches!(kind, 12 | 30 | 31)) || (mode == 2 && kind == 11))
        {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        let state = heap.get_word(this, PENDING)?;
        if state == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, SHA256_STATE_BYTES as u16)])?;
        } else {
            heap.byte_slice(state, 0, SHA256_STATE_BYTES)?;
        }
        // Admit metadata before allocating or resetting the current digest state.
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (PENDING + 1 - MATERIAL) * 2)])?;
        let state = if state == NULL {
            heap.new_transient_array(
                heap::KIND_BYTE,
                SHA256_STATE_BYTES as u16,
                context,
                heap::CLEAR_ON_RESET,
            )?
        } else {
            state
        };
        heap.byte_slice_mut(state, 0, SHA256_STATE_BYTES)?.fill(0);
        heap.put_word(this, PENDING, state)?;
        heap.put_word(this, MATERIAL, key)?;
        heap.put_word(this, COUNTER, mode as u16)?;
        heap.put_word(this, READY, 1)?;
        return Ok(Some(Native::Returned));
    }
    if matches!(method, MethodId::getMessageDigestAlgorithm
        | MethodId::getCipherAlgorithm | MethodId::getPaddingAlgorithm) {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        frame.push_short(match method {
            MethodId::getMessageDigestAlgorithm => if wide { 5 } else { 4 },
            MethodId::getCipherAlgorithm => 5,
            MethodId::getPaddingAlgorithm => 1,
            _ => unreachable!(),
        })?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::getLength {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        if word_field(heap, this, READY)? != 1 {
            return crypto_exception(heap, context, 4).map(Some);
        }
        if !key_initialized(heap, heap.get_word(this, MATERIAL)?)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        frame.push_short(if wide { 104 } else { 72 })?;
        return Ok(Some(Native::Returned));
    }
    let update = method == MethodId::update;
    let verify = matches!(method, MethodId::verify | MethodId::verifyPreComputedHash);
    let prehashed = matches!(
        method,
        MethodId::signPreComputedHash | MethodId::verifyPreComputedHash
    );
    if !update && !verify && !matches!(method, MethodId::sign | MethodId::signPreComputedHash) {
        return Ok(None);
    }
    let signature_length = if verify { frame.pop_short()? } else { 0 };
    let (signature_array, signature_offset) = if update {
        (NULL, 0)
    } else {
        let offset = frame.pop_short()?;
        (frame.pop_reference()?, offset)
    };
    let length = frame.pop_short()?;
    let offset = frame.pop_short()?;
    let input = frame.pop_reference()?;
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    heap.check_access(input, context)?;
    if word_field(heap, this, READY)? != 1
        || (!update && word_field(heap, this, COUNTER)? != if verify { 2 } else { 1 })
    {
        return crypto_exception(heap, context, 4).map(Some);
    }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? {
        return crypto_exception(heap, context, 2).map(Some);
    }
    if length < 0 || offset < 0 || signature_offset < 0 || signature_length < 0 {
        return Err(Error::Bounds);
    }
    if prehashed && length != if wide { 48 } else { 32 } {
        return crypto_exception(heap, context, 5).map(Some);
    }
    if !update {
        heap.check_access(signature_array, context)?;
        heap.byte_slice(
            signature_array,
            signature_offset as usize,
            if verify {
                signature_length as usize
            } else {
                if wide { 104 } else { 72 }
            },
        )?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut state = Zeroizing::new([0; SHA256_STATE_BYTES]);
    state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
    let mut digest = Zeroizing::new([0; 48]);
    if prehashed {
        digest[..input.len()].copy_from_slice(input);
        state.fill(0);
    } else if wide {
        host.sha384_stream(
            &mut state,
            input,
            if update { None } else { Some(&mut digest) },
        )?;
    } else {
        host.sha256_stream(
            &mut state,
            input,
            if update { None } else { Some((&mut digest[..32]).try_into().map_err(|_| Error::Bounds)?) },
        )?;
    }
    if update {
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?
            .copy_from_slice(&state[..]);
        return Ok(Some(Native::Returned));
    }
    let material = heap.get_word(key, MATERIAL)?;
    if verify {
        let public = heap.byte_slice(material, 1, if wide { 97 } else { 65 })?;
        let encoded = heap.byte_slice(
            signature_array,
            signature_offset as usize,
            signature_length as usize,
        )?;
        let valid = if wide {
            host.p384_verify_hash(public.try_into().map_err(|_| Error::Bounds)?, &digest, encoded)?
        } else {
            host.p256_verify_hash(public.try_into().map_err(|_| Error::Bounds)?,
                (&digest[..32]).try_into().map_err(|_| Error::Bounds)?, encoded)?
        };
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        let private = heap.byte_slice(material, 1, if wide { 48 } else { 32 })?;
        let mut encoded = Zeroizing::new([0; 104]);
        let written = if wide {
            host.p384_sign_hash(private.try_into().map_err(|_| Error::Bounds)?,
                &digest, &mut encoded)?
        } else {
            host.p256_sign_hash(private.try_into().map_err(|_| Error::Bounds)?,
                (&digest[..32]).try_into().map_err(|_| Error::Bounds)?,
                (&mut encoded[..72]).try_into().map_err(|_| Error::Bounds)?)?
        };
        if !(8..=if wide { 104 } else { 72 }).contains(&written) {
            return Err(Error::Format);
        }
        heap.byte_slice_mut(signature_array, signature_offset as usize, written)?
            .copy_from_slice(&encoded[..written]);
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(written as i16)?;
    }
    Ok(Some(Native::Returned))
}

/// Validate the private fields of a restored Signature object. The VM has
/// already checked that every non-null field points to an object start.
pub(super) fn validate_saved_signature(payload: &[u8], saved_heap: &[u8]) -> Result<()> {
    let word = |at: usize| u16::from_be_bytes([payload[at * 2], payload[at * 2 + 1]]);
    let material = word(MATERIAL);

    let algorithm = word(0);
    let pending = word(5);
    let des_algorithm = {
        #[cfg(feature = "des-legacy")]
        {
            des_mac_params(algorithm).is_some()
        }
        #[cfg(not(feature = "des-legacy"))]
        {
            false
        }
    };
    if (!matches!(algorithm, 18 | 33 | 34) && !des_algorithm)
        || word(3) > 1
        || (word(3) == 1 && (material == 0 || pending == 0 || !matches!(word(4), 1 | 2)))
    {
        return Err(Error::Format);
    }
    if pending != 0 {
        let header = &saved_heap[pending as usize..pending as usize + heap::HEADER];
        #[cfg(feature = "des-legacy")]
        let des_state_bytes = ISO9797_CONTEXT_BYTES;
        #[cfg(not(feature = "des-legacy"))]
        let des_state_bytes = 0;
        let expected_length = if algorithm == 18 {
            34
        } else if matches!(algorithm, 33 | 34) {
            crate::host::SHA256_STATE_BYTES
        } else {
            des_state_bytes
        };
        if header[4] != heap::KIND_BYTE | (heap::CLEAR_ON_RESET << 4)
            || u16::from_be_bytes([header[2], header[3]]) as usize != expected_length
        {
            return Err(Error::Format);
        }
    }
    if material != 0 {
        let start = material as usize;
        let key_class = u16::from_be_bytes([saved_heap[start], saved_heap[start + 1]]);
        let expected = if algorithm == 18 {
            ClassId::AESKey
        } else if !matches!(algorithm, 33 | 34) {
            ClassId::DESKey
        } else if word(4) == 1 {
            ClassId::ECPrivateKey
        } else {
            ClassId::ECPublicKey
        };
        let invalid_des_key = if des_algorithm {
            let bits = u16::from_be_bytes([
                saved_heap[start + heap::HEADER + SIZE * 2],
                saved_heap[start + heap::HEADER + SIZE * 2 + 1],
            ]);
            #[cfg(feature = "des-legacy")]
            let retail_with_des = des_mac_params(algorithm)
                .is_some_and(|(mode, _, _, _)| mode == MacAlgorithm::Retail && bits == 64);
            #[cfg(not(feature = "des-legacy"))]
            let retail_with_des = false;
            !matches!(bits, 64 | 128 | 192) || retail_with_des
        } else {
            false
        };
        let invalid_ec_size = if matches!(algorithm, 33 | 34) {
            let bits = u16::from_be_bytes([
                saved_heap[start + heap::HEADER + SIZE * 2],
                saved_heap[start + heap::HEADER + SIZE * 2 + 1],
            ]);
            bits != if algorithm == 34 { 384 } else { 256 }
        } else { false };
        if super::super::api_class(key_class).map(|entry| entry.id) != Some(expected)
            || saved_heap[start + 4] != heap::KIND_OBJECT
            || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
            || invalid_des_key
            || invalid_ec_size
        {
            return Err(Error::Type);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WideProvider { fail_sign: bool }
    impl crate::host::Host for WideProvider {
        fn supports_signature(&self, algorithm: u8) -> bool { algorithm == 34 }
        fn sha384_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], input: &[u8],
            output: Option<&mut [u8; 48]>) -> Result<()> {
            for byte in input { state[0] = state[0].wrapping_add(*byte); }
            if let Some(output) = output { output.fill(state[0]); state.fill(0); }
            Ok(())
        }
        fn p384_sign_hash(&mut self, _: &[u8; 48], hash: &[u8; 48],
            output: &mut [u8; 104]) -> Result<usize> {
            if self.fail_sign { output.fill(0x42); return Err(Error::Unauthorized); }
            output[..8].copy_from_slice(&[0x30, 6, 2, 1, hash[0], 2, 1, 1]);
            Ok(8)
        }
        fn p384_verify_hash(&mut self, _: &[u8; 97], hash: &[u8; 48],
            signature: &[u8]) -> Result<bool> {
            Ok(signature == [0x30, 6, 2, 1, hash[0], 2, 1, 1])
        }
    }

    #[test]
    fn p384_signature_factory_streaming_verify_and_provider_failure() {
        let init_signature = crate::jcvm_api::PACKAGES.iter().flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature).unwrap().methods.iter()
            .find(|method| method.id == MethodId::init && !method.signature.init_vector())
            .unwrap().signature;
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = WideProvider { fail_sign: false };
        let mut instances = [0; 2];
        for instance in &mut instances {
            frame.push_short(34).unwrap();
            frame.push_short(0).unwrap();
            assert!(matches!(factory::get_instance(ClassId::Signature, &mut heap,
                &mut host, &mut frame, 1), Ok(Native::Returned)));
            *instance = frame.pop_reference().unwrap();
        }
        let mut keys = [0; 2];
        for (index, key) in keys.iter_mut().enumerate() {
            let class = if index == 0 { ClassId::ECPrivateKey } else { ClassId::ECPublicKey };
            let kind = if index == 0 { 12 } else { 11 };
            let length = if index == 0 { 49 } else { 98 };
            *key = new_native(&mut heap, class, STATE_WORDS, 1).unwrap();
            heap.put_word(*key, KIND, kind).unwrap();
            heap.put_word(*key, SIZE, 384).unwrap();
            let material = heap.new_array(heap::KIND_BYTE, length, 1).unwrap();
            heap.array_put(material, 0, 0x5f).unwrap();
            if index == 0 { heap.array_put(material, 48, 1).unwrap(); }
            else { heap.array_put(material, 1, 4).unwrap(); }
            heap.put_word(*key, MATERIAL, material).unwrap();
        }
        let array = heap.new_array(heap::KIND_BYTE, 120, 1).unwrap();
        heap.byte_slice_mut(array, 0, 3).unwrap().copy_from_slice(&[1, 2, 3]);
        for (instance, key, mode) in [(instances[0], keys[0], 1), (instances[1], keys[1], 2)] {
            frame.push_reference(instance).unwrap();
            frame.push_reference(key).unwrap();
            frame.push_short(mode).unwrap();
            assert!(matches!(call(MethodId::init, init_signature, &mut heap, &mut host,
                &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
            frame.push_reference(instance).unwrap();
            assert!(matches!(call(MethodId::getLength, init_signature, &mut heap, &mut host,
                &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short(), Ok(104));
        }
        frame.push_reference(instances[0]).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(call(MethodId::update, init_signature, &mut heap, &mut host,
            &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
        let pending = heap.get_word(instances[0], PENDING).unwrap();
        let before = heap.byte_slice(array, 10, 8).unwrap().to_vec();
        host.fail_sign = true;
        frame.push_reference(instances[0]).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(1).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(10).unwrap();
        assert!(matches!(call(MethodId::sign, init_signature, &mut heap, &mut host,
            &mut frame, 1, &mut 100), Err(Error::Unauthorized)));
        assert_eq!(heap.byte_slice(array, 10, 8).unwrap(), before);
        assert_eq!(heap.array_get(pending, 0), Ok(3));
        host.fail_sign = false;
        frame.push_reference(instances[0]).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(1).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(10).unwrap();
        assert!(matches!(call(MethodId::sign, init_signature, &mut heap, &mut host,
            &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
        assert_eq!(frame.pop_short(), Ok(8));
        assert_eq!(heap.byte_slice(array, 10, 8).unwrap(), &[0x30, 6, 2, 1, 6, 2, 1, 1]);
        frame.push_reference(instances[1]).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(3).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(10).unwrap();
        frame.push_short(8).unwrap();
        assert!(matches!(call(MethodId::verify, init_signature, &mut heap, &mut host,
            &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
        assert_eq!(frame.pop_short(), Ok(1));
    }

    #[cfg(not(feature = "des-legacy"))]
    #[test]
    fn compact_build_rejects_des_key_and_signature_factories() {
        struct NoHost;
        impl crate::host::Host for NoHost {}
        let mut slab = [0u8; 1024];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut words = [0; 8];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = NoHost;
        frame.push_short(3).unwrap();
        frame.push_short(128).unwrap();
        frame.push_short(0).unwrap();
        let Ok(Native::Threw(exception)) = key::call(ClassId::KeyBuilder,
            MethodId::buildKey, &mut heap, &mut host, &mut frame, 1)
        else { panic!("compact build accepted DESKey"); };
        assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(3));
        frame.push_short(20).unwrap();
        frame.push_short(0).unwrap();
        let Ok(Native::Threw(exception)) = factory::get_instance(ClassId::Signature,
            &mut heap, &mut host, &mut frame, 1)
        else { panic!("compact build accepted DES MAC"); };
        assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(3));
    }

    #[cfg(feature = "des-legacy")]
    #[test]
    fn des_mac_factory_admits_only_implemented_legacy_ids() {
        struct NoHost;
        impl crate::host::Host for NoHost {}
        let mut slab = [0u8; 1024];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut words = [0; 8];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = NoHost;
        for algorithm in [2, 3, 4, 5, 6, 7, 8, 19, 20, 47, 48] {
            frame.push_short(algorithm).unwrap();
            frame.push_short(0).unwrap();
            assert!(matches!(
                factory::get_instance(ClassId::Signature, &mut heap, &mut host, &mut frame, 1),
                Ok(Native::Returned)
            ));
            let signer = frame.pop_reference().unwrap();
            assert_eq!(word_field(&heap, signer, KIND), Ok(algorithm as u16));
        }
        frame.push_short(1).unwrap();
        frame.push_short(0).unwrap();
        let Ok(Native::Threw(exception)) =
            factory::get_instance(ClassId::Signature, &mut heap, &mut host, &mut frame, 1)
        else {
            panic!("unsupported MAC4 NOPAD accepted");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(3)
        );
    }

    #[cfg(feature = "des-legacy")]
    #[test]
    fn des_mac_variants_match_independent_des_cbc_vectors() {
        struct NoHost;
        impl crate::host::Host for NoHost {}
        // OpenSSL DES-EDE CBC and DES-EDE ECB results for ANSI X9.19's message.
        let cases: &[(u16, usize, [u8; 8])] = &[
            (2, 24, [0x93, 0x46, 0x2a, 0x6d, 0xb9, 0xb4, 0xa4, 0xd1]),
            (3, 23, [0x15, 0x2f, 0x89, 0xe6, 0x81, 0x35, 0x08, 0x77]),
            (4, 23, [0x15, 0x2f, 0x89, 0xe6, 0x81, 0x35, 0x08, 0x77]),
            (5, 24, [0x80, 0x50, 0x36, 0xd5, 0x0b, 0xb7, 0x61, 0x07]),
            (6, 24, [0x80, 0x50, 0x36, 0xd5, 0x0b, 0xb7, 0x61, 0x07]),
            (7, 24, [0x7c, 0x3f, 0xfc, 0x6c, 0xd3, 0x5a, 0x76, 0xee]),
            (8, 24, [0x7c, 0x3f, 0xfc, 0x6c, 0xd3, 0x5a, 0x76, 0xee]),
            (19, 24, [0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96]),
            (20, 24, [0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96]),
            (47, 23, [0x4b, 0xad, 0x7f, 0xbb, 0x7c, 0xa1, 0xb8, 0x03]),
            (48, 23, [0x4b, 0xad, 0x7f, 0xbb, 0x7c, 0xa1, 0xb8, 0x03]),
        ];
        let methods = crate::jcvm_api::PACKAGES
            .iter()
            .flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature)
            .unwrap()
            .methods;
        let init_plain = methods
            .iter()
            .find(|entry| entry.id == MethodId::init && !entry.signature.init_vector())
            .unwrap()
            .signature;
        for &(algorithm, message_len, expected) in cases {
            let mut slab = [0u8; 2048];
            let mut heap = Heap::new(&mut slab).unwrap();
            let key = new_native(&mut heap, ClassId::DESKey, STATE_WORDS, 1).unwrap();
            heap.put_word(key, KIND, 3).unwrap();
            heap.put_word(key, SIZE, 128).unwrap();
            let material = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
            heap.byte_slice_mut(material, 0, 16)
                .unwrap()
                .copy_from_slice(&[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ]);
            heap.put_word(key, MATERIAL, material).unwrap();
            heap.put_word(key, READY, 1).unwrap();
            let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
            heap.put_word(signer, KIND, algorithm).unwrap();
            let bytes = heap.new_array(heap::KIND_BYTE, 48, 1).unwrap();
            heap.byte_slice_mut(bytes, 0, 24)
                .unwrap()
                .copy_from_slice(b"Now is the time for all ");
            let mut words = [0; 16];
            let mut tags = [0; 8];
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            let mut host = NoHost;
            frame.push_reference(signer).unwrap();
            frame.push_reference(key).unwrap();
            frame.push_short(1).unwrap();
            assert!(matches!(
                call(
                    MethodId::init,
                    init_plain,
                    &mut heap,
                    &mut host,
                    &mut frame,
                    1,
                    &mut 100
                ),
                Ok(Some(Native::Returned))
            ));
            frame.push_reference(signer).unwrap();
            frame.push_reference(bytes).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(message_len as i16).unwrap();
            frame.push_reference(bytes).unwrap();
            frame.push_short(32).unwrap();
            assert!(matches!(
                call(
                    MethodId::sign,
                    init_plain,
                    &mut heap,
                    &mut host,
                    &mut frame,
                    1,
                    &mut 100
                ),
                Ok(Some(Native::Returned))
            ));
            let tag_len = des_mac_params(algorithm).unwrap().2;
            assert_eq!(frame.pop_short(), Ok(tag_len as i16));
            assert_eq!(
                heap.byte_slice(bytes, 32, tag_len).unwrap(),
                &expected[..tag_len]
            );
        }
    }

    #[cfg(feature = "des-legacy")]
    #[test]
    fn retail_mac_streams_real_vector_and_rejects_bad_state() {
        struct NoHost;
        impl crate::host::Host for NoHost {}
        let methods = crate::jcvm_api::PACKAGES
            .iter()
            .flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature)
            .unwrap()
            .methods;
        let init_plain = methods
            .iter()
            .find(|entry| entry.id == MethodId::init && !entry.signature.init_vector())
            .unwrap()
            .signature;
        let mut slab = [0u8; 4096];
        let mut heap = Heap::new(&mut slab).unwrap();
        let key = new_native(&mut heap, ClassId::DESKey, STATE_WORDS, 1).unwrap();
        heap.put_word(key, KIND, 3).unwrap();
        heap.put_word(key, SIZE, 128).unwrap();
        let material = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        heap.byte_slice_mut(material, 0, 16)
            .unwrap()
            .copy_from_slice(&[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ]);
        heap.put_word(key, MATERIAL, material).unwrap();
        heap.put_word(key, READY, 1).unwrap();
        let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
        heap.put_word(signer, KIND, 20).unwrap();
        let bytes = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        heap.byte_slice_mut(bytes, 0, 24)
            .unwrap()
            .copy_from_slice(b"Now is the time for all ");
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = NoHost;
        let mut budget = 100;
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        let pending = heap.get_word(signer, PENDING).unwrap();
        for (offset, length) in [(0, 9), (9, 7)] {
            frame.push_reference(signer).unwrap();
            frame.push_reference(bytes).unwrap();
            frame.push_short(offset).unwrap();
            frame.push_short(length).unwrap();
            assert!(matches!(
                call(
                    MethodId::update,
                    init_plain,
                    &mut heap,
                    &mut host,
                    &mut frame,
                    1,
                    &mut budget
                ),
                Ok(Some(Native::Returned))
            ));
        }
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(16).unwrap();
        frame.push_short(8).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(32).unwrap();
        assert!(matches!(
            call(
                MethodId::sign,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(8));
        assert_eq!(
            heap.byte_slice(bytes, 32, 8).unwrap(),
            &[0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96]
        );
        assert!(heap
            .byte_slice(pending, 0, ISO9797_CONTEXT_BYTES)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0));

        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(24).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(32).unwrap();
        frame.push_short(8).unwrap();
        assert!(matches!(
            call(
                MethodId::verify,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(1));

        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(24).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(32).unwrap();
        let Ok(Some(Native::Threw(exception))) = call(
            MethodId::sign,
            init_plain,
            &mut heap,
            &mut host,
            &mut frame,
            1,
            &mut budget,
        ) else {
            panic!("reset state accepted");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(4)
        );
        assert_eq!(
            heap.byte_slice(bytes, 32, 8).unwrap(),
            &[0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96]
        );
    }

    #[test]
    fn aes_mac_nopad_uses_cbc_vectors_and_preserves_state_on_failure() {
        // NIST SP 800-38A F.2.1 AES-CBC blocks, with its IV and a zero-IV block.
        const KEY: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        const FIRST: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        const SECOND: [u8; 16] = [
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
            0x8e, 0x51,
        ];
        const IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        const CBC_FIRST: [u8; 16] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d,
        ];
        const CBC_SECOND: [u8; 16] = [
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
            0x78, 0xb2,
        ];
        const ZERO_IV_FIRST: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66,
            0xef, 0x97,
        ];
        struct AesVector {
            fail: bool,
        }
        impl crate::host::Host for AesVector {
            fn aes128_block(
                &mut self,
                key: &[u8; 16],
                block: &mut [u8; 16],
                encrypt: bool,
            ) -> Result<()> {
                assert_eq!(key, &KEY);
                assert!(encrypt);
                if self.fail {
                    block.fill(0);
                    return Err(Error::Unauthorized);
                }
                let mut first_with_iv = FIRST;
                for (byte, iv) in first_with_iv.iter_mut().zip(IV) {
                    *byte ^= iv;
                }
                let mut second_with_chain = SECOND;
                for (byte, chain) in second_with_chain.iter_mut().zip(CBC_FIRST) {
                    *byte ^= chain;
                }
                *block = if *block == first_with_iv {
                    CBC_FIRST
                } else if *block == second_with_chain {
                    CBC_SECOND
                } else if *block == FIRST {
                    ZERO_IV_FIRST
                } else {
                    return Err(Error::Format);
                };
                Ok(())
            }
        }
        let methods = crate::jcvm_api::PACKAGES
            .iter()
            .flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature)
            .unwrap()
            .methods;
        let init_plain = methods
            .iter()
            .find(|entry| entry.id == MethodId::init && !entry.signature.init_vector())
            .unwrap()
            .signature;
        let init_vector = methods
            .iter()
            .find(|entry| entry.id == MethodId::init && entry.signature.init_vector())
            .unwrap()
            .signature;
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        let key = new_native(&mut heap, ClassId::AESKey, STATE_WORDS, 1).unwrap();
        heap.put_word(key, KIND, 15).unwrap();
        heap.put_word(key, SIZE, 128).unwrap();
        let material = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        heap.byte_slice_mut(material, 0, 16)
            .unwrap()
            .copy_from_slice(&KEY);
        heap.put_word(key, MATERIAL, material).unwrap();
        heap.put_word(key, READY, 1).unwrap();
        let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
        heap.put_word(signer, KIND, 18).unwrap();
        let bytes = heap.new_array(heap::KIND_BYTE, 80, 1).unwrap();
        heap.byte_slice_mut(bytes, 0, 16)
            .unwrap()
            .copy_from_slice(&FIRST);
        heap.byte_slice_mut(bytes, 16, 16)
            .unwrap()
            .copy_from_slice(&SECOND);
        heap.byte_slice_mut(bytes, 32, 16)
            .unwrap()
            .copy_from_slice(&IV);
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = AesVector { fail: false };
        let mut budget = 200;
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(32).unwrap();
        frame.push_short(16).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                init_vector,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        let pending = heap.get_word(signer, PENDING).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(7).unwrap();
        assert!(matches!(
            call(
                MethodId::update,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(7).unwrap();
        frame.push_short(9).unwrap();
        assert!(matches!(
            call(
                MethodId::update,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(heap.byte_slice(pending, 0, 16).unwrap(), &CBC_FIRST);
        let prior = heap
            .byte_slice(pending, 0, AES_MAC_STATE_BYTES)
            .unwrap()
            .to_vec();
        heap.byte_slice_mut(bytes, 48, 16).unwrap().fill(0xaa);
        host.fail = true;
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(16).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(48).unwrap();
        assert!(matches!(
            call(
                MethodId::sign,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Err(Error::Unauthorized)
        ));
        assert_eq!(
            heap.byte_slice(pending, 0, AES_MAC_STATE_BYTES).unwrap(),
            &prior
        );
        assert_eq!(heap.byte_slice(bytes, 48, 16).unwrap(), &[0xaa; 16]);
        host.fail = false;
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(16).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(48).unwrap();
        assert!(matches!(
            call(
                MethodId::sign,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(16));
        assert_eq!(heap.byte_slice(bytes, 48, 16).unwrap(), &CBC_SECOND);
        assert_eq!(
            heap.byte_slice(pending, 0, AES_MAC_STATE_BYTES).unwrap(),
            &[0; AES_MAC_STATE_BYTES]
        );
        // Finalization discards the supplied IV. A subsequent operation starts at zero.
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(64).unwrap();
        assert!(matches!(
            call(
                MethodId::sign,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(16));
        assert_eq!(heap.byte_slice(bytes, 64, 16).unwrap(), &ZERO_IV_FIRST);
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(64).unwrap();
        frame.push_short(15).unwrap();
        assert!(matches!(
            call(
                MethodId::verify,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(0));
        assert_eq!(
            heap.byte_slice(pending, 0, AES_MAC_STATE_BYTES).unwrap(),
            &[0; AES_MAC_STATE_BYTES]
        );
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(64).unwrap();
        frame.push_short(16).unwrap();
        assert!(matches!(
            call(
                MethodId::verify,
                init_plain,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(frame.pop_short(), Ok(1));
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(0).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(64).unwrap();
        frame.push_short(16).unwrap();
        let Ok(Some(Native::Threw(exception))) = call(
            MethodId::verify,
            init_plain,
            &mut heap,
            &mut host,
            &mut frame,
            1,
            &mut budget,
        ) else {
            panic!("empty MAC accepted");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(5)
        );
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(15).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(64).unwrap();
        frame.push_short(16).unwrap();
        let Ok(Some(Native::Threw(exception))) = call(
            MethodId::verify,
            init_plain,
            &mut heap,
            &mut host,
            &mut frame,
            1,
            &mut budget,
        ) else {
            panic!("unaligned MAC accepted");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(5)
        );
        assert_eq!(
            heap.byte_slice(pending, 0, AES_MAC_STATE_BYTES).unwrap(),
            &[0; AES_MAC_STATE_BYTES]
        );
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(16).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(1).unwrap();
        let Ok(Some(Native::Threw(exception))) = call(
            MethodId::setInitialDigest,
            init_plain,
            &mut heap,
            &mut host,
            &mut frame,
            1,
            &mut budget,
        ) else {
            panic!("AES MAC accepted a hash state");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(5)
        );
        heap.put_word(key, READY, 0).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(bytes).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(16).unwrap();
        let Ok(Some(Native::Threw(exception))) = call(
            MethodId::update,
            init_plain,
            &mut heap,
            &mut host,
            &mut frame,
            1,
            &mut budget,
        ) else {
            panic!("cleared key accepted");
        };
        assert_eq!(
            heap.get_word(exception, crate::natives::REASON_FIELD),
            Ok(2)
        );
    }
    struct Provider {
        fail: bool,
    }
    impl crate::host::Host for Provider {
        fn sha256_stream(
            &mut self,
            state: &mut [u8; SHA256_STATE_BYTES],
            input: &[u8],
            output: Option<&mut [u8; 32]>,
        ) -> Result<()> {
            state[0] = input
                .iter()
                .fold(state[0], |sum, byte| sum.wrapping_add(*byte));
            if let Some(output) = output {
                output.fill(state[0]);
                state.fill(0);
            }
            Ok(())
        }
        fn p256_sign_hash(
            &mut self,
            _: &[u8; 32],
            hash: &[u8; 32],
            output: &mut [u8; 72],
        ) -> Result<usize> {
            output.fill(hash[0]);
            if self.fail {
                Err(Error::Unauthorized)
            } else {
                Ok(8)
            }
        }
        fn p256_verify_hash(
            &mut self,
            _: &[u8; 65],
            hash: &[u8; 32],
            signature: &[u8],
        ) -> Result<bool> {
            Ok(signature == [hash[0]; 8])
        }
    }

    #[test]
    fn streaming_signatures_stage_output_reset_after_success_and_observe_key_clearing() {
        let signature = crate::jcvm_api::PACKAGES
            .iter()
            .flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature)
            .unwrap()
            .methods
            .iter()
            .find(|method| method.id == MethodId::init && !method.signature.init_vector())
            .unwrap()
            .signature;
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        let key = new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
        heap.put_word(key, KIND, 30).unwrap();
        heap.put_word(key, SIZE, 256).unwrap();
        let material = ec::material(&mut heap, key, 1).unwrap();
        heap.array_put(material, 0, 0x5f).unwrap();
        heap.array_put(material, 32, 1).unwrap();
        let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
        heap.put_word(signer, KIND, 33).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 96, 1).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false };
        heap.begin_transaction(14).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                signature,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut 100
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.commit_transaction().unwrap();
        let pending = heap.get_word(signer, PENDING).unwrap();
        heap.byte_slice_mut(array, 0, 2)
            .unwrap()
            .copy_from_slice(&[1, 2]);
        frame.push_reference(signer).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(
            call(
                MethodId::update,
                signature,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut 100
            ),
            Ok(Some(Native::Returned))
        ));
        assert_eq!(heap.array_get(pending, 0), Ok(3));
        let before = heap.image().to_vec();
        heap.begin_transaction(8).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                signature,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut 100
            ),
            Err(Error::TransactionFull)
        ));
        heap.commit_transaction().unwrap();
        assert_eq!(
            heap.image(),
            before,
            "failed init must preserve the accumulated digest"
        );
        for case in 0..4 {
            host.fail = case == 0;
            heap.byte_slice_mut(array, 0, 96).unwrap().fill(0xaa);
            heap.array_put(array, 0, 3).unwrap();
            if case == 3 {
                heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
            }
            frame.push_reference(signer).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(1).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            let mut budget = 1;
            let result = call(
                MethodId::sign,
                signature,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut budget,
            );
            match case {
                0 => {
                    assert!(matches!(result, Err(Error::Unauthorized)));
                    assert_eq!(heap.array_get(pending, 0), Ok(3));
                    assert_eq!(heap.array_get(array, 0), Ok(3));
                    assert_eq!(heap.array_get(array, 1), Ok(-86));
                }
                1 | 2 => {
                    assert!(matches!(result, Ok(Some(Native::Returned))));
                    assert_eq!(frame.pop_short(), Ok(8));
                    assert_eq!(
                        heap.byte_slice(array, 0, 8).unwrap(),
                        &[if case == 1 { 6 } else { 3 }; 8]
                    );
                    assert_eq!(
                        heap.byte_slice(pending, 0, SHA256_STATE_BYTES).unwrap(),
                        &[0; SHA256_STATE_BYTES]
                    );
                    assert_eq!(budget, 0);
                }
                _ => {
                    let Ok(Some(Native::Threw(exception))) = result else {
                        panic!("cleared key accepted");
                    };
                    assert_eq!(
                        heap.get_word(exception, crate::natives::REASON_FIELD),
                        Ok(2)
                    );
                    assert_eq!(budget, 1);
                }
            }
        }
        let public = new_native(&mut heap, ClassId::ECPublicKey, STATE_WORDS, 1).unwrap();
        heap.put_word(public, KIND, 11).unwrap();
        heap.put_word(public, SIZE, 256).unwrap();
        let public_material = ec::material(&mut heap, public, 1).unwrap();
        heap.array_put(public_material, 0, 0x5f).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(public).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(
            call(
                MethodId::init,
                signature,
                &mut heap,
                &mut host,
                &mut frame,
                1,
                &mut 100
            ),
            Ok(Some(Native::Returned))
        ));
        for valid in [true, false] {
            heap.byte_slice_mut(array, 0, 32).unwrap().fill(9);
            heap.byte_slice_mut(array, 64, 8)
                .unwrap()
                .fill(if valid { 9 } else { 8 });
            // Precomputed input must discard any accumulated update state.
            heap.array_put(pending, 0, 99).unwrap();
            frame.push_reference(signer).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(32).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(64).unwrap();
            frame.push_short(8).unwrap();
            assert!(matches!(
                call(
                    MethodId::verifyPreComputedHash,
                    signature,
                    &mut heap,
                    &mut host,
                    &mut frame,
                    1,
                    &mut 100
                ),
                Ok(Some(Native::Returned))
            ));
            assert_eq!(frame.pop_short(), Ok(i16::from(valid)));
            assert_eq!(
                heap.byte_slice(pending, 0, SHA256_STATE_BYTES).unwrap(),
                &[0; SHA256_STATE_BYTES]
            );
        }
    }
}
