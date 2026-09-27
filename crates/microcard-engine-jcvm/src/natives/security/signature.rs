//! Signature operations retain only reset-scoped streaming state between updates.
use super::*;
use crate::host::SHA256_STATE_BYTES;

const AES_MAC_STATE_BYTES: usize = 34;

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
    if word_field(heap, receiver, KIND)? == 18 {
        if matches!(
            method,
            MethodId::signPreComputedHash | MethodId::verifyPreComputedHash
        ) {
            return crypto_exception(heap, context, 5).map(Some);
        }
        return aes_mac_call(method, signature, heap, host, frame, context, budget);
    }
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
            || word_field(heap, this, KIND)? != 33
            || word_field(heap, key, SIZE)? != 256
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
    if method == MethodId::getLength {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        if word_field(heap, this, READY)? != 1 {
            return crypto_exception(heap, context, 4).map(Some);
        }
        if !key_initialized(heap, heap.get_word(this, MATERIAL)?)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        frame.push_short(72)?;
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
    if prehashed && length != 32 {
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
                72
            },
        )?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut state = Zeroizing::new([0; SHA256_STATE_BYTES]);
    state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
    let mut digest = Zeroizing::new([0; 32]);
    if prehashed {
        digest.copy_from_slice(input);
        state.fill(0);
    } else {
        host.sha256_stream(
            &mut state,
            input,
            if update { None } else { Some(&mut digest) },
        )?;
    }
    if update {
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?
            .copy_from_slice(&state[..]);
        return Ok(Some(Native::Returned));
    }
    let material = heap.get_word(key, MATERIAL)?;
    if verify {
        let public = heap
            .byte_slice(material, 1, 65)?
            .try_into()
            .map_err(|_| Error::Bounds)?;
        let encoded = heap.byte_slice(
            signature_array,
            signature_offset as usize,
            signature_length as usize,
        )?;
        let valid = host.p256_verify_hash(public, &digest, encoded)?;
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        let private = heap
            .byte_slice(material, 1, 32)?
            .try_into()
            .map_err(|_| Error::Bounds)?;
        let mut encoded = Zeroizing::new([0; 72]);
        let written = host.p256_sign_hash(private, &digest, &mut encoded)?;
        if !(8..=72).contains(&written) {
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
    if !matches!(algorithm, 18 | 33)
        || word(3) > 1
        || (word(3) == 1 && (material == 0 || pending == 0 || !matches!(word(4), 1 | 2)))
    {
        return Err(Error::Format);
    }
    if pending != 0 {
        let header = &saved_heap[pending as usize..pending as usize + heap::HEADER];
        let expected_length = if algorithm == 18 {
            34
        } else {
            crate::host::SHA256_STATE_BYTES
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
        } else if word(4) == 1 {
            ClassId::ECPrivateKey
        } else {
            ClassId::ECPublicKey
        };
        if super::super::api_class(key_class).map(|entry| entry.id) != Some(expected)
            || saved_heap[start + 4] != heap::KIND_OBJECT
            || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
        {
            return Err(Error::Type);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
