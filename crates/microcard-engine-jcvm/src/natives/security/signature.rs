//! ECDSA/SHA-256 keeps only reset-scoped provider hash state between updates.
use super::*;
use crate::host::SHA256_STATE_BYTES;

#[allow(clippy::too_many_arguments)]
pub(super) fn call(method: MethodId, signature: Signature, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, context: heap::Context,
    budget: &mut u32) -> Result<Option<Native>> {
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
        if signature.init_vector() || word_field(heap, this, KIND)? != 33
            || word_field(heap, key, SIZE)? != 256
            || !((mode == 1 && matches!(kind, 12 | 30 | 31)) || (mode == 2 && kind == 11)) {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
        let state = heap.get_word(this, PENDING)?;
        if state == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, SHA256_STATE_BYTES as u16)])?;
        } else { heap.byte_slice(state, 0, SHA256_STATE_BYTES)?; }
        // Admit metadata before allocating or resetting the current digest state.
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (PENDING + 1 - MATERIAL) * 2)])?;
        let state = if state == NULL {
            heap.new_transient_array(heap::KIND_BYTE, SHA256_STATE_BYTES as u16,
                context, heap::CLEAR_ON_RESET)?
        } else { state };
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
        if word_field(heap, this, READY)? != 1 { return crypto_exception(heap, context, 4).map(Some); }
        if !key_initialized(heap, heap.get_word(this, MATERIAL)?)? {
            return crypto_exception(heap, context, 2).map(Some);
        }
        frame.push_short(72)?;
        return Ok(Some(Native::Returned));
    }
    let update = method == MethodId::update;
    let verify = matches!(method, MethodId::verify | MethodId::verifyPreComputedHash);
    let prehashed = matches!(method, MethodId::signPreComputedHash | MethodId::verifyPreComputedHash);
    if !update && !verify && !matches!(method, MethodId::sign | MethodId::signPreComputedHash) {
        return Ok(None);
    }
    let signature_length = if verify { frame.pop_short()? } else { 0 };
    let (signature_array, signature_offset) = if update { (NULL, 0) } else {
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
        || (!update && word_field(heap, this, COUNTER)? != if verify { 2 } else { 1 }) {
        return crypto_exception(heap, context, 4).map(Some);
    }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
    if length < 0 || offset < 0 || signature_offset < 0 || signature_length < 0 { return Err(Error::Bounds); }
    if prehashed && length != 32 { return crypto_exception(heap, context, 5).map(Some); }
    if !update {
        heap.check_access(signature_array, context)?;
        heap.byte_slice(signature_array, signature_offset as usize,
            if verify { signature_length as usize } else { 72 })?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut state = Zeroizing::new([0; SHA256_STATE_BYTES]);
    state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
    let mut digest = Zeroizing::new([0; 32]);
    if prehashed { digest.copy_from_slice(input); state.fill(0); }
    else { host.sha256_stream(&mut state, input, if update { None } else { Some(&mut digest) })?; }
    if update {
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.copy_from_slice(&state[..]);
        return Ok(Some(Native::Returned));
    }
    let material = heap.get_word(key, MATERIAL)?;
    if verify {
        let public = heap.byte_slice(material, 1, 65)?.try_into().map_err(|_| Error::Bounds)?;
        let encoded = heap.byte_slice(signature_array, signature_offset as usize, signature_length as usize)?;
        let valid = host.p256_verify_hash(public, &digest, encoded)?;
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        let private = heap.byte_slice(material, 1, 32)?.try_into().map_err(|_| Error::Bounds)?;
        let mut encoded = Zeroizing::new([0; 72]);
        let written = host.p256_sign_hash(private, &digest, &mut encoded)?;
        if !(8..=72).contains(&written) { return Err(Error::Format); }
        heap.byte_slice_mut(signature_array, signature_offset as usize, written)?.copy_from_slice(&encoded[..written]);
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(written as i16)?;
    }
    Ok(Some(Native::Returned))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider { fail: bool }
    impl crate::host::Host for Provider {
        fn sha256_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], input: &[u8],
            output: Option<&mut [u8; 32]>) -> Result<()> {
            state[0] = input.iter().fold(state[0], |sum, byte| sum.wrapping_add(*byte));
            if let Some(output) = output { output.fill(state[0]); state.fill(0); }
            Ok(())
        }
        fn p256_sign_hash(&mut self, _: &[u8; 32], hash: &[u8; 32], output: &mut [u8; 72]) -> Result<usize> {
            output.fill(hash[0]);
            if self.fail { Err(Error::Unauthorized) } else { Ok(8) }
        }
        fn p256_verify_hash(&mut self, _: &[u8; 65], hash: &[u8; 32], signature: &[u8]) -> Result<bool> {
            Ok(signature == [hash[0]; 8])
        }
    }

    #[test]
    fn streaming_signatures_stage_output_reset_after_success_and_observe_key_clearing() {
        let signature = crate::jcvm_api::PACKAGES.iter().flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::Signature).unwrap().methods.iter()
            .find(|method| method.id == MethodId::init && !method.signature.init_vector()).unwrap().signature;
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
        assert!(matches!(call(MethodId::init, signature, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Ok(Some(Native::Returned))));
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.commit_transaction().unwrap();
        let pending = heap.get_word(signer, PENDING).unwrap();
        heap.byte_slice_mut(array, 0, 2).unwrap().copy_from_slice(&[1, 2]);
        frame.push_reference(signer).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(call(MethodId::update, signature, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Ok(Some(Native::Returned))));
        assert_eq!(heap.array_get(pending, 0), Ok(3));
        let before = heap.image().to_vec();
        heap.begin_transaction(8).unwrap();
        frame.push_reference(signer).unwrap();
        frame.push_reference(key).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(call(MethodId::init, signature, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Err(Error::TransactionFull)));
        heap.commit_transaction().unwrap();
        assert_eq!(heap.image(), before, "failed init must preserve the accumulated digest");
        for case in 0..4 {
            host.fail = case == 0;
            heap.byte_slice_mut(array, 0, 96).unwrap().fill(0xaa);
            heap.array_put(array, 0, 3).unwrap();
            if case == 3 { heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap(); }
            frame.push_reference(signer).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(1).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            let mut budget = 1;
            let result = call(MethodId::sign, signature, &mut heap, &mut host, &mut frame, 1, &mut budget);
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
                    assert_eq!(heap.byte_slice(array, 0, 8).unwrap(), &[if case == 1 { 6 } else { 3 }; 8]);
                    assert_eq!(heap.byte_slice(pending, 0, SHA256_STATE_BYTES).unwrap(), &[0; SHA256_STATE_BYTES]);
                    assert_eq!(budget, 0);
                }
                _ => {
                    let Ok(Some(Native::Threw(exception))) = result else { panic!("cleared key accepted"); };
                    assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(2));
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
        assert!(matches!(call(MethodId::init, signature, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Ok(Some(Native::Returned))));
        for valid in [true, false] {
            heap.byte_slice_mut(array, 0, 32).unwrap().fill(9);
            heap.byte_slice_mut(array, 64, 8).unwrap().fill(if valid { 9 } else { 8 });
            // Precomputed input must discard any accumulated update state.
            heap.array_put(pending, 0, 99).unwrap();
            frame.push_reference(signer).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(32).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(64).unwrap();
            frame.push_short(8).unwrap();
            assert!(matches!(call(MethodId::verifyPreComputedHash, signature, &mut heap,
                &mut host, &mut frame, 1, &mut 100), Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short(), Ok(i16::from(valid)));
            assert_eq!(heap.byte_slice(pending, 0, SHA256_STATE_BYTES).unwrap(), &[0; SHA256_STATE_BYTES]);
        }
    }
}
