//! P-256 containers hold key references; generation publishes both values together.
use super::*;

// MATERIAL holds the public key; PENDING holds the private key.
#[allow(clippy::too_many_arguments)]
pub(super) fn call(method: MethodId, signature: Signature, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, context: heap::Context,
    budget: &mut u32) -> Result<Native> {
    if method == MethodId::Constructor {
        let (this, public, private) = if signature.key_pair_references() {
            let private = frame.pop_reference()?;
            let public = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            for key in [public, private] { heap.check_access(key, context)?; }
            if word_field(heap, public, KIND)? != 11
                || !matches!(word_field(heap, private, KIND)?, 12 | 30 | 31)
                || word_field(heap, public, SIZE)? != word_field(heap, private, SIZE)? {
                return crypto_exception(heap, context, 1);
            }
            if word_field(heap, public, SIZE)? != 256 || host.p256_parameter(0).is_none() {
                return crypto_exception(heap, context, 3);
            }
            (this, public, private)
        } else {
            let size = frame.pop_short()?;
            let algorithm = frame.pop_short()?;
            let this = frame.pop_reference()?;
            heap.check_access(this, context)?;
            if algorithm != 5 || size != 256 || host.p256_parameter(0).is_none() {
                return crypto_exception(heap, context, 3);
            }
            heap.check_allocations(&[(heap::KIND_OBJECT, STATE_WORDS); 2])?;
            let public = new_native(heap, ClassId::ECPublicKey, STATE_WORDS, context)?;
            let private = new_native(heap, ClassId::ECPrivateKey, STATE_WORDS, context)?;
            for (key, kind) in [(public, 11), (private, 12)] {
                heap.put_word(key, KIND, kind)?;
                heap.put_word(key, SIZE, 256)?;
            }
            (this, public, private)
        };
        heap.check_access(this, context)?;
        heap.put_word(this, KIND, 5)?;
        heap.put_word(this, SIZE, 256)?;
        heap.put_word(this, MATERIAL, public)?;
        heap.put_word(this, PENDING, private)?;
        return Ok(Native::Returned);
    }
    if !matches!(method, MethodId::getPublic | MethodId::getPrivate | MethodId::genKeyPair) {
        return Ok(Native::Unimplemented);
    }
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    let public = heap.get_word(this, MATERIAL)?;
    let private = heap.get_word(this, PENDING)?;
    if method != MethodId::genKeyPair {
        frame.push_reference(if method == MethodId::getPublic { public } else { private })?;
        return Ok(Native::Returned);
    }
    for key in [public, private] { heap.check_access(key, context)?; }
    *budget = budget.checked_sub(97).ok_or(Error::Quota)?;
    let mut allocations = [(heap::KIND_BYTE, 0); 2];
    let mut count = 0;
    for (key, bytes) in [(public, 66), (private, 33)] {
        if heap.get_word(key, MATERIAL)? == NULL {
            allocations[count] = (heap::KIND_BYTE, bytes);
            count += 1;
        }
    }
    heap.check_allocations(&allocations[..count])?;
    let public_material = ec::material(heap, public, context)?;
    let private_material = ec::material(heap, private, context)?;
    // Validate both destinations before the provider runs or any key value changes.
    heap.byte_slice(public_material, 0, 66)?;
    heap.byte_slice(private_material, 0, 33)?;
    let mut scalar = Zeroizing::new([0; 32]);
    let mut point = Zeroizing::new([0; 65]);
    host.p256_generate(&mut scalar, &mut point)?;
    heap.prepare_payload_writes(&[(public_material, 0, 66), (private_material, 0, 33)])?;
    heap.byte_slice_mut(public_material, 1, 65)?.copy_from_slice(&point[..]);
    heap.byte_slice_mut(private_material, 1, 32)?.copy_from_slice(&scalar[..]);
    // Every accepted parameter set is the same fixed curve, including default K=1.
    heap.byte_slice_mut(public_material, 0, 1)?[0] = 0x7f;
    heap.byte_slice_mut(private_material, 0, 1)?[0] = 0x7f;
    Ok(Native::Returned)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider { fail: bool }
    impl crate::host::Host for Provider {
        fn p256_parameter(&self, _: u8) -> Option<&'static [u8]> { Some(&[1]) }
        fn p256_generate(&mut self, private: &mut [u8; 32], public: &mut [u8; 65]) -> Result<()> {
            private.fill(if self.fail { 9 } else { 7 });
            public.fill(if self.fail { 10 } else { 8 });
            public[0] = 4;
            if self.fail { Err(Error::Unauthorized) } else { Ok(()) }
        }
    }

    #[test]
    fn constructors_preserve_references_and_failed_regeneration_preserves_both_keys() {
        let class = crate::jcvm_api::PACKAGES.iter().flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::KeyPair).unwrap();
        let signature = |references| class.methods.iter()
            .find(|method| method.id == MethodId::Constructor
                && method.signature.key_pair_references() == references).unwrap().signature;
        // Enough room for one component must not consume a partial pair.
        let mut tiny = [0; 38];
        let mut small = Heap::new(&mut tiny).unwrap();
        let container = new_native(&mut small, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        let mut small_words = [0; 16];
        let mut small_tags = [0; 8];
        let mut small_frame = Frame::new(&mut small_words, &mut small_tags, 0, 8).unwrap();
        small_frame.push_reference(container).unwrap();
        small_frame.push_short(5).unwrap();
        small_frame.push_short(256).unwrap();
        let before = small.image().to_vec();
        assert!(matches!(call(MethodId::Constructor, signature(false), &mut small,
            &mut Provider { fail: false }, &mut small_frame, 1, &mut 100), Err(Error::Quota)));
        assert_eq!(small.image(), before);
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        heap.begin_transaction(0).unwrap();
        let pair = new_native(&mut heap, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false };
        frame.push_reference(pair).unwrap();
        frame.push_short(5).unwrap();
        frame.push_short(256).unwrap();
        assert!(matches!(call(MethodId::Constructor, signature(false), &mut heap,
            &mut host, &mut frame, 1, &mut 100), Ok(Native::Returned)));
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.commit_transaction().unwrap();
        let public = heap.get_word(pair, MATERIAL).unwrap();
        let private = heap.get_word(pair, PENDING).unwrap();
        assert!(!key_initialized(&heap, public).unwrap());
        assert!(!key_initialized(&heap, private).unwrap());
        let alias = new_native(&mut heap, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        frame.push_reference(alias).unwrap();
        frame.push_reference(public).unwrap();
        frame.push_reference(private).unwrap();
        assert!(matches!(call(MethodId::Constructor, signature(true), &mut heap,
            &mut host, &mut frame, 1, &mut 100), Ok(Native::Returned)));
        assert_eq!(heap.get_word(alias, MATERIAL), Ok(public));
        assert_eq!(heap.get_word(alias, PENDING), Ok(private));
        for fail in [false, true] {
            host.fail = fail;
            frame.push_reference(alias).unwrap();
            let mut budget = 97;
            let result = call(MethodId::genKeyPair, signature(false), &mut heap,
                &mut host, &mut frame, 1, &mut budget);
            if fail { assert!(matches!(result, Err(Error::Unauthorized))); }
            else { assert!(matches!(result, Ok(Native::Returned))); }
            assert_eq!(budget, 0);
            for (key, length, expected) in [(private, 32, 7), (public, 65, 8)] {
                assert!(key_initialized(&heap, key).unwrap());
                let array = heap.get_word(key, MATERIAL).unwrap();
                let bytes = heap.byte_slice(array, 1, length).unwrap();
                if key == public { assert_eq!(bytes[0], 4); }
                assert!(bytes[usize::from(key == public)..].iter().all(|byte| *byte == expected));
            }
        }
        // A caller may catch TransactionFull and commit; neither component may change.
        host.fail = false;
        for key in [public, private] {
            let array = heap.get_word(key, MATERIAL).unwrap();
            heap.byte_slice_mut(array, 2, 1).unwrap()[0] = 3;
        }
        let before = heap.image().to_vec();
        heap.begin_transaction(80).unwrap();
        frame.push_reference(alias).unwrap();
        assert!(matches!(call(MethodId::genKeyPair, signature(false), &mut heap,
            &mut host, &mut frame, 1, &mut 97), Err(Error::TransactionFull)));
        assert_eq!(heap.transaction_remaining(), Some(80));
        heap.commit_transaction().unwrap();
        assert_eq!(heap.image(), before);
        heap.begin_transaction(111).unwrap();
        frame.push_reference(alias).unwrap();
        assert!(matches!(call(MethodId::genKeyPair, signature(false), &mut heap,
            &mut host, &mut frame, 1, &mut 97), Ok(Native::Returned)));
        assert_eq!(heap.transaction_remaining(), Some(0));
        assert_ne!(heap.image(), before);
        assert!(!heap.abort_transaction(&mut []).unwrap());
        assert_eq!(heap.image(), before);
    }
}
