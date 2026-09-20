//! Raw P-256 ECDH, Java Card ALG_EC_SVDP_DH_PLAIN.
use super::*;

pub(super) fn call(method: MethodId, heap: &mut Heap, host: &mut dyn crate::host::Host,
    frame: &mut Frame, context: heap::Context, budget: &mut u32) -> Result<Option<Native>> {
    if method == MethodId::init {
        let key = frame.pop_reference()?;
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        heap.check_access(key, context)?;
        if word_field(heap, this, KIND)? != 3
            || !matches!(word_field(heap, key, KIND)?, 12 | 30 | 31)
            || word_field(heap, key, SIZE)? != 256 {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (READY + 1 - MATERIAL) * 2)])?;
        heap.put_word(this, MATERIAL, key)?;
        heap.put_word(this, READY, 1)?;
        return Ok(Some(Native::Returned));
    }
    if method != MethodId::generateSecret { return Ok(None); }
    let output_offset = frame.pop_short()?;
    let output = frame.pop_reference()?;
    let length = frame.pop_short()?;
    let offset = frame.pop_short()?;
    let input = frame.pop_reference()?;
    let this = frame.pop_reference()?;
    for reference in [this, input, output] { heap.check_access(reference, context)?; }
    if word_field(heap, this, READY)? != 1 { return crypto_exception(heap, context, 4).map(Some); }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
    if offset < 0 || output_offset < 0 { return Err(Error::Bounds); }
    if length != 65 { return crypto_exception(heap, context, 1).map(Some); }
    heap.byte_slice(output, output_offset as usize, 32)?;
    let peer: &[u8; 65] = heap.byte_slice(input, offset as usize, 65)?.try_into().map_err(|_| Error::Bounds)?;
    let material = heap.get_word(key, MATERIAL)?;
    let scalar: &[u8; 32] = heap.byte_slice(material, 1, 32)?.try_into().map_err(|_| Error::Bounds)?;
    *budget = budget.checked_sub(65).ok_or(Error::Quota)?;
    let mut result = Zeroizing::new([0; 32]);
    match host.p256_agree(scalar, peer, &mut result) {
        Ok(()) => {}
        Err(Error::Bounds) => return crypto_exception(heap, context, 1).map(Some),
        Err(error) => return Err(error),
    }
    heap.byte_slice_mut(output, output_offset as usize, 32)?.copy_from_slice(&result[..]);
    frame.push_short(32)?;
    Ok(Some(Native::Returned))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Provider { fail: bool, calls: usize }
    impl crate::host::Host for Provider {
        fn p256_agree(&mut self, key: &[u8; 32], peer: &[u8; 65], output: &mut [u8; 32]) -> Result<()> {
            self.calls += 1;
            assert_eq!(key[31], 1);
            assert_eq!(peer, &[4; 65]);
            output.fill(0x42);
            if self.fail { Err(Error::Unauthorized) } else { Ok(()) }
        }
    }

    #[test]
    fn agreement_stages_overlapping_output_and_rechecks_quota_and_key_lifetime() {
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        let key = new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
        let material = heap.new_transient_array(heap::KIND_BYTE, 33, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.array_put(material, 0, 0x5f).unwrap();
        heap.array_put(material, 32, 1).unwrap();
        heap.put_word(key, KIND, 30).unwrap();
        heap.put_word(key, SIZE, 256).unwrap();
        heap.put_word(key, MATERIAL, material).unwrap();
        let agreement = new_native(&mut heap, ClassId::KeyAgreement, STATE_WORDS, 1).unwrap();
        heap.put_word(agreement, KIND, 3).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 65, 1).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false, calls: 0 };
        let before = heap.image().to_vec();
        heap.begin_transaction(8).unwrap();
        frame.push_reference(agreement).unwrap();
        frame.push_reference(key).unwrap();
        assert!(matches!(call(MethodId::init, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Err(Error::TransactionFull)));
        heap.commit_transaction().unwrap();
        assert_eq!(heap.image(), before, "failed init must not retain a partial key binding");
        heap.begin_transaction(10).unwrap();
        frame.push_reference(agreement).unwrap();
        frame.push_reference(key).unwrap();
        assert!(matches!(call(MethodId::init, &mut heap, &mut host, &mut frame, 1, &mut 100),
            Ok(Some(Native::Returned))));
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.commit_transaction().unwrap();
        for case in 0..4 {
            heap.byte_slice_mut(array, 0, 65).unwrap().fill(4);
            host.fail = case == 0;
            let mut budget = if case == 1 { 64 } else { 65 };
            if case == 3 { heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap(); }
            frame.push_reference(agreement).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(65).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(1).unwrap();
            let before = host.calls;
            let result = call(MethodId::generateSecret, &mut heap, &mut host, &mut frame, 1, &mut budget);
            match case {
                0 => {
                    assert!(matches!(result, Err(Error::Unauthorized)));
                    assert_eq!(host.calls, before + 1);
                }
                1 => {
                    assert!(matches!(result, Err(Error::Quota)));
                    assert_eq!(host.calls, before);
                }
                2 => {
                    assert!(matches!(result, Ok(Some(Native::Returned))));
                    assert_eq!(frame.pop_short(), Ok(32));
                    assert_eq!(heap.byte_slice(array, 1, 32).unwrap(), &[0x42; 32]);
                    assert_eq!(heap.array_get(array, 0), Ok(4));
                    assert_eq!(budget, 0);
                    continue;
                }
                _ => {
                    let Ok(Some(Native::Threw(exception))) = result else { panic!("cleared key accepted"); };
                    assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(2));
                    assert_eq!(host.calls, before);
                }
            }
            assert_eq!(heap.byte_slice(array, 0, 65).unwrap(), &[4; 65]);
        }
    }
}
