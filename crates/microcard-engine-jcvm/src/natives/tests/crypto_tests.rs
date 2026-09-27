use super::*;

#[test]
fn aes_cipher_streams_overlapping_buffers_and_preserves_output_on_failure() {
    struct CipherHost { calls: usize, fail_at: usize }
    impl crate::host::Host for CipherHost {
        fn supports_cipher(&self, algorithm: u8) -> bool { algorithm == 14 }
        fn aes128_block(&mut self, key: &[u8; 16], block: &mut [u8; 16], encrypt: bool) -> Result<()> {
            assert_eq!(key, &[0x11; 16]);
            assert!(encrypt);
            self.calls += 1;
            for byte in block.iter_mut() { *byte ^= 0xaa; }
            if self.calls == self.fail_at { return Err(Error::Unauthorized); }
            Ok(())
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut host = CipherHost { calls: 0, fail_at: usize::MAX };
    let key = new_native(&mut heap, ClassId::AESKey, security::STATE_WORDS, 1).unwrap();
    heap.put_word(key, 0, 13).unwrap(); // transient reset key
    heap.put_word(key, 1, 128).unwrap();
    let data = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
    heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
    invoke_security(ClassId::AESKey, MethodId::setKey, &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::Cipher, MethodId::getInstance, &[(false,14),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
    let cipher = frame.pop_reference().unwrap();
    invoke_security(ClassId::Cipher, MethodId::init, &[(true,cipher),(true,key),(false,2)], &mut heap, &mut frame, &mut host).unwrap();
    for (at, byte) in heap.byte_slice_mut(data, 0, 64).unwrap().iter_mut().enumerate() { *byte = at as u8; }
    invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,5),(true,data),(false,8)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 0);
    invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,5),(false,27),(true,data),(false,8)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 32);
    for (at, byte) in heap.byte_slice(data, 8, 32).unwrap().iter().enumerate() { assert_eq!(*byte, at as u8 ^ 0xaa); }
    assert_eq!(host.calls, 2);
    let before = heap.byte_slice(data, 0, 64).unwrap().to_vec();
    for (reference, value) in [(true,cipher),(true,data),(false,0),(false,32),(true,data),(false,0)] {
        if reference { frame.push_reference(value).unwrap(); } else { frame.push_short(value as i16).unwrap(); }
    }
    let mut budget = 31;
    assert!(matches!(test_call_with_budget(
        framework(ClassId::Cipher, MethodId::doFinal, false),
        NativeContext { heap: &mut heap, host: &mut host, frame: &mut frame,
            context: 1, jcre: &mut idle(), budget: &mut budget, statics: &mut [] },
    ), Err(Error::Quota)));
    assert_eq!(host.calls, 2);
    assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), before);
    host.fail_at = 4;
    assert!(invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,32),(true,data),(false,0)], &mut heap, &mut frame, &mut host).is_err());
    assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), before);
    assert_eq!(heap.byte_slice(heap.get_word(cipher, 5).unwrap(), 0, 16).unwrap(), &[0; 16]);
    heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
    let result = invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
    let Native::Threw(exception) = result else { panic!("cleared key accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 2);
    assert_eq!(host.calls, 4);
}

#[test]
fn cbc_tracks_ciphertext_iv_and_resets_after_final_or_reset() {
    struct CbcHost { calls: alloc::vec::Vec<([u8; 16], usize, bool)>, fail: bool }
    impl crate::host::Host for CbcHost {
        fn supports_cipher(&self, algorithm: u8) -> bool { algorithm == 13 }
        fn aes128_cbc(&mut self, key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8], encrypt: bool) -> Result<()> {
            assert_eq!(key, &[0x11; 16]);
            self.calls.push((*iv, buffer.len(), encrypt));
            buffer.fill(0x30 + self.calls.len() as u8);
            if self.fail { return Err(Error::Unauthorized); }
            Ok(())
        }
    }
    for mode in [1, 2] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = CbcHost { calls: vec![], fail: false };
        let key = new_native(&mut heap, ClassId::AESKey, security::STATE_WORDS, 1).unwrap();
        heap.put_word(key, 0, 15).unwrap();
        heap.put_word(key, 1, 128).unwrap();
        let data = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
        invoke_security(ClassId::AESKey, MethodId::setKey, &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x19);
        invoke_security(ClassId::Cipher, MethodId::getInstance, &[(false,13),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        let cipher = frame.pop_reference().unwrap();
        heap.begin_transaction(12).unwrap();
        invoke_security(ClassId::Cipher, MethodId::init, &[(true,cipher),(true,key),(false,mode),(true,data),(false,0),(false,16)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.commit_transaction().unwrap();
        heap.byte_slice_mut(data, 0, 64).unwrap().fill(7);
        for (offset, length, written) in [(0,5,0),(5,27,32)] {
            invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,offset),(false,length),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), written);
        }
        assert_eq!(host.calls, [([0x19;16],32,mode == 2)]);
        if mode == 1 {
            let before = heap.image().to_vec();
            heap.begin_transaction(8).unwrap();
            assert!(matches!(invoke_security(ClassId::Cipher, MethodId::init,
                &[(true,cipher),(true,key),(false,2),(true,data),(false,0),(false,16)],
                &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
            heap.commit_transaction().unwrap();
            assert_eq!(heap.image(), before, "failed init must preserve CBC state and mode");
        }
        invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,32),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 16);
        assert_eq!(host.calls[1], ([if mode == 2 { 0x31 } else { 7 };16],16,mode == 2));
        let pending = heap.get_word(cipher, 5).unwrap();
        assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), &[0;32]);
        let result = invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,0),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        let Native::Threw(exception) = result else { panic!("empty operation accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 5);
        invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 16);
        assert_eq!(host.calls[2].0, [0;16]);
        invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,0),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0);
        assert_eq!(host.calls.len(), 3);
        invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 16);
        let state = heap.byte_slice(pending, 0, 32).unwrap().to_vec();
        let output = heap.byte_slice(data, 0, 64).unwrap().to_vec();
        host.fail = true;
        assert!(invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).is_err());
        assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), state);
        assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), output);
        heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
        assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), &[0;32]);
    }
}

#[test]
fn ctr_buffers_partial_updates_and_keeps_failed_output_private() {
    struct CtrHost { counters: alloc::vec::Vec<[u8; 16]>, fail: bool }
    impl crate::host::Host for CtrHost {
        fn supports_cipher(&self, algorithm: u8) -> bool { algorithm == 240 }
        fn aes128_ctr(&mut self, key: &[u8; 16], counter: &[u8; 16], buffer: &mut [u8]) -> Result<()> {
            assert_eq!(key, &[0x11; 16]);
            self.counters.push(*counter);
            for byte in buffer.iter_mut() { *byte ^= 0xaa; }
            if self.fail { Err(Error::Unauthorized) } else { Ok(()) }
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut host = CtrHost { counters: vec![], fail: false };
    let key = new_native(&mut heap, ClassId::AESKey, security::STATE_WORDS, 1).unwrap();
    heap.put_word(key, 0, 15).unwrap();
    heap.put_word(key, 1, 128).unwrap();
    let data = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
    heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
    invoke_security(ClassId::AESKey, MethodId::setKey,
        &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
    heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x19);
    invoke_security(ClassId::Cipher, MethodId::getInstance,
        &[(false,0xfff0),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
    let cipher = frame.pop_reference().unwrap();
    invoke_security(ClassId::Cipher, MethodId::init,
        &[(true,cipher),(true,key),(false,2),(true,data),(false,0),(false,16)],
        &mut heap, &mut frame, &mut host).unwrap();
    for (at, byte) in heap.byte_slice_mut(data, 0, 64).unwrap().iter_mut().enumerate() { *byte = at as u8; }
    for (offset, length, written) in [(0,5,0),(5,27,32)] {
        invoke_security(ClassId::Cipher, MethodId::update,
            &[(true,cipher),(true,data),(false,offset),(false,length),(true,data),(false,8)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), written);
    }
    assert_eq!(host.counters, [[0x19; 16]]);
    assert_eq!(heap.byte_slice(data, 8, 32).unwrap(),
        &(0u8..32).map(|byte| byte ^ 0xaa).collect::<alloc::vec::Vec<_>>());
    invoke_security(ClassId::Cipher, MethodId::doFinal,
        &[(true,cipher),(true,data),(false,40),(false,7),(true,data),(false,0)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 7);
    let next = (u128::from_be_bytes([0x19; 16]) + 2).to_be_bytes();
    assert_eq!(host.counters, [[0x19; 16], next]);
    assert_eq!(heap.byte_slice(heap.get_word(cipher, 5).unwrap(), 0, 32).unwrap(), &[0; 32]);

    let before = heap.byte_slice(data, 0, 64).unwrap().to_vec();
    let pending = heap.byte_slice(heap.get_word(cipher, 5).unwrap(), 0, 32).unwrap().to_vec();
    host.fail = true;
    assert!(invoke_security(ClassId::Cipher, MethodId::doFinal,
        &[(true,cipher),(true,data),(false,0),(false,7),(true,data),(false,8)],
        &mut heap, &mut frame, &mut host).is_err());
    assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), before);
    assert_eq!(heap.byte_slice(heap.get_word(cipher, 5).unwrap(), 0, 32).unwrap(), pending);
}

#[test]
fn des_cipher_uses_eight_byte_blocks_and_des_key_sizes() {
    struct DesHost { ivs: alloc::vec::Vec<Option<[u8; 8]>> }
    impl crate::host::Host for DesHost {
        fn supports_cipher(&self, id: u8) -> bool { matches!(id, 1 | 5) }
        fn des_crypt(&mut self, key: &[u8], iv: Option<&[u8; 8]>, buffer: &mut [u8], _: bool) -> Result<()> {
            assert_eq!(key, &[0x11; 16]);
            self.ivs.push(iv.copied());
            for byte in buffer { *byte ^= 0xaa; }
            Ok(())
        }
    }
    for (algorithm, chained) in [(1, true), (5, false)] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = DesHost { ivs: vec![] };
        let key = new_native(&mut heap, ClassId::DESKey, security::STATE_WORDS, 1).unwrap();
        heap.put_word(key, 0, 3).unwrap();
        heap.put_word(key, 1, 128).unwrap();
        let data = heap.new_array(heap::KIND_BYTE, 48, 1).unwrap();
        heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
        invoke_security(ClassId::DESKey, MethodId::setKey,
            &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        invoke_security(ClassId::Cipher, MethodId::getInstance,
            &[(false,algorithm),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        let cipher = frame.pop_reference().unwrap();
        let init = if chained {
            heap.byte_slice_mut(data, 0, 8).unwrap().fill(0x19);
            vec![(true,cipher),(true,key),(false,2),(true,data),(false,0),(false,8)]
        } else {
            vec![(true,cipher),(true,key),(false,2)]
        };
        invoke_security(ClassId::Cipher, MethodId::init,
            &init, &mut heap, &mut frame, &mut host).unwrap();
        for (at, byte) in heap.byte_slice_mut(data, 0, 48).unwrap().iter_mut().enumerate() { *byte = at as u8; }
        for (offset, length, written) in [(0,3,0),(3,13,16)] {
            invoke_security(ClassId::Cipher, MethodId::update,
                &[(true,cipher),(true,data),(false,offset),(false,length),(true,data),(false,24)],
                &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), written);
        }
        assert_eq!(heap.byte_slice(data, 24, 16).unwrap(),
            &(0u8..16).map(|byte| byte ^ 0xaa).collect::<alloc::vec::Vec<_>>());
        assert_eq!(host.ivs, [if chained { Some([0x19;8]) } else { None }]);
        invoke_security(ClassId::Cipher, MethodId::doFinal,
            &[(true,cipher),(true,data),(false,0),(false,0),(true,data),(false,0)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0);
    }
}

#[test]
fn digest_borrows_overlapping_input_and_publishes_only_complete_results() {
    struct DigestHost { input: usize, calls: usize, result: Result<usize> }
    impl crate::host::Host for DigestHost {
        fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
            self.calls += 1;
            assert_eq!(algorithm, 4);
            assert_eq!(message.as_ptr() as usize, self.input);
            assert_eq!(message, &[0x42; 32]);
            assert_eq!(output.len(), 32);
            output.fill(0x99);
            self.result
        }
    }
    for (offset, result, allowance, succeeds, calls) in [
        (0, Ok(32), 32, true, 1),
        (0, Ok(32), 31, false, 0),
        (1, Ok(32), 32, false, 0),
        (0, Ok(65), 32, false, 1),
        (0, Ok(0), 32, false, 1),
        (0, Err(Error::Unsupported), 32, false, 1),
    ] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let digest = new_native(&mut heap, ClassId::MessageDigest, security::STATE_WORDS, 1).unwrap();
        heap.put_word(digest, 0, 4).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 32, 1).unwrap();
        heap.byte_slice_mut(array, 0, 32).unwrap().fill(0x42);
        let mut host = DigestHost { input: heap.byte_slice(array, 0, 32).unwrap().as_ptr() as usize, calls: 0, result };
        frame.push_reference(digest).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(32).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(offset).unwrap();
        let mut budget = allowance;
        let actual = security::call(ClassId::MessageDigest, MethodId::doFinal,
            framework(ClassId::MessageDigest, MethodId::doFinal, false).method.signature,
            &mut heap, &mut host, &mut frame, 1, &mut idle(), &mut budget, &[]);
        if allowance == 31 { assert!(matches!(actual, Err(Error::Quota))); }
        assert_eq!(budget, if calls == 0 { allowance } else { 0 });
        assert_eq!(actual.is_ok(), succeeds);
        assert_eq!(host.calls, calls);
        assert_eq!(heap.byte_slice(array, 0, 32).unwrap(), &[if succeeds { 0x99 } else { 0x42 }; 32]);
        if succeeds { assert_eq!(frame.pop_short().unwrap(), 32); }
    }
}

#[test]
fn sha256_digest_streams_only_after_update_and_reset_discards_pending_input() {
    use sha2::{Digest, Sha256};

    struct DigestHost { one_shots: usize, streams: usize, fail: bool }
    impl crate::host::Host for DigestHost {
        fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 4 }
        fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
            assert_eq!(algorithm, 4);
            self.one_shots += 1;
            output[..32].copy_from_slice(&Sha256::digest(message));
            Ok(32)
        }
        fn sha256_stream(&mut self, state: &mut [u8; crate::host::SHA256_STATE_BYTES],
                input: &[u8], output: Option<&mut [u8; 32]>) -> Result<()> {
            self.streams += 1;
            let prior = state[0] as usize;
            state[1 + prior..1 + prior + input.len()].copy_from_slice(input);
            state[0] = (prior + input.len()) as u8;
            if self.fail { return Err(Error::Unauthorized); }
            if let Some(output) = output {
                output.copy_from_slice(&Sha256::digest(&state[1..1 + state[0] as usize]));
                state.fill(0);
            }
            Ok(())
        }
    }

    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let input = heap.new_array(heap::KIND_BYTE, 6, 1).unwrap();
    heap.byte_slice_mut(input, 0, 6).unwrap().copy_from_slice(b"abcdef");
    let output = heap.new_array(heap::KIND_BYTE, 32, 1).unwrap();
    let mut host = DigestHost { one_shots: 0, streams: 0, fail: false };
    invoke_security(ClassId::MessageDigest, MethodId::getInstance,
        &[(false, 4), (false, 0)], &mut heap, &mut frame, &mut host).unwrap();
    let digest = frame.pop_reference().unwrap();
    let final_part = |offset, length, heap: &mut Heap, frame: &mut Frame,
                          host: &mut DigestHost| {
        invoke_security(ClassId::MessageDigest, MethodId::doFinal,
            &[(true, digest), (true, input), (false, offset), (false, length),
              (true, output), (false, 0)], heap, frame, host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 32);
    };
    invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 0), (false, 0)],
        &mut heap, &mut frame, &mut host).unwrap();
    final_part(0, 3, &mut heap, &mut frame, &mut host);
    assert_eq!(heap.byte_slice(output, 0, 32).unwrap(), Sha256::digest(b"abc").as_slice());
    assert_eq!((host.one_shots, host.streams), (1, 0));

    for offset in [0, 2] {
        invoke_security(ClassId::MessageDigest, MethodId::update,
            &[(true, digest), (true, input), (false, offset), (false, 2)],
            &mut heap, &mut frame, &mut host).unwrap();
    }
    final_part(4, 2, &mut heap, &mut frame, &mut host);
    assert_eq!(heap.byte_slice(output, 0, 32).unwrap(), Sha256::digest(b"abcdef").as_slice());
    assert_eq!((host.one_shots, host.streams), (1, 3));

    invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 0), (false, 2)],
        &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::MessageDigest, MethodId::reset,
        &[(true, digest)], &mut heap, &mut frame, &mut host).unwrap();
    final_part(4, 2, &mut heap, &mut frame, &mut host);
    assert_eq!(heap.byte_slice(output, 0, 32).unwrap(), Sha256::digest(b"ef").as_slice());

    invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 0), (false, 2)],
        &mut heap, &mut frame, &mut host).unwrap();
    let before_failure = heap.byte_slice(output, 0, 32).unwrap().to_vec();
    host.fail = true;
    assert!(invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 2), (false, 2)],
        &mut heap, &mut frame, &mut host).is_err());
    assert!(invoke_security(ClassId::MessageDigest, MethodId::doFinal,
        &[(true, digest), (true, input), (false, 4), (false, 2),
          (true, output), (false, 0)],
        &mut heap, &mut frame, &mut host).is_err());
    assert_eq!(heap.byte_slice(output, 0, 32).unwrap(), before_failure);
    host.fail = false;
    final_part(4, 2, &mut heap, &mut frame, &mut host);
    assert_eq!(heap.byte_slice(output, 0, 32).unwrap(), Sha256::digest(b"abef").as_slice());
}

#[test]
fn sha224_digest_factory_streams_and_preserves_output_on_failure() {
    use sha2::{Digest, Sha224};
    struct DigestHost { fail: bool }
    impl crate::host::Host for DigestHost {
        fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 7 }
        fn digest(&mut self, algorithm: u8, input: &[u8], output: &mut [u8]) -> Result<usize> {
            assert_eq!(algorithm, 7);
            output[..28].copy_from_slice(&Sha224::digest(input));
            Ok(28)
        }
        fn sha224_stream(&mut self, state: &mut [u8; crate::host::SHA256_STATE_BYTES],
            input: &[u8], output: Option<&mut [u8; 28]>) -> Result<()> {
            if self.fail { return Err(Error::Unauthorized); }
            let used = state[0] as usize;
            state[1 + used..1 + used + input.len()].copy_from_slice(input);
            state[0] = (used + input.len()) as u8;
            if let Some(output) = output {
                output.copy_from_slice(&Sha224::digest(&state[1..1 + state[0] as usize]));
                state.fill(0);
            }
            Ok(())
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let input = heap.new_array(heap::KIND_BYTE, 3, 1).unwrap();
    heap.byte_slice_mut(input, 0, 3).unwrap().copy_from_slice(b"abc");
    let output = heap.new_array(heap::KIND_BYTE, 28, 1).unwrap();
    let mut host = DigestHost { fail: false };
    invoke_security(ClassId::MessageDigest, MethodId::getInstance,
        &[(false, 7), (false, 0)], &mut heap, &mut frame, &mut host).unwrap();
    let digest = frame.pop_reference().unwrap();
    invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 0), (false, 1)],
        &mut heap, &mut frame, &mut host).unwrap();
    host.fail = true;
    assert!(invoke_security(ClassId::MessageDigest, MethodId::doFinal,
        &[(true, digest), (true, input), (false, 1), (false, 2),
          (true, output), (false, 0)], &mut heap, &mut frame, &mut host).is_err());
    assert_eq!(heap.byte_slice(output, 0, 28).unwrap(), &[0; 28]);
    host.fail = false;
    invoke_security(ClassId::MessageDigest, MethodId::doFinal,
        &[(true, digest), (true, input), (false, 1), (false, 2),
          (true, output), (false, 0)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 28);
    assert_eq!(heap.byte_slice(output, 0, 28).unwrap(), Sha224::digest(b"abc").as_slice());
    invoke_security(ClassId::MessageDigest, MethodId::update,
        &[(true, digest), (true, input), (false, 0), (false, 1)],
        &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::MessageDigest, MethodId::reset,
        &[(true, digest)], &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::MessageDigest, MethodId::doFinal,
        &[(true, digest), (true, input), (false, 1), (false, 2),
          (true, output), (false, 0)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 28);
    assert_eq!(heap.byte_slice(output, 0, 28).unwrap(), Sha224::digest(b"bc").as_slice());
}

#[test]
fn one_shot_digest_open_use_close_and_release_follow_temporary_contract() {
    use sha2::{Digest, Sha224, Sha256};
    struct DigestHost;
    impl crate::host::Host for DigestHost {
        fn supports_digest(&self, algorithm: u8) -> bool { matches!(algorithm, 1 | 4 | 7) }
        fn digest(&mut self, algorithm: u8, input: &[u8], output: &mut [u8]) -> Result<usize> {
            assert_eq!(input, b"abc");
            let bytes: alloc::vec::Vec<u8> = match algorithm {
                1 => vec![0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                    0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d],
                4 => Sha256::digest(input).to_vec(),
                7 => Sha224::digest(input).to_vec(),
                _ => unreachable!(),
            };
            output.copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let buffer = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
    let mut host = DigestHost;
    let mut call = |method, args: &[(bool, u16)], heap: &mut Heap, frame: &mut Frame| {
        let mut budget = u32::MAX;
        for &(reference, value) in args {
            if reference { frame.push_reference(value).unwrap(); }
            else { frame.push_short(value as i16).unwrap(); }
        }
        security::call(ClassId::MessageDigest_OneShot, method,
            framework(ClassId::MessageDigest_OneShot, method, method == MethodId::open).method.signature,
            heap, &mut host, frame, 1, &mut idle(), &mut budget, &[]).unwrap()
    };
    for (algorithm, expected) in [(1, 20), (7, 28), (4, 32)] {
        assert!(matches!(call(MethodId::open, &[(false, algorithm)], &mut heap, &mut frame), Native::Returned));
        let digest = frame.pop_reference().unwrap();
        assert_eq!(heap.info(digest).unwrap().owner, 0);
        assert!(is_temporary_native(heap.info(digest).unwrap().class, security::STATE_WORDS));
        let Native::Threw(exception) = call(MethodId::open, &[(false, 4)], &mut heap, &mut frame) else { panic!("second open must exhaust the single slot"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
        heap.byte_slice_mut(buffer, 0, 3).unwrap().copy_from_slice(b"abc");
        assert!(matches!(call(MethodId::update, &[(true, digest), (true, buffer), (false, 0), (false, 0)], &mut heap, &mut frame), Native::Threw(_)));
        assert!(matches!(call(MethodId::doFinal, &[(true, digest), (true, buffer), (false, 0), (false, 3), (true, buffer), (false, 0)], &mut heap, &mut frame), Native::Returned));
        assert_eq!(frame.pop_short().unwrap(), expected);
        let answer = match algorithm {
            1 => vec![0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d],
            4 => Sha256::digest(b"abc").to_vec(),
            7 => Sha224::digest(b"abc").to_vec(),
            _ => unreachable!(),
        };
        assert_eq!(heap.byte_slice(buffer, 0, expected as usize).unwrap(), &answer);
        assert!(matches!(call(MethodId::close, &[(true, digest)], &mut heap, &mut frame), Native::Returned));
        assert!(matches!(call(MethodId::close, &[(true, digest)], &mut heap, &mut frame), Native::Returned));
        for method in [MethodId::getAlgorithm, MethodId::getLength, MethodId::reset] {
            let Native::Threw(exception) = call(method, &[(true, digest)], &mut heap, &mut frame) else { panic!("closed digest method {method:?} succeeded"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
        }
    }
    let Native::Threw(exception) = call(MethodId::open, &[(false, 99)], &mut heap, &mut frame) else { panic!("unsupported algorithm succeeded"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(3));
    assert!(matches!(call(MethodId::open, &[(false, 4)], &mut heap, &mut frame), Native::Returned));
    let abandoned = frame.pop_reference().unwrap();
    security::release_one_shot_digests(&mut heap).unwrap();
    let Native::Threw(exception) = call(MethodId::doFinal, &[(true, abandoned), (true, buffer), (false, 0), (false, 3), (true, buffer), (false, 0)], &mut heap, &mut frame) else { panic!("released digest remained usable"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
    let used = heap.used();
    assert!(matches!(call(MethodId::open, &[(false, 1)], &mut heap, &mut frame), Native::Returned));
    let reopened = frame.pop_reference().unwrap();
    assert_eq!(reopened, abandoned);
    assert_eq!(heap.used(), used, "a released slot should be reused across callbacks");
    let mut budget = u32::MAX;
    frame.push_reference(reopened).unwrap();
    assert!(matches!(security::call(ClassId::MessageDigest_OneShot, MethodId::getLength,
        framework(ClassId::MessageDigest_OneShot, MethodId::getLength, false).method.signature,
        &mut heap, &mut host, &mut frame, 2, &mut idle(), &mut budget, &[]), Err(Error::Firewall)));
}

#[test]
fn exhausted_crypto_factory_throws_without_consuming_heap() {
    struct DigestHost;
    impl crate::host::Host for DigestHost {
        fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 7 }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    while heap.available() >= 18 {
        heap.new_array(heap::KIND_BYTE, 1, 1).unwrap();
    }
    let before = heap.used();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    for _ in 0..2 {
        let Native::Threw(exception) = invoke_security(ClassId::MessageDigest,
            MethodId::getInstance, &[(false, 7), (false, 0)],
            &mut heap, &mut frame, &mut DigestHost).unwrap() else {
            panic!("exhausted factory returned without a Java Card exception");
        };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
        assert_eq!(heap.used(), before);
    }
}

#[test]
fn crypto_factories_follow_host_capabilities_and_reject_unsupported_requests() {
    struct Capabilities;
    impl crate::host::Host for Capabilities {
        fn supports_cipher(&self, algorithm: u8) -> bool { matches!(algorithm, 13 | 14) }
        fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 4 }
        fn supports_random(&self, algorithm: u8) -> bool { algorithm == 2 }
        fn supports_agreement(&self, algorithm: u8) -> bool { algorithm == 3 }
        fn supports_signature(&self, algorithm: u8) -> bool { matches!(algorithm, 18 | 33) }
    }
    for (class, algorithm, external, supported) in [
        (ClassId::Checksum, 1, false, true),
        (ClassId::Checksum, 2, false, true),
        (ClassId::Checksum, 3, false, false),
        (ClassId::Checksum, 1, true, false),
        (ClassId::MessageDigest, 4, false, true),
        (ClassId::MessageDigest, 5, false, false),
        (ClassId::MessageDigest, 4, true, false),
        (ClassId::RandomData, 2, false, true),
        (ClassId::RandomData, 99, false, false),
        (ClassId::Signature, 1, false, false),
        (ClassId::Signature, 18, false, true),
        (ClassId::Signature, 33, false, true),
        (ClassId::Signature, 33, true, false),
        (ClassId::Signature, 34, false, false),
        (ClassId::KeyAgreement, 1, false, false),
        (ClassId::KeyAgreement, 3, false, true),
        (ClassId::KeyAgreement, 3, true, false),
        (ClassId::KeyAgreement, 4, false, false),
        (ClassId::Cipher, 1, false, false),
        (ClassId::Cipher, 13, false, true),
        (ClassId::Cipher, 14, false, true),
    ] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_short(algorithm).unwrap();
        if class != ClassId::RandomData { frame.push_short(i16::from(external)).unwrap(); }
        let result = security::call(class, MethodId::getInstance, framework(class, MethodId::getInstance, true).method.signature, &mut heap, &mut Capabilities, &mut frame, 1, &mut idle(), &mut { u32::MAX }, &[]).unwrap();
        if supported {
            assert!(matches!(result, Native::Returned));
            let instance = frame.pop_reference().unwrap();
            assert_eq!(api_class(heap.info(instance).unwrap().class).unwrap().id, class);
        } else {
            let Native::Threw(exception) = result else { panic!("unsupported {class:?} returned an algorithm holder"); };
            assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::CryptoException);
            assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 3);
        }
    }
    for algorithm in [13, 14] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        while heap.available() >= 40 { heap.new_array(heap::KIND_BYTE, 1, 1).unwrap(); }
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_short(algorithm).unwrap();
        frame.push_short(0).unwrap();
        let before = heap.used();
        let result = security::call(ClassId::Cipher, MethodId::getInstance,
            framework(ClassId::Cipher, MethodId::getInstance, true).method.signature,
            &mut heap, &mut Capabilities, &mut frame, 1, &mut idle(), &mut 100, &[]);
        let Ok(Native::Threw(exception)) = result else { panic!("exhausted cipher factory did not throw"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
        assert_eq!(heap.used(), before, "failed cipher creation must not leave an incomplete holder");
    }

    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    for argument in [0, 6, 1, 0] { frame.push_short(argument).unwrap(); }
    let combined = framework_token(ClassId::Signature, MethodId::getInstance, true, Some(2));
    assert!(matches!(security::call(ClassId::Signature, MethodId::getInstance,
        combined.method.signature, &mut heap, &mut Capabilities, &mut frame, 1,
        &mut idle(), &mut 100, &[]), Ok(Native::Returned)));
    let mac = frame.pop_reference().unwrap();
    assert_eq!(heap.get_word(mac, security::KIND), Ok(18));

    for (class, method, token, arguments) in [
        (ClassId::MessageDigest, MethodId::getInitializedMessageDigestInstance, None, 2),
        (ClassId::InitializedMessageDigest_OneShot, MethodId::open, None, 1),
        (ClassId::RandomData_OneShot, MethodId::open, None, 1),
        (ClassId::Signature_OneShot, MethodId::open, None, 3),
        (ClassId::Cipher_OneShot, MethodId::open, None, 2),
        (ClassId::Signature, MethodId::getInstance, Some(2), 4),
        (ClassId::Cipher, MethodId::getInstance, Some(2), 3),
    ] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        for value in 0..arguments { frame.push_short(value).unwrap(); }
        let target = framework_token(class, method, true, token);
        let Native::Threw(exception) = security::call(class, method,
            target.method.signature, &mut heap, &mut Capabilities, &mut frame, 1,
            &mut idle(), &mut 100, &[]).unwrap()
            else { panic!("optional factory {class:?}.{method:?} did not throw"); };
        assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id,
            ClassId::CryptoException);
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(3));
    }
}
