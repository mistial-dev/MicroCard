use super::*;

#[test]
fn random_data_methods_obey_return_contracts_and_reject_empty_requests() {
    struct Entropy { random_calls: usize, digest_calls: usize, fail_random: bool, fail_digest: bool }
    impl crate::host::Host for Entropy {
        fn supports_random(&self, algorithm: u8) -> bool { matches!(algorithm, 1 | 2) }
        fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 4 }
        fn random(&mut self, output: &mut [u8]) -> Result<()> {
            self.random_calls += 1;
            output.fill(0x42);
            if self.fail_random { return Err(Error::Storage); }
            Ok(())
        }
        fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
            assert_eq!(algorithm, 4);
            self.digest_calls += 1;
            if self.fail_digest { return Err(Error::Storage); }
            let mut value = 0xcbf2_9ce4_8422_2325u64 ^ u64::from(algorithm);
            for byte in message {
                value ^= u64::from(*byte);
                value = value.wrapping_mul(0x0000_0100_0000_01b3);
            }
            for byte in output.iter_mut() {
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                *byte = value as u8;
            }
            Ok(output.len())
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
    let mut host = Entropy { random_calls: 0, digest_calls: 0, fail_random: false, fail_digest: false };
    invoke_security(ClassId::RandomData, MethodId::getInstance, &[(false, 2)],
        &mut heap, &mut frame, &mut host).unwrap();
    let secure = frame.pop_reference().unwrap();
    invoke_security(ClassId::RandomData, MethodId::getInstance, &[(false, 1)],
        &mut heap, &mut frame, &mut host).unwrap();
    let pseudo = frame.pop_reference().unwrap();
    let output = heap.new_array(heap::KIND_BYTE, 6, 1).unwrap();
    for method in [MethodId::generateData, MethodId::nextBytes] {
        for allowance in [3, 4] {
            let before = heap.image().to_vec();
            let calls = host.random_calls;
            frame.push_reference(secure).unwrap();
            frame.push_reference(output).unwrap();
            frame.push_short(1).unwrap();
            frame.push_short(4).unwrap();
            let mut budget = allowance;
            let result = test_call_with_budget(
                framework(ClassId::RandomData, method, false),
                NativeContext { heap: &mut heap, host: &mut host, frame: &mut frame,
                    context: 1, jcre: &mut idle(), budget: &mut budget, statics: &mut [] },
            );
            if allowance == 3 {
                assert!(matches!(result, Err(Error::Quota)));
                assert_eq!(budget, 3);
                assert_eq!(host.random_calls, calls);
                assert!(heap.image() == before);
            } else { result.unwrap(); assert_eq!(budget, 0); }
        }
        if method == MethodId::nextBytes { assert_eq!(frame.pop_short(), Ok(5)); }
        assert_eq!(frame.depth(), 0);
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0, 0x42, 0x42, 0x42, 0x42, 0]);
        let calls = host.random_calls;
        let Native::Threw(exception) = invoke_security(ClassId::RandomData, method,
            &[(true, secure), (true, output), (false, 1), (false, 0)],
            &mut heap, &mut frame, &mut host).unwrap()
            else { panic!("empty random request accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        assert_eq!(host.random_calls, calls);
        assert_eq!(frame.depth(), 0);
    }
    assert_eq!(host.random_calls, 3, "pseudo construction seeds once; secure output always uses entropy");

    let seed = heap.new_array(heap::KIND_BYTE, 6, 1).unwrap();
    heap.byte_slice_mut(seed, 0, 6).unwrap().copy_from_slice(b"seed!!");
    let digest_calls = host.digest_calls;
    invoke_security(ClassId::RandomData, MethodId::setSeed,
        &[(true, pseudo), (true, seed), (false, 0), (false, 4)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(host.digest_calls, digest_calls + 2);
    let random_calls = host.random_calls;
    let mut pseudo_outputs = [[0u8; 6]; 2];
    for captured in &mut pseudo_outputs {
        invoke_security(ClassId::RandomData, MethodId::nextBytes,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(6));
        captured.copy_from_slice(heap.byte_slice(output, 0, 6).unwrap());
    }
    assert_ne!(pseudo_outputs[0], pseudo_outputs[1], "the PRNG chain must advance");
    assert_eq!(host.random_calls, random_calls, "pseudo output must not request entropy");

    invoke_security(ClassId::RandomData, MethodId::setSeed,
        &[(true, pseudo), (true, seed), (false, 0), (false, 4)],
        &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::RandomData, MethodId::nextBytes,
        &[(true, pseudo), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short(), Ok(6));
    assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), pseudo_outputs[0],
        "re-seeding with the same fixture must replay the deterministic stream");

    host.fail_digest = true;
    heap.byte_slice_mut(output, 0, 6).unwrap().fill(0x55);
    assert!(matches!(invoke_security(ClassId::RandomData, MethodId::nextBytes,
        &[(true, pseudo), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host), Err(Error::Storage)));
    assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
    host.fail_digest = false;

    heap.begin_transaction(64).unwrap();
    invoke_security(ClassId::RandomData, MethodId::nextBytes,
        &[(true, pseudo), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short(), Ok(6));
    let generated_in_transaction: [u8; 6] = heap.byte_slice(output, 0, 6).unwrap().try_into().unwrap();
    assert!(!heap.abort_transaction(&mut []).unwrap());
    assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
    invoke_security(ClassId::RandomData, MethodId::nextBytes,
        &[(true, pseudo), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short(), Ok(6));
    assert_ne!(heap.byte_slice(output, 0, 6).unwrap(), generated_in_transaction,
        "transaction abort must not roll the PRNG stream backward");

    let random_calls = host.random_calls;
    let digest_calls = host.digest_calls;
    invoke_security(ClassId::RandomData, MethodId::setSeed,
        &[(true, secure), (true, seed), (false, 0), (false, 4)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(host.random_calls, random_calls + 1, "secure seeding must add provider entropy");
    assert_eq!(host.digest_calls, digest_calls + 2);
    invoke_security(ClassId::RandomData, MethodId::generateData,
        &[(true, secure), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(host.random_calls, random_calls + 2, "secure output must always use provider entropy");
    assert_ne!(heap.byte_slice(output, 0, 6).unwrap(), &[0x42; 6],
        "the caller seed must contribute to secure output");
    host.fail_random = true;
    heap.byte_slice_mut(output, 0, 6).unwrap().fill(0x55);
    assert!(matches!(invoke_security(ClassId::RandomData, MethodId::generateData,
        &[(true, secure), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host), Err(Error::Storage)));
    assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
    host.fail_random = false;

    heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
    let random_calls = host.random_calls;
    invoke_security(ClassId::RandomData, MethodId::generateData,
        &[(true, pseudo), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(host.random_calls, random_calls, "reset must preserve persistent PRNG state");
    let digest_calls = host.digest_calls;
    invoke_security(ClassId::RandomData, MethodId::generateData,
        &[(true, secure), (true, output), (false, 0), (false, 6)],
        &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(host.random_calls, random_calls + 1);
    assert_eq!(host.digest_calls, digest_calls, "reset must clear the optional secure seed mask");
    assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x42; 6]);

    // Cross the inline staging boundary. Either size must keep the caller's
    // array unchanged when an entropy provider fails after writing into staging.
    let large = heap.new_array(heap::KIND_BYTE, 257, 1).unwrap();
    for length in [256, 257] {
        heap.byte_slice_mut(large, 0, length).unwrap().fill(0x55);
        host.fail_random = true;
        assert!(matches!(invoke_security(ClassId::RandomData, MethodId::generateData,
            &[(true, secure), (true, large), (false, 0), (false, length as u16)],
            &mut heap, &mut frame, &mut host), Err(Error::Storage)));
        assert!(heap.byte_slice(large, 0, length).unwrap().iter().all(|byte| *byte == 0x55));
        host.fail_random = false;
    }
}
