use super::*;

#[test]
fn unsupported_symmetric_key_sizes_fail_before_allocation() {
    let signature = framework(ClassId::KeyBuilder, MethodId::buildKey, true).method.signature;
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let exception = new_exception(&mut heap, ClassId::CryptoException, 1).unwrap();
    let used = heap.used();
    for (key_type, length) in [(15, 512), (13, 64), (1, 256)] {
        frame.push_short(key_type).unwrap();
        frame.push_short(length).unwrap();
        frame.push_short(0).unwrap();
        let result = security::call(ClassId::KeyBuilder, MethodId::buildKey, signature,
            &mut heap, &mut crate::host::NoHost, &mut frame, 1,
            &mut idle(), &mut { u32::MAX }, &[]).unwrap();
        assert!(matches!(result, Native::Threw(reference) if reference == exception));
        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 3);
        assert_eq!(heap.used(), used);
    }
}

#[test]
fn symmetric_keys_clear_material_and_initialization_with_their_lifetime() {
    let signature = framework(ClassId::KeyBuilder, MethodId::buildKey, true).method.signature;
    let invoke = |class, method, heap: &mut Heap, frame: &mut Frame| {
        security::call(class, method, signature, heap, &mut crate::host::NoHost, frame, 1, &mut idle(), &mut { u32::MAX }, &[]).unwrap()
    };
    for (class, first) in [(ClassId::DESKey, 1), (ClassId::AESKey, 13)]
        .into_iter().filter(|(class, _)| cfg!(feature = "des-legacy") || *class != ClassId::DESKey) {
        for lifetime in 0..3 {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            frame.push_short(first + lifetime).unwrap();
            frame.push_short(128).unwrap();
            frame.push_short(0).unwrap();
            invoke(ClassId::KeyBuilder, MethodId::buildKey, &mut heap, &mut frame);
            let key = frame.pop_reference().unwrap();
            let input = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
            let output = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
            if class == ClassId::AESKey {
                let before = heap.image().to_vec();
                heap.begin_transaction(0).unwrap();
                let result = invoke_security(class, MethodId::setKey,
                    &[(true, key), (true, input), (false, 0)],
                    &mut heap, &mut frame, &mut crate::host::NoHost);
                assert!(matches!(result, Err(Error::TransactionFull)));
                heap.commit_transaction().unwrap();
                assert_eq!(heap.image(), before, "failed first import must not consume heap storage");
            }
            // Include a zero-valued key: readiness cannot be inferred from its bytes.
            for event in [heap::CLEAR_ON_DESELECT, heap::CLEAR_ON_RESET] {
                let value = if event == heap::CLEAR_ON_DESELECT { 0x42 } else { 0 };
                heap.byte_slice_mut(input, 0, 16).unwrap().fill(value);
                frame.push_reference(key).unwrap();
                frame.push_reference(input).unwrap();
                frame.push_short(0).unwrap();
                if class == ClassId::HMACKey { frame.push_short(16).unwrap(); }
                invoke(class, MethodId::setKey, &mut heap, &mut frame);
                frame.push_reference(key).unwrap();
                invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
                assert_eq!(frame.pop_short().unwrap(), 1);
                heap.clear_transient(event, 1).unwrap();
                let retained = lifetime == 2 || (lifetime == 0 && event == heap::CLEAR_ON_DESELECT);
                frame.push_reference(key).unwrap();
                invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
                assert_eq!(frame.pop_short().unwrap(), i16::from(retained));
                heap.byte_slice_mut(output, 0, 16).unwrap().fill(0x55);
                frame.push_reference(key).unwrap();
                frame.push_reference(output).unwrap();
                frame.push_short(0).unwrap();
                let result = invoke(class, MethodId::getKey, &mut heap, &mut frame);
                if retained {
                    assert!(matches!(result, Native::Returned));
                    assert_eq!(frame.pop_short().unwrap(), 16);
                    assert_eq!(heap.byte_slice(output, 0, 16).unwrap(), &[value; 16]);
                } else {
                    let Native::Threw(exception) = result else { panic!("cleared key remained readable"); };
                    assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 2);
                    assert_eq!(heap.byte_slice(output, 0, 16).unwrap(), &[0x55; 16]);
                    let material = heap.get_word(key, 2).unwrap();
                    let length = heap.info(material).unwrap().length as usize;
                    assert!(heap.byte_slice(material, 0, length).unwrap().iter().all(|byte| *byte == 0));
                }
            }
            if class == ClassId::AESKey {
                // Persistent updates must reject insufficient undo before either bytes
                // or readiness changes. Transient key state needs no undo space.
                heap.byte_slice_mut(input, 0, 16).unwrap().fill(0x77);
                invoke_security(class, MethodId::setKey,
                    &[(true, key), (true, input), (false, 0)],
                    &mut heap, &mut frame, &mut crate::host::NoHost).unwrap();
                for method in [MethodId::clearKey, MethodId::setKey] {
                    heap.byte_slice_mut(input, 0, 16).unwrap().fill(0x33);
                    let before = heap.image().to_vec();
                    let capacities: &[usize] = if lifetime == 2 { &[22, 30] } else { &[0] };
                    for &capacity in capacities {
                        heap.begin_transaction(capacity).unwrap();
                        let arguments = [(true, key), (true, input), (false, 0)];
                        let count = if method == MethodId::clearKey { 1 } else { 3 };
                        let result = invoke_security(class, method, &arguments[..count],
                            &mut heap, &mut frame, &mut crate::host::NoHost);
                        if capacity == 22 {
                            assert!(matches!(result, Err(Error::TransactionFull)));
                            assert_eq!(heap.transaction_remaining(), Some(capacity));
                            heap.commit_transaction().unwrap();
                            assert_eq!(heap.image(), before);
                        } else {
                            assert!(matches!(result, Ok(Native::Returned)));
                            assert_eq!(heap.transaction_remaining(), Some(0));
                            assert_ne!(heap.image(), before);
                            assert!(!heap.abort_transaction(&mut []).unwrap());
                            assert_eq!(heap.image() == before, lifetime == 2);
                        }
                    }
                }
            }
            frame.push_reference(key).unwrap();
            invoke(class, MethodId::clearKey, &mut heap, &mut frame);
            frame.push_reference(key).unwrap();
            invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
            assert_eq!(frame.pop_short().unwrap(), 0);
        }
    }
}
