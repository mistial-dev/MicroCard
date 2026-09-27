use super::*;

#[test]
fn apdu_incoming_queries_enforce_direction_and_single_receive_per_command() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    let buffer = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let used = heap.used();
    // Exhausted transaction capacity must not prevent a catchable API error.
    heap.begin_transaction(0).unwrap();
    for incoming in [0, 3] {
        let mut jcre = Jcre::new(0, buffer);
        jcre.incoming = incoming;
        for (method, expected) in [
            (MethodId::getIncomingLength, None),
            (MethodId::getOffsetCdata, None),
            (MethodId::setIncomingAndReceive, Some(incoming as i16)),
            (MethodId::getIncomingLength, Some(incoming as i16)),
            (MethodId::getOffsetCdata, Some(5)),
            (MethodId::setIncomingAndReceive, None),
            (MethodId::setOutgoing, Some(256)),
            (MethodId::getIncomingLength, None),
            (MethodId::getOffsetCdata, None),
            (MethodId::setIncomingAndReceive, None),
        ] {
            frame.push_reference(0).unwrap();
            let result = apdu(method, &mut heap, &mut frame, &mut jcre, 1).unwrap();
            if let Some(expected) = expected {
                assert!(matches!(result, Native::Returned));
                assert_eq!(frame.pop_short(), Ok(expected));
            } else {
                let Native::Threw(exception) = result else { panic!("invalid receive sequence accepted"); };
                assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::APDUException);
                assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
            }
        }
    }
    assert_eq!(heap.used(), used);
    assert_eq!(heap.transaction_remaining(), Some(0));
}

#[test]
fn contacted_transport_parameters_and_buffered_receive_match_the_runtime() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    let buffer = heap.new_array(heap::KIND_BYTE, 261, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut jcre = Jcre::new(0, buffer);

    for method in [MethodId::getInBlockSize, MethodId::getOutBlockSize] {
        assert!(matches!(apdu(method, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(254));
    }
    frame.push_reference(0).unwrap();
    assert!(matches!(apdu(MethodId::getNAD, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
    assert_eq!(frame.pop_short(), Ok(0));

    jcre.incoming_started = true;
    frame.push_reference(0).unwrap();
    frame.push_short(7).unwrap();
    assert!(matches!(apdu(MethodId::receiveBytes, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
    assert_eq!(frame.pop_short(), Ok(0));
    frame.push_reference(0).unwrap();
    frame.push_short(8).unwrap();
    let Native::Threw(exception) = apdu(MethodId::receiveBytes, &mut heap, &mut frame, &mut jcre, 1).unwrap()
        else { panic!("an undersized receive window was accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));

    assert!(matches!(jcsystem(MethodId::getVersion, 0, &mut heap, &mut frame, 1,
        &mut jcre, &mut [], &mut crate::host::NoHost), Ok(Native::Returned)));
    assert_eq!(frame.pop_short(), Ok(0x0305));
}

#[test]
fn apdu_cla_flags_follow_channel_encoding_and_reject_reserved_values() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let buffer = heap.new_array(heap::KIND_BYTE, 1, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut jcre = Jcre::new(0, buffer);
    // Java Card 3.0.5 APDU: first/further channel encodings, proprietary
    // classes, the reserved 001 range, and the invalid FF class.
    for (cla, chaining, secure) in [
        (0x00, false, false), (0x03, false, false), (0x04, false, true),
        (0x08, false, true), (0x1c, true, true), (0x10, true, false),
        (0x40, false, false), (0x4c, false, false), (0x60, false, true),
        (0x5f, true, false), (0x7f, true, true), (0x84, false, true),
        (0xcc, false, false), (0xe0, false, true), (0x20, false, false),
        (0x3c, false, false), (0xff, false, false),
    ] {
        heap.byte_slice_mut(buffer, 0, 1).unwrap()[0] = cla;
        for (method, expected) in [(MethodId::isCommandChainingCLA, chaining),
            (MethodId::isSecureMessagingCLA, secure)] {
            frame.push_reference(0).unwrap();
            assert!(matches!(apdu(method, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(i16::from(expected)), "CLA {cla:02x}");
        }
    }
}

#[test]
fn apdu_sends_capture_bytes_before_buffer_reuse_and_enforce_the_declared_length() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    let buffer = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
    heap.byte_slice_mut(buffer, 0, 8).unwrap().copy_from_slice(b"abcdefgh");
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut jcre = Jcre::new(0, buffer);
    jcre.expected = 7;
    frame.push_reference(0).unwrap();
    apdu(MethodId::setOutgoing, &mut heap, &mut frame, &mut jcre, 1).unwrap();
    assert_eq!(frame.pop_short(), Ok(7));
    frame.push_reference(0).unwrap(); frame.push_short(4).unwrap();
    apdu(MethodId::setOutgoingLength, &mut heap, &mut frame, &mut jcre, 1).unwrap();
    for method in [MethodId::sendBytes, MethodId::sendBytesLong] {
        frame.push_reference(0).unwrap();
        if method == MethodId::sendBytesLong { frame.push_reference(buffer).unwrap(); }
        frame.push_short(1).unwrap(); frame.push_short(2).unwrap();
        apdu(method, &mut heap, &mut frame, &mut jcre, 1).unwrap();
        if method == MethodId::sendBytes { assert_eq!(jcre.response_data(), Err(Error::Bounds)); }
        heap.byte_slice_mut(buffer, 0, 8).unwrap().fill(b'X');
    }
    assert_eq!(jcre.response_data(), Ok(&b"bcXX"[..]));
    frame.push_reference(0).unwrap(); frame.push_short(0).unwrap(); frame.push_short(1).unwrap();
    let Native::Threw(exception) = apdu(MethodId::sendBytes, &mut heap, &mut frame, &mut jcre, 1).unwrap() else { panic!("excess response accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
    assert_eq!(jcre.outgoing, 4);
    frame.push_reference(0).unwrap();
    let Native::Threw(exception) = apdu(MethodId::setOutgoing, &mut heap, &mut frame, &mut jcre, 1).unwrap() else { panic!("repeated outgoing accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));

    for combined in [false, true] {
        let mut next = Jcre::new(0, buffer);
        if !combined {
            frame.push_reference(0).unwrap();
            apdu(MethodId::setOutgoingNoChaining, &mut heap, &mut frame, &mut next, 1).unwrap();
            frame.pop_short().unwrap();
        }
        for length in [-1, 257] {
            frame.push_reference(0).unwrap();
            if combined { frame.push_short(0).unwrap(); }
            frame.push_short(length).unwrap();
            let method = if combined { MethodId::setOutgoingAndSend } else { MethodId::setOutgoingLength };
            let Native::Threw(exception) = apdu(method, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("invalid length accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(3));
            assert_eq!(next.outgoing_length, None);
            assert_eq!(next.outgoing, 0);
        }
    }
    let mut next = Jcre::new(0, buffer);
    for offset in [-1, 8] {
        frame.push_reference(0).unwrap(); frame.push_short(offset).unwrap(); frame.push_short(1).unwrap();
        let Native::Threw(exception) = apdu(MethodId::setOutgoingAndSend, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("invalid source accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));
        assert!(!next.outgoing_started);
    }
    frame.push_reference(0).unwrap(); frame.push_short(0).unwrap(); frame.push_short(1).unwrap();
    apdu(MethodId::setOutgoingAndSend, &mut heap, &mut frame, &mut next, 1).unwrap();
    assert_eq!(next.response_data(), Ok(&b"X"[..]));
    for method in [MethodId::sendBytes, MethodId::sendBytesLong] {
        frame.push_reference(0).unwrap();
        if method == MethodId::sendBytesLong { frame.push_reference(buffer).unwrap(); }
        frame.push_short(0).unwrap(); frame.push_short(0).unwrap();
        let Native::Threw(exception) = apdu(method, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("send after combined output accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        assert_eq!(next.response_data(), Ok(&b"X"[..]));
    }
}
