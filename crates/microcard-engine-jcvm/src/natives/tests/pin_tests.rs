use super::*;

#[test]
fn pin_replacement_honors_configured_capacity_and_reserves_the_complete_update() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
    let mut host = crate::host::NoHost;
    let pin = new_native(&mut heap, ClassId::OwnerPIN, 6, 1).unwrap();
    for (tries, size) in [(0, 126), (3, 0)] {
        let Native::Threw(exception) = invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
            &[(true, pin), (false, tries), (false, size)], &mut heap, &mut frame, &mut host).unwrap()
            else { panic!("invalid PIN limits accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
    }
    let before = heap.image().to_vec();
    heap.begin_transaction(8).unwrap();
    assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
        &[(true, pin), (false, 3), (false, 126)], &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
    assert_eq!(heap.transaction_remaining(), Some(8));
    heap.commit_transaction().unwrap();
    assert!(heap.image() == before, "catching constructor failure must not commit a partial PIN");
    invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
        &[(true, pin), (false, 3), (false, 126)], &mut heap, &mut frame, &mut host).unwrap();
    // The protected accessors share the public flag, but the setter follows
    // the default conditional-state rule rather than PIN presentation semantics.
    heap.begin_transaction(0).unwrap();
    assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::setValidatedFlag,
        &[(true, pin), (false, 1)], &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
    heap.abort_transaction(&mut []).unwrap();
    heap.begin_transaction(16).unwrap();
    invoke_security(ClassId::OwnerPIN, MethodId::setValidatedFlag,
        &[(true, pin), (false, 1)], &mut heap, &mut frame, &mut host).unwrap();
    for method in [MethodId::getValidatedFlag, MethodId::isValidated] {
        invoke_security(ClassId::OwnerPIN, method,
            &[(true, pin)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(1));
    }
    heap.abort_transaction(&mut []).unwrap();
    invoke_security(ClassId::OwnerPIN, MethodId::getValidatedFlag,
        &[(true, pin)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short(), Ok(0));
    let source = heap.new_array(heap::KIND_BYTE, 127, 1).unwrap();
    heap.byte_slice_mut(source, 0, 127).unwrap().fill(0x42);
    let material = heap.get_word(pin, 2).unwrap();
    let args = |length| [(true, pin), (true, source), (false, 0), (false, length)];
    let Native::Threw(exception) = invoke_security(ClassId::OwnerPIN, MethodId::update,
        &args(127), &mut heap, &mut frame, &mut host).unwrap()
        else { panic!("oversized PIN accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
    heap.begin_transaction(32).unwrap();
    assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::update,
        &args(126), &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
    assert_eq!(heap.get_word(pin, 1), Ok(0));
    assert!(heap.byte_slice(material, 0, 126).unwrap().iter().all(|byte| *byte == 0));
    heap.abort_transaction(&mut []).unwrap();
    heap.begin_transaction(256).unwrap();
    invoke_security(ClassId::OwnerPIN, MethodId::update,
        &args(126), &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(heap.byte_slice(material, 0, 126).unwrap(), &[0x42; 126]);
    heap.abort_transaction(&mut []).unwrap();
    assert_eq!(heap.get_word(pin, 1), Ok(0));
    assert!(heap.byte_slice(material, 0, 126).unwrap().iter().all(|byte| *byte == 0));
}

#[test]
fn transactions_keep_pin_presentations_and_nonatomic_copies_outside_undo() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
    let mut host = crate::host::NoHost;
    let pin = new_native(&mut heap, ClassId::OwnerPIN, 6, 1).unwrap();
    let original = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
    let replacement = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
    let destination = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
    heap.byte_slice_mut(original, 0, 4).unwrap().copy_from_slice(b"1234");
    heap.byte_slice_mut(replacement, 0, 4).unwrap().copy_from_slice(b"9999");
    invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
        &[(true, pin), (false, 3), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
    invoke_security(ClassId::OwnerPIN, MethodId::update,
        &[(true, pin), (true, original), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
    for _ in 0..2 {
        invoke_security(ClassId::OwnerPIN, MethodId::check,
            &[(true, pin), (true, replacement), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0);
    }
    assert_eq!(heap.get_word(pin, 4), Ok(1));
    let mut jcre = idle();
    jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
    let Native::Threw(exception) = jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap()
        else { panic!("nested transaction accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
    invoke_security(ClassId::OwnerPIN, MethodId::update,
        &[(true, pin), (true, replacement), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
    struct PinCheckpoint { saved: alloc::vec::Vec<u8>, fail: bool, no_capacity: bool }
    impl crate::host::Host for PinCheckpoint {
        fn ensure_checkpoint_capacity(&mut self, _count: u32) -> Result<()> {
            if self.no_capacity { Err(Error::Storage) } else { Ok(()) }
        }
        fn checkpoint(&mut self, state: crate::applet::PersistentView<'_>, reason: crate::host::CheckpointReason) -> Result<()> {
            assert_eq!(reason, crate::host::CheckpointReason::OwnerPin);
            if self.fail { return Err(Error::Storage); }
            self.saved.resize(state.heap_bytes(), 0);
            state.save_into(&mut self.saved)?;
            Ok(())
        }
    }
    let mut checkpoint = PinCheckpoint { saved: vec![], fail: false, no_capacity: false };
    jcre.instance = Some(pin);
    jcre.buffer = destination;
    for value in [(pin, true), (original, true), (0, false), (4, false)] {
        frame.push_raw(value).unwrap();
    }
    let signature = framework(ClassId::OwnerPIN, MethodId::check, false).method.signature;
    security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
        &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 0);
    let saved_length = checkpoint.saved.len();
    let saved = Heap::resume(&mut checkpoint.saved, saved_length).unwrap();
    let saved_material = saved.get_word(pin, 2).unwrap();
    assert_eq!(saved.byte_slice(saved_material, 0, 4).unwrap(), b"1234",
        "PIN checkpoint must not publish the conditional PIN update");
    assert_eq!(saved.get_word(pin, 4), Ok(2));
    assert_eq!(saved.get_word(pin, 3), Ok(0));
    checkpoint.no_capacity = true;
    for value in [(pin, true), (replacement, true), (0, false), (4, false)] {
        frame.push_raw(value).unwrap();
    }
    assert!(matches!(security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
        &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]), Err(Error::Storage)));
    assert_eq!(heap.get_word(pin, 4), Ok(2), "capacity failure must precede retry mutation");
    checkpoint.no_capacity = false;
    // Save a conditional image first, then overwrite it through the non-atomic API.
    heap.byte_slice_mut(destination, 0, 4).unwrap().fill(7);
    for (reference, value) in [(true, replacement), (false, 0), (true, destination), (false, 0), (false, 4)] {
        frame.push_raw((value, reference)).unwrap();
    }
    util(MethodId::arrayCopyNonAtomic, &mut heap, &mut frame, 1, &mut 100).unwrap();
    assert_eq!(frame.pop_short(), Ok(4));
    jcsystem(MethodId::abortTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
    let material = heap.get_word(pin, 2).unwrap();
    assert_eq!(heap.byte_slice(material, 0, 4).unwrap(), b"1234");
    assert_eq!(heap.get_word(pin, 4), Ok(2), "PIN presentation must survive aborting its update");
    assert_eq!(heap.byte_slice(destination, 0, 4).unwrap(), b"9999");
    let used = heap.used();
    jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
    invoke_security(ClassId::OwnerPIN, MethodId::check,
        &[(true, pin), (true, original), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
    assert_eq!(frame.pop_short(), Ok(1));
    jcsystem(MethodId::abortTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
    assert_eq!(heap.get_word(pin, 3), Ok(1));
    assert_eq!(heap.get_word(pin, 4), Ok(3));
    assert_eq!(heap.used(), used, "transaction exceptions are reused");
    let Native::Threw(exception) = jcsystem(MethodId::commitTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap()
        else { panic!("commit without begin accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));
    // Invalid presentations still consume a retry, including when their exception
    // is caught and the surrounding transaction is aborted (OwnerPIN.check).
    for (candidate, offset, length, class) in [
        (crate::vm::NULL, 0, 4, ClassId::NullPointerException),
        (original, u16::MAX, 4, ClassId::ArrayIndexOutOfBoundsException),
        (original, 0, u16::MAX, ClassId::ArrayIndexOutOfBoundsException),
        (original, 3, 2, ClassId::ArrayIndexOutOfBoundsException),
    ] {
        // Allocate runtime exceptions before the transaction so abort does not
        // terminate the session because of a newly allocated object.
        let exception = new_exception(&mut heap, class, 1).unwrap();
        heap.put_word_unconditional(pin, 4, 3).unwrap();
        heap.put_word_unconditional(pin, 3, 1).unwrap();
        heap.begin_transaction(256).unwrap();
        let result = invoke_security(ClassId::OwnerPIN, MethodId::check,
            &[(true, pin), (true, candidate), (false, offset), (false, length)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert!(matches!(result, Native::Threw(reference) if reference == exception));
        heap.abort_transaction(&mut []).unwrap();
        assert_eq!(heap.get_word(pin, 4), Ok(2));
        assert_eq!(heap.get_word(pin, 3), Ok(0));
    }
    heap.put_word_unconditional(pin, 4, 3).unwrap();
    checkpoint.fail = true;
    for value in [(pin, true), (original, true), (0, false), (4, false)] {
        frame.push_raw(value).unwrap();
    }
    assert!(matches!(security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
        &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]), Err(Error::Storage)));
    assert_eq!(heap.get_word(pin, 4), Ok(2), "failure must stop before a matching PIN resets retries");
    assert_eq!(heap.get_word(pin, 3), Ok(0));

    // A blocked presentation cannot turn an earlier ordinary write into an
    // anchored PIN checkpoint. The rejecting host makes that boundary visible.
    heap.put_word_unconditional(pin, 4, 0).unwrap();
    heap.mark_checkpointed();
    heap.byte_slice_mut(destination, 0, 1).unwrap()[0] = 1;
    for value in [(pin, true), (original, true), (0, false), (4, false)] {
        frame.push_raw(value).unwrap();
    }
    assert!(matches!(security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
        &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]), Ok(Native::Returned)));
    assert_eq!(frame.pop_short(), Ok(0));
    assert!(heap.has_uncheckpointed_writes());
}

#[test]
fn owner_pin_builder_and_extended_counter_methods_follow_the_declared_type() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
    let signature = framework(ClassId::OwnerPINBuilder, MethodId::buildOwnerPIN, true)
        .method.signature;
    let mut jcre = idle();
    let mut budget = u32::MAX;
    for (pin_type, class) in [(1, ClassId::OwnerPIN), (2, ClassId::OwnerPINx),
        (3, ClassId::OwnerPINxWithPredecrement)] {
        for value in [3, 8, pin_type] { frame.push_short(value).unwrap(); }
        assert!(matches!(security::call(ClassId::OwnerPINBuilder, MethodId::buildOwnerPIN,
            signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
            &mut budget, &[]), Ok(Native::Returned)));
        let pin = frame.pop_reference().unwrap();
        assert_eq!(api_class(heap.info(pin).unwrap().class).unwrap().id, class);
        frame.push_reference(pin).unwrap();
        assert!(matches!(security::call(ClassId::PIN, MethodId::getTriesRemaining,
            signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
            &mut budget, &[]), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(3));
        if pin_type >= 2 {
            frame.push_reference(pin).unwrap();
            frame.push_short(4).unwrap();
            assert!(matches!(security::call(ClassId::OwnerPINx, MethodId::setTryLimit,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            frame.push_reference(pin).unwrap();
            assert!(matches!(security::call(ClassId::OwnerPINx, MethodId::getTryLimit,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(4));
            frame.push_reference(pin).unwrap();
            frame.push_short(2).unwrap();
            assert!(matches!(security::call(ClassId::OwnerPINx, MethodId::setTriesRemaining,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            assert_eq!(heap.get_word(pin, security::COUNTER), Ok(2));
            heap.begin_transaction(32).unwrap();
            frame.push_reference(pin).unwrap();
            frame.push_short(5).unwrap();
            security::call(ClassId::OwnerPINx, MethodId::setTryLimit, signature,
                &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]).unwrap();
            heap.abort_transaction(&mut []).unwrap();
            assert_eq!(heap.get_word(pin, security::KIND), Ok(4));
            assert_eq!(heap.get_word(pin, security::COUNTER), Ok(2));
            heap.begin_transaction(0).unwrap();
            frame.push_reference(pin).unwrap();
            frame.push_short(5).unwrap();
            assert!(matches!(security::call(ClassId::OwnerPINx, MethodId::setTryLimit,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Err(Error::TransactionFull)));
            assert_eq!(heap.get_word(pin, security::KIND), Ok(4));
            assert_eq!(heap.get_word(pin, security::COUNTER), Ok(2));
            heap.abort_transaction(&mut []).unwrap();
        }
        if pin_type == 3 {
            jcre.installing = true;
            frame.push_reference(pin).unwrap();
            assert!(matches!(security::call(class, MethodId::decrementTriesRemaining,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(1));
            let candidate = heap.new_array(heap::KIND_BYTE, 1, 1).unwrap();
            for value in [pin, candidate] { frame.push_reference(value).unwrap(); }
            for value in [0, 1] { frame.push_short(value).unwrap(); }
            assert!(matches!(security::call(class, MethodId::check,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(0));
            assert_eq!(heap.get_word(pin, security::COUNTER), Ok(1));
            frame.push_reference(pin).unwrap();
            assert!(matches!(security::call(class, MethodId::decrementTriesRemaining,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(0));
            heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
            for value in [pin, candidate] { frame.push_reference(value).unwrap(); }
            for value in [0, 1] { frame.push_short(value).unwrap(); }
            let Native::Threw(exception) = security::call(class, MethodId::check,
                signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
                &mut budget, &[]).unwrap() else { panic!("missing predecrement accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));
            jcre.installing = false;
        }
    }
    for value in [3, 8, 0] { frame.push_short(value).unwrap(); }
    let Native::Threw(exception) = security::call(ClassId::OwnerPINBuilder,
        MethodId::buildOwnerPIN, signature, &mut heap, &mut crate::host::NoHost,
        &mut frame, 1, &mut jcre, &mut budget, &[]).unwrap()
        else { panic!("unknown OwnerPIN type was accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
}
