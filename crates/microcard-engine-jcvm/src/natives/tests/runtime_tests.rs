use super::*;

#[test]
fn lifecycle_checkpoints_before_success_and_survives_callback_and_abort() {
    struct Storage { saved: alloc::vec::Vec<u8>, fail: bool }
    impl crate::host::Host for Storage {
        fn ensure_checkpoint_capacity(&mut self, _count: u32) -> Result<()> { Ok(()) }
        fn checkpoint(&mut self, state: crate::applet::PersistentView<'_>, _: crate::host::CheckpointReason) -> Result<()> {
            if self.fail { return Err(Error::Storage); }
            self.saved.resize(state.heap_bytes(), 0);
            state.save_into(&mut self.saved)?;
            Ok(())
        }
    }
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    heap.initialize_lifecycle();
    let buffer = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
    let instance = heap.new_object(1, 1, 1).unwrap();
    let mut storage = Storage { saved: vec![], fail: false };
    let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
    let setter = framework(ClassId::GPSystem, MethodId::setCardContentState, true);
    let getter = framework(ClassId::GPSystem, MethodId::getCardContentState, true);
    let mut jcre = Jcre::new(0, buffer);
    jcre.instance = Some(instance);
    heap.begin_transaction(32).unwrap();
    heap.put_word(instance, 0, 99).unwrap();
    frame.push_short(0x0f).unwrap();
    call(setter, &mut heap, &mut storage, &mut frame, 1, &mut jcre).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 1);
    assert_eq!(&storage.saved[..2], &[3, 0x0f]);
    let used = storage.saved.len();
    let saved = Heap::resume(&mut storage.saved, used).unwrap();
    assert_eq!(saved.get_word(instance, 0), Ok(0));
    heap.abort_transaction(&mut []).unwrap();
    let mut next = Jcre::new(0, buffer);
    next.instance = Some(instance);
    call(getter, &mut heap, &mut storage, &mut frame, 1, &mut next).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 0x0f);
    storage.fail = true;
    heap.put_word(instance, 0, 1).unwrap();
    frame.push_short(0x0f).unwrap();
    call(setter, &mut heap, &mut storage, &mut frame, 1, &mut next).unwrap();
    assert_eq!(frame.pop_short().unwrap(), 1, "unchanged card state must not anchor an ordinary write");
    frame.push_short(0x17).unwrap();
    assert!(matches!(call(setter, &mut heap, &mut storage, &mut frame, 1,
        &mut next), Err(Error::Storage)));
    assert_eq!(&storage.saved[..2], &[3, 0x0f]);
}

#[test]
fn exception_calls_reuse_runtime_objects_and_preserve_explicit_reasons() {
    for name in [ClassId::ISOException, ClassId::CryptoException, ClassId::CardRuntimeException,
        ClassId::CardException, ClassId::UserException] {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let capacity = slab.len();
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        reserve_runtime_exceptions(&mut heap, 2).unwrap();
        let class = framework(name, MethodId::throwIt, true).class;
        let explicit = new_api_object(&mut heap, class, 1).unwrap();
        frame.push_reference(explicit).unwrap();
        frame.push_short(0x6a81).unwrap();
        assert!(matches!(call(framework(name, MethodId::Constructor, true), &mut heap,
            &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
        heap.begin_transaction(0).unwrap();
        frame.push_reference(explicit).unwrap();
        frame.push_short(0x6a82).unwrap();
        assert!(matches!(call(framework(name, MethodId::setReason, false), &mut heap,
            &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
        assert!(!heap.abort_transaction(&mut []).unwrap());
        frame.push_reference(explicit).unwrap();
        assert!(matches!(call(framework(name, MethodId::getReason, false), &mut heap,
            &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(0x6a82));
        let remaining = capacity - heap.used() - heap::HEADER;
        heap.new_array(heap::KIND_BYTE, remaining as u16, 1).unwrap();
        assert_eq!(heap.used(), capacity);
        let mut used = heap.used();
        let mut references = [0; 2];
        for context in [1, 2] {
            for reason in [0x6101, 0x9000, 0x6a80] {
                let mut heap = Heap::resume(&mut slab, used).unwrap();
                let reused = references[context as usize - 1] != 0;
                if reused { heap.begin_transaction(0).unwrap(); }
                frame.push_short(reason as i16).unwrap();
                let Native::Threw(reference) = call(
                    framework(name, MethodId::throwIt, true), &mut heap,
                    &mut crate::host::NoHost, &mut frame, context, &mut idle(),
                ).unwrap() else { panic!("throwIt returned"); };
                let previous = &mut references[context as usize - 1];
                if *previous == 0 { *previous = reference; }
                else {
                    assert_eq!(reference, *previous);
                    assert_eq!(heap.used(), used, "a response must not consume persistent heap");
                }
                if reused { assert!(!heap.abort_transaction(&mut []).unwrap()); }
                assert_eq!(heap.get_word(reference, REASON_FIELD), Ok(reason));
                assert_eq!(heap.get_word(explicit, REASON_FIELD), Ok(0x6a82));
                assert_ne!(reference, explicit);
                used = heap.used();
            }
        }
        assert_ne!(references[0], references[1]);
    }
}

#[test]
fn object_deletion_request_is_logged_for_the_next_process_boundary() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    heap.initialize_lifecycle();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    let mut jcre = Jcre::new(0, 0);
    assert!(matches!(jcsystem(MethodId::isObjectDeletionSupported, 0, &mut heap, &mut frame, 1,
        &mut jcre, &mut [], &mut crate::host::NoHost), Ok(Native::Returned)));
    assert_eq!(frame.pop_short(), Ok(1));
    assert!(matches!(jcsystem(MethodId::requestObjectDeletion, 0, &mut heap, &mut frame, 1,
        &mut jcre, &mut [], &mut crate::host::NoHost), Ok(Native::Returned)));
    assert!(heap.object_deletion_requested().unwrap());
}

#[test]
fn transient_factories_report_lifetimes_and_recoverable_failures() {
    for factory in [MethodId::makeTransientByteArray, MethodId::makeTransientBooleanArray, MethodId::makeTransientShortArray, MethodId::makeTransientObjectArray] {
        let (mut slab, mut words, mut tags) = setup(0);
        let capacity = slab.len();
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        for (length, event) in [(0, 1), (2, 1), (2, 2), (2, 0), (2, 3)] {
            frame.push_short(length).unwrap();
            frame.push_short(event).unwrap();
            let result = jcsystem(factory, 0, &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap();
            if matches!(event, 1 | 2) {
                assert!(matches!(result, Native::Returned));
                jcsystem(MethodId::isTransient, 0, &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap();
                assert_eq!(frame.pop_short().unwrap(), event);
            } else {
                let Native::Threw(exception) = result else { panic!("invalid clear event accepted"); };
                assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::SystemException);
                assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 1);
            }
        }
        // Even a completely full heap and undo log must deliver the API error.
        let remaining = capacity - heap.used() - heap::HEADER;
        heap.new_array(heap::KIND_BYTE, remaining as u16, 1).unwrap();
        assert_eq!(heap.used(), capacity);
        heap.begin_transaction(0).unwrap();
        for (length, event, expected, reason) in [
            (-1, 1, ClassId::NegativeArraySizeException, 0),
            (i16::MIN, 2, ClassId::NegativeArraySizeException, 0),
            (0, 1, ClassId::SystemException, 2),
            (1, 2, ClassId::SystemException, 2),
            (i16::MAX, 1, ClassId::SystemException, 2),
            (0, 3, ClassId::SystemException, 1),
        ] {
            frame.push_short(length).unwrap();
            frame.push_short(event).unwrap();
            let Native::Threw(exception) = jcsystem(factory, 0, &mut heap, &mut frame, 1,
                &mut idle(), &mut [], &mut crate::host::NoHost).unwrap()
                else { panic!("invalid transient allocation accepted"); };
            assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, expected);
            assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), reason);
            assert_eq!(heap.used(), capacity);
            assert_eq!(heap.transaction_remaining(), Some(0));
        }
        assert!(!heap.abort_transaction(&mut []).unwrap());
    }
}

#[test]
fn available_memory_supports_both_java_card_forms() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    reserve_runtime_exceptions(&mut heap, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();

    let available = heap.available();
    frame.push_short(0).unwrap();
    assert!(matches!(jcsystem(MethodId::getAvailableMemory, 16, &mut heap, &mut frame,
        1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap(), Native::Returned));
    assert_eq!(frame.pop_short().unwrap(), available.min(i16::MAX as usize) as i16);

    let output = heap.new_array(heap::KIND_SHORT, 2, 1).unwrap();
    let available = heap.available() as u32;
    frame.push_reference(output).unwrap();
    frame.push_short(0).unwrap();
    frame.push_short(2).unwrap();
    assert!(matches!(jcsystem(MethodId::getAvailableMemory, 22, &mut heap, &mut frame,
        1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap(), Native::Returned));
    assert_eq!(heap.array_get(output, 0).unwrap() as u16, (available >> 16) as u16);
    assert_eq!(heap.array_get(output, 1).unwrap() as u16, available as u16);

    frame.push_short(3).unwrap();
    let Native::Threw(exception) = jcsystem(MethodId::getAvailableMemory, 16,
        &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap()
    else { panic!("invalid memory type accepted"); };
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
}

#[test]
fn a_method_the_card_does_not_provide_says_so() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    // Shareable interfaces are not built, so this is a real API entry with nothing
    // behind it.
    let target = framework(
        ClassId::JCSystem,
        MethodId::getAppletShareableInterfaceObject,
        true,
    );
    assert!(matches!(
        call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap(),
        Native::Unimplemented
    ));
    let target = framework(ClassId::GPSystem, MethodId::getSecureChannel, true);
    let Native::Threw(exception) = call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap() else {
        panic!("an unavailable applet channel must not return a usable-looking handle");
    };
    assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::SystemException);
    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
}
