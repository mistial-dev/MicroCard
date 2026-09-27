use super::*;

#[test]
fn util_reads_and_writes_shorts_in_a_byte_array() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let array = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();

    frame.push_reference(array).unwrap();
    frame.push_short(2).unwrap();
    frame.push_short(0x1234).unwrap();
    call(
        framework(ClassId::Util, MethodId::setShort, true),
        &mut heap,
        &mut crate::host::NoHost,
        &mut frame,
        1,
        &mut idle(),
    )
    .unwrap();
    // It answers the offset one past what it wrote, which is what makes these chain.
    assert_eq!(frame.pop_short().unwrap(), 4);

    frame.push_reference(array).unwrap();
    frame.push_short(2).unwrap();
    call(
        framework(ClassId::Util, MethodId::getShort, true),
        &mut heap,
        &mut crate::host::NoHost,
        &mut frame,
        1,
        &mut idle(),
    )
    .unwrap();
    assert_eq!(frame.pop_short().unwrap(), 0x1234);

    // setShort must admit both bytes before either changes, even if the
    // caller catches a capacity failure and commits instead of aborting.
    for capacity in [0, TRANSACTION_CAPACITY] {
        heap.begin_transaction(capacity).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(-128).unwrap();
        let result = call(framework(ClassId::Util, MethodId::setShort, true),
            &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle());
        if capacity == 0 {
            assert!(matches!(result, Err(Error::TransactionFull)));
            heap.commit_transaction().unwrap();
        } else {
            assert!(matches!(result, Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(4));
            assert_eq!(heap.byte_slice(array, 2, 2).unwrap(), [0xff, 0x80]);
            heap.abort_transaction(&mut []).unwrap();
        }
        assert_eq!(heap.byte_slice(array, 2, 2).unwrap(), [0x12, 0x34]);
    }
}

#[test]
fn util_copies_within_one_array_without_overwriting_what_it_is_reading() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let array = heap.new_array(heap::KIND_BYTE, 600, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    // Cross the former 256-byte staging boundary in both overlap directions.
    for (source, destination, length) in [(0, 1, 599), (1, 0, 599), (600, 600, 0)] {
        for (index, byte) in heap.byte_slice_mut(array, 0, 600).unwrap().iter_mut().enumerate() {
            *byte = index as u8;
        }
        let before = heap.byte_slice(array, 0, 600).unwrap().to_vec();
        frame.push_reference(array).unwrap();
        frame.push_short(source).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(destination).unwrap();
        frame.push_short(length).unwrap();
        let mut budget = length as u32;
        test_call_with_budget(
            framework(ClassId::Util, MethodId::arrayCopyNonAtomic, true),
            NativeContext { heap: &mut heap, host: &mut crate::host::NoHost,
                frame: &mut frame, context: 1, jcre: &mut idle(), budget: &mut budget,
                statics: &mut [] },
        ).unwrap();
        assert_eq!(budget, 0);
        assert_eq!(frame.pop_short().unwrap(), destination + length);
        let mut expected = before;
        expected.copy_within(source as usize..(source + length) as usize, destination as usize);
        assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), expected);
    }
    let before = heap.byte_slice(array, 0, 600).unwrap().to_vec();
    frame.push_reference(array).unwrap();
    frame.push_short(0).unwrap();
    frame.push_reference(array).unwrap();
    frame.push_short(1).unwrap();
    frame.push_short(599).unwrap();
    let mut budget = 598;
    assert!(matches!(test_call_with_budget(
        framework(ClassId::Util, MethodId::arrayCopyNonAtomic, true),
        NativeContext { heap: &mut heap, host: &mut crate::host::NoHost,
            frame: &mut frame, context: 1, jcre: &mut idle(), budget: &mut budget,
            statics: &mut [] },
    ), Err(Error::Quota)));
    assert_eq!(budget, 598);
    assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), before);
    assert_eq!(heap.copy_bytes(array, 0, array, 1, 600), Err(Error::Bounds));
    assert_eq!(heap.copy_bytes(array, usize::MAX, array, 0, 1), Err(Error::Bounds));
    assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), before);
}

#[test]
fn util_fills_and_compares() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let left = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
    let right = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    for array in [left, right] {
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(4).unwrap();
        frame.push_short(7).unwrap();
        call(
            framework(ClassId::Util, MethodId::arrayFillNonAtomic, true),
            &mut heap,
            &mut crate::host::NoHost,
            &mut frame,
            1,
            &mut idle(),
        )
        .unwrap();
        frame.pop_short().unwrap();
    }
    let compare = framework(ClassId::Util, MethodId::arrayCompare, true);
    let run = |heap: &mut Heap, frame: &mut Frame| {
        frame.push_reference(left).unwrap();
        frame.push_short(0).unwrap();
        frame.push_reference(right).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(4).unwrap();
        call(compare, heap, &mut crate::host::NoHost, frame, 1, &mut idle()).unwrap();
        frame.pop_short().unwrap()
    };
    assert_eq!(run(&mut heap, &mut frame), 0);
    // It answers an ordering rather than equality, so a difference has a direction.
    heap.byte_slice_mut(right, 2, 1).unwrap()[0] = 9;
    assert_eq!(run(&mut heap, &mut frame), -1);
    heap.byte_slice_mut(right, 2, 1).unwrap()[0] = 1;
    assert_eq!(run(&mut heap, &mut frame), 1);

    // A first-byte mismatch must not hide an invalid tail or empty range.
    heap.byte_slice_mut(right, 0, 1).unwrap()[0] = 0;
    for (source, source_offset, destination, destination_offset, length, expected) in [
        (left, 0, right, 0, 5, ClassId::ArrayIndexOutOfBoundsException),
        (left, -1, right, 0, 0, ClassId::ArrayIndexOutOfBoundsException),
        (left, 0, right, -1, 0, ClassId::ArrayIndexOutOfBoundsException),
        (left, 5, right, 0, 0, ClassId::ArrayIndexOutOfBoundsException),
        (left, 0, right, 5, 0, ClassId::ArrayIndexOutOfBoundsException),
        (left, 0, right, 0, -1, ClassId::ArrayIndexOutOfBoundsException),
        (0, 0, right, 0, 0, ClassId::NullPointerException),
        (left, 0, 0, 0, 0, ClassId::NullPointerException),
    ] {
        frame.push_reference(source).unwrap();
        frame.push_short(source_offset).unwrap();
        frame.push_reference(destination).unwrap();
        frame.push_short(destination_offset).unwrap();
        frame.push_short(length).unwrap();
        let Native::Threw(exception) = call(compare, &mut heap, &mut crate::host::NoHost,
            &mut frame, 1, &mut idle()).unwrap() else { panic!("invalid comparison accepted"); };
        assert_eq!(exception, new_exception(&mut heap, expected, 1).unwrap());
    }
    for (offset, length, available, expected) in [(4, 0, 0, Ok(0)), (0, 4, 3, Err(Error::Quota)), (0, 4, 4, Ok(1))] {
        frame.push_reference(left).unwrap();
        frame.push_short(offset).unwrap();
        frame.push_reference(right).unwrap();
        frame.push_short(offset).unwrap();
        frame.push_short(length).unwrap();
        let mut budget = available;
        let result = test_call_with_budget(compare, NativeContext { heap: &mut heap,
            host: &mut crate::host::NoHost, frame: &mut frame, context: 1,
            jcre: &mut idle(), budget: &mut budget, statics: &mut [] })
            .and_then(|_| frame.pop_short());
        assert_eq!(result, expected);
        assert_eq!(budget, if expected.is_ok() { available - length as u32 } else { available });
    }

    for method in [MethodId::arrayFill, MethodId::arrayFillNonAtomic] {
        heap.byte_slice_mut(left, 0, 4).unwrap().fill(7);
        heap.begin_transaction(TRANSACTION_CAPACITY).unwrap();
        for available in [3, 4] {
            frame.push_reference(left).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(4).unwrap();
            frame.push_short(9).unwrap();
            let mut budget = available;
            let result = test_call_with_budget(
                framework(ClassId::Util, method, true),
                NativeContext { heap: &mut heap, host: &mut crate::host::NoHost,
                    frame: &mut frame, context: 1, jcre: &mut idle(), budget: &mut budget,
                    statics: &mut [] },
            );
            if available == 3 {
                assert!(matches!(result, Err(Error::Quota)));
                assert_eq!(budget, 3);
                assert_eq!(heap.byte_slice(left, 0, 4).unwrap(), [7; 4]);
            } else {
                result.unwrap();
                assert_eq!(frame.pop_short().unwrap(), 4);
                assert_eq!(budget, 0);
            }
        }
        heap.abort_transaction(&mut []).unwrap();
        assert_eq!(heap.byte_slice(left, 0, 4).unwrap(),
            [if method == MethodId::arrayFill { 7 } else { 9 }; 4]);
    }
}
