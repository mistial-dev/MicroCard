use super::*;

#[test]
fn throw_it_produces_an_exception_carrying_its_status_word() {
    let (mut slab, mut words, mut tags) = setup(0);
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
    frame.push_short(0x6a80u16 as i16).unwrap();
    let target = framework(ClassId::ISOException, MethodId::throwIt, true);
    let Native::Threw(exception) = call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap() else {
        panic!("throwIt has to throw");
    };
    assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 0x6a80);
    // It is an object of a class the card provides, which no package can define.
    let class = heap.info(exception).unwrap().class;
    assert!(is_native_class(class));
    assert_eq!(api_class(class).unwrap().id, ClassId::ISOException);
}

#[test]
fn an_exception_is_caught_by_its_own_class_or_any_it_extends() {
    let iso = {
        let (index, class) = PACKAGES
            .iter()
            .enumerate()
            .find_map(|(index, package)| {
                package
                    .classes
                    .iter()
                    .find(|entry| entry.id == ClassId::ISOException)
                    .map(|class| (index, class))
            })
            .unwrap();
        native_class(index, class.token)
    };
    let runtime = {
        let (index, class) = PACKAGES
            .iter()
            .enumerate()
            .find_map(|(index, package)| {
                package
                    .classes
                    .iter()
                    .find(|entry| entry.id == ClassId::RuntimeException)
                    .map(|class| (index, class))
            })
            .unwrap();
        native_class(index, class.token)
    };
    assert!(native_is_a(iso, iso));
    // Catching a supertype has to match, which is how catch of CardRuntimeException
    // or RuntimeException catches an ISOException.
    assert!(native_is_a(iso, runtime));
    // The other direction does not.
    assert!(!native_is_a(runtime, iso));
}
