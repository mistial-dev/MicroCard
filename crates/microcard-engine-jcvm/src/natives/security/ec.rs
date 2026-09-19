//! P-256 key objects retain checked parameter flags rather than duplicate curve data.
use super::*;

pub(crate) fn key_kind(kind: u16) -> bool { matches!(kind, 11 | 12 | 30 | 31) }

pub(crate) fn clear_event(kind: u16) -> u8 {
    match kind { 30 => heap::CLEAR_ON_RESET, 31 => heap::CLEAR_ON_DESELECT, _ => 0 }
}

fn check_key(heap: &Heap, key: u16, context: heap::Context) -> Result<u16> {
    heap.check_access(key, context)?;
    let kind = word_field(heap, key, KIND)?;
    if !key_kind(kind) || word_field(heap, key, SIZE)? != 256 { return Err(Error::Type); }
    Ok(kind)
}

// Flags share the material's lifetime, so transient clearing also clears parameters.
fn flags(heap: &Heap, key: u16) -> Result<u8> {
    let material = heap.get_word(key, MATERIAL)?;
    if material == NULL { Ok(0) } else { Ok(heap.byte_slice(material, 0, 1)?[0]) }
}

fn material(heap: &mut Heap, key: u16, context: heap::Context) -> Result<u16> {
    let existing = heap.get_word(key, MATERIAL)?;
    if existing != NULL { return Ok(existing); }
    let kind = check_key(heap, key, context)?;
    let length = if kind == 11 { 66 } else { 33 };
    let event = clear_event(kind);
    let array = if event == 0 { heap.new_array(heap::KIND_BYTE, length, context)? }
        else { heap.new_transient_array(heap::KIND_BYTE, length, context, event)? };
    heap.put_word(key, MATERIAL, array)?;
    Ok(array)
}

fn set_flags(heap: &mut Heap, key: u16, value: u8, context: heap::Context) -> Result<()> {
    let array = material(heap, key, context)?;
    heap.byte_slice_mut(array, 0, 1)?[0] = value;
    Ok(())
}

pub(super) fn initialized(heap: &Heap, key: u16) -> Result<bool> {
    // K is optional for ordinary ECDSA/ECDH.
    Ok(flags(heap, key)? & 0x5f == 0x5f)
}

// Keep this out of the main security dispatcher; measured smaller on Cortex-M4.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn call(class: ClassId, method: MethodId, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, context: heap::Context) -> Result<Option<Native>> {
    if !matches!(class, ClassId::ECKey | ClassId::ECPublicKey | ClassId::ECPrivateKey) { return Ok(None); }
    let parameter = match method {
        MethodId::setFieldFP | MethodId::getField => Some(0),
        MethodId::setA | MethodId::getA => Some(1),
        MethodId::setB | MethodId::getB => Some(2),
        MethodId::setG | MethodId::getG => Some(3),
        MethodId::setR | MethodId::getR => Some(4),
        _ => None,
    };
    if let Some(id) = parameter {
        let set = matches!(method, MethodId::setFieldFP | MethodId::setA | MethodId::setB | MethodId::setG | MethodId::setR);
        let length = if set { Some(frame.pop_short()?) } else { None };
        let offset = frame.pop_short()?;
        let array = frame.pop_reference()?;
        let key = frame.pop_reference()?;
        check_key(heap, key, context)?;
        heap.check_access(array, context)?;
        if offset < 0 { return Err(Error::Bounds); }
        let Some(expected) = host.p256_parameter(id) else { return crypto_exception(heap, context, 3).map(Some); };
        let flags = flags(heap, key)?;
        if let Some(length) = length {
            if length < 0 { return Err(Error::Bounds); }
            if heap.byte_slice(array, offset as usize, length as usize)? != expected {
                return crypto_exception(heap, context, 1).map(Some);
            }
            set_flags(heap, key, flags | (1 << id), context)?;
        } else {
            if flags & (1 << id) == 0 { return crypto_exception(heap, context, 2).map(Some); }
            heap.byte_slice_mut(array, offset as usize, expected.len())?.copy_from_slice(expected);
            frame.push_short(expected.len() as i16)?;
        }
        return Ok(Some(Native::Returned));
    }
    match method {
        MethodId::setK | MethodId::getK => {
            let cofactor = if method == MethodId::setK { Some(frame.pop_short()?) } else { None };
            let key = frame.pop_reference()?;
            check_key(heap, key, context)?;
            let flags = flags(heap, key)?;
            if let Some(value) = cofactor {
                if value != 1 { return crypto_exception(heap, context, 1).map(Some); }
                set_flags(heap, key, flags | 0x20, context)?;
            } else {
                if flags & 0x20 == 0 { return crypto_exception(heap, context, 2).map(Some); }
                frame.push_short(1)?;
            }
        }
        MethodId::copyDomainParametersFrom => {
            let source = frame.pop_reference()?;
            let key = frame.pop_reference()?;
            check_key(heap, source, context)?;
            check_key(heap, key, context)?;
            let source_flags = flags(heap, source)?;
            if source_flags & 0x1f != 0x1f { return crypto_exception(heap, context, 2).map(Some); }
            let value = (flags(heap, key)? & 0x40) | (source_flags & 0x3f);
            set_flags(heap, key, value, context)?;
        }
        MethodId::setS | MethodId::setW => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            let key = frame.pop_reference()?;
            let kind = check_key(heap, key, context)?;
            let private = kind != 11;
            heap.check_access(array, context)?;
            if offset < 0 || length < 0 { return Err(Error::Bounds); }
            if (method == MethodId::setS) != private || (private && !(1..=32).contains(&length))
                || (!private && length != 65) { return crypto_exception(heap, context, 1).map(Some); }
            let bytes = if private { 32 } else { 65 };
            let mut staged = Zeroizing::new([0u8; 65]);
            staged[bytes - length as usize..bytes].copy_from_slice(heap.byte_slice(array, offset as usize, length as usize)?);
            if !host.p256_key_valid(private, &staged[..bytes])? { return crypto_exception(heap, context, 1).map(Some); }
            let material = material(heap, key, context)?;
            heap.byte_slice_mut(material, 1, bytes)?.copy_from_slice(&staged[..bytes]);
            heap.byte_slice_mut(material, 0, 1)?[0] |= 0x40;
        }
        MethodId::getS | MethodId::getW => {
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            let key = frame.pop_reference()?;
            let private = check_key(heap, key, context)? != 11;
            heap.check_access(array, context)?;
            if offset < 0 { return Err(Error::Bounds); }
            if (method == MethodId::getS) != private { return crypto_exception(heap, context, 1).map(Some); }
            let material = heap.get_word(key, MATERIAL)?;
            if material == NULL || heap.byte_slice(material, 0, 1)?[0] & 0x40 == 0 { return crypto_exception(heap, context, 2).map(Some); }
            let bytes = if private { 32 } else { 65 };
            let mut staged = Zeroizing::new([0u8; 65]);
            staged[..bytes].copy_from_slice(heap.byte_slice(material, 1, bytes)?);
            heap.byte_slice_mut(array, offset as usize, bytes)?.copy_from_slice(&staged[..bytes]);
            frame.push_short(bytes as i16)?;
        }
        _ => return Ok(None),
    }
    Ok(Some(Native::Returned))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Provider { fail: bool }
    impl crate::host::Host for Provider {
        fn p256_parameter(&self, id: u8) -> Option<&'static [u8]> {
            match id { 0..=2 | 4 => Some(&[0x17; 32]), 3 => Some(&[0x24; 65]), _ => None }
        }
        fn p256_key_valid(&mut self, private: bool, bytes: &[u8]) -> Result<bool> {
            assert_eq!(bytes.len(), if private { 32 } else { 65 });
            if self.fail { Err(Error::Unauthorized) }
            else if private { Ok(bytes.iter().any(|byte| *byte != 0)) }
            else { Ok(bytes[0] == 4 && bytes[1..].iter().any(|byte| *byte != 0)) }
        }
    }

    #[test]
    fn factory_limits_curve_profile_and_public_import_uses_provider() {
        let signature = crate::jcvm_api::PACKAGES.iter()
            .flat_map(|package| package.classes).find(|class| class.id == ClassId::KeyBuilder).unwrap()
            .methods.iter().find(|method| method.id == MethodId::buildKey).unwrap().signature;
        let mut slab = [0; 4096];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false };
        let mut public = 0;
        for (kind, size, encrypted, accepted) in [
            (11, 256, 0, true), (12, 256, 0, true), (30, 256, 0, true), (31, 256, 0, true),
            (9, 256, 0, false), (10, 256, 0, false), (28, 256, 0, false),
            (29, 256, 0, false), (12, 384, 0, false), (12, 256, 1, false),
        ] {
            frame.push_short(kind).unwrap();
            frame.push_short(size).unwrap();
            frame.push_short(encrypted).unwrap();
            let result = super::super::call(ClassId::KeyBuilder, MethodId::buildKey, signature,
                &mut heap, &mut host, &mut frame, 1, &mut Jcre::new(0, 0), &mut { u32::MAX }).unwrap();
            if accepted {
                assert!(matches!(result, Native::Returned));
                let key = frame.pop_reference().unwrap();
                if kind == 11 { public = key; }
                assert!(!initialized(&heap, key).unwrap());
            } else {
                let Native::Threw(exception) = result else { panic!("unsupported key accepted"); };
                assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(3));
            }
        }
        let array = heap.new_array(heap::KIND_BYTE, 65, 1).unwrap();
        heap.byte_slice_mut(array, 0, 65).unwrap().fill(7);
        heap.array_put(array, 0, 4).unwrap();
        for (length, fail) in [(65, false), (33, false), (65, true)] {
            host.fail = fail;
            frame.push_reference(public).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(length).unwrap();
            let result = call(ClassId::ECPublicKey, MethodId::setW, &mut heap, &mut host, &mut frame, 1);
            match (length, fail) {
                (33, _) => assert!(matches!(result, Ok(Some(Native::Threw(_))))),
                (_, true) => assert!(matches!(result, Err(Error::Unauthorized))),
                _ => assert!(matches!(result, Ok(Some(Native::Returned)))),
            }
            heap.byte_slice_mut(array, 0, 65).unwrap().fill(0);
            frame.push_reference(public).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            assert!(matches!(call(ClassId::ECPublicKey, MethodId::getW,
                &mut heap, &mut host, &mut frame, 1), Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short(), Ok(65));
            assert_eq!(heap.array_get(array, 0), Ok(4));
            assert_eq!(heap.byte_slice(array, 1, 64).unwrap(), &[7; 64]);
        }
    }

    #[test]
    fn domain_methods_validate_before_mutation_and_copy_optional_cofactor() {
        let mut slab = [0; 2048];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut keys = [0; 2];
        for key in &mut keys {
            *key = crate::natives::new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
            heap.put_word(*key, KIND, 12).unwrap();
            heap.put_word(*key, SIZE, 256).unwrap();
        }
        let array = heap.new_array(heap::KIND_BYTE, 65, 1).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false };
        for (id, set, get) in [
            (0, MethodId::setFieldFP, MethodId::getField),
            (1, MethodId::setA, MethodId::getA),
            (2, MethodId::setB, MethodId::getB),
            (3, MethodId::setG, MethodId::getG),
            (4, MethodId::setR, MethodId::getR),
        ] {
            let expected = crate::host::Host::p256_parameter(&host, id).unwrap();
            for valid in [false, true] {
                heap.byte_slice_mut(array, 0, expected.len()).unwrap().copy_from_slice(expected);
                if !valid { heap.array_put(array, 0, 0).unwrap(); }
                let before = flags(&heap, keys[0]).unwrap();
                frame.push_reference(keys[0]).unwrap();
                frame.push_reference(array).unwrap();
                frame.push_short(0).unwrap();
                frame.push_short(expected.len() as i16).unwrap();
                let result = call(ClassId::ECKey, set, &mut heap, &mut host, &mut frame, 1).unwrap();
                if valid { assert!(matches!(result, Some(Native::Returned))); }
                else {
                    assert!(matches!(result, Some(Native::Threw(_))));
                    assert_eq!(flags(&heap, keys[0]).unwrap(), before);
                }
            }
            heap.byte_slice_mut(array, 0, 65).unwrap().fill(0);
            frame.push_reference(keys[0]).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            assert!(matches!(call(ClassId::ECKey, get, &mut heap, &mut host, &mut frame, 1),
                Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short(), Ok(expected.len() as i16));
            assert_eq!(heap.byte_slice(array, 0, expected.len()).unwrap(), expected);
        }
        // Copying domains keeps the destination's scalar-ready bit and optional K state.
        set_flags(&mut heap, keys[1], 0x40, 1).unwrap();
        for cofactor in [false, true] {
            if cofactor {
                frame.push_reference(keys[0]).unwrap();
                frame.push_short(1).unwrap();
                assert!(matches!(call(ClassId::ECKey, MethodId::setK, &mut heap, &mut host, &mut frame, 1),
                    Ok(Some(Native::Returned))));
            }
            frame.push_reference(keys[1]).unwrap();
            frame.push_reference(keys[0]).unwrap();
            assert!(matches!(call(ClassId::ECKey, MethodId::copyDomainParametersFrom,
                &mut heap, &mut host, &mut frame, 1), Ok(Some(Native::Returned))));
            assert!(initialized(&heap, keys[1]).unwrap());
            assert_eq!(flags(&heap, keys[1]).unwrap() & 0x20 != 0, cofactor);
        }
    }

    #[test]
    fn scalar_methods_pad_validate_and_preserve_key_on_failure() {
        let mut slab = [0; 1024];
        let mut heap = Heap::new(&mut slab).unwrap();
        let key = crate::natives::new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
        heap.put_word(key, KIND, 12).unwrap();
        heap.put_word(key, SIZE, 256).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 40, 1).unwrap();
        heap.array_put(array, 3, 7).unwrap();
        let mut words = [0; 16];
        let mut tags = [0; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = Provider { fail: false };
        for (length, fail) in [(1, false), (0, false), (1, true)] {
            host.fail = fail;
            frame.push_reference(key).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(3).unwrap();
            frame.push_short(length).unwrap();
            let result = call(ClassId::ECPrivateKey, MethodId::setS, &mut heap, &mut host, &mut frame, 1);
            match (length, fail) {
                (0, _) => assert!(matches!(result, Ok(Some(Native::Threw(_))))),
                (_, true) => assert!(matches!(result, Err(Error::Unauthorized))),
                _ => assert!(matches!(result, Ok(Some(Native::Returned)))),
            }
            // Export also exercises overlap with the original scalar input.
            frame.push_reference(key).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(3).unwrap();
            assert!(matches!(call(ClassId::ECPrivateKey, MethodId::getS,
                &mut heap, &mut host, &mut frame, 1), Ok(Some(Native::Returned))));
            assert_eq!(frame.pop_short(), Ok(32));
            let value = heap.byte_slice(array, 3, 32).unwrap();
            assert!(value[..31].iter().all(|byte| *byte == 0));
            assert_eq!(value[31], 7);
            assert!(!initialized(&heap, key).unwrap());
        }
        frame.push_reference(key).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(9).unwrap();
        assert!(matches!(call(ClassId::ECPrivateKey, MethodId::getS,
            &mut heap, &mut host, &mut frame, 1), Err(Error::Bounds)));
        assert_eq!(heap.array_get(array, 34), Ok(7));
    }

    #[test]
    fn initialization_and_parameter_flags_follow_key_lifetime() {
        for (kind, survives_deselect, survives_reset) in
            [(12, true, true), (30, true, false), (31, false, false)]
        {
            let mut slab = [0; 512];
            let mut heap = Heap::new(&mut slab).unwrap();
            let key = crate::natives::new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
            heap.put_word(key, KIND, kind).unwrap();
            heap.put_word(key, SIZE, 256).unwrap();
            assert!(!initialized(&heap, key).unwrap());
            // A scalar alone and domain parameters alone are both insufficient.
            for value in [0x40, 0x1f] {
                set_flags(&mut heap, key, value, 1).unwrap();
                assert!(!initialized(&heap, key).unwrap());
            }
            set_flags(&mut heap, key, 0x5f, 1).unwrap();
            assert!(initialized(&heap, key).unwrap());
            assert_eq!(flags(&heap, key).unwrap() & 0x20, 0);
            let array = material(&mut heap, key, 1).unwrap();
            heap.byte_slice_mut(array, 1, 32).unwrap().fill(7);
            heap.clear_transient(heap::CLEAR_ON_DESELECT, 1).unwrap();
            assert_eq!(initialized(&heap, key).unwrap(), survives_deselect);
            heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
            assert_eq!(initialized(&heap, key).unwrap(), survives_reset);
            if !survives_reset {
                assert_eq!(heap.byte_slice(array, 0, 33).unwrap(), &[0; 33]);
            }
        }
    }
}
