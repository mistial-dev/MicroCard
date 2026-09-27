use super::*;

/// The class a `KeyBuilder` type code builds, JCRE Table 5-1.
///
/// Transient symmetric keys keep their initialized flag with their transient bytes.
fn key_class(key_type: i16) -> Option<ClassId> {
    Some(match key_type {
        1..=3 => ClassId::DESKey,
        4 => ClassId::RSAPublicKey,
        5 | 22 | 23 => ClassId::RSAPrivateKey,
        6 | 24 | 25 => ClassId::RSAPrivateCrtKey,
        9 => ClassId::ECPublicKey,
        10 | 28 | 29 => ClassId::ECPrivateKey,
        11 => ClassId::ECPublicKey,
        12 | 30 | 31 => ClassId::ECPrivateKey,
        13..=15 => ClassId::AESKey,
        _ => return None,
    })
}

pub(crate) fn symmetric_key_clear_event(kind: u16) -> u8 {
    match kind {
        1 | 13 | 19 => heap::CLEAR_ON_RESET,
        2 | 14 | 20 => heap::CLEAR_ON_DESELECT,
        _ => 0,
    }
}

pub(super) fn key_initialized(heap: &Heap, key: u16) -> Result<bool> {
    if ec::key_kind(word_field(heap, key, KIND)?) {
        return ec::initialized(heap, key);
    }
    if symmetric_key_clear_event(word_field(heap, key, KIND)?) == 0 {
        return Ok(word_field(heap, key, READY)? != 0);
    }
    let material = heap.get_word(key, MATERIAL)?;
    Ok(material != NULL && heap.byte_slice(material, 0, 1)?[0] == 1)
}

pub(super) fn call(
    class: ClassId,
    method: MethodId,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
) -> Result<Native> {
    match (class, method) {
        (ClassId::KeyBuilder, MethodId::buildKey) => {
            let _encryption = frame.pop_short()?;
            let length = frame.pop_short()?;
            let key_type = frame.pop_short()?;
            let Some(name) = key_class(key_type) else {
                return crypto_exception(heap, context, 3);
            };
            if (matches!(key_type, 1..=3) && !matches!(length, 64 | 128 | 192))
                || (matches!(key_type, 13..=15) && !matches!(length, 128 | 192 | 256))
            {
                return crypto_exception(heap, context, 3);
            }
            if matches!(key_type, 4..=6 | 22..=25)
                && !matches!(
                    length,
                    512 | 736 | 768 | 896 | 1024 | 1280 | 1536 | 1984 | 2048
                )
            {
                return crypto_exception(heap, context, 3);
            }
            if matches!(key_type, 9..=12 | 28..=31)
                && (!ec::key_kind(key_type as u16)
                    || length != 256
                    || _encryption != 0
                    || host.p256_parameter(0).is_none())
            {
                return crypto_exception(heap, context, 3);
            }
            let key = new_native(heap, name, STATE_WORDS, context)?;
            heap.put_word(key, KIND, key_type as u16)?;
            heap.put_word(key, SIZE, length as u16)?;
            frame.push_reference(key)?;
        }
        // Every key answers what it is and how long it is, and says whether it holds
        // anything yet, JCRE §5.3.
        (name, MethodId::getSize) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, SIZE)? as i16)?;
        }
        (name, MethodId::getType) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, KIND)? as i16)?;
        }
        (name, MethodId::isInitialized) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(i16::from(key_initialized(heap, key)?))?;
        }
        (name, MethodId::clearKey) if name.is_security() => {
            let key = frame.pop_reference()?;
            let kind = word_field(heap, key, KIND)?;
            let separate_flag = !ec::key_kind(kind) && symmetric_key_clear_event(kind) == 0;
            let material = heap.get_word(key, MATERIAL)?;
            if material != NULL {
                let length = heap.info(material)?.length as usize;
                if separate_flag {
                    heap.byte_slice(material, 0, length)?;
                    heap.prepare_payload_writes(&[(key, READY * 2, 2), (material, 0, length)])?;
                }
                heap.byte_slice_mut(material, 0, length)?.fill(0);
            }
            if separate_flag {
                heap.put_word(key, READY, 0)?;
            }
        }

        // Symmetric key material, JCRE §5.3. The bytes are copied into the key's own
        // array, which the applet cannot reach, so a key never sits in a buffer the applet
        // still holds a reference to.
        (ClassId::AESKey, MethodId::setKey)
        | (ClassId::DESKey, MethodId::setKey)
        | (ClassId::HMACKey, MethodId::setKey) => {
            let length = if class == ClassId::HMACKey {
                Some(frame.pop_short()?)
            } else {
                None
            };
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(source, context)?;
            let bits = word_field(heap, this, SIZE)? as usize;
            let bytes = length.map_or(bits / 8, |value| value.max(0) as usize);
            if offset < 0 || bytes == 0 || bytes > 64 {
                return Err(Error::Bounds);
            }
            let mut staging = Zeroizing::new([0u8; 64]);
            staging[..bytes].copy_from_slice(heap.byte_slice(source, offset as usize, bytes)?);
            let event = symmetric_key_clear_event(word_field(heap, this, KIND)?);
            let prefix = usize::from(event != 0);
            let material = match heap.get_word(this, MATERIAL)? {
                NULL => {
                    heap.check_allocations(&[(heap::KIND_BYTE, (bytes + prefix) as u16)])?;
                    heap.prepare_payload_writes(&[(
                        this,
                        MATERIAL * 2,
                        if event == 0 { 4 } else { 2 },
                    )])?;
                    let array = if event == 0 {
                        heap.new_array(heap::KIND_BYTE, bytes as u16, context)?
                    } else {
                        heap.new_transient_array(
                            heap::KIND_BYTE,
                            (bytes + prefix) as u16,
                            context,
                            event,
                        )?
                    };
                    heap.put_word(this, MATERIAL, array)?;
                    array
                }
                array => array,
            };
            // Admit bytes and readiness together, including catch-and-commit failures.
            heap.byte_slice(material, 0, bytes + prefix)?;
            if event == 0 {
                heap.prepare_payload_writes(&[(this, READY * 2, 2), (material, 0, bytes)])?;
            }
            let destination = heap.byte_slice_mut(material, 0, bytes + prefix)?;
            destination[prefix..].copy_from_slice(&staging[..bytes]);
            if event == 0 {
                heap.put_word(this, READY, 1)?;
            } else {
                destination[0] = 1;
            }
        }
        (ClassId::AESKey, MethodId::getKey)
        | (ClassId::DESKey, MethodId::getKey)
        | (ClassId::HMACKey, MethodId::getKey) => {
            let offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(destination, context)?;
            if !key_initialized(heap, this)? {
                let exception =
                    super::super::new_exception(heap, ClassId::CryptoException, context)?;
                heap.put_word_unconditional(exception, super::super::REASON_FIELD, 2)?; // UNINITIALIZED_KEY
                return Ok(Native::Threw(exception));
            }
            let material = heap.get_word(this, MATERIAL)?;
            let prefix = usize::from(symmetric_key_clear_event(word_field(heap, this, KIND)?) != 0);
            let bytes = (heap.info(material)?.length as usize)
                .checked_sub(prefix)
                .ok_or(Error::Format)?;
            if bytes > 64 || offset < 0 {
                return Err(Error::Bounds);
            }
            let mut staging = Zeroizing::new([0u8; 64]);
            staging[..bytes].copy_from_slice(heap.byte_slice(material, prefix, bytes)?);
            heap.byte_slice_mut(destination, offset as usize, bytes)?
                .copy_from_slice(&staging[..bytes]);
            frame.push_short(bytes as i16)?;
        }

        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
