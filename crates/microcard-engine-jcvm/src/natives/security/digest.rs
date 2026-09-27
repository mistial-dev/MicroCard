use super::*;

/// Bytes a digest algorithm produces, JCRE §5.4.
pub fn digest_length(algorithm: u8) -> Result<usize> {
    Ok(match algorithm {
        1 | 3 => 20,
        2 => 16,
        4 | 9 => 32,
        5 | 10 => 48,
        6 | 11 => 64,
        7 | 8 => 28,
        _ => return Err(Error::Unsupported),
    })
}

/// A temporary digest cannot outlive the applet entry point which opened it.
pub(crate) fn release_one_shot_digests(heap: &mut Heap) -> Result<()> {
    heap.visit_objects(|_, info, payload| {
        if info.kind == heap::KIND_OBJECT
            && info.length == STATE_WORDS
            && super::super::api_class(info.class)
                .is_some_and(|class| class.id == ClassId::MessageDigest_OneShot)
        {
            payload[READY * 2..READY * 2 + 2].fill(0);
            // No applet local can retain a reference across this boundary.
            payload[SIZE * 2 + 1] = 1;
        }
        Ok(())
    })
}

pub(super) fn one_shot_digest(heap: &Heap, this: u16, context: heap::Context) -> Result<bool> {
    let info = heap.info(this)?;
    let one_shot = super::super::api_class(info.class)
        .is_some_and(|class| class.id == ClassId::MessageDigest_OneShot);
    if one_shot {
        if info.owner != 0 || word_field(heap, this, COUNTER)? != context as u16 {
            return Err(Error::Firewall);
        }
    } else {
        heap.check_access(this, context)?;
    }
    Ok(one_shot)
}

pub(super) fn one_shot_slot(heap: &Heap) -> Result<(bool, Option<u16>)> {
    let image = heap.image();
    let mut at = 2usize;
    let mut reusable = None;
    while at < heap.used() {
        let info = heap::Info::read(image, heap.used(), at as u16)?;
        if info.kind == heap::KIND_OBJECT
            && info.length == STATE_WORDS
            && super::super::api_class(info.class)
                .is_some_and(|class| class.id == ClassId::MessageDigest_OneShot)
        {
            if image[at + heap::HEADER + READY * 2 + 1] != 0 {
                return Ok((true, None));
            }
            if image[at + heap::HEADER + SIZE * 2 + 1] != 0 {
                reusable = Some(at as u16);
            }
        }
        at = (at + heap::HEADER + info.length as usize * info.element_size()).next_multiple_of(2);
    }
    Ok((false, reusable))
}

pub(super) fn call(
    method: MethodId,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Native> {
    match method {
        MethodId::reset => {
            let this = frame.pop_reference()?;
            if one_shot_digest(heap, this, context)? && word_field(heap, this, READY)? == 0 {
                return crypto_exception(heap, context, 5); // ILLEGAL_USE
            }
            if !matches!(word_field(heap, this, KIND)?, 1 | 4 | 5 | 6 | 7) {
                return Err(Error::Unsupported);
            }
            let pending = heap.get_word(this, PENDING)?;
            if pending != NULL {
                heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
            }
        }
        MethodId::update => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if one_shot_digest(heap, this, context)? {
                return crypto_exception(heap, context, 5); // ILLEGAL_USE, even for zero bytes
            }
            heap.check_access(input, context)?;
            let algorithm = word_field(heap, this, KIND)?;
            if !matches!(algorithm, 1 | 4 | 5 | 6 | 7) {
                return Err(Error::Unsupported);
            }
            if length < 0 || offset < 0 {
                return Err(Error::Bounds);
            }
            heap.byte_slice(input, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            if length == 0 {
                return Ok(Native::Returned);
            }
            let pending = heap.get_word(this, PENDING)?;
            let mut state = Zeroizing::new([0u8; SHA256_STATE_BYTES]);
            if pending == NULL {
                heap.check_allocations(&[(heap::KIND_BYTE, SHA256_STATE_BYTES as u16)])?;
                heap.prepare_payload_writes(&[(this, PENDING * 2, 2)])?;
            } else {
                state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
            }
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            match algorithm {
                1 => host.sha1_stream(&mut state, message, None)?,
                4 => host.sha256_stream(&mut state, message, None)?,
                5 => host.sha384_stream(&mut state, message, None)?,
                6 => host.sha512_stream(&mut state, message, None)?,
                7 => host.sha224_stream(&mut state, message, None)?,
                _ => unreachable!(),
            }
            let pending = if pending == NULL {
                let array = heap.new_transient_array(
                    heap::KIND_BYTE,
                    SHA256_STATE_BYTES as u16,
                    context,
                    heap::CLEAR_ON_RESET,
                )?;
                heap.put_word(this, PENDING, array)?;
                array
            } else {
                pending
            };
            heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?
                .copy_from_slice(&state[..]);
        }
        MethodId::doFinal => {
            let out_offset = frame.pop_short()?;
            let output = frame.pop_reference()?;
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if one_shot_digest(heap, this, context)? && word_field(heap, this, READY)? == 0 {
                return crypto_exception(heap, context, 5);
            }
            let algorithm = word_field(heap, this, KIND)? as u8;
            heap.check_access(input, context)?;
            heap.check_access(output, context)?;
            if length < 0 || offset < 0 || out_offset < 0 {
                return Err(Error::Bounds);
            }
            let expected = digest_length(algorithm)?;
            // Validate before invoking the provider. Fixed scratch allows overlapping
            // input/output without copying the message or publishing partial results.
            heap.byte_slice(output, out_offset as usize, expected)?;
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let mut digest = Zeroizing::new([0u8; 64]);
            let pending = heap.get_word(this, PENDING)?;
            let written = if matches!(algorithm, 1 | 4 | 5 | 6 | 7) && pending != NULL {
                let mut state = Zeroizing::new([0u8; SHA256_STATE_BYTES]);
                state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
                match algorithm {
                    1 => {
                        let output: &mut [u8; 20] = (&mut digest[..20]).try_into().unwrap();
                        host.sha1_stream(&mut state, message, Some(output))?;
                        20
                    }
                    4 => {
                        let output: &mut [u8; 32] = (&mut digest[..32]).try_into().unwrap();
                        host.sha256_stream(&mut state, message, Some(output))?;
                        32
                    }
                    5 => {
                        let output: &mut [u8; 48] = (&mut digest[..48]).try_into().unwrap();
                        host.sha384_stream(&mut state, message, Some(output))?;
                        48
                    }
                    6 => {
                        let output: &mut [u8; 64] = (&mut digest[..64]).try_into().unwrap();
                        host.sha512_stream(&mut state, message, Some(output))?;
                        64
                    }
                    7 => {
                        let output: &mut [u8; 28] = (&mut digest[..28]).try_into().unwrap();
                        host.sha224_stream(&mut state, message, Some(output))?;
                        28
                    }
                    _ => unreachable!(),
                }
            } else {
                host.digest(algorithm, message, &mut digest[..expected])?
            };
            if written != expected {
                return Err(Error::Format);
            }
            heap.byte_slice_mut(output, out_offset as usize, written)?
                .copy_from_slice(&digest[..written]);
            if pending != NULL {
                heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
            }
            frame.push_short(written as i16)?;
        }
        MethodId::getLength => {
            let this = frame.pop_reference()?;
            if one_shot_digest(heap, this, context)? && word_field(heap, this, READY)? == 0 {
                return crypto_exception(heap, context, 5);
            }
            let algorithm = word_field(heap, this, KIND)? as u8;
            frame.push_short(digest_length(algorithm)? as i16)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
