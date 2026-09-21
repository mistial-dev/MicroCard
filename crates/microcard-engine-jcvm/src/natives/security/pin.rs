//! OwnerPIN state, transaction exceptions and durable retry checkpoints.
use super::{COUNTER, KIND, MATERIAL, READY, SIZE, checkpoint_committed};
use crate::natives::{Jcre, Native, new_exception, new_native, word_field, REASON_FIELD};
use crate::jcvm_api::{ClassId, MethodId};
use crate::vm::{frame::Frame, heap::{self, Heap}};
use crate::{Error, Result};

fn pin_matches(material: &[u8], stored_length: usize, candidate: &[u8], blocked: bool) -> bool {
    let mut different = stored_length ^ candidate.len();
    different |= usize::from(blocked);
    different |= usize::from(stored_length > material.len());
    for (at, stored) in material.iter().copied().enumerate() {
        let presented = candidate.get(at).copied().unwrap_or(0);
        let active = 0u8.wrapping_sub(u8::from(at < stored_length));
        different |= usize::from((stored ^ presented) & active);
    }
    different == 0
}

fn initialize(heap: &mut Heap, this: u16, tries: i16, max_size: i16,
    context: heap::Context) -> Result<Option<Native>> {
    if tries < 1 || max_size < 1 {
        let exception = new_exception(heap, ClassId::PINException, context)?;
        heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
        return Ok(Some(Native::Threw(exception)));
    }
    // A caught undo-capacity error must not publish a partially initialized PIN.
    heap.check_allocations(&[(heap::KIND_BYTE, max_size as u16)])?;
    heap.prepare_payload_writes(&[(this, 0, (COUNTER + 1) * 2)])?;
    let material = heap.new_array(heap::KIND_BYTE, max_size as u16, context)?;
    heap.put_word(this, KIND, tries as u16)?;
    heap.put_word(this, SIZE, 0)?;
    heap.put_word(this, MATERIAL, material)?;
    heap.put_word(this, READY, 0)?;
    heap.put_word(this, COUNTER, tries as u16)?;
    Ok(None)
}

pub(super) fn build(heap: &mut Heap, frame: &mut Frame,
    context: heap::Context) -> Result<Native> {
    let pin_type = frame.pop_short()?;
    let max_size = frame.pop_short()?;
    let tries = frame.pop_short()?;
    if pin_type != 1 {
        let (class, reason) = if matches!(pin_type, 2 | 3) {
            (ClassId::SystemException, 6) // Optional extended PIN types: ILLEGAL_USE.
        } else {
            (ClassId::PINException, 1) // Unknown type: ILLEGAL_VALUE.
        };
        let exception = new_exception(heap, class, context)?;
        heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
        return Ok(Native::Threw(exception));
    }
    if tries < 1 || max_size < 1 {
        return initialize(heap, 0, tries, max_size, context)?
            .ok_or(Error::Inconsistent);
    }
    heap.check_allocations(&[
        (heap::KIND_OBJECT, super::STATE_WORDS),
        (heap::KIND_BYTE, max_size as u16),
    ])?;
    let this = new_native(heap, ClassId::OwnerPIN, super::STATE_WORDS, context)?;
    if let Some(result) = initialize(heap, this, tries, max_size, context)? { return Ok(result); }
    frame.push_reference(this)?;
    Ok(Native::Returned)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call(method: MethodId, heap: &mut Heap, host: &mut dyn crate::host::Host,
    frame: &mut Frame, context: heap::Context, jcre: &Jcre, statics: &[u8]) -> Result<Native> {
    match method {
        MethodId::Constructor => {
            let max_size = frame.pop_short()?;
            let tries = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if let Some(result) = initialize(heap, this, tries, max_size, context)? { return Ok(result); }
        }
        MethodId::update => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(source, context)?;
            let material = heap.get_word(this, MATERIAL)?;
            if length >= 0 && length as u16 > heap.info(material)?.length {
                let exception = new_exception(heap, ClassId::PINException, context)?;
                heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
                return Ok(Native::Threw(exception));
            }
            if length < 0 || offset < 0 { return Err(Error::Bounds); }
            let length = length as usize;
            // Validate and reserve all conditional writes before publishing the new PIN.
            heap.byte_slice(source, offset as usize, length)?;
            heap.prepare_payload_writes(&[(this, SIZE * 2, 2), (this, COUNTER * 2, 2), (material, 0, length)])?;
            heap.copy_bytes(source, offset as usize, material, 0, length)?;
            heap.put_word(this, SIZE, length as u16)?;
            // Updating resets the counter and clears the validated flag, JCRE §5.1.
            let tries = heap.get_word(this, KIND)?;
            heap.put_word(this, COUNTER, tries)?;
            heap.put_word_unconditional(this, READY, 0)?;
        }
        MethodId::check => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let candidate = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let tries = heap.get_word(this, COUNTER)?;
            // The counter is decremented before the comparison, JCRE §5.1. A card cut off
            // mid check must not give the attempt back.
            heap.put_word_unconditional(this, COUNTER, tries.saturating_sub(1))?;
            heap.put_word_unconditional(this, READY, 0)?;
            checkpoint_committed(heap, host, jcre, context, statics)?;
            if candidate == crate::vm::NULL {
                return Ok(Native::Threw(new_exception(heap, ClassId::NullPointerException, context)?));
            }
            heap.check_access(candidate, context)?;
            if length < 0 || offset < 0
                || usize::from(offset as u16) + usize::from(length as u16) > usize::from(heap.info(candidate)?.length)
            {
                return Ok(Native::Threw(new_exception(heap, ClassId::ArrayIndexOutOfBoundsException, context)?));
            }
            let material = heap.get_word(this, MATERIAL)?;
            let stored = heap.get_word(this, SIZE)? as usize;
            let capacity = heap.info(material)?.length as usize;
            let matched = pin_matches(
                heap.byte_slice(material, 0, capacity)?,
                stored,
                heap.byte_slice(candidate, offset as usize, length as usize)?,
                tries == 0,
            );
            if matched {
                let limit = heap.get_word(this, KIND)?;
                heap.put_word_unconditional(this, COUNTER, limit)?;
                heap.put_word_unconditional(this, READY, 1)?;
                checkpoint_committed(heap, host, jcre, context, statics)?;
            }
            frame.push_short(matched as i16)?;
        }
        MethodId::setValidatedFlag => {
            let value = frame.pop_short()? != 0;
            let this = frame.pop_reference()?;
            // Unlike PIN presentation, this accessor has no transaction exception
            // in the API contract; internal state follows JCRE §9.3.
            heap.put_word(this, READY, u16::from(value))?;
        }
        MethodId::isValidated | MethodId::getValidatedFlag => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, READY)? as i16)?;
        }
        MethodId::getTriesRemaining => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, COUNTER)? as i16)?;
        }
        MethodId::reset => {
            let this = frame.pop_reference()?;
            if heap.get_word(this, READY)? != 0 {
                let limit = heap.get_word(this, KIND)?;
                heap.put_word_unconditional(this, COUNTER, limit)?;
                heap.put_word_unconditional(this, READY, 0)?;
                checkpoint_committed(heap, host, jcre, context, statics)?;
            }
        }
        MethodId::resetAndUnblock => {
            let this = frame.pop_reference()?;
            let limit = heap.get_word(this, KIND)?;
            heap.put_word_unconditional(this, COUNTER, limit)?;
            heap.put_word_unconditional(this, READY, 0)?;
            checkpoint_committed(heap, host, jcre, context, statics)?;
        }

        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

#[cfg(test)]
mod tests {
    use super::pin_matches;

    #[test]
    fn pin_comparison_folds_content_length_and_blocked_state_over_full_capacity() {
        let material = b"1234\0\0\0\0";
        assert!(pin_matches(material, 4, b"1234", false));
        for candidate in [b"0234".as_slice(), b"1230", b"123", b"12340"] {
            assert!(!pin_matches(material, 4, candidate, false));
        }
        assert!(!pin_matches(material, 4, b"1234", true));
        assert!(!pin_matches(material, 4, b"12340", true));
    }
}
