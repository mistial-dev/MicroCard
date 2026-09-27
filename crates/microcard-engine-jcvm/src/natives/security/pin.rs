//! OwnerPIN state, transaction exceptions and durable retry checkpoints.
use super::{
    checkpoint_committed, ensure_checkpoint_capacity, COUNTER, KIND, MATERIAL, READY, SIZE,
};
use crate::jcvm_api::{ClassId, MethodId};
use crate::natives::{new_exception, new_native, word_field, Jcre, Native, REASON_FIELD};
use crate::vm::{
    frame::Frame,
    heap::{self, Heap},
};
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

fn initialize(
    heap: &mut Heap,
    this: u16,
    tries: i16,
    max_size: i16,
    context: heap::Context,
) -> Result<Option<Native>> {
    if !(1..=127).contains(&tries) || !(1..=127).contains(&max_size) {
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

pub(super) fn build(heap: &mut Heap, frame: &mut Frame, context: heap::Context) -> Result<Native> {
    let pin_type = frame.pop_short()?;
    let max_size = frame.pop_short()?;
    let tries = frame.pop_short()?;
    let class = match pin_type {
        1 => ClassId::OwnerPIN,
        2 => ClassId::OwnerPINx,
        3 => ClassId::OwnerPINxWithPredecrement,
        _ => {
            let exception = new_exception(heap, ClassId::PINException, context)?;
            heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
            return Ok(Native::Threw(exception));
        }
    };
    if !(1..=127).contains(&tries) || !(1..=127).contains(&max_size) {
        let exception = new_exception(heap, ClassId::PINException, context)?;
        heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
        return Ok(Native::Threw(exception));
    }
    let allocations = [
        (heap::KIND_OBJECT, super::STATE_WORDS),
        (heap::KIND_BYTE, max_size as u16),
        (heap::KIND_BYTE, u16::from(pin_type == 3)),
    ];
    heap.check_allocations(&allocations[..if pin_type == 3 { 3 } else { 2 }])?;
    let this = new_native(heap, class, super::STATE_WORDS, context)?;
    if let Some(result) = initialize(heap, this, tries, max_size, context)? {
        return Ok(result);
    }
    if pin_type == 3 {
        let flag = heap.new_transient_array(heap::KIND_BYTE, 1, context, heap::CLEAR_ON_RESET)?;
        heap.put_word(this, super::PENDING, flag)?;
    }
    frame.push_reference(this)?;
    Ok(Native::Returned)
}

fn pin_class(heap: &Heap, this: u16, declared: ClassId, context: heap::Context) -> Result<ClassId> {
    heap.check_access(this, context)?;
    let actual = crate::natives::api_class(heap.info(this)?.class)
        .map(|class| class.id)
        .ok_or(Error::Type)?;
    let allowed = match declared {
        ClassId::PIN => matches!(
            actual,
            ClassId::OwnerPIN | ClassId::OwnerPINx | ClassId::OwnerPINxWithPredecrement
        ),
        ClassId::OwnerPINx => matches!(
            actual,
            ClassId::OwnerPINx | ClassId::OwnerPINxWithPredecrement
        ),
        _ => actual == declared,
    };
    if !allowed {
        return Err(Error::Type);
    }
    Ok(actual)
}

fn clear_predecrement(heap: &mut Heap, this: u16, actual: ClassId) -> Result<bool> {
    if actual != ClassId::OwnerPINxWithPredecrement {
        return Ok(false);
    }
    let flag = heap.get_word(this, super::PENDING)?;
    let state = heap.byte_slice_mut(flag, 0, 1)?;
    let pending = state[0] != 0;
    state[0] = 0;
    Ok(pending)
}

fn pin_exception(heap: &mut Heap, context: heap::Context, reason: u16) -> Result<Native> {
    let exception = new_exception(heap, ClassId::PINException, context)?;
    heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call(
    declared: ClassId,
    method: MethodId,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &Jcre,
    statics: &[u8],
) -> Result<Native> {
    match method {
        MethodId::Constructor => {
            let max_size = frame.pop_short()?;
            let tries = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if pin_class(heap, this, declared, context)? != ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            if let Some(result) = initialize(heap, this, tries, max_size, context)? {
                return Ok(result);
            }
        }
        MethodId::update => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            heap.check_access(source, context)?;
            let material = heap.get_word(this, MATERIAL)?;
            if length >= 0 && length as u16 > heap.info(material)?.length {
                let exception = new_exception(heap, ClassId::PINException, context)?;
                heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
                return Ok(Native::Threw(exception));
            }
            if length < 0 || offset < 0 {
                return Err(Error::Bounds);
            }
            let length = length as usize;
            // Validate and reserve all conditional writes before publishing the new PIN.
            heap.byte_slice(source, offset as usize, length)?;
            let writes = [
                (this, SIZE * 2, 2),
                (this, COUNTER * 2, 2),
                (material, 0, length),
                (this, READY * 2, 2),
            ];
            heap.prepare_payload_writes(
                &writes[..if actual == ClassId::OwnerPIN { 3 } else { 4 }],
            )?;
            heap.copy_bytes(source, offset as usize, material, 0, length)?;
            heap.put_word(this, SIZE, length as u16)?;
            // Updating resets the counter and clears the validated flag, JCRE §5.1.
            let tries = heap.get_word(this, KIND)?;
            heap.put_word(this, COUNTER, tries)?;
            if actual == ClassId::OwnerPIN {
                heap.put_word_unconditional(this, READY, 0)?;
            } else {
                heap.put_word(this, READY, 0)?;
                clear_predecrement(heap, this, actual)?;
            }
        }
        MethodId::check => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let candidate = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            let predecremented = clear_predecrement(heap, this, actual)?;
            if actual == ClassId::OwnerPINxWithPredecrement && !predecremented {
                return pin_exception(heap, context, 2);
            }
            let tries = heap.get_word(this, COUNTER)?;
            let validated = heap.get_word(this, READY)? != 0;
            let first_checkpoint = (!predecremented && tries != 0) || validated;
            let possible_success = tries != 0;
            ensure_checkpoint_capacity(
                u32::from(first_checkpoint) + u32::from(possible_success),
                host,
                jcre,
            )?;
            // Presentation spends the attempt durably before comparing.
            if !predecremented {
                heap.put_word_unconditional(this, COUNTER, tries.saturating_sub(1))?;
            }
            heap.put_word_unconditional(this, READY, 0)?;
            checkpoint_committed(first_checkpoint, heap, host, jcre, context, statics)?;
            if candidate == crate::vm::NULL {
                return Ok(Native::Threw(new_exception(
                    heap,
                    ClassId::NullPointerException,
                    context,
                )?));
            }
            heap.check_access(candidate, context)?;
            if length < 0
                || offset < 0
                || usize::from(offset as u16) + usize::from(length as u16)
                    > usize::from(heap.info(candidate)?.length)
            {
                return Ok(Native::Threw(new_exception(
                    heap,
                    ClassId::ArrayIndexOutOfBoundsException,
                    context,
                )?));
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
                checkpoint_committed(true, heap, host, jcre, context, statics)?;
            }
            frame.push_short(matched as i16)?;
        }
        MethodId::setValidatedFlag => {
            let value = frame.pop_short()? != 0;
            let this = frame.pop_reference()?;
            if pin_class(heap, this, declared, context)? != ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            // Unlike PIN presentation, this accessor has no transaction exception
            // in the API contract; internal state follows JCRE §9.3.
            heap.put_word(this, READY, u16::from(value))?;
        }
        MethodId::isValidated | MethodId::getValidatedFlag => {
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            if method == MethodId::getValidatedFlag && actual != ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            frame.push_short(word_field(heap, this, READY)? as i16)?;
        }
        MethodId::getTriesRemaining => {
            let this = frame.pop_reference()?;
            pin_class(heap, this, declared, context)?;
            frame.push_short(word_field(heap, this, COUNTER)? as i16)?;
        }
        MethodId::reset => {
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            clear_predecrement(heap, this, actual)?;
            if heap.get_word(this, READY)? != 0 {
                ensure_checkpoint_capacity(1, host, jcre)?;
                let limit = heap.get_word(this, KIND)?;
                heap.put_word_unconditional(this, COUNTER, limit)?;
                heap.put_word_unconditional(this, READY, 0)?;
                checkpoint_committed(true, heap, host, jcre, context, statics)?;
            }
        }
        MethodId::resetAndUnblock => {
            let this = frame.pop_reference()?;
            if pin_class(heap, this, declared, context)? != ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            let limit = heap.get_word(this, KIND)?;
            let changed =
                heap.get_word(this, COUNTER)? != limit || heap.get_word(this, READY)? != 0;
            if changed {
                ensure_checkpoint_capacity(1, host, jcre)?;
            }
            heap.put_word_unconditional(this, COUNTER, limit)?;
            heap.put_word_unconditional(this, READY, 0)?;
            checkpoint_committed(changed, heap, host, jcre, context, statics)?;
        }

        MethodId::getTryLimit => {
            let this = frame.pop_reference()?;
            if pin_class(heap, this, declared, context)? == ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            frame.push_short(word_field(heap, this, KIND)? as i16)?;
        }
        MethodId::setTryLimit => {
            let limit = frame.pop_short()?;
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            if actual == ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            if !(1..=127).contains(&limit) {
                return pin_exception(heap, context, 1);
            }
            heap.prepare_payload_writes(&[
                (this, KIND * 2, 2),
                (this, COUNTER * 2, 2),
                (this, READY * 2, 2),
            ])?;
            heap.put_word(this, KIND, limit as u16)?;
            heap.put_word(this, COUNTER, limit as u16)?;
            heap.put_word(this, READY, 0)?;
            clear_predecrement(heap, this, actual)?;
        }
        MethodId::setTriesRemaining => {
            let remaining = frame.pop_short()?;
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            if actual == ClassId::OwnerPIN {
                return Err(Error::Type);
            }
            if remaining < 0 || remaining as u16 > heap.get_word(this, KIND)? {
                return pin_exception(heap, context, 1);
            }
            heap.prepare_payload_writes(&[(this, COUNTER * 2, 2), (this, READY * 2, 2)])?;
            heap.put_word(this, COUNTER, remaining as u16)?;
            heap.put_word(this, READY, 0)?;
            clear_predecrement(heap, this, actual)?;
        }
        MethodId::decrementTriesRemaining => {
            let this = frame.pop_reference()?;
            let actual = pin_class(heap, this, declared, context)?;
            if actual != ClassId::OwnerPINxWithPredecrement {
                return Err(Error::Type);
            }
            let tries = heap.get_word(this, COUNTER)?;
            let validated = heap.get_word(this, READY)? != 0;
            let next = tries.saturating_sub(1);
            if tries != 0 || validated {
                ensure_checkpoint_capacity(1, host, jcre)?;
            }
            heap.put_word_unconditional(this, COUNTER, next)?;
            heap.put_word_unconditional(this, READY, 0)?;
            checkpoint_committed(tries != 0 || validated, heap, host, jcre, context, statics)?;
            let flag = heap.get_word(this, super::PENDING)?;
            heap.byte_slice_mut(flag, 0, 1)?[0] = 1;
            frame.push_short(next as i16)?;
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
