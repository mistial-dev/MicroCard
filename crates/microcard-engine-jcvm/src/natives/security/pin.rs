//! OwnerPIN state, transaction exceptions and durable retry checkpoints.
use super::{COUNTER, KIND, MATERIAL, READY, SIZE, checkpoint_committed};
use crate::natives::{Jcre, Native, new_exception, word_field, REASON_FIELD};
use crate::jcvm_api::{ClassId, MethodId};
use crate::vm::{frame::Frame, heap::{self, Heap}};
use crate::{Error, Result};

#[allow(clippy::too_many_arguments)]
pub(super) fn call(method: MethodId, heap: &mut Heap, host: &mut dyn crate::host::Host,
    frame: &mut Frame, context: heap::Context, jcre: &Jcre, statics: &[u8]) -> Result<Native> {
    match method {
        MethodId::Constructor => {
            let max_size = frame.pop_short()?;
            let tries = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if tries < 1 || max_size < 1 {
                let exception = new_exception(heap, ClassId::PINException, context)?;
                heap.put_word_unconditional(exception, REASON_FIELD, 1)?;
                return Ok(Native::Threw(exception));
            }
            let material = heap.new_array(heap::KIND_BYTE, max_size as u16, context)?;
            heap.put_word(this, KIND, tries as u16)?;
            heap.put_word(this, SIZE, 0)?;
            heap.put_word(this, MATERIAL, material)?;
            heap.put_word(this, READY, 0)?;
            heap.put_word(this, COUNTER, tries as u16)?;
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
            let matched = if tries == 0 || length as usize != stored {
                false
            } else {
                let mut equal = true;
                for at in 0..stored {
                    let left = heap.byte_slice(material, at, 1)?[0];
                    let right = heap.byte_slice(candidate, offset as usize + at, 1)?[0];
                    equal &= left == right;
                }
                equal
            };
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
