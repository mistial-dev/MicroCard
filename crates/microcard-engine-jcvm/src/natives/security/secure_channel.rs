//! Command-scoped access to the platform's verified ISD command.
use super::*;

pub(super) fn call(
    class: ClassId, method: MethodId, heap: &mut Heap, host: &mut dyn crate::host::Host,
    frame: &mut Frame, context: heap::Context, jcre: &Jcre,
) -> Result<Native> {
    if class == ClassId::GPSystem {
        if !host.secure_channel_available() {
            let exception = super::super::new_exception(heap, ClassId::SystemException, context)?;
            heap.put_word_unconditional(exception, super::super::REASON_FIELD, 5)?;
            return Ok(Native::Threw(exception));
        }
        // The handle has no mutable fields or authority and can be reused after recovery.
        let mut handle = None;
        heap.visit_objects(|reference, info, _| {
            if info.owner == context && info.kind == heap::KIND_OBJECT
                && super::super::api_class(info.class).is_some_and(|class| class.id == ClassId::SecureChannel) {
                handle = Some(reference);
            }
            Ok(())
        })?;
        let handle = match handle {
            Some(handle) => handle,
            None => new_native(heap, ClassId::SecureChannel, STATE_WORDS, context)?,
        };
        frame.push_reference(handle)?;
        return Ok(Native::Returned);
    }
    match method {
        MethodId::getSecurityLevel => {
            let handle = frame.pop_reference()?;
            heap.check_access(handle, context)?;
            frame.push_short(host.secure_channel_level() as i8 as i16)?;
            Ok(Native::Returned)
        }
        MethodId::resetSecurity => {
            let handle = frame.pop_reference()?;
            heap.check_access(handle, context)?;
            if host.reset_secure_channel().is_err() { return rejected(heap, context); }
            Ok(Native::Returned)
        }
        MethodId::unwrap => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let buffer = frame.pop_reference()?;
            let handle = frame.pop_reference()?;
            heap.check_access(handle, context)?;
            if buffer != jcre.buffer || offset != 0 || length < 5 {
                return rejected(heap, context);
            }
            heap.check_access(buffer, context)?;
            let bytes = heap.byte_slice_mut(buffer, 0, length as usize)?;
            if host.unwrap_secure_command(bytes).is_err() {
                return rejected(heap, context);
            }
            frame.push_short(length)?;
            Ok(Native::Returned)
        }
        // Transport owns handshake and response protection. The remaining applet
        // encryption operations are unavailable, rather than success-shaped stubs.
        _ => rejected(heap, context),
    }
}

fn rejected(heap: &mut Heap, context: heap::Context) -> Result<Native> {
    let exception = super::super::new_exception(heap, ClassId::ISOException, context)?;
    heap.put_word_unconditional(exception, super::super::REASON_FIELD, 0x6982)?;
    Ok(Native::Threw(exception))
}
