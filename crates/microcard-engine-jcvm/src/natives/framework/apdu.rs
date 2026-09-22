//! `javacard.framework.APDU`, JCRE §4.

use super::super::{Jcre, Native, REASON_FIELD, new_exception};
use crate::jcvm_api::{ClassId, MethodId};
use crate::vm::frame::Frame;
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

pub(in crate::natives) fn call(
    name: MethodId,
    heap: &mut Heap,
    frame: &mut Frame,
    jcre: &mut Jcre,
    context: heap::Context,
) -> Result<Native> {
    match name {
        // The host presents contacted T=1 semantics. A 254-byte information field plus
        // the seven-byte extended header fits the runtime's 261-byte APDU buffer.
        MethodId::getInBlockSize | MethodId::getOutBlockSize => frame.push_short(254)?,
        MethodId::getBuffer => {
            frame.pop_reference()?;
            frame.push_reference(jcre.buffer)?;
        }
        MethodId::getNAD => {
            frame.pop_reference()?;
            frame.push_short(0)?;
        }
        MethodId::getIncomingLength => {
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started {
                return exception(heap, context, 1);
            }
            frame.push_short(jcre.incoming as i16)?;
        }
        MethodId::getOffsetCdata => {
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started {
                return exception(heap, context, 1);
            }
            frame.push_short(jcre.data_offset as i16)?;
        }
        MethodId::setIncomingAndReceive => {
            frame.pop_reference()?;
            if jcre.incoming_started || jcre.outgoing_started {
                return exception(heap, context, 1);
            }
            jcre.incoming_started = true;
            frame.push_short(jcre.incoming as i16)?;
        }
        MethodId::receiveBytes => {
            let offset = frame.pop_short()?;
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started {
                return exception(heap, context, 1); // ILLEGAL_USE
            }
            if offset < 0 {
                return exception(heap, context, 2);
            }
            let offset = offset as usize;
            let buffer = heap.info(jcre.buffer)?;
            if offset
                .checked_add(254)
                .is_none_or(|end| end > buffer.length as usize)
            {
                return exception(heap, context, 2); // BUFFER_BOUNDS
            }
            // Commands are fully framed before entering the VM, so the first receive
            // consumed every byte and a legal follow-up has nothing left to copy.
            frame.push_short(0)?;
        }
        MethodId::setOutgoing | MethodId::setOutgoingNoChaining => {
            frame.pop_reference()?;
            if jcre.outgoing_started {
                return exception(heap, context, 1);
            }
            jcre.outgoing_started = true;
            frame.push_short(jcre.expected as i16)?;
        }
        MethodId::setOutgoingLength => {
            let length = frame.pop_short()?;
            frame.pop_reference()?;
            if !jcre.outgoing_started || jcre.outgoing_length.is_some() {
                return exception(heap, context, 1);
            }
            if length < 0 || length as usize > jcre.response.len() {
                return exception(heap, context, 3);
            }
            jcre.outgoing_length = Some(length as u16);
        }
        MethodId::setOutgoingAndSend | MethodId::sendBytes | MethodId::sendBytesLong => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = if name == MethodId::sendBytesLong {
                frame.pop_reference()?
            } else {
                jcre.buffer
            };
            frame.pop_reference()?;
            let combined = name == MethodId::setOutgoingAndSend;
            let declared = if combined {
                if jcre.outgoing_started {
                    return exception(heap, context, 1);
                }
                if length < 0 || length as usize > jcre.response.len() {
                    return exception(heap, context, 3);
                }
                length as u16
            } else {
                if jcre.outgoing_combined {
                    return exception(heap, context, 1);
                }
                let Some(declared) = jcre.outgoing_length else {
                    return exception(heap, context, 1);
                };
                declared
            };
            if offset < 0 || length < 0 {
                return exception(heap, context, 2);
            }
            let start = usize::from(jcre.outgoing);
            let end = start + length as usize;
            if end > usize::from(declared) {
                return exception(heap, context, 1);
            }
            heap.check_access(source, context)?;
            let bytes = match heap.byte_slice(source, offset as usize, length as usize) {
                Ok(bytes) => bytes,
                Err(Error::Bounds) => return exception(heap, context, 2),
                Err(error) => return Err(error),
            };
            // Publish output state only after both ranges are admitted.
            jcre.response[start..end].copy_from_slice(bytes);
            if combined {
                jcre.outgoing_started = true;
                jcre.outgoing_combined = true;
                jcre.outgoing_length = Some(declared);
            }
            jcre.outgoing = end as u16;
        }
        MethodId::isCommandChainingCLA | MethodId::isSecureMessagingCLA => {
            frame.pop_reference()?;
            let cla = heap.byte_slice(jcre.buffer, 0, 1)?[0];
            let valid = cla & 0xe0 != 0x20 && cla != 0xff;
            let bit = if name == MethodId::isCommandChainingCLA {
                0x10
            } else if cla & 0x40 != 0 {
                0x20
            } else {
                0x0c
            };
            frame.push_short((valid && cla & bit != 0) as i16)?;
        }
        MethodId::getProtocol => frame.push_short(0x01)?,
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

fn exception(heap: &mut Heap, context: heap::Context, reason: u16) -> Result<Native> {
    let exception = new_exception(heap, ClassId::APDUException, context)?;
    heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}
