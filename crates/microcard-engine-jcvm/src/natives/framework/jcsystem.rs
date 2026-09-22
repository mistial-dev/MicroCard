//! `javacard.framework.JCSystem`, JCRE §7.

use super::super::{
    Jcre, Native, REASON_FIELD, TRANSACTION_CAPACITY, new_exception, transaction_exception,
};
use crate::jcvm_api::{ClassId, MethodId};
use crate::vm::frame::Frame;
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

#[allow(clippy::too_many_arguments)]
pub(in crate::natives) fn call(
    name: MethodId,
    token: u8,
    heap: &mut Heap,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
    statics: &mut [u8],
    host: &mut dyn crate::host::Host,
) -> Result<Native> {
    match name {
        MethodId::makeTransientByteArray
        | MethodId::makeTransientBooleanArray
        | MethodId::makeTransientShortArray
        | MethodId::makeTransientObjectArray => {
            let event = frame.pop_short()?;
            let length = frame.pop_short()?;
            if length < 0 {
                return Ok(Native::Threw(new_exception(
                    heap,
                    ClassId::NegativeArraySizeException,
                    context,
                )?));
            }
            let kind = match name {
                MethodId::makeTransientByteArray => heap::KIND_BYTE,
                MethodId::makeTransientBooleanArray => heap::KIND_BOOLEAN,
                MethodId::makeTransientShortArray => heap::KIND_SHORT,
                _ => heap::KIND_REFERENCE,
            };
            let event = match event {
                1 => heap::CLEAR_ON_RESET,
                2 => heap::CLEAR_ON_DESELECT,
                _ => {
                    let exception = new_exception(heap, ClassId::SystemException, context)?;
                    heap.put_word_unconditional(exception, REASON_FIELD, 1)?; // ILLEGAL_VALUE
                    return Ok(Native::Threw(exception));
                }
            };
            match heap.new_transient_array(kind, length as u16, context, event) {
                Ok(array) => frame.push_reference(array)?,
                Err(Error::Quota) => {
                    let exception = new_exception(heap, ClassId::SystemException, context)?;
                    heap.put_word_unconditional(exception, REASON_FIELD, 2)?; // NO_TRANSIENT_SPACE
                    return Ok(Native::Threw(exception));
                }
                Err(error) => return Err(error),
            }
        }
        MethodId::isTransient => {
            let reference = frame.pop_reference()?;
            frame.push_short(i16::from(heap.transient_event(reference)?))?;
        }
        MethodId::isObjectDeletionSupported => frame.push_short(0)?,
        MethodId::getVersion => frame.push_short(0x0305)?,
        MethodId::requestObjectDeletion => {}
        MethodId::getTransactionDepth => {
            frame.push_short(i16::from(heap.transaction_remaining().is_some()))?;
        }
        MethodId::getMaxCommitCapacity => frame.push_short(TRANSACTION_CAPACITY as i16)?,
        MethodId::getUnusedCommitCapacity => {
            frame.push_short(heap.transaction_remaining().unwrap_or(TRANSACTION_CAPACITY) as i16)?
        }
        MethodId::getAvailableMemory => {
            let memory_type = frame.pop_short()?;
            if !matches!(memory_type, 0..=2) {
                let exception = new_exception(heap, ClassId::SystemException, context)?;
                heap.put_word_unconditional(exception, REASON_FIELD, 1)?; // ILLEGAL_VALUE
                return Ok(Native::Threw(exception));
            }
            let available = heap.available() as u32;
            if token == 16 {
                frame.push_short(available.min(i16::MAX as u32) as i16)?;
            } else if token == 22 {
                let offset = frame.pop_short()?;
                let array = frame.pop_reference()?;
                let info = heap.check_access(array, context)?;
                if info.kind != heap::KIND_SHORT {
                    return Err(Error::Type);
                }
                let offset = usize::try_from(offset).map_err(|_| Error::ArrayBounds)?;
                if offset
                    .checked_add(2)
                    .is_none_or(|end| end > info.length as usize)
                {
                    return Err(Error::ArrayBounds);
                }
                heap.array_put(array, offset, (available >> 16) as i16)?;
                heap.array_put(array, offset + 1, available as i16)?;
            } else {
                return Err(Error::Unsupported);
            }
        }
        MethodId::beginTransaction => {
            if heap.transaction_remaining().is_some() {
                return transaction_exception(heap, jcre, context, 1); // IN_PROGRESS
            }
            if jcre.transaction_exception.is_none() {
                jcre.transaction_exception =
                    Some(new_exception(heap, ClassId::TransactionException, context)?);
            }
            heap.begin_transaction(TRANSACTION_CAPACITY)?;
        }
        MethodId::commitTransaction | MethodId::abortTransaction => {
            if heap.transaction_remaining().is_none() {
                return transaction_exception(heap, jcre, context, 2); // NOT_IN_PROGRESS
            }
            if name == MethodId::commitTransaction {
                if !jcre.installing {
                    let instance = jcre.instance.ok_or(Error::Missing)?;
                    host.checkpoint(crate::applet::PersistentView {
                        heap: heap.image(),
                        statics,
                        instance,
                        buffer: jcre.buffer,
                        projection: None,
                    })?;
                }
                heap.commit_transaction()?;
                if !jcre.installing {
                    heap.mark_checkpointed();
                }
            } else if heap.abort_transaction(statics)? {
                return Err(Error::TransactionAborted);
            }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
