//! Validate private native object state after the VM has verified heap structure.
//! These fields are not Java fields, so their owning native service defines their layout.
use crate::jcvm_api::ClassId;
use crate::vm::frame::Reference;
use crate::vm::heap::Info;
use crate::{natives, Error, Result};

pub(crate) fn validate_saved_native(
    info: Info,
    payload: &[u8],
    saved_heap: &[u8],
    valid_reference: &impl Fn(Reference) -> Result<()>,
) -> Result<()> {
    let class = natives::api_class(info.class).ok_or(Error::Format)?;
    let exception = natives::is_exception_class(class);
    if exception && info.length == 1 && payload.iter().any(|byte| *byte != 0) {
        return Err(Error::Format);
    }
    if info.length != 6 && !(info.length == 1 && (exception || class.id == ClassId::APDU)) {
        return Err(Error::Format);
    }
    if class.id == ClassId::SecureChannel
        && (info.length != 6 || payload.iter().any(|byte| *byte != 0))
    {
        return Err(Error::Format);
    }
    if info.length == 6 {
        natives::visit_native_reference_offsets(info, payload.len(), |at| {
            valid_reference(u16::from_be_bytes([payload[at], payload[at + 1]]))
        })?;
        super::security::validate_saved_security(class.id, payload, saved_heap)?;
    }

    Ok(())
}
