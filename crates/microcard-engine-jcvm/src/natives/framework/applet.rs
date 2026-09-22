//! `javacard.framework.Applet` lifecycle methods.

use super::super::{Jcre, Native};
use crate::jcvm_api::MethodId;
use crate::link::ApiTarget;
use crate::vm::frame::Frame;
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

pub(super) fn call(
    target: ApiTarget,
    heap: &mut Heap,
    frame: &mut Frame,
    jcre: &mut Jcre,
    context: heap::Context,
) -> Result<Native> {
    match target.method.id {
        MethodId::register => {
            if jcre.instance.is_some() {
                return Err(Error::Unauthorized);
            }
            // Two forms, JCRE §3.1. One registers under the installer AID, the other
            // under an AID the applet chose from a byte array it owns.
            if !target.method.signature.empty_parameters() {
                let length = frame.pop_short()?;
                let offset = frame.pop_short()?;
                let array = frame.pop_reference()?;
                heap.check_access(array, context)?;
                if !(5..=16).contains(&length) || offset < 0 {
                    return Err(Error::Bounds);
                }
                let bytes = heap.byte_slice(array, offset as usize, length as usize)?;
                jcre.aid[..length as usize].copy_from_slice(bytes);
                jcre.aid_length = length as u8;
            }
            let instance = frame.pop_reference()?;
            heap.check_access(instance, context)?;
            jcre.instance = Some(instance);
        }
        MethodId::reSelectingApplet => frame.push_short(jcre.reselecting as i16)?,
        MethodId::selectingApplet => {
            frame.pop_reference()?;
            frame.push_short(jcre.selecting as i16)?;
        }
        MethodId::Constructor => {
            frame.pop_reference()?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
