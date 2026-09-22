//! `javacard.framework` methods implemented by the runtime.
//!
//! Dispatch stays here so the package boundary is visible. Each child module owns one
//! Java Card class or one cohesive responsibility within the package.

use super::{Native, NativeContext};
use crate::jcvm_api::ClassId;
use crate::link::ApiTarget;
use crate::{Error, Result};

mod apdu;
mod applet;
mod jcsystem;
mod util;

#[cfg(test)]
pub(super) use apdu::call as apdu_call;
#[cfg(test)]
pub(super) use jcsystem::call as jcsystem_call;
#[cfg(test)]
pub(super) use util::call as util_call;

pub(super) fn call<H: crate::host::Host>(
    target: ApiTarget,
    native: &mut NativeContext<'_, '_, '_, H>,
) -> Result<Native> {
    let NativeContext {
        heap,
        host,
        frame,
        context,
        jcre,
        budget,
        statics,
    } = native;
    let context = *context;
    match target.class.id {
        ClassId::Util => match util::call(target.method.id, heap, frame, context, budget) {
            Err(Error::Bounds) => Ok(Native::Threw(super::new_exception(
                heap,
                ClassId::ArrayIndexOutOfBoundsException,
                context,
            )?)),
            Err(Error::Null) => Ok(Native::Threw(super::new_exception(
                heap,
                ClassId::NullPointerException,
                context,
            )?)),
            result => result,
        },
        ClassId::APDU => apdu::call(target.method.id, heap, frame, jcre, context),
        ClassId::JCSystem => jcsystem::call(
            target.method.id,
            target.method.token,
            heap,
            frame,
            context,
            jcre,
            statics,
            &mut **host,
        ),
        ClassId::Applet => applet::call(target, heap, frame, jcre, context),
        class => super::security::call(
            class,
            target.method.id,
            target.method.signature,
            heap,
            &mut **host,
            frame,
            context,
            jcre,
            budget,
            statics,
        ),
    }
}
