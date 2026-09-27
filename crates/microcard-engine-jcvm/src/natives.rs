//! The classes an applet borrows rather than carries, JCRE §2.
//!
//! An applet's own bytecode is only half of what it runs. The other half is the API, which
//! the card provides and the applet reaches by token. This module is the card's side.
//!
//! A native class has no Class component entry to be an instance of, so its objects carry
//! a class word with the high bit set, which no internal class reference can have. That is
//! what lets one heap hold both kinds of object and one catch clause match either.
use crate::jcvm_api::{ApiClass, PACKAGES};
use crate::jcvm_api::{ClassId, MethodId, PackageId};
use crate::link::ApiTarget;
use crate::vm::frame::{Frame, Reference};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

mod framework;
mod security;
#[cfg(test)]
use framework::{apdu_call as apdu, jcsystem_call as jcsystem, util_call as util};
pub(crate) use security::native_volatile_range;
pub(crate) use security::visit_native_reference_offsets;
pub(crate) use security::{ec_key_clear_event, ec_key_kind, symmetric_key_clear_event};

/// A class the card provides, encoded so it cannot collide with a class in a package.
///
/// The high bit marks it, the next byte is the package's position in the API table and the
/// low byte is the class token. The package position is used rather than the applet's own
/// package token, because that token means nothing outside the package that assigned it.
pub fn native_class(package: usize, class: u8) -> u16 {
    0x8000 | ((package as u16) << 8) | class as u16
}

pub fn is_native_class(class: u16) -> bool {
    class & 0x8000 != 0
}

/// The API class a native class word names.
pub fn api_class(class: u16) -> Option<&'static ApiClass> {
    if !is_native_class(class) {
        return None;
    }
    let package = PACKAGES.get(((class >> 8) & 0x7f) as usize)?;
    package
        .classes
        .iter()
        .find(|entry| entry.token == class as u8)
}

/// Whether an object of `thrown` can be caught as `caught`, following the chain up.
///
/// The export files record what each class extends, so a catch of a supertype matches
/// without the card holding a class hierarchy of its own.
pub fn native_is_a(thrown: u16, caught: u16) -> bool {
    if thrown == caught {
        return true;
    }
    let (Some(thrown), Some(caught)) = (api_class(thrown), api_class(caught)) else {
        return false;
    };
    thrown.supers.contains(&caught.id)
}

/// Field zero of an `ISOException`, which carries the status word to report.
pub const REASON_FIELD: usize = 0;

pub(crate) fn is_exception_class(class: &ApiClass) -> bool {
    class.id == ClassId::Throwable || class.supers.contains(&ClassId::Throwable)
}

/// Runtime APDU and exception objects may be used locally but never retained by applets.
pub(crate) fn is_temporary_native(class: u16, words: u16) -> bool {
    api_class(class).is_some_and(|class| {
        (words == 1 && (class.id == ClassId::APDU || is_exception_class(class)))
            || (words == security::STATE_WORDS && class.id == ClassId::MessageDigest_OneShot)
    })
}

/// Clear reset-scoped native fields in live state or a persistence staging buffer.
pub fn reset_native_volatile(heap: &mut Heap) -> Result<()> {
    security::reset_native_volatile(heap)
}

pub(crate) fn release_temporary_natives(heap: &mut Heap) -> Result<()> {
    security::release_one_shot_digests(heap)
}

/// What the runtime environment knows while a command is being processed, JCRE §4.
///
/// An applet sees this through the APDU object it is handed and through the static methods
/// of `JCSystem`. It is held here rather than on the heap, because an applet must not be
/// able to reach it with a field access.
pub struct Jcre {
    /// The `APDU` object handed to `process`.
    pub apdu: Reference,
    /// The byte array that object wraps, which `getBuffer` answers.
    pub buffer: Reference,
    /// The applet instance, once it has registered itself.
    pub instance: Option<Reference>,
    /// Installation publishes state only after the whole callback succeeds.
    pub installing: bool,
    /// Bytes of command data in the buffer, after the header.
    pub incoming: u16,
    /// Bytes of response the applet has asked to send.
    pub outgoing: u16,
    response: [u8; 256],
    pub expected: u16,
    incoming_started: bool,
    outgoing_started: bool,
    outgoing_combined: bool,
    outgoing_length: Option<u16>,
    /// Where the command data starts in the buffer. Five for a short APDU, JCRE §4.
    pub data_offset: u16,
    /// Whether this command is the one that selected the applet.
    pub selecting: bool,
    pub reselecting: bool,
    /// Allocated before begin so a full undo log can still report its exception.
    transaction_exception: Option<Reference>,
    /// The AID the applet registered under, if it chose one.
    pub aid: [u8; 16],
    pub aid_length: u8,
}

impl Jcre {
    pub(crate) fn response_data(&self) -> Result<&[u8]> {
        if self
            .outgoing_length
            .is_some_and(|declared| declared != self.outgoing)
        {
            return Err(Error::Bounds);
        }
        self.response
            .get(..usize::from(self.outgoing))
            .ok_or(Error::Bounds)
    }

    pub fn new(apdu: Reference, buffer: Reference) -> Self {
        Self {
            apdu,
            buffer,
            instance: None,
            installing: false,
            incoming: 0,
            outgoing: 0,
            response: [0; 256],
            expected: 256,
            incoming_started: false,
            outgoing_started: false,
            outgoing_combined: false,
            outgoing_length: None,
            data_offset: 5,
            selecting: false,
            reselecting: false,
            transaction_exception: None,
            // Selectable, GP 2.3 Table 11-4. An applet moves itself on from here.
            aid: [0; 16],
            aid_length: 0,
        }
    }
}

impl Drop for Jcre {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.response.zeroize();
        self.aid.zeroize();
    }
}

/// What a native call did.
pub enum Native {
    /// It returned, and anything it produced is already on the stack.
    Returned,
    /// It threw. The reference is an object on the heap, as any throw is.
    Threw(Reference),
    /// This build does not implement it.
    Unimplemented,
}

/// The complete state visible to one native call.
///
/// Keeping this as one typed value prevents dispatch layers from accidentally pairing
/// a heap, host, frame, or applet context from different executions.
pub struct NativeContext<'a, 'heap, 'frame, H: crate::host::Host> {
    pub(crate) heap: &'a mut Heap<'heap>,
    pub(crate) host: &'a mut H,
    pub(crate) frame: &'a mut Frame<'frame>,
    pub(crate) context: heap::Context,
    pub(crate) jcre: &'a mut Jcre,
    pub(crate) budget: &'a mut u32,
    pub(crate) statics: &'a mut [u8],
}

#[cfg(test)]
pub fn call(
    target: ApiTarget,
    heap: &mut Heap,
    host: &mut impl crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
) -> Result<Native> {
    let mut budget = u32::MAX;
    let mut native = NativeContext {
        heap,
        host,
        frame,
        context,
        jcre,
        budget: &mut budget,
        statics: &mut [],
    };
    call_with_budget(target, &mut native)
}

/// Call an API method.
///
/// Arguments are on the frame's stack, receiver first as in any instance call, and a
/// result is left there the same way.
pub fn call_with_budget<H: crate::host::Host>(
    target: ApiTarget,
    native: &mut NativeContext<'_, '_, '_, H>,
) -> Result<Native> {
    let package = target.package.id;
    let class = target.class.id;
    let method = target.method.id;
    if matches!(
        method,
        MethodId::Constructor | MethodId::throwIt | MethodId::getReason | MethodId::setReason
    ) && (matches!(
        class,
        ClassId::CardException | ClassId::CardRuntimeException
    ) || target
        .class
        .supers
        .iter()
        .any(|base| matches!(base, ClassId::CardException | ClassId::CardRuntimeException)))
    {
        let NativeContext {
            heap,
            frame,
            context,
            ..
        } = native;
        let context = *context;
        let reason = if method == MethodId::getReason {
            None
        } else {
            Some(frame.pop_short()? as u16)
        };
        let exception = if method == MethodId::throwIt {
            new_exception(heap, class, context)?
        } else {
            frame.pop_reference()?
        };
        heap.check_access(exception, context)?;
        if let Some(reason) = reason {
            // Java Card exception reasons do not participate in transactions.
            heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
        } else {
            frame.push_short(heap.get_word(exception, REASON_FIELD)? as i16)?;
        }
        return Ok(if method == MethodId::throwIt {
            Native::Threw(exception)
        } else {
            Native::Returned
        });
    }
    let result = match (package, class, method) {
        // Constructing an Object or any exception does nothing the engine has to model.
        // The allocation already happened, and the fields start zeroed.
        (PackageId::java_lang, _, MethodId::Constructor) => {
            native.frame.pop_reference()?;
            Ok(Native::Returned)
        }
        (PackageId::javacard_framework, _, _) => framework::call(target, native),
        _ => {
            let NativeContext {
                heap,
                host,
                frame,
                context,
                jcre,
                budget,
                statics,
            } = native;
            let handled = security::call(
                class,
                method,
                target.method.signature,
                heap,
                &mut **host,
                frame,
                *context,
                jcre,
                budget,
                statics,
            )?;
            Ok(handled)
        }
    };
    #[cfg(feature = "diagnostics")]
    if matches!(result, Ok(Native::Unimplemented)) {
        report(class.diagnostic_name(), method.diagnostic_name());
    }
    result
}

#[cfg(test)]
fn test_call_with_budget<H: crate::host::Host>(
    target: ApiTarget,
    mut native: NativeContext<'_, '_, '_, H>,
) -> Result<Native> {
    call_with_budget(target, &mut native)
}

/// Name what the card cannot answer, which is the difference between a usable diagnostic
/// and a refusal with nothing to act on. A card build leaves this out.
pub(crate) fn report(class: &str, method: &str) {
    #[cfg(feature = "diagnostics")]
    {
        extern crate std;
        std::eprintln!("jcvm: no native for {class}.{method}");
    }
    let _ = (class, method);
}

/// Read one of a native object's state words, checking it is one.
fn word_field(heap: &Heap, object: Reference, index: usize) -> Result<u16> {
    if !is_native_class(heap.info(object)?.class) {
        return Err(Error::Type);
    }
    heap.get_word(object, index)
}

/// Allocate an instance of a class the card provides, named by its API entry.
pub fn new_api_object(
    heap: &mut Heap,
    class: &ApiClass,
    context: heap::Context,
) -> Result<Reference> {
    let index = PACKAGES
        .iter()
        .position(|package| package.classes.iter().any(|entry| entry == class))
        .ok_or(Error::Missing)?;
    heap.new_object(
        native_class(index, class.token),
        security::STATE_WORDS,
        context,
    )
}

/// Allocate an instance of a class the card provides, with room for its state.
fn new_native(
    heap: &mut Heap,
    name: ClassId,
    words: u16,
    context: heap::Context,
) -> Result<Reference> {
    for (index, package) in PACKAGES.iter().enumerate() {
        if let Some(class) = package.classes.iter().find(|entry| entry.id == name) {
            return heap.new_object(native_class(index, class.token), words, context);
        }
    }
    Err(Error::Missing)
}

/// Shared logical bound for payload before-images and their metadata.
pub const TRANSACTION_CAPACITY: usize = 8192;

pub(crate) fn transaction_exception(
    heap: &mut Heap,
    jcre: &mut Jcre,
    context: heap::Context,
    reason: u16,
) -> Result<Native> {
    let exception = match jcre.transaction_exception {
        Some(reference) => reference,
        None => {
            let reference = new_exception(heap, ClassId::TransactionException, context)?;
            jcre.transaction_exception = Some(reference);
            reference
        }
    };
    heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}

/// Reserve VM and native API failure objects before applet allocations can exhaust
/// the heap. The runtime prefix keeps them outside applet transactions.
pub(crate) fn runtime_exception_classes() -> impl Iterator<Item = ClassId> {
    [
        ClassId::ArithmeticException,
        ClassId::ArrayIndexOutOfBoundsException,
        ClassId::ClassCastException,
        ClassId::NegativeArraySizeException,
        ClassId::NullPointerException,
        ClassId::SecurityException,
    ]
    .into_iter()
    .chain(
        PACKAGES
            .iter()
            .flat_map(|package| package.classes)
            .filter(|class| {
                is_exception_class(class)
                    && class
                        .methods
                        .iter()
                        .any(|method| method.id == MethodId::throwIt)
            })
            .map(|class| class.id),
    )
}

pub(crate) fn reserve_runtime_exceptions(heap: &mut Heap, context: heap::Context) -> Result<()> {
    for class in runtime_exception_classes() {
        new_exception(heap, class, context)?;
    }
    Ok(())
}

/// Obtain a runtime exception. Repeated native errors must not leak
/// persistent heap; explicit applet-created exception objects remain independent.
pub fn new_exception(heap: &mut Heap, name: ClassId, context: heap::Context) -> Result<Reference> {
    for (index, package) in PACKAGES.iter().enumerate() {
        if let Some(class) = package.classes.iter().find(|entry| entry.id == name) {
            let native = native_class(index, class.token);
            let mut at = 2;
            while at < heap.used() {
                let info = heap.info(at as Reference)?;
                // Runtime exceptions have only the reason word. Explicit `new`
                // objects have the larger native state layout and must stay distinct.
                if info.class == native && info.owner == context && info.length == 1 {
                    return Ok(at as Reference);
                }
                at = (at + heap::HEADER + info.length as usize * info.element_size())
                    .next_multiple_of(2);
            }
            // One word, which every exception uses for its reason.
            return heap.new_object(native, 1, context);
        }
    }
    Err(Error::Missing)
}

#[cfg(test)]
mod tests;
