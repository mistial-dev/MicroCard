//! The classes an applet borrows rather than carries, JCRE §2.
//!
//! An applet's own bytecode is only half of what it runs. The other half is the API, which
//! the card provides and the applet reaches by token. This module is the card's side.
//!
//! A native class has no Class component entry to be an instance of, so its objects carry
//! a class word with the high bit set, which no internal class reference can have. That is
//! what lets one heap hold both kinds of object and one catch clause match either.
use crate::jcvm_api::{ClassId, MethodId, PackageId};
use crate::jcvm_api::{ApiClass, PACKAGES};
use crate::link::ApiTarget;
use crate::vm::frame::{Frame, Reference};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

mod security;
pub(crate) use security::native_volatile_range;
pub(crate) use security::{symmetric_key_clear_event, ec_key_clear_event, ec_key_kind};

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
    words == 1 && api_class(class).is_some_and(|class|
        class.id == ClassId::APDU || is_exception_class(class))
}

/// Clear reset-scoped native fields in live state or a persistence staging buffer.
pub fn reset_native_volatile(heap: &mut Heap) -> Result<()> {
    security::reset_native_volatile(heap)
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
        if self.outgoing_length.is_some_and(|declared| declared != self.outgoing) {
            return Err(Error::Bounds);
        }
        self.response.get(..usize::from(self.outgoing)).ok_or(Error::Bounds)
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
    target: ApiTarget, heap: &mut Heap, host: &mut impl crate::host::Host,
    frame: &mut Frame, context: heap::Context, jcre: &mut Jcre,
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
    let NativeContext { heap, host, frame, context, jcre, budget, statics } = native;
    let context = *context;
    let package = target.package.id;
    let class = target.class.id;
    let method = target.method.id;
    if matches!(method, MethodId::Constructor | MethodId::throwIt | MethodId::getReason | MethodId::setReason)
        && (matches!(class, ClassId::CardException | ClassId::CardRuntimeException)
            || target.class.supers.iter().any(|base| matches!(base, ClassId::CardException | ClassId::CardRuntimeException))) {
        let reason = if method == MethodId::getReason { None } else { Some(frame.pop_short()? as u16) };
        let exception = if method == MethodId::throwIt { new_exception(heap, class, context)? }
            else { frame.pop_reference()? };
        heap.check_access(exception, context)?;
        if let Some(reason) = reason {
            // Java Card exception reasons do not participate in transactions.
            heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
        } else { frame.push_short(heap.get_word(exception, REASON_FIELD)? as i16)?; }
        return Ok(if method == MethodId::throwIt { Native::Threw(exception) } else { Native::Returned });
    }
    let result = match (package, class, method) {
        // Constructing an Object or any exception does nothing the engine has to model.
        // The allocation already happened, and the fields start zeroed.
        (PackageId::java_lang, _, MethodId::Constructor) => {
            frame.pop_reference()?;
            Ok(Native::Returned)
        }
        (PackageId::javacard_framework, ClassId::Util, name) => {
            match util(name, heap, frame, context, budget) {
                Err(Error::Bounds) => Ok(Native::Threw(new_exception(heap, ClassId::ArrayIndexOutOfBoundsException, context)?)),
                Err(Error::Null) => Ok(Native::Threw(new_exception(heap, ClassId::NullPointerException, context)?)),
                result => result,
            }
        }
        (PackageId::javacard_framework, ClassId::APDU, name) => {
            apdu(name, heap, frame, jcre, context)
        }
        (PackageId::javacard_framework, ClassId::JCSystem, name) => {
            jcsystem(name, target.method.token, heap, frame, context, jcre, statics, &mut **host)
        }
        (PackageId::javacard_framework, ClassId::Applet, MethodId::register) => {
            if jcre.instance.is_some() { return Err(Error::Unauthorized); }
            // Two forms, JCRE §3.1. One registers under the AID the installer gave, the
            // other under an AID the applet chose out of a byte array it holds.
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
            // The applet hands itself to the runtime. Everything after this command can
            // select it.
            let instance = frame.pop_reference()?;
            heap.check_access(instance, context)?;
            jcre.instance = Some(instance);
            Ok(Native::Returned)
        }
        (PackageId::javacard_framework, ClassId::Applet, MethodId::reSelectingApplet) => {
            frame.push_short(jcre.reselecting as i16)?;
            Ok(Native::Returned)
        }
        (PackageId::javacard_framework, ClassId::Applet, MethodId::selectingApplet) => {
            frame.pop_reference()?;
            frame.push_short(jcre.selecting as i16)?;
            Ok(Native::Returned)
        }
        (PackageId::javacard_framework, ClassId::Applet, MethodId::Constructor) => {
            frame.pop_reference()?;
            Ok(Native::Returned)
        }
        _ => {
            let handled = security::call(
                class,
                method,
                target.method.signature,
                heap,
                &mut **host,
                frame,
                context,
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
fn test_call_with_budget(
    target: ApiTarget,
    heap: &mut Heap,
    host: &mut impl crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
    budget: &mut u32,
    statics: &mut [u8],
) -> Result<Native> {
    let mut native = NativeContext { heap, host, frame, context, jcre, budget, statics };
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
    heap.new_object(native_class(index, class.token), security::STATE_WORDS, context)
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

/// `javacard.framework.APDU`, JCRE §4. The buffer is an ordinary byte array on the heap,
/// so an applet reading it goes through the same bounds and firewall checks as any array.
fn apdu(name: MethodId, heap: &mut Heap, frame: &mut Frame, jcre: &mut Jcre, context: heap::Context) -> Result<Native> {
    match name {
        // The host presents contacted T=1 semantics. A 254-byte information field plus
        // the seven-byte extended header fits the runtime's 261-byte APDU buffer.
        MethodId::getInBlockSize | MethodId::getOutBlockSize => {
            frame.push_short(254)?;
        }
        MethodId::getBuffer => {
            frame.pop_reference()?;
            frame.push_reference(jcre.buffer)?;
        }
        MethodId::getNAD => {
            frame.pop_reference()?;
            // NAD is optional in T=1 and zero when it is not used.
            frame.push_short(0)?;
        }
        MethodId::getIncomingLength => {
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started { return apdu_exception(heap, context, 1); }
            frame.push_short(jcre.incoming as i16)?;
        }
        MethodId::getOffsetCdata => {
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started { return apdu_exception(heap, context, 1); }
            frame.push_short(jcre.data_offset as i16)?;
        }
        MethodId::setIncomingAndReceive => {
            frame.pop_reference()?;
            if jcre.incoming_started || jcre.outgoing_started { return apdu_exception(heap, context, 1); }
            jcre.incoming_started = true;
            // The whole command is already in the buffer, so there is nothing to wait for
            // and the answer is everything that arrived.
            frame.push_short(jcre.incoming as i16)?;
        }
        MethodId::receiveBytes => {
            let offset = frame.pop_short()?;
            frame.pop_reference()?;
            if !jcre.incoming_started || jcre.outgoing_started {
                return apdu_exception(heap, context, 1); // ILLEGAL_USE
            }
            if offset < 0 { return apdu_exception(heap, context, 2); }
            let offset = offset as usize;
            let buffer = heap.info(jcre.buffer)?;
            if offset.checked_add(254).is_none_or(|end| end > buffer.length as usize) {
                return apdu_exception(heap, context, 2); // BUFFER_BOUNDS
            }
            // Commands are fully framed before the VM is entered, so the primary receive
            // consumed every byte and a legal follow-up receive has nothing left to copy.
            frame.push_short(0)?;
        }
        MethodId::setOutgoing | MethodId::setOutgoingNoChaining => {
            frame.pop_reference()?;
            if jcre.outgoing_started { return apdu_exception(heap, context, 1); }
            jcre.outgoing_started = true;
            frame.push_short(jcre.expected as i16)?;
        }
        MethodId::setOutgoingLength => {
            let length = frame.pop_short()?;
            frame.pop_reference()?;
            if !jcre.outgoing_started || jcre.outgoing_length.is_some() { return apdu_exception(heap, context, 1); }
            if length < 0 || length as usize > jcre.response.len() { return apdu_exception(heap, context, 3); }
            jcre.outgoing_length = Some(length as u16);
        }
        MethodId::setOutgoingAndSend | MethodId::sendBytes | MethodId::sendBytesLong => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = if name == MethodId::sendBytesLong { frame.pop_reference()? } else { jcre.buffer };
            frame.pop_reference()?;
            let combined = name == MethodId::setOutgoingAndSend;
            let declared = if combined {
                if jcre.outgoing_started { return apdu_exception(heap, context, 1); }
                if length < 0 || length as usize > jcre.response.len() { return apdu_exception(heap, context, 3); }
                length as u16
            } else {
                if jcre.outgoing_combined { return apdu_exception(heap, context, 1); }
                let Some(declared) = jcre.outgoing_length else { return apdu_exception(heap, context, 1); };
                declared
            };
            if offset < 0 || length < 0 { return apdu_exception(heap, context, 2); }
            let start = usize::from(jcre.outgoing);
            let end = start + length as usize;
            if end > usize::from(declared) { return apdu_exception(heap, context, 1); }
            heap.check_access(source, context)?;
            let bytes = match heap.byte_slice(source, offset as usize, length as usize) {
                Ok(bytes) => bytes,
                Err(Error::Bounds) => return apdu_exception(heap, context, 2),
                Err(error) => return Err(error),
            };
            // Publish output state only after the source and destination are admitted.
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
            // Further-channel encoding uses b6 for secure messaging; b4/b3
            // are channel bits. Reserved and invalid CLA values report neither flag.
            let valid = cla & 0xe0 != 0x20 && cla != 0xff;
            let bit = if name == MethodId::isCommandChainingCLA { 0x10 }
                else if cla & 0x40 != 0 { 0x20 } else { 0x0c };
            frame.push_short((valid && cla & bit != 0) as i16)?;
        }
        MethodId::getProtocol => {
            // A contacted card. An applet that refuses contactless selection reads this,
            // so answering with a contactless value would make it refuse every session.
            frame.push_short(0x01)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

fn apdu_exception(heap: &mut Heap, context: heap::Context, reason: u16) -> Result<Native> {
    let exception = new_exception(heap, ClassId::APDUException, context)?;
    heap.put_word_unconditional(exception, REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}

/// `javacard.framework.JCSystem`, JCRE §7.
#[allow(clippy::too_many_arguments)]
fn jcsystem(
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
        MethodId::makeTransientByteArray | MethodId::makeTransientBooleanArray | MethodId::makeTransientShortArray
        | MethodId::makeTransientObjectArray => {
            let event = frame.pop_short()?;
            let length = frame.pop_short()?;
            if length < 0 {
                return Ok(Native::Threw(new_exception(heap, ClassId::NegativeArraySizeException, context)?));
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
        MethodId::requestObjectDeletion => {
            // Legal to do nothing, JCRE §7.4. An applet that depends on it asks first.
        }
        MethodId::getTransactionDepth => frame.push_short(i16::from(heap.transaction_remaining().is_some()))?,
        MethodId::getMaxCommitCapacity => frame.push_short(TRANSACTION_CAPACITY as i16)?,
        MethodId::getUnusedCommitCapacity => frame.push_short(heap.transaction_remaining().unwrap_or(TRANSACTION_CAPACITY) as i16)?,
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
                if info.kind != heap::KIND_SHORT { return Err(Error::Type); }
                let offset = usize::try_from(offset).map_err(|_| Error::ArrayBounds)?;
                if offset.checked_add(2).is_none_or(|end| end > info.length as usize) {
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
                jcre.transaction_exception = Some(new_exception(heap, ClassId::TransactionException, context)?);
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
                        heap: heap.image(), statics, instance, buffer: jcre.buffer, projection: None,
                    })?;
                }
                heap.commit_transaction()?;
                if !jcre.installing { heap.mark_checkpointed(); }
            }
            else if heap.abort_transaction(statics)? { return Err(Error::TransactionAborted); }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

/// Shared logical bound for payload before-images and their metadata.
pub const TRANSACTION_CAPACITY: usize = 8192;

pub(crate) fn transaction_exception(heap: &mut Heap, jcre: &mut Jcre, context: heap::Context, reason: u16) -> Result<Native> {
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
    [ClassId::ArithmeticException, ClassId::ArrayIndexOutOfBoundsException,
        ClassId::ClassCastException, ClassId::NegativeArraySizeException,
        ClassId::NullPointerException, ClassId::SecurityException].into_iter().chain(
        PACKAGES.iter().flat_map(|package| package.classes).filter(|class|
            is_exception_class(class) && class.methods.iter().any(|method| method.id == MethodId::throwIt))
            .map(|class| class.id))
}

pub(crate) fn reserve_runtime_exceptions(heap: &mut Heap, context: heap::Context) -> Result<()> {
    for class in runtime_exception_classes() { new_exception(heap, class, context)?; }
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
                at = (at + heap::HEADER + info.length as usize * info.element_size()).next_multiple_of(2);
            }
            // One word, which every exception uses for its reason.
            return heap.new_object(native, 1, context);
        }
    }
    Err(Error::Missing)
}

/// `javacard.framework.Util`, JCRE §3. Every method here works on arrays the applet owns,
/// so every access goes through the firewall like any other.
fn util(name: MethodId, heap: &mut Heap, frame: &mut Frame, context: heap::Context, budget: &mut u32) -> Result<Native> {
    match name {
        MethodId::makeShort => {
            let low = frame.pop_short()?;
            let high = frame.pop_short()?;
            frame.push_short((((high as u16) << 8) | (low as u8 as u16)) as i16)?;
        }
        MethodId::getShort => {
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            let bytes = heap.byte_slice(array, index(offset)?, 2)?;
            frame.push_short(i16::from_be_bytes([bytes[0], bytes[1]]))?;
        }
        MethodId::setShort => {
            let value = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            heap.byte_slice_mut(array, index(offset)?, 2)?
                .copy_from_slice(&value.to_be_bytes());
            // It answers the offset one past the short it wrote.
            frame.push_short(offset.wrapping_add(2))?;
        }
        MethodId::arrayCopy | MethodId::arrayCopyNonAtomic => {
            let length = frame.pop_short()?;
            let destination_offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let source_offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            heap.check_access(source, context)?;
            heap.check_access(destination, context)?;
            let length = index(length)?;
            heap.byte_slice(source, index(source_offset)?, length)?;
            heap.byte_slice(destination, index(destination_offset)?, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            if name == MethodId::arrayCopy {
                heap.copy_bytes(source, index(source_offset)?, destination, index(destination_offset)?, length)?;
            } else {
                heap.copy_bytes_unconditional(source, index(source_offset)?, destination, index(destination_offset)?, length)?;
            }
            frame.push_short(destination_offset.wrapping_add(length as i16))?;
        }
        MethodId::arrayFill | MethodId::arrayFillNonAtomic => {
            let value = frame.pop_short()?;
            let length = index(frame.pop_short()?)?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            let start = index(offset)?;
            heap.byte_slice(array, start, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            if name == MethodId::arrayFill {
                heap.byte_slice_mut(array, start, length)?.fill(value as u8);
            } else {
                heap.fill_bytes_unconditional(array, start, length, value as u8)?;
            }
            frame.push_short(offset.wrapping_add(length as i16))?;
        }
        MethodId::arrayCompare => {
            let length = frame.pop_short()?;
            let right_offset = frame.pop_short()?;
            let right = frame.pop_reference()?;
            let left_offset = frame.pop_short()?;
            let left = frame.pop_reference()?;
            heap.check_access(left, context)?;
            heap.check_access(right, context)?;
            let length = index(length)?;
            // Validate the entire request, even when comparison stops at the first byte.
            let left = heap.byte_slice(left, index(left_offset)?, length)?;
            let right = heap.byte_slice(right, index(right_offset)?, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let answer = match left.cmp(right) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            };
            frame.push_short(answer)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

/// An offset or length the API takes as a signed short. A negative one is out of bounds.
fn index(value: i16) -> Result<usize> {
    if value < 0 {
        return Err(Error::Bounds);
    }
    Ok(value as usize)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    fn framework(class: ClassId, method: MethodId, static_token: bool) -> ApiTarget {
        framework_token(class, method, static_token, None)
    }

    fn framework_token(class: ClassId, method: MethodId, static_token: bool,
        token: Option<u8>) -> ApiTarget {
        for package in PACKAGES.iter() {
            for entry in package.classes.iter() {
                if entry.id != class {
                    continue;
                }
                for candidate in entry.methods.iter() {
                    if candidate.id == method && candidate.static_token == static_token
                        && token.is_none_or(|token| candidate.token == token) {
                        return ApiTarget {
                            package,
                            class: entry,
                            method: candidate,
                        };
                    }
                }
            }
        }
        panic!("no {class:?}.{method:?}");
    }

    fn setup(words: usize) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u16>, alloc::vec::Vec<u8>) {
        (vec![0; 1024], vec![0; words + 16], vec![0; 8])
    }

    /// A runtime with no command in flight, for the methods that do not read one.
    fn idle() -> Jcre {
        Jcre::new(0, 0)
    }

    #[test]
    fn lifecycle_checkpoints_before_success_and_survives_callback_and_abort() {
        struct Storage { saved: alloc::vec::Vec<u8>, fail: bool }
        impl crate::host::Host for Storage {
            fn checkpoint(&mut self, state: crate::applet::PersistentView<'_>) -> Result<()> {
                if self.fail { return Err(Error::Storage); }
                self.saved.resize(state.heap_bytes(), 0);
                state.save_into(&mut self.saved)?;
                Ok(())
            }
        }
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        heap.initialize_lifecycle();
        let buffer = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        let instance = heap.new_object(1, 1, 1).unwrap();
        let mut storage = Storage { saved: vec![], fail: false };
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let setter = framework(ClassId::GPSystem, MethodId::setCardContentState, true);
        let getter = framework(ClassId::GPSystem, MethodId::getCardContentState, true);
        let mut jcre = Jcre::new(0, buffer);
        jcre.instance = Some(instance);
        heap.begin_transaction(32).unwrap();
        heap.put_word(instance, 0, 99).unwrap();
        frame.push_short(0x0f).unwrap();
        call(setter, &mut heap, &mut storage, &mut frame, 1, &mut jcre).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 1);
        assert_eq!(&storage.saved[..2], &[2, 0x0f]);
        let used = storage.saved.len();
        let saved = Heap::resume(&mut storage.saved, used).unwrap();
        assert_eq!(saved.get_word(instance, 0), Ok(0));
        heap.abort_transaction(&mut []).unwrap();
        let mut next = Jcre::new(0, buffer);
        next.instance = Some(instance);
        call(getter, &mut heap, &mut storage, &mut frame, 1, &mut next).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0x0f);
        storage.fail = true;
        frame.push_short(0x17).unwrap();
        assert!(matches!(call(setter, &mut heap, &mut storage, &mut frame, 1,
            &mut next), Err(Error::Storage)));
        assert_eq!(&storage.saved[..2], &[2, 0x0f]);
    }

    #[test]
    fn exception_calls_reuse_runtime_objects_and_preserve_explicit_reasons() {
        for name in [ClassId::ISOException, ClassId::CryptoException, ClassId::CardRuntimeException,
            ClassId::CardException, ClassId::UserException] {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
            let capacity = slab.len();
            let mut heap = Heap::new(&mut slab).unwrap();
            reserve_runtime_exceptions(&mut heap, 1).unwrap();
            reserve_runtime_exceptions(&mut heap, 2).unwrap();
            let class = framework(name, MethodId::throwIt, true).class;
            let explicit = new_api_object(&mut heap, class, 1).unwrap();
            frame.push_reference(explicit).unwrap();
            frame.push_short(0x6a81).unwrap();
            assert!(matches!(call(framework(name, MethodId::Constructor, true), &mut heap,
                &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
            heap.begin_transaction(0).unwrap();
            frame.push_reference(explicit).unwrap();
            frame.push_short(0x6a82).unwrap();
            assert!(matches!(call(framework(name, MethodId::setReason, false), &mut heap,
                &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
            assert!(!heap.abort_transaction(&mut []).unwrap());
            frame.push_reference(explicit).unwrap();
            assert!(matches!(call(framework(name, MethodId::getReason, false), &mut heap,
                &mut crate::host::NoHost, &mut frame, 1, &mut idle()), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(0x6a82));
            let remaining = capacity - heap.used() - heap::HEADER;
            heap.new_array(heap::KIND_BYTE, remaining as u16, 1).unwrap();
            assert_eq!(heap.used(), capacity);
            let mut used = heap.used();
            let mut references = [0; 2];
            for context in [1, 2] {
                for reason in [0x6101, 0x9000, 0x6a80] {
                    let mut heap = Heap::resume(&mut slab, used).unwrap();
                    let reused = references[context as usize - 1] != 0;
                    if reused { heap.begin_transaction(0).unwrap(); }
                    frame.push_short(reason as i16).unwrap();
                    let Native::Threw(reference) = call(
                        framework(name, MethodId::throwIt, true), &mut heap,
                        &mut crate::host::NoHost, &mut frame, context, &mut idle(),
                    ).unwrap() else { panic!("throwIt returned"); };
                    let previous = &mut references[context as usize - 1];
                    if *previous == 0 { *previous = reference; }
                    else {
                        assert_eq!(reference, *previous);
                        assert_eq!(heap.used(), used, "a response must not consume persistent heap");
                    }
                    if reused { assert!(!heap.abort_transaction(&mut []).unwrap()); }
                    assert_eq!(heap.get_word(reference, REASON_FIELD), Ok(reason));
                    assert_eq!(heap.get_word(explicit, REASON_FIELD), Ok(0x6a82));
                    assert_ne!(reference, explicit);
                    used = heap.used();
                }
            }
            assert_ne!(references[0], references[1]);
        }
    }

    #[test]
    fn random_data_methods_obey_return_contracts_and_reject_empty_requests() {
        struct Entropy { random_calls: usize, digest_calls: usize, fail_random: bool, fail_digest: bool }
        impl crate::host::Host for Entropy {
            fn supports_random(&self, algorithm: u8) -> bool { matches!(algorithm, 1 | 2) }
            fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 4 }
            fn random(&mut self, output: &mut [u8]) -> Result<()> {
                self.random_calls += 1;
                output.fill(0x42);
                if self.fail_random { return Err(Error::Storage); }
                Ok(())
            }
            fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
                assert_eq!(algorithm, 4);
                self.digest_calls += 1;
                if self.fail_digest { return Err(Error::Storage); }
                let mut value = 0xcbf2_9ce4_8422_2325u64 ^ u64::from(algorithm);
                for byte in message {
                    value ^= u64::from(*byte);
                    value = value.wrapping_mul(0x0000_0100_0000_01b3);
                }
                for byte in output.iter_mut() {
                    value ^= value << 13;
                    value ^= value >> 7;
                    value ^= value << 17;
                    *byte = value as u8;
                }
                Ok(output.len())
            }
        }
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let mut host = Entropy { random_calls: 0, digest_calls: 0, fail_random: false, fail_digest: false };
        invoke_security(ClassId::RandomData, MethodId::getInstance, &[(false, 2)],
            &mut heap, &mut frame, &mut host).unwrap();
        let secure = frame.pop_reference().unwrap();
        invoke_security(ClassId::RandomData, MethodId::getInstance, &[(false, 1)],
            &mut heap, &mut frame, &mut host).unwrap();
        let pseudo = frame.pop_reference().unwrap();
        let output = heap.new_array(heap::KIND_BYTE, 6, 1).unwrap();
        for method in [MethodId::generateData, MethodId::nextBytes] {
            for allowance in [3, 4] {
                let before = heap.image().to_vec();
                let calls = host.random_calls;
                frame.push_reference(secure).unwrap();
                frame.push_reference(output).unwrap();
                frame.push_short(1).unwrap();
                frame.push_short(4).unwrap();
                let mut budget = allowance;
                let result = test_call_with_budget(framework(ClassId::RandomData, method, false),
                    &mut heap, &mut host, &mut frame, 1, &mut idle(), &mut budget, &mut []);
                if allowance == 3 {
                    assert!(matches!(result, Err(Error::Quota)));
                    assert_eq!(budget, 3);
                    assert_eq!(host.random_calls, calls);
                    assert!(heap.image() == before);
                } else { result.unwrap(); assert_eq!(budget, 0); }
            }
            if method == MethodId::nextBytes { assert_eq!(frame.pop_short(), Ok(5)); }
            assert_eq!(frame.depth(), 0);
            assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0, 0x42, 0x42, 0x42, 0x42, 0]);
            let calls = host.random_calls;
            let Native::Threw(exception) = invoke_security(ClassId::RandomData, method,
                &[(true, secure), (true, output), (false, 1), (false, 0)],
                &mut heap, &mut frame, &mut host).unwrap()
                else { panic!("empty random request accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
            assert_eq!(host.random_calls, calls);
            assert_eq!(frame.depth(), 0);
        }
        assert_eq!(host.random_calls, 3, "pseudo construction seeds once; secure output always uses entropy");

        let seed = heap.new_array(heap::KIND_BYTE, 6, 1).unwrap();
        heap.byte_slice_mut(seed, 0, 6).unwrap().copy_from_slice(b"seed!!");
        let digest_calls = host.digest_calls;
        invoke_security(ClassId::RandomData, MethodId::setSeed,
            &[(true, pseudo), (true, seed), (false, 0), (false, 4)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(host.digest_calls, digest_calls + 2);
        let random_calls = host.random_calls;
        let mut pseudo_outputs = [[0u8; 6]; 2];
        for captured in &mut pseudo_outputs {
            invoke_security(ClassId::RandomData, MethodId::nextBytes,
                &[(true, pseudo), (true, output), (false, 0), (false, 6)],
                &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short(), Ok(6));
            captured.copy_from_slice(heap.byte_slice(output, 0, 6).unwrap());
        }
        assert_ne!(pseudo_outputs[0], pseudo_outputs[1], "the PRNG chain must advance");
        assert_eq!(host.random_calls, random_calls, "pseudo output must not request entropy");

        invoke_security(ClassId::RandomData, MethodId::setSeed,
            &[(true, pseudo), (true, seed), (false, 0), (false, 4)],
            &mut heap, &mut frame, &mut host).unwrap();
        invoke_security(ClassId::RandomData, MethodId::nextBytes,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(6));
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), pseudo_outputs[0],
            "re-seeding with the same fixture must replay the deterministic stream");

        host.fail_digest = true;
        heap.byte_slice_mut(output, 0, 6).unwrap().fill(0x55);
        assert!(matches!(invoke_security(ClassId::RandomData, MethodId::nextBytes,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host), Err(Error::Storage)));
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
        host.fail_digest = false;

        heap.begin_transaction(64).unwrap();
        invoke_security(ClassId::RandomData, MethodId::nextBytes,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(6));
        let generated_in_transaction: [u8; 6] = heap.byte_slice(output, 0, 6).unwrap().try_into().unwrap();
        assert!(!heap.abort_transaction(&mut []).unwrap());
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
        invoke_security(ClassId::RandomData, MethodId::nextBytes,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(6));
        assert_ne!(heap.byte_slice(output, 0, 6).unwrap(), generated_in_transaction,
            "transaction abort must not roll the PRNG stream backward");

        let random_calls = host.random_calls;
        let digest_calls = host.digest_calls;
        invoke_security(ClassId::RandomData, MethodId::setSeed,
            &[(true, secure), (true, seed), (false, 0), (false, 4)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(host.random_calls, random_calls + 1, "secure seeding must add provider entropy");
        assert_eq!(host.digest_calls, digest_calls + 2);
        invoke_security(ClassId::RandomData, MethodId::generateData,
            &[(true, secure), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(host.random_calls, random_calls + 2, "secure output must always use provider entropy");
        assert_ne!(heap.byte_slice(output, 0, 6).unwrap(), &[0x42; 6],
            "the caller seed must contribute to secure output");
        host.fail_random = true;
        heap.byte_slice_mut(output, 0, 6).unwrap().fill(0x55);
        assert!(matches!(invoke_security(ClassId::RandomData, MethodId::generateData,
            &[(true, secure), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host), Err(Error::Storage)));
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x55; 6]);
        host.fail_random = false;

        heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
        let random_calls = host.random_calls;
        invoke_security(ClassId::RandomData, MethodId::generateData,
            &[(true, pseudo), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(host.random_calls, random_calls, "reset must preserve persistent PRNG state");
        let digest_calls = host.digest_calls;
        invoke_security(ClassId::RandomData, MethodId::generateData,
            &[(true, secure), (true, output), (false, 0), (false, 6)],
            &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(host.random_calls, random_calls + 1);
        assert_eq!(host.digest_calls, digest_calls, "reset must clear the optional secure seed mask");
        assert_eq!(heap.byte_slice(output, 0, 6).unwrap(), &[0x42; 6]);
    }

    #[test]
    fn pin_replacement_honors_configured_capacity_and_reserves_the_complete_update() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let mut host = crate::host::NoHost;
        let pin = new_native(&mut heap, ClassId::OwnerPIN, 6, 1).unwrap();
        for (tries, size) in [(0, 126), (3, 0)] {
            let Native::Threw(exception) = invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
                &[(true, pin), (false, tries), (false, size)], &mut heap, &mut frame, &mut host).unwrap()
                else { panic!("invalid PIN limits accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        }
        let before = heap.image().to_vec();
        heap.begin_transaction(8).unwrap();
        assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
            &[(true, pin), (false, 3), (false, 126)], &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
        assert_eq!(heap.transaction_remaining(), Some(8));
        heap.commit_transaction().unwrap();
        assert!(heap.image() == before, "catching constructor failure must not commit a partial PIN");
        invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
            &[(true, pin), (false, 3), (false, 126)], &mut heap, &mut frame, &mut host).unwrap();
        // The protected accessors share the public flag, but the setter follows
        // the default conditional-state rule rather than PIN presentation semantics.
        heap.begin_transaction(0).unwrap();
        assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::setValidatedFlag,
            &[(true, pin), (false, 1)], &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
        heap.abort_transaction(&mut []).unwrap();
        heap.begin_transaction(16).unwrap();
        invoke_security(ClassId::OwnerPIN, MethodId::setValidatedFlag,
            &[(true, pin), (false, 1)], &mut heap, &mut frame, &mut host).unwrap();
        for method in [MethodId::getValidatedFlag, MethodId::isValidated] {
            invoke_security(ClassId::OwnerPIN, method,
                &[(true, pin)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short(), Ok(1));
        }
        heap.abort_transaction(&mut []).unwrap();
        invoke_security(ClassId::OwnerPIN, MethodId::getValidatedFlag,
            &[(true, pin)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(0));
        let source = heap.new_array(heap::KIND_BYTE, 127, 1).unwrap();
        heap.byte_slice_mut(source, 0, 127).unwrap().fill(0x42);
        let material = heap.get_word(pin, 2).unwrap();
        let args = |length| [(true, pin), (true, source), (false, 0), (false, length)];
        let Native::Threw(exception) = invoke_security(ClassId::OwnerPIN, MethodId::update,
            &args(127), &mut heap, &mut frame, &mut host).unwrap()
            else { panic!("oversized PIN accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        heap.begin_transaction(32).unwrap();
        assert!(matches!(invoke_security(ClassId::OwnerPIN, MethodId::update,
            &args(126), &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
        assert_eq!(heap.get_word(pin, 1), Ok(0));
        assert!(heap.byte_slice(material, 0, 126).unwrap().iter().all(|byte| *byte == 0));
        heap.abort_transaction(&mut []).unwrap();
        heap.begin_transaction(256).unwrap();
        invoke_security(ClassId::OwnerPIN, MethodId::update,
            &args(126), &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(heap.byte_slice(material, 0, 126).unwrap(), &[0x42; 126]);
        heap.abort_transaction(&mut []).unwrap();
        assert_eq!(heap.get_word(pin, 1), Ok(0));
        assert!(heap.byte_slice(material, 0, 126).unwrap().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn transactions_keep_pin_presentations_and_nonatomic_copies_outside_undo() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let mut host = crate::host::NoHost;
        let pin = new_native(&mut heap, ClassId::OwnerPIN, 6, 1).unwrap();
        let original = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
        let replacement = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
        let destination = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
        heap.byte_slice_mut(original, 0, 4).unwrap().copy_from_slice(b"1234");
        heap.byte_slice_mut(replacement, 0, 4).unwrap().copy_from_slice(b"9999");
        invoke_security(ClassId::OwnerPIN, MethodId::Constructor,
            &[(true, pin), (false, 3), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
        invoke_security(ClassId::OwnerPIN, MethodId::update,
            &[(true, pin), (true, original), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
        for _ in 0..2 {
            invoke_security(ClassId::OwnerPIN, MethodId::check,
                &[(true, pin), (true, replacement), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), 0);
        }
        assert_eq!(heap.get_word(pin, 4), Ok(1));
        let mut jcre = idle();
        jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
        let Native::Threw(exception) = jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap()
            else { panic!("nested transaction accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        invoke_security(ClassId::OwnerPIN, MethodId::update,
            &[(true, pin), (true, replacement), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
        struct PinCheckpoint { saved: alloc::vec::Vec<u8>, fail: bool }
        impl crate::host::Host for PinCheckpoint {
            fn checkpoint(&mut self, state: crate::applet::PersistentView<'_>) -> Result<()> {
                if self.fail { return Err(Error::Storage); }
                self.saved.resize(state.heap_bytes(), 0);
                state.save_into(&mut self.saved)?;
                Ok(())
            }
        }
        let mut checkpoint = PinCheckpoint { saved: vec![], fail: false };
        jcre.instance = Some(pin);
        jcre.buffer = destination;
        for value in [(pin, true), (original, true), (0, false), (4, false)] {
            frame.push_raw(value).unwrap();
        }
        let signature = framework(ClassId::OwnerPIN, MethodId::check, false).method.signature;
        security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
            &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0);
        let saved_length = checkpoint.saved.len();
        let saved = Heap::resume(&mut checkpoint.saved, saved_length).unwrap();
        let saved_material = saved.get_word(pin, 2).unwrap();
        assert_eq!(saved.byte_slice(saved_material, 0, 4).unwrap(), b"1234",
            "PIN checkpoint must not publish the conditional PIN update");
        assert_eq!(saved.get_word(pin, 4), Ok(2));
        assert_eq!(saved.get_word(pin, 3), Ok(0));
        // Save a conditional image first, then overwrite it through the non-atomic API.
        heap.byte_slice_mut(destination, 0, 4).unwrap().fill(7);
        for (reference, value) in [(true, replacement), (false, 0), (true, destination), (false, 0), (false, 4)] {
            frame.push_raw((value, reference)).unwrap();
        }
        util(MethodId::arrayCopyNonAtomic, &mut heap, &mut frame, 1, &mut 100).unwrap();
        assert_eq!(frame.pop_short(), Ok(4));
        jcsystem(MethodId::abortTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
        let material = heap.get_word(pin, 2).unwrap();
        assert_eq!(heap.byte_slice(material, 0, 4).unwrap(), b"1234");
        assert_eq!(heap.get_word(pin, 4), Ok(2), "PIN presentation must survive aborting its update");
        assert_eq!(heap.byte_slice(destination, 0, 4).unwrap(), b"9999");
        let used = heap.used();
        jcsystem(MethodId::beginTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
        invoke_security(ClassId::OwnerPIN, MethodId::check,
            &[(true, pin), (true, original), (false, 0), (false, 4)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short(), Ok(1));
        jcsystem(MethodId::abortTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap();
        assert_eq!(heap.get_word(pin, 3), Ok(1));
        assert_eq!(heap.get_word(pin, 4), Ok(3));
        assert_eq!(heap.used(), used, "transaction exceptions are reused");
        let Native::Threw(exception) = jcsystem(MethodId::commitTransaction, 0, &mut heap, &mut frame, 1, &mut jcre, &mut [], &mut crate::host::NoHost).unwrap()
            else { panic!("commit without begin accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));
        // Invalid presentations still consume a retry, including when their exception
        // is caught and the surrounding transaction is aborted (OwnerPIN.check).
        for (candidate, offset, length, class) in [
            (crate::vm::NULL, 0, 4, ClassId::NullPointerException),
            (original, u16::MAX, 4, ClassId::ArrayIndexOutOfBoundsException),
            (original, 0, u16::MAX, ClassId::ArrayIndexOutOfBoundsException),
            (original, 3, 2, ClassId::ArrayIndexOutOfBoundsException),
        ] {
            // Allocate runtime exceptions before the transaction so abort does not
            // terminate the session because of a newly allocated object.
            let exception = new_exception(&mut heap, class, 1).unwrap();
            heap.put_word_unconditional(pin, 4, 3).unwrap();
            heap.put_word_unconditional(pin, 3, 1).unwrap();
            heap.begin_transaction(256).unwrap();
            let result = invoke_security(ClassId::OwnerPIN, MethodId::check,
                &[(true, pin), (true, candidate), (false, offset), (false, length)],
                &mut heap, &mut frame, &mut host).unwrap();
            assert!(matches!(result, Native::Threw(reference) if reference == exception));
            heap.abort_transaction(&mut []).unwrap();
            assert_eq!(heap.get_word(pin, 4), Ok(2));
            assert_eq!(heap.get_word(pin, 3), Ok(0));
        }
        heap.put_word_unconditional(pin, 4, 3).unwrap();
        checkpoint.fail = true;
        for value in [(pin, true), (original, true), (0, false), (4, false)] {
            frame.push_raw(value).unwrap();
        }
        assert!(matches!(security::call(ClassId::OwnerPIN, MethodId::check, signature, &mut heap,
            &mut checkpoint, &mut frame, 1, &mut jcre, &mut { u32::MAX }, &[]), Err(Error::Storage)));
        assert_eq!(heap.get_word(pin, 4), Ok(2), "failure must stop before a matching PIN resets retries");
        assert_eq!(heap.get_word(pin, 3), Ok(0));
    }

    #[test]
    fn apdu_incoming_queries_enforce_direction_and_single_receive_per_command() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let buffer = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let used = heap.used();
        // Exhausted transaction capacity must not prevent a catchable API error.
        heap.begin_transaction(0).unwrap();
        for incoming in [0, 3] {
            let mut jcre = Jcre::new(0, buffer);
            jcre.incoming = incoming;
            for (method, expected) in [
                (MethodId::getIncomingLength, None),
                (MethodId::getOffsetCdata, None),
                (MethodId::setIncomingAndReceive, Some(incoming as i16)),
                (MethodId::getIncomingLength, Some(incoming as i16)),
                (MethodId::getOffsetCdata, Some(5)),
                (MethodId::setIncomingAndReceive, None),
                (MethodId::setOutgoing, Some(256)),
                (MethodId::getIncomingLength, None),
                (MethodId::getOffsetCdata, None),
                (MethodId::setIncomingAndReceive, None),
            ] {
                frame.push_reference(0).unwrap();
                let result = apdu(method, &mut heap, &mut frame, &mut jcre, 1).unwrap();
                if let Some(expected) = expected {
                    assert!(matches!(result, Native::Returned));
                    assert_eq!(frame.pop_short(), Ok(expected));
                } else {
                    let Native::Threw(exception) = result else { panic!("invalid receive sequence accepted"); };
                    assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::APDUException);
                    assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
                }
            }
        }
        assert_eq!(heap.used(), used);
        assert_eq!(heap.transaction_remaining(), Some(0));
    }

    #[test]
    fn contacted_transport_parameters_and_buffered_receive_match_the_runtime() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let buffer = heap.new_array(heap::KIND_BYTE, 261, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut jcre = Jcre::new(0, buffer);

        for method in [MethodId::getInBlockSize, MethodId::getOutBlockSize] {
            assert!(matches!(apdu(method, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
            assert_eq!(frame.pop_short(), Ok(254));
        }
        frame.push_reference(0).unwrap();
        assert!(matches!(apdu(MethodId::getNAD, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(0));

        jcre.incoming_started = true;
        frame.push_reference(0).unwrap();
        frame.push_short(7).unwrap();
        assert!(matches!(apdu(MethodId::receiveBytes, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(0));
        frame.push_reference(0).unwrap();
        frame.push_short(8).unwrap();
        let Native::Threw(exception) = apdu(MethodId::receiveBytes, &mut heap, &mut frame, &mut jcre, 1).unwrap()
            else { panic!("an undersized receive window was accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));

        assert!(matches!(jcsystem(MethodId::getVersion, 0, &mut heap, &mut frame, 1,
            &mut jcre, &mut [], &mut crate::host::NoHost), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(0x0305));
    }

    #[test]
    fn apdu_cla_flags_follow_channel_encoding_and_reject_reserved_values() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let buffer = heap.new_array(heap::KIND_BYTE, 1, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut jcre = Jcre::new(0, buffer);
        // Java Card 3.0.5 APDU: first/further channel encodings, proprietary
        // classes, the reserved 001 range, and the invalid FF class.
        for (cla, chaining, secure) in [
            (0x00, false, false), (0x03, false, false), (0x04, false, true),
            (0x08, false, true), (0x1c, true, true), (0x10, true, false),
            (0x40, false, false), (0x4c, false, false), (0x60, false, true),
            (0x5f, true, false), (0x7f, true, true), (0x84, false, true),
            (0xcc, false, false), (0xe0, false, true), (0x20, false, false),
            (0x3c, false, false), (0xff, false, false),
        ] {
            heap.byte_slice_mut(buffer, 0, 1).unwrap()[0] = cla;
            for (method, expected) in [(MethodId::isCommandChainingCLA, chaining),
                (MethodId::isSecureMessagingCLA, secure)] {
                frame.push_reference(0).unwrap();
                assert!(matches!(apdu(method, &mut heap, &mut frame, &mut jcre, 1), Ok(Native::Returned)));
                assert_eq!(frame.pop_short(), Ok(i16::from(expected)), "CLA {cla:02x}");
            }
        }
    }

    #[test]
    fn apdu_sends_capture_bytes_before_buffer_reuse_and_enforce_the_declared_length() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let buffer = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
        heap.byte_slice_mut(buffer, 0, 8).unwrap().copy_from_slice(b"abcdefgh");
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut jcre = Jcre::new(0, buffer);
        jcre.expected = 7;
        frame.push_reference(0).unwrap();
        apdu(MethodId::setOutgoing, &mut heap, &mut frame, &mut jcre, 1).unwrap();
        assert_eq!(frame.pop_short(), Ok(7));
        frame.push_reference(0).unwrap(); frame.push_short(4).unwrap();
        apdu(MethodId::setOutgoingLength, &mut heap, &mut frame, &mut jcre, 1).unwrap();
        for method in [MethodId::sendBytes, MethodId::sendBytesLong] {
            frame.push_reference(0).unwrap();
            if method == MethodId::sendBytesLong { frame.push_reference(buffer).unwrap(); }
            frame.push_short(1).unwrap(); frame.push_short(2).unwrap();
            apdu(method, &mut heap, &mut frame, &mut jcre, 1).unwrap();
            if method == MethodId::sendBytes { assert_eq!(jcre.response_data(), Err(Error::Bounds)); }
            heap.byte_slice_mut(buffer, 0, 8).unwrap().fill(b'X');
        }
        assert_eq!(jcre.response_data(), Ok(&b"bcXX"[..]));
        frame.push_reference(0).unwrap(); frame.push_short(0).unwrap(); frame.push_short(1).unwrap();
        let Native::Threw(exception) = apdu(MethodId::sendBytes, &mut heap, &mut frame, &mut jcre, 1).unwrap() else { panic!("excess response accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
        assert_eq!(jcre.outgoing, 4);
        frame.push_reference(0).unwrap();
        let Native::Threw(exception) = apdu(MethodId::setOutgoing, &mut heap, &mut frame, &mut jcre, 1).unwrap() else { panic!("repeated outgoing accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));

        for combined in [false, true] {
            let mut next = Jcre::new(0, buffer);
            if !combined {
                frame.push_reference(0).unwrap();
                apdu(MethodId::setOutgoingNoChaining, &mut heap, &mut frame, &mut next, 1).unwrap();
                frame.pop_short().unwrap();
            }
            for length in [-1, 257] {
                frame.push_reference(0).unwrap();
                if combined { frame.push_short(0).unwrap(); }
                frame.push_short(length).unwrap();
                let method = if combined { MethodId::setOutgoingAndSend } else { MethodId::setOutgoingLength };
                let Native::Threw(exception) = apdu(method, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("invalid length accepted"); };
                assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(3));
                assert_eq!(next.outgoing_length, None);
                assert_eq!(next.outgoing, 0);
            }
        }
        let mut next = Jcre::new(0, buffer);
        for offset in [-1, 8] {
            frame.push_reference(0).unwrap(); frame.push_short(offset).unwrap(); frame.push_short(1).unwrap();
            let Native::Threw(exception) = apdu(MethodId::setOutgoingAndSend, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("invalid source accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(2));
            assert!(!next.outgoing_started);
        }
        frame.push_reference(0).unwrap(); frame.push_short(0).unwrap(); frame.push_short(1).unwrap();
        apdu(MethodId::setOutgoingAndSend, &mut heap, &mut frame, &mut next, 1).unwrap();
        assert_eq!(next.response_data(), Ok(&b"X"[..]));
        for method in [MethodId::sendBytes, MethodId::sendBytesLong] {
            frame.push_reference(0).unwrap();
            if method == MethodId::sendBytesLong { frame.push_reference(buffer).unwrap(); }
            frame.push_short(0).unwrap(); frame.push_short(0).unwrap();
            let Native::Threw(exception) = apdu(method, &mut heap, &mut frame, &mut next, 1).unwrap() else { panic!("send after combined output accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
            assert_eq!(next.response_data(), Ok(&b"X"[..]));
        }
    }

    #[test]
    fn transient_factories_report_lifetimes_and_recoverable_failures() {
        for factory in [MethodId::makeTransientByteArray, MethodId::makeTransientBooleanArray, MethodId::makeTransientShortArray, MethodId::makeTransientObjectArray] {
            let (mut slab, mut words, mut tags) = setup(0);
            let capacity = slab.len();
            let mut heap = Heap::new(&mut slab).unwrap();
            reserve_runtime_exceptions(&mut heap, 1).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            for (length, event) in [(0, 1), (2, 1), (2, 2), (2, 0), (2, 3)] {
                frame.push_short(length).unwrap();
                frame.push_short(event).unwrap();
                let result = jcsystem(factory, 0, &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap();
                if matches!(event, 1 | 2) {
                    assert!(matches!(result, Native::Returned));
                    jcsystem(MethodId::isTransient, 0, &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap();
                    assert_eq!(frame.pop_short().unwrap(), event);
                } else {
                    let Native::Threw(exception) = result else { panic!("invalid clear event accepted"); };
                    assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::SystemException);
                    assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 1);
                }
            }
            // Even a completely full heap and undo log must deliver the API error.
            let remaining = capacity - heap.used() - heap::HEADER;
            heap.new_array(heap::KIND_BYTE, remaining as u16, 1).unwrap();
            assert_eq!(heap.used(), capacity);
            heap.begin_transaction(0).unwrap();
            for (length, event, expected, reason) in [
                (-1, 1, ClassId::NegativeArraySizeException, 0),
                (i16::MIN, 2, ClassId::NegativeArraySizeException, 0),
                (0, 1, ClassId::SystemException, 2),
                (1, 2, ClassId::SystemException, 2),
                (i16::MAX, 1, ClassId::SystemException, 2),
                (0, 3, ClassId::SystemException, 1),
            ] {
                frame.push_short(length).unwrap();
                frame.push_short(event).unwrap();
                let Native::Threw(exception) = jcsystem(factory, 0, &mut heap, &mut frame, 1,
                    &mut idle(), &mut [], &mut crate::host::NoHost).unwrap()
                    else { panic!("invalid transient allocation accepted"); };
                assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, expected);
                assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), reason);
                assert_eq!(heap.used(), capacity);
                assert_eq!(heap.transaction_remaining(), Some(0));
            }
            assert!(!heap.abort_transaction(&mut []).unwrap());
        }
    }

    #[test]
    fn symmetric_keys_clear_material_and_initialization_with_their_lifetime() {
        let signature = framework(ClassId::KeyBuilder, MethodId::buildKey, true).method.signature;
        let invoke = |class, method, heap: &mut Heap, frame: &mut Frame| {
            security::call(class, method, signature, heap, &mut crate::host::NoHost, frame, 1, &mut idle(), &mut { u32::MAX }, &[]).unwrap()
        };
        for (class, first) in [(ClassId::DESKey, 1), (ClassId::AESKey, 13), (ClassId::HMACKey, 19)] {
            for lifetime in 0..3 {
                let (mut slab, mut words, mut tags) = setup(0);
                let mut heap = Heap::new(&mut slab).unwrap();
                let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
                frame.push_short(first + lifetime).unwrap();
                frame.push_short(128).unwrap();
                frame.push_short(0).unwrap();
                invoke(ClassId::KeyBuilder, MethodId::buildKey, &mut heap, &mut frame);
                let key = frame.pop_reference().unwrap();
                let input = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
                let output = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
                if class == ClassId::AESKey {
                    let before = heap.image().to_vec();
                    heap.begin_transaction(0).unwrap();
                    let result = invoke_security(class, MethodId::setKey,
                        &[(true, key), (true, input), (false, 0)],
                        &mut heap, &mut frame, &mut crate::host::NoHost);
                    assert!(matches!(result, Err(Error::TransactionFull)));
                    heap.commit_transaction().unwrap();
                    assert_eq!(heap.image(), before, "failed first import must not consume heap storage");
                }
                // Include a zero-valued key: readiness cannot be inferred from its bytes.
                for event in [heap::CLEAR_ON_DESELECT, heap::CLEAR_ON_RESET] {
                    let value = if event == heap::CLEAR_ON_DESELECT { 0x42 } else { 0 };
                    heap.byte_slice_mut(input, 0, 16).unwrap().fill(value);
                    frame.push_reference(key).unwrap();
                    frame.push_reference(input).unwrap();
                    frame.push_short(0).unwrap();
                    if class == ClassId::HMACKey { frame.push_short(16).unwrap(); }
                    invoke(class, MethodId::setKey, &mut heap, &mut frame);
                    frame.push_reference(key).unwrap();
                    invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
                    assert_eq!(frame.pop_short().unwrap(), 1);
                    heap.clear_transient(event, 1).unwrap();
                    let retained = lifetime == 2 || (lifetime == 0 && event == heap::CLEAR_ON_DESELECT);
                    frame.push_reference(key).unwrap();
                    invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
                    assert_eq!(frame.pop_short().unwrap(), i16::from(retained));
                    heap.byte_slice_mut(output, 0, 16).unwrap().fill(0x55);
                    frame.push_reference(key).unwrap();
                    frame.push_reference(output).unwrap();
                    frame.push_short(0).unwrap();
                    let result = invoke(class, MethodId::getKey, &mut heap, &mut frame);
                    if retained {
                        assert!(matches!(result, Native::Returned));
                        assert_eq!(frame.pop_short().unwrap(), 16);
                        assert_eq!(heap.byte_slice(output, 0, 16).unwrap(), &[value; 16]);
                    } else {
                        let Native::Threw(exception) = result else { panic!("cleared key remained readable"); };
                        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 2);
                        assert_eq!(heap.byte_slice(output, 0, 16).unwrap(), &[0x55; 16]);
                        let material = heap.get_word(key, 2).unwrap();
                        let length = heap.info(material).unwrap().length as usize;
                        assert!(heap.byte_slice(material, 0, length).unwrap().iter().all(|byte| *byte == 0));
                    }
                }
                if class == ClassId::AESKey {
                    // Persistent updates must reject insufficient undo before either bytes
                    // or readiness changes. Transient key state needs no undo space.
                    heap.byte_slice_mut(input, 0, 16).unwrap().fill(0x77);
                    invoke_security(class, MethodId::setKey,
                        &[(true, key), (true, input), (false, 0)],
                        &mut heap, &mut frame, &mut crate::host::NoHost).unwrap();
                    for method in [MethodId::clearKey, MethodId::setKey] {
                        heap.byte_slice_mut(input, 0, 16).unwrap().fill(0x33);
                        let before = heap.image().to_vec();
                        let capacities: &[usize] = if lifetime == 2 { &[22, 30] } else { &[0] };
                        for &capacity in capacities {
                            heap.begin_transaction(capacity).unwrap();
                            let arguments = [(true, key), (true, input), (false, 0)];
                            let count = if method == MethodId::clearKey { 1 } else { 3 };
                            let result = invoke_security(class, method, &arguments[..count],
                                &mut heap, &mut frame, &mut crate::host::NoHost);
                            if capacity == 22 {
                                assert!(matches!(result, Err(Error::TransactionFull)));
                                assert_eq!(heap.transaction_remaining(), Some(capacity));
                                heap.commit_transaction().unwrap();
                                assert_eq!(heap.image(), before);
                            } else {
                                assert!(matches!(result, Ok(Native::Returned)));
                                assert_eq!(heap.transaction_remaining(), Some(0));
                                assert_ne!(heap.image(), before);
                                assert!(!heap.abort_transaction(&mut []).unwrap());
                                assert_eq!(heap.image() == before, lifetime == 2);
                            }
                        }
                    }
                }
                frame.push_reference(key).unwrap();
                invoke(class, MethodId::clearKey, &mut heap, &mut frame);
                frame.push_reference(key).unwrap();
                invoke(class, MethodId::isInitialized, &mut heap, &mut frame);
                assert_eq!(frame.pop_short().unwrap(), 0);
            }
        }
    }

    fn invoke_security(class: ClassId, method: MethodId, args: &[(bool, u16)], heap: &mut Heap,
            frame: &mut Frame, host: &mut dyn crate::host::Host) -> Result<Native> {
            for &(reference, value) in args {
                if reference { frame.push_reference(value)?; } else { frame.push_short(value as i16)?; }
            }
            let target = framework(class, method, matches!(method, MethodId::getInstance | MethodId::Constructor));
            let signature = if method == MethodId::init {
                target.class.methods.iter().find(|entry| entry.id == method && entry.signature.init_vector() == (args.len() == 6)).unwrap().signature
            } else { target.method.signature };
            security::call(class, method, signature,
                heap, host, frame, 1, &mut Jcre { installing: true, ..idle() }, &mut { u32::MAX }, &[])
        }
    #[test]
    fn aes_cipher_streams_overlapping_buffers_and_preserves_output_on_failure() {
        struct CipherHost { calls: usize, fail_at: usize }
        impl crate::host::Host for CipherHost {
            fn supports_cipher(&self, algorithm: u8) -> bool { algorithm == 14 }
            fn aes128_block(&mut self, key: &[u8; 16], block: &mut [u8; 16], encrypt: bool) -> Result<()> {
                assert_eq!(key, &[0x11; 16]);
                assert!(encrypt);
                self.calls += 1;
                for byte in block.iter_mut() { *byte ^= 0xaa; }
                if self.calls == self.fail_at { return Err(Error::Unauthorized); }
                Ok(())
            }
        }
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let mut host = CipherHost { calls: 0, fail_at: usize::MAX };
        let key = new_native(&mut heap, ClassId::AESKey, security::STATE_WORDS, 1).unwrap();
        heap.put_word(key, 0, 13).unwrap(); // transient reset key
        heap.put_word(key, 1, 128).unwrap();
        let data = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
        invoke_security(ClassId::AESKey, MethodId::setKey, &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        invoke_security(ClassId::Cipher, MethodId::getInstance, &[(false,14),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        let cipher = frame.pop_reference().unwrap();
        invoke_security(ClassId::Cipher, MethodId::init, &[(true,cipher),(true,key),(false,2)], &mut heap, &mut frame, &mut host).unwrap();
        for (at, byte) in heap.byte_slice_mut(data, 0, 64).unwrap().iter_mut().enumerate() { *byte = at as u8; }
        invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,5),(true,data),(false,8)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0);
        invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,5),(false,27),(true,data),(false,8)], &mut heap, &mut frame, &mut host).unwrap();
        assert_eq!(frame.pop_short().unwrap(), 32);
        for (at, byte) in heap.byte_slice(data, 8, 32).unwrap().iter().enumerate() { assert_eq!(*byte, at as u8 ^ 0xaa); }
        assert_eq!(host.calls, 2);
        let before = heap.byte_slice(data, 0, 64).unwrap().to_vec();
        for (reference, value) in [(true,cipher),(true,data),(false,0),(false,32),(true,data),(false,0)] {
            if reference { frame.push_reference(value).unwrap(); } else { frame.push_short(value as i16).unwrap(); }
        }
        let mut budget = 31;
        assert!(matches!(test_call_with_budget(framework(ClassId::Cipher, MethodId::doFinal, false),
            &mut heap, &mut host, &mut frame, 1, &mut idle(), &mut budget, &mut []), Err(Error::Quota)));
        assert_eq!(host.calls, 2);
        assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), before);
        host.fail_at = 4;
        assert!(invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,32),(true,data),(false,0)], &mut heap, &mut frame, &mut host).is_err());
        assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), before);
        assert_eq!(heap.byte_slice(heap.get_word(cipher, 5).unwrap(), 0, 16).unwrap(), &[0; 16]);
        heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
        let result = invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
        let Native::Threw(exception) = result else { panic!("cleared key accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 2);
        assert_eq!(host.calls, 4);
    }

    #[test]
    fn cbc_tracks_ciphertext_iv_and_resets_after_final_or_reset() {
        struct CbcHost { calls: alloc::vec::Vec<([u8; 16], usize, bool)>, fail: bool }
        impl crate::host::Host for CbcHost {
            fn supports_cipher(&self, algorithm: u8) -> bool { algorithm == 13 }
            fn aes128_cbc(&mut self, key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8], encrypt: bool) -> Result<()> {
                assert_eq!(key, &[0x11; 16]);
                self.calls.push((*iv, buffer.len(), encrypt));
                buffer.fill(0x30 + self.calls.len() as u8);
                if self.fail { return Err(Error::Unauthorized); }
                Ok(())
            }
        }
        for mode in [1, 2] {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            let mut host = CbcHost { calls: vec![], fail: false };
            let key = new_native(&mut heap, ClassId::AESKey, security::STATE_WORDS, 1).unwrap();
            heap.put_word(key, 0, 15).unwrap();
            heap.put_word(key, 1, 128).unwrap();
            let data = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
            heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x11);
            invoke_security(ClassId::AESKey, MethodId::setKey, &[(true,key),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            heap.byte_slice_mut(data, 0, 16).unwrap().fill(0x19);
            invoke_security(ClassId::Cipher, MethodId::getInstance, &[(false,13),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            let cipher = frame.pop_reference().unwrap();
            heap.begin_transaction(12).unwrap();
            invoke_security(ClassId::Cipher, MethodId::init, &[(true,cipher),(true,key),(false,mode),(true,data),(false,0),(false,16)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(heap.transaction_remaining(), Some(0));
            heap.commit_transaction().unwrap();
            heap.byte_slice_mut(data, 0, 64).unwrap().fill(7);
            for (offset, length, written) in [(0,5,0),(5,27,32)] {
                invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,offset),(false,length),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
                assert_eq!(frame.pop_short().unwrap(), written);
            }
            assert_eq!(host.calls, [([0x19;16],32,mode == 2)]);
            if mode == 1 {
                let before = heap.image().to_vec();
                heap.begin_transaction(8).unwrap();
                assert!(matches!(invoke_security(ClassId::Cipher, MethodId::init,
                    &[(true,cipher),(true,key),(false,2),(true,data),(false,0),(false,16)],
                    &mut heap, &mut frame, &mut host), Err(Error::TransactionFull)));
                heap.commit_transaction().unwrap();
                assert_eq!(heap.image(), before, "failed init must preserve CBC state and mode");
            }
            invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,32),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), 16);
            assert_eq!(host.calls[1], ([if mode == 2 { 0x31 } else { 7 };16],16,mode == 2));
            let pending = heap.get_word(cipher, 5).unwrap();
            assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), &[0;32]);
            let result = invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,0),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            let Native::Threw(exception) = result else { panic!("empty operation accepted"); };
            assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 5);
            invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), 16);
            assert_eq!(host.calls[2].0, [0;16]);
            invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,0),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), 0);
            assert_eq!(host.calls.len(), 3);
            invoke_security(ClassId::Cipher, MethodId::update, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).unwrap();
            assert_eq!(frame.pop_short().unwrap(), 16);
            let state = heap.byte_slice(pending, 0, 32).unwrap().to_vec();
            let output = heap.byte_slice(data, 0, 64).unwrap().to_vec();
            host.fail = true;
            assert!(invoke_security(ClassId::Cipher, MethodId::doFinal, &[(true,cipher),(true,data),(false,0),(false,16),(true,data),(false,0)], &mut heap, &mut frame, &mut host).is_err());
            assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), state);
            assert_eq!(heap.byte_slice(data, 0, 64).unwrap(), output);
            heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
            assert_eq!(heap.byte_slice(pending, 0, 32).unwrap(), &[0;32]);
        }
    }

    #[test]
    fn digest_borrows_overlapping_input_and_publishes_only_complete_results() {
        struct DigestHost { input: usize, calls: usize, result: Result<usize> }
        impl crate::host::Host for DigestHost {
            fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
                self.calls += 1;
                assert_eq!(algorithm, 4);
                assert_eq!(message.as_ptr() as usize, self.input);
                assert_eq!(message, &[0x42; 32]);
                assert_eq!(output.len(), 32);
                output.fill(0x99);
                self.result
            }
        }
        for (offset, result, allowance, succeeds, calls) in [
            (0, Ok(32), 32, true, 1),
            (0, Ok(32), 31, false, 0),
            (1, Ok(32), 32, false, 0),
            (0, Ok(65), 32, false, 1),
            (0, Ok(0), 32, false, 1),
            (0, Err(Error::Unsupported), 32, false, 1),
        ] {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            let digest = new_native(&mut heap, ClassId::MessageDigest, security::STATE_WORDS, 1).unwrap();
            heap.put_word(digest, 0, 4).unwrap();
            let array = heap.new_array(heap::KIND_BYTE, 32, 1).unwrap();
            heap.byte_slice_mut(array, 0, 32).unwrap().fill(0x42);
            let mut host = DigestHost { input: heap.byte_slice(array, 0, 32).unwrap().as_ptr() as usize, calls: 0, result };
            frame.push_reference(digest).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(32).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(offset).unwrap();
            let mut budget = allowance;
            let actual = security::call(ClassId::MessageDigest, MethodId::doFinal,
                framework(ClassId::MessageDigest, MethodId::doFinal, false).method.signature,
                &mut heap, &mut host, &mut frame, 1, &mut idle(), &mut budget, &[]);
            if allowance == 31 { assert!(matches!(actual, Err(Error::Quota))); }
            assert_eq!(budget, if calls == 0 { allowance } else { 0 });
            assert_eq!(actual.is_ok(), succeeds);
            assert_eq!(host.calls, calls);
            assert_eq!(heap.byte_slice(array, 0, 32).unwrap(), &[if succeeds { 0x99 } else { 0x42 }; 32]);
            if succeeds { assert_eq!(frame.pop_short().unwrap(), 32); }
        }
    }

    #[test]
    fn crypto_factories_follow_host_capabilities_and_reject_unsupported_requests() {
        struct Capabilities;
        impl crate::host::Host for Capabilities {
            fn supports_cipher(&self, algorithm: u8) -> bool { matches!(algorithm, 13 | 14) }
            fn supports_digest(&self, algorithm: u8) -> bool { algorithm == 4 }
            fn supports_random(&self, algorithm: u8) -> bool { algorithm == 2 }
            fn supports_agreement(&self, algorithm: u8) -> bool { algorithm == 3 }
            fn supports_signature(&self, algorithm: u8) -> bool { algorithm == 33 }
        }
        for (class, algorithm, external, supported) in [
            (ClassId::MessageDigest, 4, false, true),
            (ClassId::MessageDigest, 5, false, false),
            (ClassId::MessageDigest, 4, true, false),
            (ClassId::RandomData, 2, false, true),
            (ClassId::RandomData, 99, false, false),
            (ClassId::Signature, 1, false, false),
            (ClassId::Signature, 33, false, true),
            (ClassId::Signature, 33, true, false),
            (ClassId::Signature, 34, false, false),
            (ClassId::KeyAgreement, 1, false, false),
            (ClassId::KeyAgreement, 3, false, true),
            (ClassId::KeyAgreement, 3, true, false),
            (ClassId::KeyAgreement, 4, false, false),
            (ClassId::Cipher, 1, false, false),
            (ClassId::Cipher, 13, false, true),
            (ClassId::Cipher, 14, false, true),
        ] {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            frame.push_short(algorithm).unwrap();
            if class != ClassId::RandomData { frame.push_short(i16::from(external)).unwrap(); }
            let result = security::call(class, MethodId::getInstance, framework(class, MethodId::getInstance, true).method.signature, &mut heap, &mut Capabilities, &mut frame, 1, &mut idle(), &mut { u32::MAX }, &[]).unwrap();
            if supported {
                assert!(matches!(result, Native::Returned));
                let instance = frame.pop_reference().unwrap();
                assert_eq!(api_class(heap.info(instance).unwrap().class).unwrap().id, class);
            } else {
                let Native::Threw(exception) = result else { panic!("unsupported {class:?} returned an algorithm holder"); };
                assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::CryptoException);
                assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 3);
            }
        }
        for algorithm in [13, 14] {
            let mut slab = [0; 32]; // Holder fits, its streaming-state array does not.
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut words = [0; 16];
            let mut tags = [0; 8];
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            frame.push_short(algorithm).unwrap();
            frame.push_short(0).unwrap();
            let before = heap.image().to_vec();
            let result = security::call(ClassId::Cipher, MethodId::getInstance,
                framework(ClassId::Cipher, MethodId::getInstance, true).method.signature,
                &mut heap, &mut Capabilities, &mut frame, 1, &mut idle(), &mut 100, &[]);
            assert!(matches!(result, Err(Error::Quota)));
            assert!(heap.image() == before, "failed cipher creation must not leave an incomplete holder");
        }

        for (class, method, token, arguments) in [
            (ClassId::Checksum, MethodId::getInstance, None, 2),
            (ClassId::MessageDigest, MethodId::getInitializedMessageDigestInstance, None, 2),
            (ClassId::InitializedMessageDigest_OneShot, MethodId::open, None, 1),
            (ClassId::MessageDigest_OneShot, MethodId::open, None, 1),
            (ClassId::RandomData_OneShot, MethodId::open, None, 1),
            (ClassId::Signature_OneShot, MethodId::open, None, 3),
            (ClassId::Cipher_OneShot, MethodId::open, None, 2),
            (ClassId::Signature, MethodId::getInstance, Some(2), 4),
            (ClassId::Cipher, MethodId::getInstance, Some(2), 3),
        ] {
            let (mut slab, mut words, mut tags) = setup(0);
            let mut heap = Heap::new(&mut slab).unwrap();
            let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
            for value in 0..arguments { frame.push_short(value).unwrap(); }
            let target = framework_token(class, method, true, token);
            let Native::Threw(exception) = security::call(class, method,
                target.method.signature, &mut heap, &mut Capabilities, &mut frame, 1,
                &mut idle(), &mut 100, &[]).unwrap()
                else { panic!("optional factory {class:?}.{method:?} did not throw"); };
            assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id,
                ClassId::CryptoException);
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(3));
        }
    }

    #[test]
    fn throw_it_produces_an_exception_carrying_its_status_word() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_short(0x6a80u16 as i16).unwrap();
        let target = framework(ClassId::ISOException, MethodId::throwIt, true);
        let Native::Threw(exception) = call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap() else {
            panic!("throwIt has to throw");
        };
        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 0x6a80);
        // It is an object of a class the card provides, which no package can define.
        let class = heap.info(exception).unwrap().class;
        assert!(is_native_class(class));
        assert_eq!(api_class(class).unwrap().id, ClassId::ISOException);
    }

    #[test]
    fn an_exception_is_caught_by_its_own_class_or_any_it_extends() {
        let iso = {
            let (index, class) = PACKAGES
                .iter()
                .enumerate()
                .find_map(|(index, package)| {
                    package
                        .classes
                        .iter()
                        .find(|entry| entry.id == ClassId::ISOException)
                        .map(|class| (index, class))
                })
                .unwrap();
            native_class(index, class.token)
        };
        let runtime = {
            let (index, class) = PACKAGES
                .iter()
                .enumerate()
                .find_map(|(index, package)| {
                    package
                        .classes
                        .iter()
                        .find(|entry| entry.id == ClassId::RuntimeException)
                        .map(|class| (index, class))
                })
                .unwrap();
            native_class(index, class.token)
        };
        assert!(native_is_a(iso, iso));
        // Catching a supertype has to match, which is how catch of CardRuntimeException
        // or RuntimeException catches an ISOException.
        assert!(native_is_a(iso, runtime));
        // The other direction does not.
        assert!(!native_is_a(runtime, iso));
    }

    #[test]
    fn util_reads_and_writes_shorts_in_a_byte_array() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();

        frame.push_reference(array).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(0x1234).unwrap();
        call(
            framework(ClassId::Util, MethodId::setShort, true),
            &mut heap,
            &mut crate::host::NoHost,
            &mut frame,
            1,
            &mut idle(),
        )
        .unwrap();
        // It answers the offset one past what it wrote, which is what makes these chain.
        assert_eq!(frame.pop_short().unwrap(), 4);

        frame.push_reference(array).unwrap();
        frame.push_short(2).unwrap();
        call(
            framework(ClassId::Util, MethodId::getShort, true),
            &mut heap,
            &mut crate::host::NoHost,
            &mut frame,
            1,
            &mut idle(),
        )
        .unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0x1234);

        // setShort must admit both bytes before either changes, even if the
        // caller catches a capacity failure and commits instead of aborting.
        for capacity in [0, TRANSACTION_CAPACITY] {
            heap.begin_transaction(capacity).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(2).unwrap();
            frame.push_short(-128).unwrap();
            let result = call(framework(ClassId::Util, MethodId::setShort, true),
                &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle());
            if capacity == 0 {
                assert!(matches!(result, Err(Error::TransactionFull)));
                heap.commit_transaction().unwrap();
            } else {
                assert!(matches!(result, Ok(Native::Returned)));
                assert_eq!(frame.pop_short(), Ok(4));
                assert_eq!(heap.byte_slice(array, 2, 2).unwrap(), [0xff, 0x80]);
                heap.abort_transaction(&mut []).unwrap();
            }
            assert_eq!(heap.byte_slice(array, 2, 2).unwrap(), [0x12, 0x34]);
        }
    }

    #[test]
    fn util_copies_within_one_array_without_overwriting_what_it_is_reading() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 600, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        // Cross the former 256-byte staging boundary in both overlap directions.
        for (source, destination, length) in [(0, 1, 599), (1, 0, 599), (600, 600, 0)] {
            for (index, byte) in heap.byte_slice_mut(array, 0, 600).unwrap().iter_mut().enumerate() {
                *byte = index as u8;
            }
            let before = heap.byte_slice(array, 0, 600).unwrap().to_vec();
            frame.push_reference(array).unwrap();
            frame.push_short(source).unwrap();
            frame.push_reference(array).unwrap();
            frame.push_short(destination).unwrap();
            frame.push_short(length).unwrap();
            let mut budget = length as u32;
            test_call_with_budget(
                framework(ClassId::Util, MethodId::arrayCopyNonAtomic, true),
                &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle(), &mut budget, &mut [],
            ).unwrap();
            assert_eq!(budget, 0);
            assert_eq!(frame.pop_short().unwrap(), destination + length);
            let mut expected = before;
            expected.copy_within(source as usize..(source + length) as usize, destination as usize);
            assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), expected);
        }
        let before = heap.byte_slice(array, 0, 600).unwrap().to_vec();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(1).unwrap();
        frame.push_short(599).unwrap();
        let mut budget = 598;
        assert!(matches!(test_call_with_budget(
            framework(ClassId::Util, MethodId::arrayCopyNonAtomic, true),
            &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle(), &mut budget, &mut [],
        ), Err(Error::Quota)));
        assert_eq!(budget, 598);
        assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), before);
        assert_eq!(heap.copy_bytes(array, 0, array, 1, 600), Err(Error::Bounds));
        assert_eq!(heap.copy_bytes(array, usize::MAX, array, 0, 1), Err(Error::Bounds));
        assert_eq!(heap.byte_slice(array, 0, 600).unwrap(), before);
    }

    #[test]
    fn util_fills_and_compares() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let left = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
        let right = heap.new_array(heap::KIND_BYTE, 4, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        for array in [left, right] {
            frame.push_reference(array).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(4).unwrap();
            frame.push_short(7).unwrap();
            call(
                framework(ClassId::Util, MethodId::arrayFillNonAtomic, true),
                &mut heap,
                &mut crate::host::NoHost,
                &mut frame,
                1,
                &mut idle(),
            )
            .unwrap();
            frame.pop_short().unwrap();
        }
        let compare = framework(ClassId::Util, MethodId::arrayCompare, true);
        let run = |heap: &mut Heap, frame: &mut Frame| {
            frame.push_reference(left).unwrap();
            frame.push_short(0).unwrap();
            frame.push_reference(right).unwrap();
            frame.push_short(0).unwrap();
            frame.push_short(4).unwrap();
            call(compare, heap, &mut crate::host::NoHost, frame, 1, &mut idle()).unwrap();
            frame.pop_short().unwrap()
        };
        assert_eq!(run(&mut heap, &mut frame), 0);
        // It answers an ordering rather than equality, so a difference has a direction.
        heap.byte_slice_mut(right, 2, 1).unwrap()[0] = 9;
        assert_eq!(run(&mut heap, &mut frame), -1);
        heap.byte_slice_mut(right, 2, 1).unwrap()[0] = 1;
        assert_eq!(run(&mut heap, &mut frame), 1);

        // A first-byte mismatch must not hide an invalid tail or empty range.
        heap.byte_slice_mut(right, 0, 1).unwrap()[0] = 0;
        for (source, source_offset, destination, destination_offset, length, expected) in [
            (left, 0, right, 0, 5, ClassId::ArrayIndexOutOfBoundsException),
            (left, -1, right, 0, 0, ClassId::ArrayIndexOutOfBoundsException),
            (left, 0, right, -1, 0, ClassId::ArrayIndexOutOfBoundsException),
            (left, 5, right, 0, 0, ClassId::ArrayIndexOutOfBoundsException),
            (left, 0, right, 5, 0, ClassId::ArrayIndexOutOfBoundsException),
            (left, 0, right, 0, -1, ClassId::ArrayIndexOutOfBoundsException),
            (0, 0, right, 0, 0, ClassId::NullPointerException),
            (left, 0, 0, 0, 0, ClassId::NullPointerException),
        ] {
            frame.push_reference(source).unwrap();
            frame.push_short(source_offset).unwrap();
            frame.push_reference(destination).unwrap();
            frame.push_short(destination_offset).unwrap();
            frame.push_short(length).unwrap();
            let Native::Threw(exception) = call(compare, &mut heap, &mut crate::host::NoHost,
                &mut frame, 1, &mut idle()).unwrap() else { panic!("invalid comparison accepted"); };
            assert_eq!(exception, new_exception(&mut heap, expected, 1).unwrap());
        }
        for (offset, length, available, expected) in [(4, 0, 0, Ok(0)), (0, 4, 3, Err(Error::Quota)), (0, 4, 4, Ok(1))] {
            frame.push_reference(left).unwrap();
            frame.push_short(offset).unwrap();
            frame.push_reference(right).unwrap();
            frame.push_short(offset).unwrap();
            frame.push_short(length).unwrap();
            let mut budget = available;
            let result = test_call_with_budget(compare, &mut heap, &mut crate::host::NoHost,
                &mut frame, 1, &mut idle(), &mut budget, &mut []).and_then(|_| frame.pop_short());
            assert_eq!(result, expected);
            assert_eq!(budget, if expected.is_ok() { available - length as u32 } else { available });
        }

        for method in [MethodId::arrayFill, MethodId::arrayFillNonAtomic] {
            heap.byte_slice_mut(left, 0, 4).unwrap().fill(7);
            heap.begin_transaction(TRANSACTION_CAPACITY).unwrap();
            for available in [3, 4] {
                frame.push_reference(left).unwrap();
                frame.push_short(0).unwrap();
                frame.push_short(4).unwrap();
                frame.push_short(9).unwrap();
                let mut budget = available;
                let result = test_call_with_budget(framework(ClassId::Util, method, true), &mut heap,
                    &mut crate::host::NoHost, &mut frame, 1, &mut idle(), &mut budget, &mut []);
                if available == 3 {
                    assert!(matches!(result, Err(Error::Quota)));
                    assert_eq!(budget, 3);
                    assert_eq!(heap.byte_slice(left, 0, 4).unwrap(), [7; 4]);
                } else {
                    result.unwrap();
                    assert_eq!(frame.pop_short().unwrap(), 4);
                    assert_eq!(budget, 0);
                }
            }
            heap.abort_transaction(&mut []).unwrap();
            assert_eq!(heap.byte_slice(left, 0, 4).unwrap(),
                [if method == MethodId::arrayFill { 7 } else { 9 }; 4]);
        }
    }

    #[test]
    fn owner_pin_builder_constructs_the_supported_type_and_names_optional_types() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 16).unwrap();
        let signature = framework(ClassId::OwnerPINBuilder, MethodId::buildOwnerPIN, true)
            .method.signature;
        let mut jcre = idle();
        let mut budget = u32::MAX;
        for value in [3, 8, 1] { frame.push_short(value).unwrap(); }
        assert!(matches!(security::call(ClassId::OwnerPINBuilder, MethodId::buildOwnerPIN,
            signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
            &mut budget, &[]), Ok(Native::Returned)));
        let pin = frame.pop_reference().unwrap();
        assert_eq!(api_class(heap.info(pin).unwrap().class).unwrap().id, ClassId::OwnerPIN);
        frame.push_reference(pin).unwrap();
        assert!(matches!(security::call(ClassId::OwnerPIN, MethodId::getTriesRemaining,
            signature, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut jcre,
            &mut budget, &[]), Ok(Native::Returned)));
        assert_eq!(frame.pop_short(), Ok(3));

        for (pin_type, class, reason) in [
            (0, ClassId::PINException, 1),
            (2, ClassId::SystemException, 6),
            (3, ClassId::SystemException, 6),
        ] {
            for value in [3, 8, pin_type] { frame.push_short(value).unwrap(); }
            let Native::Threw(exception) = security::call(ClassId::OwnerPINBuilder,
                MethodId::buildOwnerPIN, signature, &mut heap, &mut crate::host::NoHost,
                &mut frame, 1, &mut jcre, &mut budget, &[]).unwrap()
                else { panic!("unsupported OwnerPIN type was accepted"); };
            assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, class);
            assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(reason));
        }
    }

    #[test]
    fn available_memory_supports_both_java_card_forms() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        reserve_runtime_exceptions(&mut heap, 1).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();

        let available = heap.available();
        frame.push_short(0).unwrap();
        assert!(matches!(jcsystem(MethodId::getAvailableMemory, 16, &mut heap, &mut frame,
            1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap(), Native::Returned));
        assert_eq!(frame.pop_short().unwrap(), available.min(i16::MAX as usize) as i16);

        let output = heap.new_array(heap::KIND_SHORT, 2, 1).unwrap();
        let available = heap.available() as u32;
        frame.push_reference(output).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(jcsystem(MethodId::getAvailableMemory, 22, &mut heap, &mut frame,
            1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap(), Native::Returned));
        assert_eq!(heap.array_get(output, 0).unwrap() as u16, (available >> 16) as u16);
        assert_eq!(heap.array_get(output, 1).unwrap() as u16, available as u16);

        frame.push_short(3).unwrap();
        let Native::Threw(exception) = jcsystem(MethodId::getAvailableMemory, 16,
            &mut heap, &mut frame, 1, &mut idle(), &mut [], &mut crate::host::NoHost).unwrap()
        else { panic!("invalid memory type accepted"); };
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(1));
    }

    #[test]
    fn a_method_the_card_does_not_provide_says_so() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        // Shareable interfaces are not built, so this is a real API entry with nothing
        // behind it.
        let target = framework(
            ClassId::JCSystem,
            MethodId::getAppletShareableInterfaceObject,
            true,
        );
        assert!(matches!(
            call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap(),
            Native::Unimplemented
        ));
        let target = framework(ClassId::GPSystem, MethodId::getSecureChannel, true);
        let Native::Threw(exception) = call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap() else {
            panic!("an unavailable applet channel must not return a usable-looking handle");
        };
        assert_eq!(api_class(heap.info(exception).unwrap().class).unwrap().id, ClassId::SystemException);
        assert_eq!(heap.get_word(exception, REASON_FIELD), Ok(5));
    }
}
