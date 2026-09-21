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
mod tests;
