//! The classes an applet borrows rather than carries, JCRE §2.
//!
//! An applet's own bytecode is only half of what it runs. The other half is the API, which
//! the card provides and the applet reaches by token. This module is the card's side.
//!
//! A native class has no Class component entry to be an instance of, so its objects carry
//! a class word with the high bit set, which no internal class reference can have. That is
//! what lets one heap hold both kinds of object and one catch clause match either.
use crate::jcvm_api::{ApiClass, PACKAGES};
use crate::link::ApiTarget;
use crate::vm::frame::{Frame, Reference};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

mod security;

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
    thrown.supers.contains(&caught.name)
}

/// Field zero of an `ISOException`, which carries the status word to report.
pub const REASON_FIELD: usize = 0;

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
    /// Bytes of command data in the buffer, after the header.
    pub incoming: u16,
    /// Bytes of response the applet has asked to send.
    pub outgoing: u16,
    /// Where the command data starts in the buffer. Five for a short APDU, JCRE §4.
    pub data_offset: u16,
    /// Whether this command is the one that selected the applet.
    pub selecting: bool,
    /// Transactions are counted rather than nested. A second begin is an error, JCRE §7.
    pub transaction_depth: u8,
    /// The applet's lifecycle byte, which GlobalPlatform keeps rather than the applet.
    pub lifecycle: u8,
    /// The AID the applet registered under, if it chose one.
    pub aid: [u8; 16],
    pub aid_length: u8,
}

impl Jcre {
    pub fn new(apdu: Reference, buffer: Reference) -> Self {
        Self {
            apdu,
            buffer,
            instance: None,
            incoming: 0,
            outgoing: 0,
            data_offset: 5,
            selecting: false,
            transaction_depth: 0,
            // Selectable, GP 2.3 Table 11-4. An applet moves itself on from here.
            lifecycle: 0x07,
            aid: [0; 16],
            aid_length: 0,
        }
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

/// Call an API method.
///
/// Arguments are on the frame's stack, receiver first as in any instance call, and a
/// result is left there the same way.
pub fn call(
    target: ApiTarget,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
) -> Result<Native> {
    let package = target.package.name;
    let class = target.class.name;
    let method = target.method.name;
    match (package, class, method) {
        // Constructing an Object or any exception does nothing the engine has to model.
        // The allocation already happened, and the fields start zeroed.
        ("java.lang", _, "<init>") => {
            frame.pop_reference()?;
            Ok(Native::Returned)
        }
        ("javacard.framework", "javacard/framework/ISOException", "throwIt") => {
            let reason = frame.pop_short()?;
            let exception = new_exception(heap, "javacard/framework/ISOException", context)?;
            heap.put_word(exception, REASON_FIELD, reason as u16)?;
            Ok(Native::Threw(exception))
        }
        ("javacard.framework", "javacard/framework/ISOException", "<init>") => {
            let reason = frame.pop_short()?;
            let this = frame.pop_reference()?;
            heap.put_word(this, REASON_FIELD, reason as u16)?;
            Ok(Native::Returned)
        }
        ("javacard.framework", "javacard/framework/ISOException", "getReason") => {
            let this = frame.pop_reference()?;
            let reason = heap.get_word(this, REASON_FIELD)?;
            frame.push_short(reason as i16)?;
            Ok(Native::Returned)
        }
        ("javacard.framework", "javacard/framework/Util", name) => util(name, heap, frame, context),
        ("javacard.framework", "javacard/framework/APDU", name) => {
            apdu(name, heap, frame, jcre)
        }
        ("javacard.framework", "javacard/framework/JCSystem", name) => {
            jcsystem(name, heap, frame, context, jcre)
        }
        ("javacard.framework", "javacard/framework/Applet", "register") => {
            // Two forms, JCRE §3.1. One registers under the AID the installer gave, the
            // other under an AID the applet chose out of a byte array it holds.
            if target.method.descriptor != "()V" {
                let length = frame.pop_short()?;
                let offset = frame.pop_short()?;
                let array = frame.pop_reference()?;
                heap.check_access(array, context)?;
                if length < 0 || offset < 0 || length as usize > jcre.aid.len() {
                    return Err(Error::Bounds);
                }
                let bytes = heap.byte_slice(array, offset as usize, length as usize)?;
                jcre.aid[..length as usize].copy_from_slice(bytes);
                jcre.aid_length = length as u8;
            }
            // The applet hands itself to the runtime. Everything after this command can
            // select it.
            let instance = frame.pop_reference()?;
            jcre.instance = Some(instance);
            Ok(Native::Returned)
        }
        ("javacard.framework", "javacard/framework/Applet", "selectingApplet") => {
            frame.pop_reference()?;
            frame.push_short(jcre.selecting as i16)?;
            Ok(Native::Returned)
        }
        ("javacard.framework", "javacard/framework/Applet", "<init>") => {
            frame.pop_reference()?;
            Ok(Native::Returned)
        }
        _ => {
            let handled = security::call(
                class,
                method,
                target.method.descriptor,
                heap,
                host,
                frame,
                context,
                jcre,
            )?;
            if let Native::Unimplemented = handled {
                report(class, method);
            }
            Ok(handled)
        }
    }
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
    name: &str,
    words: u16,
    context: heap::Context,
) -> Result<Reference> {
    for (index, package) in PACKAGES.iter().enumerate() {
        if let Some(class) = package.classes.iter().find(|entry| entry.name == name) {
            return heap.new_object(native_class(index, class.token), words, context);
        }
    }
    Err(Error::Missing)
}

/// `javacard.framework.APDU`, JCRE §4. The buffer is an ordinary byte array on the heap,
/// so an applet reading it goes through the same bounds and firewall checks as any array.
fn apdu(name: &str, heap: &mut Heap, frame: &mut Frame, jcre: &mut Jcre) -> Result<Native> {
    match name {
        "getBuffer" => {
            frame.pop_reference()?;
            frame.push_reference(jcre.buffer)?;
        }
        "getIncomingLength" => {
            frame.pop_reference()?;
            frame.push_short(jcre.incoming as i16)?;
        }
        "getOffsetCdata" => {
            frame.pop_reference()?;
            frame.push_short(jcre.data_offset as i16)?;
        }
        "setIncomingAndReceive" => {
            frame.pop_reference()?;
            // The whole command is already in the buffer, so there is nothing to wait for
            // and the answer is everything that arrived.
            frame.push_short(jcre.incoming as i16)?;
        }
        "setOutgoing" => {
            frame.pop_reference()?;
            frame.push_short(0)?;
        }
        "setOutgoingLength" => {
            let length = frame.pop_short()?;
            frame.pop_reference()?;
            jcre.outgoing = length.max(0) as u16;
        }
        "setOutgoingAndSend" => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            frame.pop_reference()?;
            if offset < 0 || length < 0 {
                return Err(Error::Bounds);
            }
            // The response has to start at the front of the buffer, which is what the
            // transport sends. Anything else is moved there now.
            if offset != 0 && length != 0 {
                let mut staging = [0u8; 256];
                let step = (length as usize).min(staging.len());
                staging[..step]
                    .copy_from_slice(heap.byte_slice(jcre.buffer, offset as usize, step)?);
                heap.byte_slice_mut(jcre.buffer, 0, step)?
                    .copy_from_slice(&staging[..step]);
            }
            jcre.outgoing = length as u16;
        }
        "isCommandChainingCLA" | "isSecureMessagingCLA" => {
            frame.pop_reference()?;
            let cla = heap.byte_slice(jcre.buffer, 0, 1)?[0];
            let bit = if name == "isCommandChainingCLA" { 0x10 } else { 0x0c };
            frame.push_short((cla & bit != 0) as i16)?;
        }
        "getProtocol" => {
            // A contacted card. An applet that refuses contactless selection reads this,
            // so answering with a contactless value would make it refuse every session.
            frame.push_short(0x01)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

/// `javacard.framework.JCSystem`, JCRE §7.
fn jcsystem(
    name: &str,
    heap: &mut Heap,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
) -> Result<Native> {
    match name {
        "makeTransientByteArray" | "makeTransientBooleanArray" | "makeTransientShortArray"
        | "makeTransientObjectArray" => {
            // The clear event is taken and ignored. Nothing here survives a reset yet, so
            // both events are honoured by the heap being rebuilt rather than by tracking.
            let _event = frame.pop_short()?;
            let length = frame.pop_short()?;
            if length < 0 {
                return Err(Error::Bounds);
            }
            let kind = match name {
                "makeTransientByteArray" => heap::KIND_BYTE,
                "makeTransientBooleanArray" => heap::KIND_BOOLEAN,
                "makeTransientShortArray" => heap::KIND_SHORT,
                _ => heap::KIND_REFERENCE,
            };
            let array = heap.new_array(kind, length as u16, context)?;
            frame.push_reference(array)?;
        }
        "isObjectDeletionSupported" => frame.push_short(0)?,
        "requestObjectDeletion" => {
            // Legal to do nothing, JCRE §7.4. An applet that depends on it asks first.
        }
        "getTransactionDepth" => frame.push_short(jcre.transaction_depth as i16)?,
        "beginTransaction" => {
            // Transactions do not nest, JCRE §7.6, so a second begin is an error rather
            // than a deeper level.
            if jcre.transaction_depth != 0 {
                return Ok(Native::Threw(new_exception(
                    heap,
                    "javacard/framework/TransactionException",
                    context,
                )?));
            }
            jcre.transaction_depth = 1;
        }
        "commitTransaction" | "abortTransaction" => {
            if jcre.transaction_depth == 0 {
                return Ok(Native::Threw(new_exception(
                    heap,
                    "javacard/framework/TransactionException",
                    context,
                )?));
            }
            jcre.transaction_depth = 0;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

/// Allocate an instance of a class the card provides.
pub fn new_exception(heap: &mut Heap, name: &str, context: heap::Context) -> Result<Reference> {
    for (index, package) in PACKAGES.iter().enumerate() {
        if let Some(class) = package.classes.iter().find(|entry| entry.name == name) {
            // One word, which every exception uses for its reason.
            return heap.new_object(native_class(index, class.token), 1, context);
        }
    }
    Err(Error::Missing)
}

/// `javacard.framework.Util`, JCRE §3. Every method here works on arrays the applet owns,
/// so every access goes through the firewall like any other.
fn util(name: &str, heap: &mut Heap, frame: &mut Frame, context: heap::Context) -> Result<Native> {
    match name {
        "makeShort" => {
            let low = frame.pop_short()?;
            let high = frame.pop_short()?;
            frame.push_short((((high as u16) << 8) | (low as u8 as u16)) as i16)?;
        }
        "getShort" => {
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            let bytes = heap.byte_slice(array, index(offset)?, 2)?;
            frame.push_short(i16::from_be_bytes([bytes[0], bytes[1]]))?;
        }
        "setShort" => {
            let value = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            heap.byte_slice_mut(array, index(offset)?, 2)?
                .copy_from_slice(&value.to_be_bytes());
            // It answers the offset one past the short it wrote.
            frame.push_short(offset.wrapping_add(2))?;
        }
        "arrayCopy" | "arrayCopyNonAtomic" => {
            let length = frame.pop_short()?;
            let destination_offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let source_offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            heap.check_access(source, context)?;
            heap.check_access(destination, context)?;
            let length = index(length)?;
            // Read the source out before writing, because the two may be the same array.
            let mut buffer = [0u8; 256];
            let mut copied = 0;
            while copied < length {
                let step = (length - copied).min(buffer.len());
                buffer[..step].copy_from_slice(heap.byte_slice(
                    source,
                    index(source_offset)? + copied,
                    step,
                )?);
                heap.byte_slice_mut(destination, index(destination_offset)? + copied, step)?
                    .copy_from_slice(&buffer[..step]);
                copied += step;
            }
            frame.push_short(destination_offset.wrapping_add(length as i16))?;
        }
        "arrayFill" | "arrayFillNonAtomic" => {
            let value = frame.pop_short()?;
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            heap.byte_slice_mut(array, index(offset)?, index(length)?)?
                .fill(value as u8);
            frame.push_short(offset.wrapping_add(length))?;
        }
        "arrayCompare" => {
            let length = frame.pop_short()?;
            let right_offset = frame.pop_short()?;
            let right = frame.pop_reference()?;
            let left_offset = frame.pop_short()?;
            let left = frame.pop_reference()?;
            heap.check_access(left, context)?;
            heap.check_access(right, context)?;
            let length = index(length)?;
            // It answers an ordering rather than equality, so this cannot be a constant
            // time comparison. A caller wanting one compares the answer against zero and
            // accepts that the card leaks where the first difference is.
            let mut answer = 0i16;
            for at in 0..length {
                let left_byte = heap.byte_slice(left, index(left_offset)? + at, 1)?[0];
                let right_byte = heap.byte_slice(right, index(right_offset)? + at, 1)?[0];
                if left_byte != right_byte {
                    answer = if left_byte < right_byte { -1 } else { 1 };
                    break;
                }
            }
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

    fn framework(class: &str, method: &str, static_token: bool) -> ApiTarget {
        for package in PACKAGES.iter() {
            for entry in package.classes.iter() {
                if entry.name != class {
                    continue;
                }
                for candidate in entry.methods.iter() {
                    if candidate.name == method && candidate.static_token == static_token {
                        return ApiTarget {
                            package,
                            class: entry,
                            method: candidate,
                        };
                    }
                }
            }
        }
        panic!("no {class}.{method}");
    }

    fn setup(words: usize) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u16>, alloc::vec::Vec<u8>) {
        (vec![0; 1024], vec![0; words + 16], vec![0; 8])
    }

    /// A runtime with no command in flight, for the methods that do not read one.
    fn idle() -> Jcre {
        Jcre::new(0, 0)
    }

    #[test]
    fn throw_it_produces_an_exception_carrying_its_status_word() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_short(0x6a80u16 as i16).unwrap();
        let target = framework("javacard/framework/ISOException", "throwIt", true);
        let Native::Threw(exception) = call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap() else {
            panic!("throwIt has to throw");
        };
        assert_eq!(heap.get_word(exception, REASON_FIELD).unwrap(), 0x6a80);
        // It is an object of a class the card provides, which no package can define.
        let class = heap.info(exception).unwrap().class;
        assert!(is_native_class(class));
        assert_eq!(api_class(class).unwrap().name, "javacard/framework/ISOException");
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
                        .find(|entry| entry.name == "javacard/framework/ISOException")
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
                        .find(|entry| entry.name == "java/lang/RuntimeException")
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
            framework("javacard/framework/Util", "setShort", true),
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
            framework("javacard/framework/Util", "getShort", true),
            &mut heap,
            &mut crate::host::NoHost,
            &mut frame,
            1,
            &mut idle(),
        )
        .unwrap();
        assert_eq!(frame.pop_short().unwrap(), 0x1234);
    }

    #[test]
    fn util_copies_within_one_array_without_overwriting_what_it_is_reading() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let array = heap.new_array(heap::KIND_BYTE, 8, 1).unwrap();
        heap.byte_slice_mut(array, 0, 4)
            .unwrap()
            .copy_from_slice(&[1, 2, 3, 4]);
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        // Overlapping copy forwards, the case that would smear the first byte if the copy
        // read and wrote one byte at a time.
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(1).unwrap();
        frame.push_short(3).unwrap();
        call(
            framework("javacard/framework/Util", "arrayCopyNonAtomic", true),
            &mut heap,
            &mut crate::host::NoHost,
            &mut frame,
            1,
            &mut idle(),
        )
        .unwrap();
        assert_eq!(frame.pop_short().unwrap(), 4);
        assert_eq!(heap.byte_slice(array, 0, 5).unwrap(), &[1, 1, 2, 3, 0]);
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
                framework("javacard/framework/Util", "arrayFillNonAtomic", true),
                &mut heap,
                &mut crate::host::NoHost,
                &mut frame,
                1,
                &mut idle(),
            )
            .unwrap();
            frame.pop_short().unwrap();
        }
        let compare = framework("javacard/framework/Util", "arrayCompare", true);
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
    }

    #[test]
    fn a_method_the_card_does_not_provide_says_so() {
        let (mut slab, mut words, mut tags) = setup(0);
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        // Shareable interfaces are not built, so this is a real API entry with nothing
        // behind it.
        let target = framework(
            "javacard/framework/JCSystem",
            "getAppletShareableInterfaceObject",
            true,
        );
        assert!(matches!(
            call(target, &mut heap, &mut crate::host::NoHost, &mut frame, 1, &mut idle()).unwrap(),
            Native::Unimplemented
        ));
    }
}
