//! The applet lifecycle, JCRE §3.
//!
//! An applet is installed once, selected when a host asks for it by AID, and then handed
//! one command at a time. This drives that from outside, so the transport never has to know
//! anything about frames, tokens or the heap.
//!
//! The status word an applet produces is not a return value. It comes from the exception
//! that left `process`, or from nothing going wrong, which is why every path here ends in
//! one rather than in a result the applet chose.
use crate::jcvm_api::{ClassId, MethodId};
use crate::cap::LoadFile;
use crate::code::Limits;
use crate::jcvm_api::PACKAGES;
use crate::link::Linked;
use crate::host::Host;
use crate::natives::{self, Jcre};
use crate::vm::exec::{Arena, Machine, invoke};
use crate::vm::frame::{Frame, Reference};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};
use alloc::vec::Vec;
use zeroize::Zeroize;
mod persistence;
pub use persistence::{PersistentState, VolatileState};

/// Status words the runtime environment produces itself, ISO 7816-4.
pub const SW_SUCCESS: u16 = 0x9000;
pub const SW_UNKNOWN: u16 = 0x6f00;

/// How much of the card one applet is given.
#[derive(Clone, Copy, Debug)]
pub struct Sizes {
    pub heap_bytes: usize,
    pub frame_words: usize,
    /// Bytes of APDU buffer, which bounds a command and its response.
    pub buffer_bytes: u16,
    /// Instructions one command may run.
    pub budget: u32,
}

impl Default for Sizes {
    fn default() -> Self {
        Self {
            heap_bytes: 8192,
            frame_words: 1024,
            // A short APDU, its header and its status word, JCRE §4.
            buffer_bytes: 261,
            budget: 1_000_000,
        }
    }
}

/// One installed applet and everything it owns.
pub struct Card {
    heap: Vec<u8>,
    heap_used: usize,
    runtime_bytes: usize,
    statics: Vec<u8>,
    words: Vec<u16>,
    tags: Vec<u8>,
    apdu: Reference,
    buffer: Reference,
    instance: Option<Reference>,
    selected: bool,
    context: heap::Context,
    sizes: Sizes,
}

impl Drop for Card {
    fn drop(&mut self) {
        self.heap.zeroize();
        self.statics.zeroize();
        self.words.zeroize();
        self.tags.zeroize();
    }
}

/// What a command produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

/// Authenticated management identity and the framed GlobalPlatform install data.
pub struct Installation<'a> {
    pub module_aid: &'a [u8],
    pub instance_aid: &'a [u8],
    pub parameters: &'a [u8],
}

impl Card {
    /// Lay out the memory one applet gets, and build the objects the runtime hands it.
    pub fn new(file: &LoadFile, sizes: Sizes) -> Result<Self> {
        let statics = file.static_fields()?;
        let mut card = Self {
            heap: Vec::new(),
            heap_used: 0,
            runtime_bytes: 0,
            statics: Vec::new(),
            words: Vec::new(),
            tags: Vec::new(),
            apdu: 0,
            buffer: 0,
            // Every applet in this package shares one context until a second package can
            // be loaded, JCRE §6.1.2.
            instance: None,
            selected: false,
            context: 1,
            sizes,
        };
        reserve(&mut card.heap, sizes.heap_bytes)?;
        reserve(&mut card.statics, statics.image_size as usize)?;
        reserve_words(&mut card.words, sizes.frame_words)?;
        reserve(&mut card.tags, sizes.frame_words.div_ceil(8))?;

        let mut heap = Heap::new(&mut card.heap)?;
        // The buffer and the APDU object outlive every command, because an applet is
        // allowed to keep the reference it was handed, JCRE §4.
        card.buffer = heap.new_array(heap::KIND_BYTE, sizes.buffer_bytes, card.context)?;
        let apdu_class = native_class_of(ClassId::APDU)?;
        card.apdu = heap.new_object(apdu_class, 1, card.context)?;
        card.runtime_bytes = heap.used();
        use crate::cap::{TYPE_BOOLEAN, TYPE_BYTE, TYPE_SHORT, TYPE_INT};
        for (index, array) in statics.array_inits().enumerate() {
            let kind = match array.element_type {
                TYPE_BOOLEAN => heap::KIND_BOOLEAN,
                TYPE_BYTE => heap::KIND_BYTE,
                TYPE_SHORT => heap::KIND_SHORT,
                TYPE_INT if file.header()?.int() => heap::KIND_INT,
                _ => return Err(Error::Unsupported),
            };
            let reference = heap.new_array(kind, array.length() as u16, card.context)?;
            for (element, bytes) in array.values.chunks_exact(array.element_size()).enumerate() {
                let value = match bytes {
                    [byte] => i32::from(*byte as i8),
                    [a, b] => i32::from(i16::from_be_bytes([*a, *b])),
                    [a, b, c, d] => i32::from_be_bytes([*a, *b, *c, *d]),
                    _ => return Err(Error::Format),
                };
                if kind == heap::KIND_INT { heap.array_put_int(reference, element, value)?; }
                else { heap.array_put(reference, element, value as i16)?; }
            }
            card.statics[index * 2..index * 2 + 2].copy_from_slice(&reference.to_be_bytes());
        }
        let start = usize::from(statics.reference_count) * 2 + usize::from(statics.default_value_count);
        card.statics[start..].copy_from_slice(statics.non_default_values);
        card.heap_used = heap.used();
        Ok(card)
    }

    /// Run the package's install method, which is expected to register an applet.
    ///
    /// The parameters are the bytes GlobalPlatform delivered, and the applet reads them
    /// from a byte array like any other.
    pub fn install(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        parameters: &[u8],
    ) -> Result<()> {
        let applets = file.applets()?;
        let entry = applets.iter().next().ok_or(Error::Missing)?;
        self.install_module(file, host, entry.aid, parameters)
    }

    /// Install the module named by the authenticated management request.
    pub fn install_module(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        module_aid: &[u8],
        parameters: &[u8],
    ) -> Result<()> {
        self.install_module_with_cancel(file, host, module_aid, parameters, &mut || false)
    }

    /// A cancelled or failed installation must be discarded by the caller.
    pub fn install_module_with_cancel(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        module_aid: &[u8],
        parameters: &[u8],
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.run_install(file, host, Installation { module_aid, instance_aid: &[], parameters }, cancel)
    }

    /// Require any explicit registration AID to match the management request.
    pub fn install_instance_with_cancel(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        installation: Installation<'_>,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        if !(5..=16).contains(&installation.instance_aid.len()) { return Err(Error::Bounds); }
        self.run_install(file, host, installation, cancel)
    }

    fn run_install(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        installation: Installation<'_>,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        let Installation { module_aid, instance_aid, parameters } = installation;
        if cancel() { return Err(Error::Cancelled); }
        if self.installed() { return Err(Error::Inconsistent); }
        if parameters.len() > u8::MAX as usize { return Err(Error::Bounds); }
        let applets = file.applets()?;
        let entry = applets.iter().find(|entry| entry.aid == module_aid).ok_or(Error::Missing)?;
        let install = entry.install_method_offset;
        let linked = Linked::new(file)?;
        linked.imports_resolve()?;

        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        let array = heap.new_array(heap::KIND_BYTE, parameters.len() as u16, self.context)?;
        heap.byte_slice_mut(array, 0, parameters.len())?
            .copy_from_slice(parameters);
        let outcome = {
            let mut machine = Machine::new(
                &mut heap,
                host,
                &linked,
                file.methods()?,
                &mut self.statics,
                self.context,
                Limits {
                    int: file.header()?.int(),
                    ..Limits::IMPLEMENTED
                },
                Jcre::new(self.apdu, self.buffer),
            ).with_cancel(cancel);
            let mut budget = self.sizes.budget;
            let mut arena = Arena {
                words: &mut self.words,
                tags: &mut self.tags,
            };
            let mut outer_words = [0u16; 8];
            let mut outer_tags = [0u8; 1];
            let mut outer = Frame::new(&mut outer_words, &mut outer_tags, 0, 8)?;
            // install takes the parameter array, its offset and its length.
            outer.push_reference(array)?;
            outer.push_short(0)?;
            outer.push_short(i16::from(parameters.len() as u8 as i8))?;
            let thrown = invoke(&mut machine, install, &mut outer, &mut arena, &mut budget)?;
            (thrown, machine.jcre.instance, machine.jcre.aid, machine.jcre.aid_length)
        };
        self.heap_used = heap.used();
        if outcome.0.is_some() {
            return Err(Error::Unauthorized);
        }
        if !instance_aid.is_empty() && outcome.3 != 0 && &outcome.2[..usize::from(outcome.3)] != instance_aid {
            return Err(Error::Unauthorized);
        }
        // An install that does not register leaves nothing to select, JCRE §3.1.
        let instance = outcome.1.ok_or(Error::Missing)?;
        check_applet(&linked, &heap, instance)?;
        self.instance = Some(instance);
        Ok(())
    }

    pub fn installed(&self) -> bool {
        self.instance.is_some()
    }

    pub fn selected(&self) -> bool { self.selected }

    /// Clear reset-scoped data while retaining the installed instance and persistent state.
    pub fn reset(&mut self) -> Result<()> {
        self.selected = false;
        self.words.fill(0);
        self.tags.fill(0);
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        heap.clear_transient(heap::CLEAR_ON_RESET, self.context)?;
        heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?.fill(0);
        natives::reset_pin_validations(&mut heap)
    }

    /// Hand the applet one command, as a selection or as ordinary processing.
    pub fn process(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        command: &[u8],
        selecting: bool,
    ) -> Result<Response> {
        self.process_with_cancel(file, host, command, selecting, &mut || false)
    }

    /// Cancellation is polled before execution and at each instruction boundary.
    /// On an engine error, restore committed state before using this card again.
    pub fn process_with_cancel(
        &mut self,
        file: &LoadFile,
        host: &mut dyn Host,
        command: &[u8],
        selecting: bool,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Response> {
        if cancel() { return Err(Error::Cancelled); }
        self.instance.ok_or(Error::Missing)?;
        if selecting { self.selected = false; }
        if command.len() < 4 || command.len() > self.sizes.buffer_bytes as usize {
            return Err(Error::Bounds);
        }
        let incoming = incoming_length(command)?;
        let expected = expected_length(command)?;
        {
            let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
            heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?.fill(0);
            heap.byte_slice_mut(self.buffer, 0, command.len())?.copy_from_slice(command);
        }
        let mut budget = self.sizes.budget;
        if selecting {
            let answer = self.callback(file, host, Callback::Select, (incoming, expected), &mut budget, cancel)?;
            if answer.exception.is_some() || answer.returned == 0 {
                return Ok(Response { data: Vec::new(), sw: 0x6999 });
            }
            self.selected = true;
        }
        // Selection is decided by select(), not by the status that process() returns.
        let answer = self.callback(file, host, Callback::Process { selecting }, (incoming, expected), &mut budget, cancel)?;
        let heap = Heap::resume(&mut self.heap, self.heap_used)?;
        let sw = answer.exception.map_or(SW_SUCCESS, |exception| status_word(&heap, exception));
        Ok(Response { data: answer.data, sw })
    }

    /// Applet exceptions do not prevent deselection; engine and persistence failures
    /// still require caller recovery. Reset and power loss never run this callback.
    pub fn deselect_with_cancel(
        &mut self, file: &LoadFile, host: &mut dyn Host, cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        if cancel() { return Err(Error::Cancelled); }
        if !self.selected { return Ok(()); }
        self.selected = false;
        let mut budget = self.sizes.budget;
        self.callback(file, host, Callback::Deselect, (0, 0), &mut budget, cancel)?;
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        heap.clear_transient(heap::CLEAR_ON_DESELECT, self.context)?;
        heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?.fill(0);
        self.words.fill(0);
        self.tags.fill(0);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn callback(
        &mut self, file: &LoadFile, host: &mut dyn Host, callback: Callback,
        lengths: (u16, u16), budget: &mut u32, cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Invocation> {
        if cancel() { return Err(Error::Cancelled); }
        let instance = self.instance.ok_or(Error::Missing)?;
        let linked = Linked::new(file)?;
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        let class = heap.info(instance)?.class;
        let method = match linked.lookup(class, applet_token(callback.id())?) {
            Ok(method) => method,
            // Applet's inherited select accepts, and its inherited deselect is a no-op.
            Err(Error::Missing) if !matches!(callback, Callback::Process { .. }) => {
                return Ok(Invocation { exception: None, returned: 1, data: Vec::new() });
            }
            Err(error) => return Err(error),
        };
        let mut jcre = Jcre::new(self.apdu, self.buffer);
        jcre.selecting = matches!(callback, Callback::Select | Callback::Process { selecting: true });
        jcre.incoming = lengths.0;
        jcre.expected = lengths.1;
        jcre.data_offset = 5;
        let answer = {
            let mut machine = Machine::new(
                &mut heap, host, &linked, file.methods()?, &mut self.statics, self.context,
                Limits { int: file.header()?.int(), ..Limits::IMPLEMENTED }, jcre,
            ).with_cancel(cancel);
            let mut arena = Arena { words: &mut self.words, tags: &mut self.tags };
            let mut outer_words = [0; 8];
            let mut outer_tags = [0; 1];
            let mut outer = Frame::new(&mut outer_words, &mut outer_tags, 0, 8)?;
            outer.push_reference(instance)?;
            if matches!(callback, Callback::Process { .. }) { outer.push_reference(self.apdu)?; }
            let exception = invoke(&mut machine, method, &mut outer, &mut arena, budget)?;
            let returned = if exception.is_none() && matches!(callback, Callback::Select) {
                outer.pop_short()? as u16
            } else { 0 };
            let mut data = Vec::new();
            if exception.is_none() {
                let response = machine.jcre.response_data()?;
                data.try_reserve_exact(response.len()).map_err(|_| Error::Quota)?;
                data.extend_from_slice(response);
            }
            Invocation { exception, returned, data }
        };
        self.heap_used = heap.used();
        Ok(answer)
    }

}

#[derive(Clone, Copy)]
enum Callback { Select, Process { selecting: bool }, Deselect }
impl Callback {
    fn id(self) -> MethodId {
        match self { Self::Select => MethodId::select, Self::Process { .. } => MethodId::process, Self::Deselect => MethodId::deselect }
    }
}
struct Invocation { exception: Option<Reference>, returned: u16, data: Vec<u8> }

fn check_applet(linked: &Linked, heap: &Heap, instance: Reference) -> Result<()> {
    use crate::cap::ClassRef;
    let root = heap.info(instance)?;
    if root.kind != heap::KIND_OBJECT || natives::is_native_class(root.class) { return Err(Error::Type); }
    linked.lookup(root.class, applet_token(MethodId::process)?)?;
    let mut class = ClassRef::Internal(root.class);
    for _ in 0..=u8::MAX {
        match class {
            ClassRef::Internal(offset) => { class = linked.classes().at(offset)?.super_class; }
            ClassRef::External { package, class } => {
                let api = linked.api_class(package, class)?;
                return if api.id == ClassId::Applet { Ok(()) } else { Err(Error::Type) };
            }
            ClassRef::None => return Err(Error::Type),
        }
    }
    Err(Error::Format)
}

/// The status word an escaped exception reports.
///
/// An `ISOException` carries the word the applet chose. Anything else is a failure the
/// applet did not describe, so the card answers with the one that says exactly that.
/// How many bytes of command data a short APDU carries, ISO 7816-4 §5.1.
///
/// Byte four is Lc when the command carries data and Le when it carries none, so the
/// overall length is what says which case this is. A case 4 command carries both, and
/// reading its trailing Le byte as a further data byte is what makes an applet reject a
/// well formed command. Every real PIV GET DATA is case 4.
fn incoming_length(command: &[u8]) -> Result<u16> {
    if !(4..=261).contains(&command.len()) { return Err(Error::Bounds); }
    // Case 1 has no Lc and no Le. Case 2 has Le alone, which byte four holds.
    if command.len() <= 5 {
        return Ok(0);
    }
    let declared = command[4] as usize;
    if declared == 0 { return Err(Error::Bounds); }
    // Case 3 ends with the data. Case 4 appends one Le byte. Any other length disagrees
    // with its own Lc, so the command is refused rather than truncated to fit.
    if command.len() == 5 + declared || command.len() == 6 + declared {
        Ok(declared as u16)
    } else {
        Err(Error::Bounds)
    }
}

fn expected_length(command: &[u8]) -> Result<u16> {
    incoming_length(command)?;
    let le = if command.len() == 5 || (command.len() > 5 && command.len() == 6 + usize::from(command[4])) {
        *command.last().ok_or(Error::Bounds)?
    } else { return Ok(0); };
    Ok(if le == 0 { 256 } else { u16::from(le) })
}

fn status_word(heap: &Heap, exception: Reference) -> u16 {
    let Ok(info) = heap.info(exception) else {
        return SW_UNKNOWN;
    };
    let Some(class) = natives::api_class(info.class) else {
        return SW_UNKNOWN;
    };
    if class.id != ClassId::ISOException {
        return SW_UNKNOWN;
    }
    heap.get_word(exception, natives::REASON_FIELD)
        .unwrap_or(SW_UNKNOWN)
}

/// The class word an instance of a card-provided class carries.
fn native_class_of(name: ClassId) -> Result<u16> {
    for (index, package) in PACKAGES.iter().enumerate() {
        if let Some(class) = package.classes.iter().find(|entry| entry.id == name) {
            return Ok(natives::native_class(index, class.token));
        }
    }
    Err(Error::Missing)
}

/// The virtual method token `javacard.framework.Applet` assigns to one of its methods.
///
/// A subclass overriding it uses the same token, because a public virtual method token is
/// inherited across packages, JCVM §4.3.7.6. That is what lets the card call an applet's
/// own `process` without knowing anything about the applet's package.
fn applet_token(name: MethodId) -> Result<u8> {
    for package in PACKAGES.iter() {
        for class in package.classes.iter() {
            if class.id != ClassId::Applet {
                continue;
            }
            if let Some(method) = class
                .methods
                .iter()
                .find(|entry| entry.id == name && !entry.static_token)
            {
                return Ok(method.token);
            }
        }
    }
    Err(Error::Missing)
}

fn reserve(buffer: &mut Vec<u8>, bytes: usize) -> Result<()> {
    buffer.try_reserve_exact(bytes).map_err(|_| Error::Quota)?;
    buffer.resize(bytes, 0);
    Ok(())
}

fn reserve_words(buffer: &mut Vec<u16>, words: usize) -> Result<()> {
    buffer.try_reserve_exact(words).map_err(|_| Error::Quota)?;
    buffer.resize(words, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_STATIC_FIELDREF, CONSTANT_STATIC_METHODREF, CONSTANT_VIRTUAL_METHODREF};
    use crate::test_support::{ClassSpec, Package};
    use alloc::vec;

    /// Opcodes this test spells out, so the bytecode reads like the applet it stands for.
    mod op {
        #[allow(dead_code)]
        pub const ACONST_NULL: u8 = 1;
        pub const SCONST_0: u8 = 3;
        #[allow(dead_code)]
        pub const SCONST_1: u8 = 4;
        pub const SSPUSH: u8 = 17;
        pub const ALOAD_0: u8 = 24;
        #[allow(dead_code)]
        pub const SLOAD_1: u8 = 29;
        pub const ASTORE_0: u8 = 43;
        pub const DUP: u8 = 61;
        pub const SRETURN: u8 = 120;
        pub const RETURN: u8 = 122;
        pub const INVOKEVIRTUAL: u8 = 139;
        pub const INVOKESPECIAL: u8 = 140;
        pub const INVOKESTATIC: u8 = 141;
        pub const NEW: u8 = 143;
    }

    const FRAMEWORK_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
    const JAVA_LANG_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x00, 0x62, 0x00, 0x01];

    /// An applet that registers itself, accepts selection and answers one command.
    ///
    /// The shape is the smallest thing that is still an applet: a static install that
    /// constructs the class and registers it, a select that agrees, and a process that
    /// writes into the APDU buffer and sends it.
    fn applet(process: Vec<u8>, process_stack: u8) -> Package {
        applet_registration(process, process_stack, false)
    }

    fn applet_registration(process: Vec<u8>, process_stack: u8, explicit: bool) -> Package {
        let mut package = Package {
            imports: vec![
                (Vec::from(JAVA_LANG_AID), 1, 0),
                (Vec::from(FRAMEWORK_AID), 1, 6),
            ],
            // install: new Applet, dup, invokespecial <init>, invokevirtual register.
            code: vec![
                op::NEW, 0x00, 0x03,
                op::DUP,
                op::INVOKESPECIAL, 0x00, 0x04,
                op::INVOKEVIRTUAL, 0x00, 0x00,
                op::RETURN,
            ],
            max_stack: 8,
            nargs: 3,
            max_locals: 0,
            extra: vec![
                // The constructor, which just runs the superclass one.
                (1, 0, vec![op::ALOAD_0, op::INVOKESPECIAL, 0x00, 0x05, op::RETURN]),
                // select, which accepts.
                (1, 0, vec![op::SCONST_1, op::SRETURN]),
                // process, supplied by the caller.
                (2, 2, process),
            ],
            ..Package::default()
        };
        if explicit {
            package.code.splice(7..7, [op::ALOAD_0, op::SCONST_0, op::SLOAD_1 + 1]);
        }
        let bodies = package.extra_offsets();
        package.classes = vec![ClassSpec {
            // The applet class extends javacard.framework.Applet, which is external, and
            // its method table is indexed by the tokens that package assigned.
            super_class: 0x8103,
            public: {
                // Tokens zero to seven of Applet, with the three this class defines.
                let mut table = vec![0xffff; 8];
                table[applet_token(MethodId::select).unwrap() as usize] = bodies[1];
                table[applet_token(MethodId::process).unwrap() as usize] = bodies[2];
                table
            },
            ..ClassSpec::default()
        }];
        package.max_stack = 8;
        package.constants = vec![
            // Applet.register, virtual token 1 in the framework.
            [CONSTANT_VIRTUAL_METHODREF, 0x81, 3, if explicit { 2 } else { 1 }],
            [CONSTANT_CLASSREF, 0x81, 3, 0],
            [CONSTANT_CLASSREF, 0x81, 10, 0],
            // The applet's own class.
            [CONSTANT_CLASSREF, 0x00, 0x00, 0],
            // Its constructor, and the superclass constructor in the framework.
            [CONSTANT_STATIC_METHODREF, 0x00, (bodies[0] >> 8) as u8, bodies[0] as u8],
            [CONSTANT_STATIC_METHODREF, 0x81, 3, 0],
        ];
        let _ = process_stack;
        package
    }

    #[test]
    fn an_applet_installs_registers_selects_and_answers_a_command() {
        // process: write 0x9000 worth of nothing, then send two bytes from the buffer.
        let process = vec![
            // apdu.getBuffer(), keeping it in local 0.
            op::ALOAD_0 + 1, op::INVOKEVIRTUAL, 0x00, 0x06, op::ASTORE_0,
            // Util.setShort(buffer, 0, 0x1234)
            op::ALOAD_0, op::SCONST_0, op::SSPUSH, 0x12, 0x34,
            op::INVOKESTATIC, 0x00, 0x07,
            // The answer of setShort is the next offset, which is also the length to send.
            op::ALOAD_0 + 1, op::SCONST_0, op::SSPUSH, 0x00, 0x02,
            op::INVOKEVIRTUAL, 0x00, 0x08,
            op::RETURN,
        ];
        let mut package = applet(process, 8);
        package.constants.push([CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 1]);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 16, 6]);
        package.constants.push([CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 8]);
        package.static_bytes = 2;
        package.constants.push([CONSTANT_STATIC_FIELDREF, 0, 0, 0]);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 7, 1]);
        // deselect records that it ran, then throws; JCRE must still clear its arrays.
        package.extra.push((1, 0, vec![op::SCONST_1, 129, 0, 9,
            op::SSPUSH, 0x6a, 0x82, op::INVOKESTATIC, 0, 10, op::RETURN]));
        package.classes[0].public[applet_token(MethodId::deselect).unwrap() as usize] = package.extra_offsets()[3];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();

        let mut card = Card::new(&file, Sizes::default()).unwrap();
        let initial_heap = card.heap_used;
        let module = file.applets().unwrap().iter().next().unwrap().aid;
        assert_eq!(card.install_module_with_cancel(&file, &mut crate::host::NoHost, module, &[], &mut || true), Err(Error::Cancelled));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, &[0; 5], &[]), Err(Error::Missing));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, module, &[0; 256]), Err(Error::Bounds));
        assert_eq!(card.heap_used, initial_heap);
        assert!(!card.installed());
        {
            let mut interrupted = Card::new(&file, Sizes::default()).unwrap();
            let mut polls = 0;
            assert_eq!(interrupted.install_module_with_cancel(&file, &mut crate::host::NoHost, module, &[], &mut || {
                polls += 1;
                polls == 3
            }), Err(Error::Cancelled));
            assert_eq!(polls, 3);
        }
        card.install_module(&file, &mut crate::host::NoHost, module, &[]).unwrap();
        assert!(card.installed());
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[]), Err(Error::Inconsistent));
        assert_eq!(card.process_with_cancel(&file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true, &mut || true), Err(Error::Cancelled));

        // SELECT, which the applet accepts.
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0xa4, 0x04, 0x00, 0x00], true)
            .unwrap();
        assert_eq!(response.sw, SW_SUCCESS);
        assert_eq!(response.data, [0x12, 0x34]);
        assert!(card.selected());

        // Then an ordinary command, whose answer the applet wrote into the buffer.
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        assert_eq!(response.sw, SW_SUCCESS);
        assert_eq!(response.data, [0x12, 0x34]);

        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let transient = heap.new_transient_array(heap::KIND_BYTE, 1, 1, heap::CLEAR_ON_RESET).unwrap();
        let on_deselect = heap.new_transient_array(heap::KIND_BYTE, 1, 1, heap::CLEAR_ON_DESELECT).unwrap();
        heap.array_put(on_deselect, 0, 8).unwrap();
        let persistent = heap.new_array(heap::KIND_BYTE, 1, 1).unwrap();
        let pin = heap.new_object(native_class_of(ClassId::OwnerPIN).unwrap(), 6, 1).unwrap();
        heap.array_put(transient, 0, 7).unwrap();
        heap.array_put(persistent, 0, 9).unwrap();
        heap.put_word(pin, 0, 3).unwrap();
        heap.put_word(pin, 2, persistent).unwrap();
        heap.put_word(pin, 3, 1).unwrap(); // Validated flag.
        heap.put_word(pin, 4, 2).unwrap(); // Remaining attempts are persistent.
        card.heap_used = heap.used();
        let mut saved_heap = vec![0; card.persistent_heap_bytes()];
        let saved = card.save_into(&mut saved_heap).unwrap();
        let instance = saved.instance;
        let saved_statics = saved.statics.to_vec();
        let mut restored = Card::restore(&file, Sizes::default(), saved).unwrap();
        assert!(!restored.selected());
        let recovered = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(recovered.array_get(transient, 0), Ok(0));
        assert_eq!(recovered.array_get(persistent, 0), Ok(9));
        assert_eq!(recovered.get_word(pin, 3), Ok(0));
        assert_eq!(recovered.get_word(pin, 4), Ok(2));
        assert_eq!(restored.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0, 0], false).unwrap().data, [0x12, 0x34]);
        // Saving must not clear authorization or transient values in the live session.
        let live = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(live.array_get(transient, 0), Ok(7));
        assert_eq!(live.get_word(pin, 3), Ok(1));
        for case in 0..5 {
            let mut invalid = saved_heap.clone();
            let root = match case {
                0 => instance + 2, // A field is not an object handle.
                1 => { invalid[transient as usize + heap::HEADER] = 1; instance }
                2 => { invalid[pin as usize + heap::HEADER + 7] = 1; instance }
                3 => { invalid[persistent as usize + 5] = 2; instance }
                _ => { invalid.truncate(invalid.len() - 1); instance }
            };
            assert!(Card::restore(&file, Sizes::default(), PersistentState { heap: &invalid, statics: &saved_statics, instance: root }).is_err());
        }
        card.deselect_with_cancel(&file, &mut crate::host::NoHost, &mut || false).unwrap();
        assert!(!card.selected());
        assert_eq!(card.statics, [0, 1]);
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(on_deselect, 0), Ok(0));
        assert_eq!(heap.array_get(transient, 0), Ok(7));
        assert!(matches!(card.retain_volatile(5), Err(Error::Quota)));
        let retained = card.retain_volatile(6).unwrap();
        assert_eq!(retained.bytes(), 6);
        // Deselection allocated an exception, so the older committed layout is stale.
        assert_eq!(restored.restore_volatile(&retained), Err(Error::Format));
        let mut suspended_heap = vec![0; card.persistent_heap_bytes()];
        restored = Card::restore(&file, Sizes::default(), card.save_into(&mut suspended_heap).unwrap()).unwrap();
        restored.restore_volatile(&retained).unwrap();
        let resumed = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(resumed.array_get(transient, 0), Ok(7));
        assert_eq!(resumed.array_get(on_deselect, 0), Ok(0));
        assert_eq!(resumed.get_word(pin, 3), Ok(0));
        card.reset().unwrap();
        assert!(card.installed());
        assert!(card.words.iter().all(|word| *word == 0));
        assert!(card.tags.iter().all(|tag| *tag == 0));
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(transient, 0), Ok(0));
        assert_eq!(heap.array_get(persistent, 0), Ok(9));
        assert_eq!(heap.get_word(pin, 3), Ok(0));
        assert_eq!(heap.get_word(pin, 4), Ok(2));
        assert!(heap.byte_slice(card.buffer, 0, card.sizes.buffer_bytes as usize).unwrap().iter().all(|byte| *byte == 0));
        // Explicit registration may not change the instance management authorized.
        let bytes = applet_registration(vec![op::RETURN], 1, true).build();
        let file = LoadFile::parse(&bytes).unwrap();
        let module_aid = file.applets().unwrap().iter().next().unwrap().aid;
        let requested = [0xf0, 1, 2, 3, 4];
        for (parameters, expected) in [(&requested[..], Ok(())), (&[0xf0, 1, 2, 3, 5][..], Err(Error::Unauthorized)), (&[0xf0, 1, 2, 3][..], Err(Error::Bounds))] {
            let mut card = Card::new(&file, Sizes::default()).unwrap();
            assert_eq!(card.install_instance_with_cancel(&file, &mut crate::host::NoHost,
                Installation { module_aid, instance_aid: &requested, parameters }, &mut || false), expected);
        }
    }

    #[test]
    fn an_exception_the_applet_throws_becomes_the_status_word() {
        // process: ISOException.throwIt(0x6a82)
        let process = vec![
            op::SSPUSH, 0x6a, 0x82, op::INVOKESTATIC, 0x00, 0x06, op::RETURN,
        ];
        let mut package = applet(process, 8);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 7, 1]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = Card::new(&file, Sizes::default()).unwrap();
        card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        // The word the applet chose, not a generic failure.
        assert_eq!(response.sw, 0x6a82);
        assert!(response.data.is_empty());
        let response = card.process(&file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap();
        assert_eq!(response.sw, 0x6a82);
        assert!(card.selected(), "a process status word does not undo accepted selection");
        package.extra[1].2[0] = op::SCONST_0;
        let declined_bytes = package.build();
        let declined_file = LoadFile::parse(&declined_bytes).unwrap();
        let mut declined = Card::new(&declined_file, Sizes::default()).unwrap();
        declined.install(&declined_file, &mut crate::host::NoHost, &[]).unwrap();
        assert_eq!(declined.process(&declined_file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x6999);
        assert!(!declined.selected());
        // Inherited Applet.select() accepts; process still chooses the response status.
        package.classes[0].public[applet_token(MethodId::select).unwrap() as usize] = 0xffff;
        let inherited_bytes = package.build();
        let inherited_file = LoadFile::parse(&inherited_bytes).unwrap();
        let mut inherited = Card::new(&inherited_file, Sizes::default()).unwrap();
        inherited.install(&inherited_file, &mut crate::host::NoHost, &[]).unwrap();
        assert_eq!(inherited.process(&inherited_file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x6a82);
        assert!(inherited.selected());
        let mut polls = 0;
        assert_eq!(card.process_with_cancel(&file, &mut crate::host::NoHost, &[0, 1, 0, 0, 0], false, &mut || {
            polls += 1;
            polls == 3
        }), Err(Error::Cancelled));
        assert_eq!(polls, 3);
    }

    #[test]
    fn a_failure_the_applet_did_not_describe_answers_with_the_word_that_says_so() {
        // process: commit a transaction that was never begun, which the runtime refuses
        // with an exception that carries no status word of its own.
        let process = vec![op::INVOKESTATIC, 0x00, 0x06, op::RETURN];
        let mut package = applet(process, 8);
        // JCSystem.commitTransaction, static token 2 of class token 8.
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 8, 2]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = Card::new(&file, Sizes::default()).unwrap();
        card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        // Not a word the applet chose, so the card answers with the one that says exactly
        // that rather than inventing a plausible one.
        assert_eq!(response.sw, SW_UNKNOWN);
        assert!(response.data.is_empty());
    }

    #[test]
    fn short_apdu_lengths_distinguish_command_data_from_expected_response() {
        for (raw, incoming, expected) in [
            (&[0, 0xa4, 4, 0][..], 0, 0),
            (&[0, 0xa4, 4, 0, 0][..], 0, 256),
            (&[0, 0xa4, 4, 0, 7][..], 0, 7),
            (&[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7][..], 5, 0),
            (&[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0][..], 5, 256),
        ] {
            assert_eq!(incoming_length(raw), Ok(incoming));
            assert_eq!(expected_length(raw), Ok(expected));
        }
        for raw in [&[0, 0xa4, 4][..], &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3],
            &[0, 0xcb, 0x3f, 0xff, 1, 1, 2, 3, 4], &[0, 0xcb, 0, 0, 0, 0]] {
            assert_eq!(incoming_length(raw), Err(Error::Bounds));
        }
    }

    #[test]
    fn an_install_that_registers_nothing_leaves_nothing_to_select() {
        let mut package = applet(vec![op::RETURN], 8);
        package.code = vec![op::RETURN];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = Card::new(&file, Sizes::default()).unwrap();
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[]), Err(Error::Missing));
        assert!(!card.installed());
    }
}
