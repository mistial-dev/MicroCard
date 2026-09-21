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
pub use persistence::{PersistentState, PersistentView, VolatileState};

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
pub struct AppletInstance {
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
    reselecting: bool,
    transaction_aborted: bool,
    pending_writes: heap::PendingWrites,
    context: heap::Context,
    sizes: Sizes,
}

impl Drop for AppletInstance {
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

impl AppletInstance {
    /// Release callback scratch only at an idle maintenance boundary.
    pub fn release_execution_frames(&mut self) {
        self.words.zeroize();
        self.tags.zeroize();
        self.words = Vec::new();
        self.tags = Vec::new();
    }

    /// Recreate zeroed callback scratch before resuming execution.
    pub fn restore_execution_frames(&mut self) -> Result<()> {
        if self.words.len() != self.sizes.frame_words {
            reserve_words(&mut self.words, self.sizes.frame_words)?;
        }
        if self.tags.len() != self.sizes.frame_words.div_ceil(8) {
            reserve(&mut self.tags, self.sizes.frame_words.div_ceil(8))?;
        }
        Ok(())
    }

    /// Preserve all live objects while releasing unused capacity between callbacks.
    pub fn release_idle_memory(&mut self) {
        self.release_execution_frames();
        self.heap.truncate(self.heap_used);
        self.heap.shrink_to_fit();
    }

    /// Restore the configured allocation quota before any applet instruction runs.
    pub fn restore_idle_memory(&mut self) -> Result<()> {
        let additional = self.sizes.heap_bytes.checked_sub(self.heap.len()).ok_or(Error::Bounds)?;
        self.heap.try_reserve_exact(additional).map_err(|_| Error::Quota)?;
        self.heap.resize(self.sizes.heap_bytes, 0);
        self.restore_execution_frames()
    }

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
            reselecting: false,
            transaction_aborted: false,
            pending_writes: heap::PendingWrites::default(),
            context: 1,
            sizes,
        };
        reserve(&mut card.heap, sizes.heap_bytes)?;
        reserve(&mut card.statics, statics.image_size as usize)?;
        reserve_words(&mut card.words, sizes.frame_words)?;
        reserve(&mut card.tags, sizes.frame_words.div_ceil(8))?;

        let mut heap = Heap::new(&mut card.heap)?;
        heap.initialize_lifecycle();
        // Runtime-owned objects are reused across callbacks. Applets may use their
        // references locally but may not retain them in fields or arrays, JCRE §6.2.
        card.buffer = heap.new_transient_array(heap::KIND_BYTE, sizes.buffer_bytes, card.context, heap::CLEAR_ON_RESET)?;
        let apdu_class = native_class_of(ClassId::APDU)?;
        card.apdu = heap.new_object(apdu_class, 1, card.context)?;
        natives::reserve_runtime_exceptions(&mut heap, card.context)?;
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
        host: &mut impl Host,
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
        host: &mut impl Host,
        module_aid: &[u8],
        parameters: &[u8],
    ) -> Result<()> {
        self.install_module_with_cancel(file, host, module_aid, parameters, &mut || false)
    }

    /// A cancelled or failed installation must be discarded by the caller.
    pub fn install_module_with_cancel(
        &mut self,
        file: &LoadFile,
        host: &mut impl Host,
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
        host: &mut impl Host,
        installation: Installation<'_>,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        if !(5..=16).contains(&installation.instance_aid.len()) { return Err(Error::Bounds); }
        self.run_install(file, host, installation, cancel)
    }

    fn run_install(
        &mut self,
        file: &LoadFile,
        host: &mut impl Host,
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
        // Installation parameters are a global array, just like the APDU buffer
        // (JCRE §6.2.2). Reuse its storage and reference-store protection.
        let array = self.buffer;
        heap.byte_slice_mut(array, 0, parameters.len())?
            .copy_from_slice(parameters);
        let outcome = {
            let mut jcre = Jcre::new(self.apdu, self.buffer);
            jcre.installing = true;
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
                jcre,
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
            let result = invoke(&mut machine, install, &mut outer, &mut arena, &mut budget);
            if machine.abort_unfinished_transaction()? { return Err(Error::Unauthorized); }
            let thrown = result?;
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
        check_applet(&linked, heap.info(instance)?)?;
        self.instance = Some(instance);
        Ok(())
    }

    pub fn installed(&self) -> bool {
        self.instance.is_some()
    }

    pub fn selected(&self) -> bool { self.selected }

    /// Clear reset-scoped data while retaining the installed instance and persistent state.
    pub fn reset(&mut self) -> Result<()> {
        self.transaction_aborted = false;
        self.selected = false;
        self.words.fill(0);
        self.tags.fill(0);
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        heap.clear_transient(heap::CLEAR_ON_RESET, self.context)?;
        heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?.fill(0);
        natives::reset_native_volatile(&mut heap)
    }

    /// Hand the applet one command, as a selection or as ordinary processing.
    pub fn process(
        &mut self,
        file: &LoadFile,
        host: &mut impl Host,
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
        host: &mut impl Host,
        command: &[u8],
        selecting: bool,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Response> {
        if cancel() { return Err(Error::Cancelled); }
        self.instance.ok_or(Error::Missing)?;
        if self.transaction_aborted { return Err(Error::TransactionAborted); }
        self.reselecting = selecting && self.selected;
        if self.reselecting { self.deselect_inner(file, host, cancel, true)?; }
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
            if answer.aborted || answer.exception.is_some() || answer.returned == 0 {
                if cancel() { return Err(Error::Cancelled); }
                self.checkpoint_dirty(host)?;
                return Ok(Response { data: Vec::new(), sw: 0x6999 });
            }
            self.selected = true;
        }
        // Selection is decided by select(), not by the status that process() returns.
        let answer = self.callback(file, host, Callback::Process { selecting }, (incoming, expected), &mut budget, cancel)?;
        let heap = Heap::resume(&mut self.heap, self.heap_used)?;
        let sw = if answer.aborted { SW_UNKNOWN } else { answer.exception.map_or(SW_SUCCESS, |exception| status_word(&heap, exception)) };
        drop(heap);
        if cancel() { return Err(Error::Cancelled); }
        self.checkpoint_dirty(host)?;
        Ok(Response { data: answer.data, sw })
    }

    /// Applet exceptions do not prevent deselection; engine and persistence failures
    /// still require caller recovery. Reset and power loss never run this callback.
    pub fn deselect_with_cancel(
        &mut self, file: &LoadFile, host: &mut impl Host, cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.deselect_inner(file, host, cancel, false)?;
        if cancel() { return Err(Error::Cancelled); }
        self.checkpoint_dirty(host)
    }

    fn checkpoint_dirty(&mut self, host: &mut impl Host) -> Result<()> {
        if !self.pending_writes.any() { return Ok(()); }
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        heap.merge_pending_writes(self.pending_writes);
        host.checkpoint(PersistentView {
            heap: heap.image(), statics: &self.statics,
            instance: self.instance.ok_or(Error::Missing)?, buffer: self.buffer,
            projection: Some(&heap),
        })?;
        self.pending_writes = heap::PendingWrites::default();
        Ok(())
    }

    fn deselect_inner(
        &mut self, file: &LoadFile, host: &mut impl Host, cancel: &mut dyn FnMut() -> bool,
        reselecting: bool,
    ) -> Result<()> {
        if cancel() { return Err(Error::Cancelled); }
        if !self.selected { return Ok(()); }
        self.reselecting = reselecting;
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
        &mut self, file: &LoadFile, host: &mut impl Host, callback: Callback,
        lengths: (u16, u16), budget: &mut u32, cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Invocation> {
        if self.transaction_aborted { return Err(Error::TransactionAborted); }
        if cancel() { return Err(Error::Cancelled); }
        let instance = self.instance.ok_or(Error::Missing)?;
        let linked = Linked::new(file)?;
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        heap.merge_pending_writes(core::mem::take(&mut self.pending_writes));
        let class = heap.info(instance)?.class;
        let method = match linked.lookup(class, applet_token(callback.id())?) {
            Ok(method) => method,
            // Applet's inherited select accepts, and its inherited deselect is a no-op.
            Err(Error::Missing) if !matches!(callback, Callback::Process { .. }) => {
                self.pending_writes = heap.pending_writes();
                return Ok(Invocation { exception: None, returned: 1, data: Vec::new(), aborted: false });
            }
            Err(error) => {
                self.pending_writes = heap.pending_writes();
                return Err(error);
            }
        };
        let mut jcre = Jcre::new(self.apdu, self.buffer);
        jcre.instance = Some(instance);
        jcre.reselecting = self.reselecting;
        jcre.selecting = matches!(callback, Callback::Select | Callback::Process { selecting: true });
        jcre.incoming = lengths.0;
        jcre.expected = lengths.1;
        jcre.data_offset = 5;
        let answer = (|| -> Result<Invocation> {
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
            let result = invoke(&mut machine, method, &mut outer, &mut arena, budget);
            let unfinished = machine.abort_unfinished_transaction()?;
            self.transaction_aborted |= machine.heap.allocations_aborted();
            let (exception, aborted) = match result {
                Ok(exception) => (exception, unfinished),
                Err(Error::TransactionAborted) => (None, true),
                Err(error) => return Err(error),
            };
            // An aborted transaction may have discarded the exception object itself.
            let exception = if aborted { None } else { exception };
            let returned = if !aborted && exception.is_none() && matches!(callback, Callback::Select) {
                outer.pop_short()? as u16
            } else { 0 };
            let mut data = Vec::new();
            // ISOException is also how applets finish a successful or chained response.
            // Preserve bytes already sent with its status word; VM failures still discard them.
            let iso_status = exception.is_some_and(|reference| machine.heap.info(reference).ok()
                .and_then(|info| natives::api_class(info.class))
                .is_some_and(|class| class.id == ClassId::ISOException));
            if !aborted && (exception.is_none() || iso_status) {
                let response = machine.jcre.response_data()?;
                data.try_reserve_exact(response.len()).map_err(|_| Error::Quota)?;
                data.extend_from_slice(response);
            }
            Ok(Invocation { exception, returned, data, aborted })
        })();
        self.heap_used = heap.used();
        self.pending_writes = heap.pending_writes();
        answer
    }

}

#[derive(Clone, Copy)]
enum Callback { Select, Process { selecting: bool }, Deselect }
impl Callback {
    fn id(self) -> MethodId {
        match self { Self::Select => MethodId::select, Self::Process { .. } => MethodId::process, Self::Deselect => MethodId::deselect }
    }
}
struct Invocation {
    aborted: bool,
    exception: Option<Reference>,
    returned: u16,
    data: Vec<u8>,
}

fn check_applet(linked: &Linked, root: heap::Info) -> Result<()> {
    use crate::cap::ClassRef;
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
        pub const PUTSTATIC_A: u8 = 127;
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
        let typed_component = 0x800b; // java.lang.ArrayStoreException
        // deselect records that it ran, then throws; JCRE must still clear its arrays.
        package.extra.push((1, 0, vec![op::SCONST_1, 129, 0, 9,
            op::SSPUSH, 0x6a, 0x82, op::INVOKESTATIC, 0, 10, op::RETURN]));
        package.classes[0].public[applet_token(MethodId::deselect).unwrap() as usize] = package.extra_offsets()[3];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();

        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        let initial_heap = card.heap_used;
        let module = file.applets().unwrap().iter().next().unwrap().aid;
        assert_eq!(card.install_module_with_cancel(&file, &mut crate::host::NoHost, module, &[], &mut || true), Err(Error::Cancelled));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, &[0; 5], &[]), Err(Error::Missing));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, module, &[0; 256]), Err(Error::Bounds));
        assert_eq!(card.heap_used, initial_heap);
        assert!(!card.installed());
        {
            let mut interrupted = AppletInstance::new(&file, Sizes::default()).unwrap();
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
        let persistent = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        let pin = heap.new_object(native_class_of(ClassId::OwnerPIN).unwrap(), 6, 1).unwrap();
        heap.array_put(transient, 0, 7).unwrap();
        heap.byte_slice_mut(persistent, 0, 64).unwrap().fill(9);
        heap.put_word(pin, 0, 3).unwrap();
        heap.put_word(pin, 1, 64).unwrap(); // PIN length is bounded by its configured material array.
        heap.put_word(pin, 2, persistent).unwrap();
        heap.put_word(pin, 3, 1).unwrap(); // Validated flag.
        heap.put_word(pin, 4, 2).unwrap(); // Remaining attempts are persistent.
        let key = heap.new_object(native_class_of(ClassId::AESKey).unwrap(), 6, 1).unwrap();
        let key_material = heap.new_transient_array(heap::KIND_BYTE, 17, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.byte_slice_mut(key_material, 0, 17).unwrap().fill(0x42);
        heap.array_put(key_material, 0, 1).unwrap(); // Initialization lives with transient bytes.
        heap.put_word(key, 0, 13).unwrap();
        heap.put_word(key, 1, 128).unwrap();
        heap.put_word(key, 2, key_material).unwrap();
        let cipher = heap.new_object(native_class_of(ClassId::Cipher).unwrap(), 6, 1).unwrap();
        let pending = heap.new_transient_array(heap::KIND_BYTE, 32, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.byte_slice_mut(pending, 0, 32).unwrap().fill(3);
        heap.put_word(cipher, 0, 13).unwrap();
        heap.put_word(cipher, 2, key).unwrap();
        heap.put_word(cipher, 3, 1).unwrap();
        heap.put_word(cipher, 4, 2).unwrap();
        heap.put_word(cipher, 5, pending).unwrap();
        let ec_public = heap.new_object(native_class_of(ClassId::ECPublicKey).unwrap(), 6, 1).unwrap();
        let ec_public_bytes = heap.new_array(heap::KIND_BYTE, 66, 1).unwrap();
        heap.array_put(ec_public_bytes, 0, 0x5f).unwrap();
        heap.put_word(ec_public, 0, 11).unwrap();
        heap.put_word(ec_public, 1, 256).unwrap();
        heap.put_word(ec_public, 2, ec_public_bytes).unwrap();
        let ec_private = heap.new_object(native_class_of(ClassId::ECPrivateKey).unwrap(), 6, 1).unwrap();
        let ec_private_bytes = heap.new_transient_array(heap::KIND_BYTE, 33, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.array_put(ec_private_bytes, 0, 0x5f).unwrap();
        heap.array_put(ec_private_bytes, 32, 1).unwrap();
        heap.put_word(ec_private, 0, 30).unwrap();
        heap.put_word(ec_private, 1, 256).unwrap();
        heap.put_word(ec_private, 2, ec_private_bytes).unwrap();
        let agreement = heap.new_object(native_class_of(ClassId::KeyAgreement).unwrap(), 6, 1).unwrap();
        heap.put_word(agreement, 0, 3).unwrap();
        heap.put_word(agreement, 2, ec_private).unwrap();
        heap.put_word(agreement, 3, 1).unwrap();
        let pair = heap.new_object(native_class_of(ClassId::KeyPair).unwrap(), 6, 1).unwrap();
        heap.put_word(pair, 0, 5).unwrap();
        heap.put_word(pair, 1, 256).unwrap();
        heap.put_word(pair, 2, ec_public).unwrap();
        heap.put_word(pair, 5, ec_private).unwrap();
        let signature = heap.new_object(native_class_of(ClassId::Signature).unwrap(), 6, 1).unwrap();
        let hash_state = heap.new_transient_array(heap::KIND_BYTE, crate::host::SHA256_STATE_BYTES as u16,
            1, heap::CLEAR_ON_RESET).unwrap();
        heap.array_put(hash_state, 0, 1).unwrap();
        heap.put_word(signature, 0, 33).unwrap();
        heap.put_word(signature, 2, ec_private).unwrap();
        heap.put_word(signature, 3, 1).unwrap();
        heap.put_word(signature, 4, 1).unwrap();
        heap.put_word(signature, 5, hash_state).unwrap();
        let reserved_exception = natives::new_exception(&mut heap, ClassId::SystemException, 1).unwrap();
        heap.put_word_unconditional(reserved_exception, natives::REASON_FIELD, 2).unwrap();
        let runtime_exception = natives::new_exception(&mut heap, ClassId::CryptoException, 1).unwrap();
        let explicit_exception = heap.new_object(native_class_of(ClassId::CryptoException).unwrap(), 6, 1).unwrap();
        heap.put_word_unconditional(runtime_exception, natives::REASON_FIELD, 3).unwrap();
        heap.put_word_unconditional(explicit_exception, natives::REASON_FIELD, 4).unwrap();
        let retained_references = heap.new_array(heap::KIND_REFERENCE, 1, 1).unwrap();
        heap.array_put_reference(retained_references, 0, explicit_exception).unwrap();
        let typed_references = heap.new_reference_array(typed_component, 1, 1).unwrap();
        let pair_class = PACKAGES.iter().flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::KeyPair).unwrap();
        // NEW checkpoints before invokespecial runs the constructor.
        let unconstructed_pair = natives::new_api_object(&mut heap, pair_class, 1).unwrap();
        assert_eq!(heap.set_lifecycle(0x0f), Ok(true));
        card.heap_used = heap.used();
        let mut saved_heap = vec![0; card.persistent_heap_bytes()];
        let saved = card.save_into(&mut saved_heap).unwrap();
        for width in [1, 3, 17, 127] {
            let mut windowed = vec![0xa5; saved.heap.len()];
            for (index, chunk) in windowed.chunks_mut(width).enumerate() {
                card.persistent_view().unwrap().save_range(index * width, chunk).unwrap();
            }
            assert_eq!(windowed, saved.heap);
        }
        let instance = saved.instance;
        let saved_statics = saved.statics.to_vec();
        let mut restored = AppletInstance::restore_without_frames(&file, Sizes::default(), saved).unwrap();
        assert_eq!((restored.words.capacity(), restored.tags.capacity()), (0, 0));
        let live_heap = restored.heap[..restored.heap_used].to_vec();
        restored.release_idle_memory();
        assert_eq!(restored.heap.len(), restored.heap_used);
        assert_eq!(restored.heap, live_heap);
        restored.restore_idle_memory().unwrap();
        assert_eq!(restored.heap.len(), Sizes::default().heap_bytes);
        assert_eq!(restored.heap[..restored.heap_used], live_heap);
        assert!(restored.heap[restored.heap_used..].iter().all(|byte| *byte == 0));
        assert!(restored.words.iter().all(|word| *word == 0));
        assert!(restored.tags.iter().all(|tag| *tag == 0));
        assert!(!restored.selected());
        let recovered = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(recovered.lifecycle(), Ok(0x0f));
        assert_eq!(recovered.array_get(transient, 0), Ok(0));
        assert_eq!(recovered.array_get(persistent, 0), Ok(9));
        assert_eq!(recovered.get_word(pin, 1), Ok(64));
        assert_eq!(recovered.byte_slice(persistent, 0, 64).unwrap(), &[9; 64]);
        assert_eq!(recovered.get_word(pin, 3), Ok(0));
        assert_eq!(recovered.get_word(pin, 4), Ok(2));
        assert_eq!(recovered.get_word(reserved_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(recovered.get_word(runtime_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(recovered.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        assert_eq!(recovered.info(typed_references).unwrap().class, typed_component);
        assert_eq!(recovered.byte_slice(key_material, 0, 17).unwrap(), &[0; 17]);
        assert_eq!(recovered.byte_slice(pending, 0, 32).unwrap(), &[0; 32]);
        assert_eq!(recovered.get_word(cipher, 2), Ok(key));
        assert_eq!(recovered.get_word(signature, 2), Ok(ec_private));
        assert_eq!(recovered.byte_slice(hash_state, 0, crate::host::SHA256_STATE_BYTES).unwrap(),
            &[0; crate::host::SHA256_STATE_BYTES]);
        assert_eq!(recovered.get_word(pair, 2), Ok(ec_public));
        assert_eq!(recovered.get_word(pair, 5), Ok(ec_private));
        assert_eq!(recovered.get_word(agreement, 2), Ok(ec_private));
        assert_eq!(recovered.get_word(agreement, 3), Ok(1));
        assert_eq!(recovered.array_get(ec_public_bytes, 0), Ok(0x5f));
        assert_eq!(recovered.byte_slice(ec_private_bytes, 0, 33).unwrap(), &[0; 33]);
        assert_eq!(restored.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0, 0], false).unwrap().data, [0x12, 0x34]);
        // Saving must not clear authorization or transient values in the live session.
        let live = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(live.array_get(transient, 0), Ok(7));
        assert_eq!(live.get_word(pin, 3), Ok(1));
        assert_eq!(live.get_word(reserved_exception, natives::REASON_FIELD), Ok(2));
        assert_eq!(live.get_word(runtime_exception, natives::REASON_FIELD), Ok(3));
        assert_eq!(live.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        let mut old_heap = saved_heap.clone();
        old_heap[0] = 1;
        assert!(matches!(
            AppletInstance::restore(
                &file,
                Sizes::default(),
                PersistentState {
                    heap: &old_heap,
                    statics: &saved_statics,
                    instance,
                },
            ),
            Err(Error::IncompatibleState)
        ));
        for case in 0..30 {
            let mut invalid = saved_heap.clone();
            let root = match case {
                0 => instance + 2, // A field is not an object handle.
                1 => { invalid[transient as usize + heap::HEADER] = 1; instance }
                2 => { invalid[pin as usize + heap::HEADER + 7] = 1; instance }
                3 => { invalid[persistent as usize + 5] = 2; instance }
                4 => { invalid[key_material as usize + 4] &= 0x0f; instance } // Old persistent-key layout.
                5 => { invalid[pending as usize + 4] &= 0x0f; instance }
                6 => { invalid[cipher as usize + heap::HEADER + 10..cipher as usize + heap::HEADER + 12].fill(0); instance }
                7 => { invalid[cipher as usize + heap::HEADER + 1] = 14; instance }
                8 => { invalid[ec_public_bytes as usize + heap::HEADER] = 0x80; instance }
                9 => { invalid[ec_private_bytes as usize + 4] &= 0x0f; instance }
                10 => { invalid[ec_public as usize + heap::HEADER + 1] = 12; instance }
                11 => { invalid[ec_public as usize + heap::HEADER + 7] = 1; instance }
                12 => { invalid[agreement as usize + heap::HEADER + 1] = 1; instance }
                13 => { invalid[agreement as usize + heap::HEADER + 4..agreement as usize + heap::HEADER + 6].copy_from_slice(&ec_public.to_be_bytes()); instance }
                14 => { invalid[pair as usize + heap::HEADER + 10..pair as usize + heap::HEADER + 12].copy_from_slice(&(ec_private + 2).to_be_bytes()); instance }
                15 => { invalid[pair as usize + heap::HEADER + 10..pair as usize + heap::HEADER + 12].copy_from_slice(&ec_public.to_be_bytes()); instance }
                16 => { invalid[hash_state as usize + 4] &= 0x0f; instance }
                17 => { invalid[signature as usize + heap::HEADER + 9] = 2; instance }
                18 => { invalid[signature as usize + heap::HEADER + 10..signature as usize + heap::HEADER + 12].copy_from_slice(&pending.to_be_bytes()); instance }
                19 => { invalid[runtime_exception as usize + heap::HEADER + 1] = 3; instance }
                20..=22 => {
                    let reference = match case { 20 => runtime_exception, 21 => card.apdu, _ => card.buffer };
                    let at = retained_references as usize + heap::HEADER;
                    invalid[at..at + 2].copy_from_slice(&reference.to_be_bytes());
                    instance
                }
                23 => { invalid[pin as usize + heap::HEADER + 3] = 65; instance } // Exceeds configured PIN capacity.
                24 => { invalid[unconstructed_pair as usize + heap::HEADER + 1] = 5; instance }
                25 => { invalid[..2].fill(0); instance } // Pre-lifecycle heap format.
                26 => { invalid[0] = 3; instance } // Unknown header version.
                27 => { invalid[1] = 0x80; instance } // Invalid application state.
                28 => { invalid.truncate(invalid.len() - 1); instance }
                _ => {
                    let at = typed_references as usize + heap::HEADER;
                    invalid[at..at + 2].copy_from_slice(&explicit_exception.to_be_bytes());
                    instance
                }
            };
            assert!(AppletInstance::restore(&file, Sizes::default(), PersistentState { heap: &invalid, statics: &saved_statics, instance: root }).is_err());
        }
        card.deselect_with_cancel(&file, &mut crate::host::NoHost, &mut || false).unwrap();
        assert!(!card.selected());
        assert_eq!(card.statics, [0, 1]);
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(on_deselect, 0), Ok(0));
        assert_eq!(heap.array_get(transient, 0), Ok(7));
        assert!(matches!(card.retain_volatile(363), Err(Error::Quota)));
        let retained = card.retain_volatile(364).unwrap();
        assert_eq!(retained.bytes(), 364);
        // Runtime exceptions are reserved, so deselection preserves the heap layout.
        restored.restore_volatile(&retained).unwrap();
        let mut suspended_heap = vec![0; card.persistent_heap_bytes()];
        restored = AppletInstance::restore(&file, Sizes::default(), card.save_into(&mut suspended_heap).unwrap()).unwrap();
        restored.restore_volatile(&retained).unwrap();
        let resumed = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(resumed.array_get(transient, 0), Ok(7));
        assert_eq!(resumed.array_get(on_deselect, 0), Ok(0));
        assert_eq!(resumed.get_word(pin, 3), Ok(0));
        assert_eq!(resumed.array_get(key_material, 0), Ok(1));
        assert_eq!(resumed.array_get(hash_state, 0), Ok(1));
        assert_eq!(resumed.array_get(ec_private_bytes, 0), Ok(0x5f));
        assert_eq!(resumed.array_get(ec_private_bytes, 32), Ok(1));
        assert_eq!(resumed.byte_slice(key_material, 1, 16).unwrap(), &[0x42; 16]);
        card.reset().unwrap();
        assert!(card.installed());
        assert!(card.words.iter().all(|word| *word == 0));
        assert!(card.tags.iter().all(|tag| *tag == 0));
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(transient, 0), Ok(0));
        assert_eq!(heap.array_get(persistent, 0), Ok(9));
        assert_eq!(heap.get_word(pin, 3), Ok(0));
        assert_eq!(heap.get_word(pin, 4), Ok(2));
        assert_eq!(heap.get_word(runtime_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(heap.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        assert!(heap.byte_slice(card.buffer, 0, card.sizes.buffer_bytes as usize).unwrap().iter().all(|byte| *byte == 0));
        // Explicit registration may not change the instance management authorized.
        let bytes = applet_registration(vec![op::RETURN], 1, true).build();
        let file = LoadFile::parse(&bytes).unwrap();
        let module_aid = file.applets().unwrap().iter().next().unwrap().aid;
        let requested = [0xf0, 1, 2, 3, 4];
        for (parameters, expected) in [(&requested[..], Ok(())), (&[0xf0, 1, 2, 3, 5][..], Err(Error::Unauthorized)), (&[0xf0, 1, 2, 3][..], Err(Error::Bounds))] {
            let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
            assert_eq!(card.install_instance_with_cancel(&file, &mut crate::host::NoHost,
                Installation { module_aid, instance_aid: &requested, parameters }, &mut || false), expected);
        }
    }

    #[test]
    fn installation_parameters_cannot_escape_into_static_storage() {
        let mut package = applet(vec![op::RETURN], 1);
        package.static_bytes = 2;
        package.constants.push([crate::cap::CONSTANT_STATIC_FIELDREF, 0, 0, 0]);
        // Keep method offsets unchanged; this installation only attempts the store.
        package.code[..5].copy_from_slice(&[op::ALOAD_0, op::PUTSTATIC_A, 0, 6, op::RETURN]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[0x42]), Err(Error::Unauthorized));
        assert_eq!(card.statics, [0, 0]);
        assert!(!card.installed());
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
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
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
        let mut declined = AppletInstance::new(&declined_file, Sizes::default()).unwrap();
        declined.install(&declined_file, &mut crate::host::NoHost, &[]).unwrap();
        assert_eq!(declined.process(&declined_file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x6999);
        assert!(!declined.selected());
        // Inherited Applet.select() accepts; process still chooses the response status.
        package.classes[0].public[applet_token(MethodId::select).unwrap() as usize] = 0xffff;
        let inherited_bytes = package.build();
        let inherited_file = LoadFile::parse(&inherited_bytes).unwrap();
        let mut inherited = AppletInstance::new(&inherited_file, Sizes::default()).unwrap();
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
    fn transactions_restore_fields_and_statics_at_real_callback_boundaries() {
        #[derive(Default)]
        struct CheckpointHost { saved: Vec<(Vec<u8>, Vec<u8>, Reference)>, fail_at: Option<usize>, calls: usize }
        impl Host for CheckpointHost {
            fn checkpoint(&mut self, state: PersistentView<'_>) -> Result<()> {
                self.calls += 1;
                if self.fail_at == Some(self.calls) { return Err(Error::Storage); }
                let mut heap = vec![0; state.heap_bytes()];
                let saved = state.save_into(&mut heap)?;
                self.saved.push((saved.heap.to_vec(), saved.statics.to_vec(), saved.instance));
                Ok(())
            }
        }
        for ending in ["commit", "commit-throw", "commit-cancel", "commit-fail", "abort", "return", "throw", "allocate-abort", "cancel", "plain-cancel", "plain-store-fail", "full", "full-caught"] {
            // Constants 6..12: begin, commit, abort, static field, instance field,
            // ISOException.throwIt, Util.arrayCopy.
            let mut process = vec![
                op::SSPUSH, 0, 9, 0x81, 0, 9,
                op::ALOAD_0, op::SSPUSH, 0, 9, 0x89, 10,
            ];
            if ending.starts_with("full") {
                process.extend_from_slice(&[op::SSPUSH, 0x20, 0, 144, 11, op::ASTORE_0 + 2]);
            }
            if !ending.starts_with("plain-") { process.extend_from_slice(&[op::INVOKESTATIC, 0, 6]); }
            process.extend_from_slice(&[
                op::SSPUSH, 0, 12, 0x81, 0, 9,
                op::ALOAD_0, op::SSPUSH, 0, 12, 0x89, 10,
                op::ALOAD_0 + 1, op::INVOKEVIRTUAL, 0, 13,
                op::SCONST_0, op::SSPUSH, 0, 42, 56,
            ]);
            match ending {
                "commit" | "commit-fail" => process.extend_from_slice(&[op::INVOKESTATIC, 0, 7]),
                "commit-throw" | "commit-cancel" => {
                    process.extend_from_slice(&[
                        op::INVOKESTATIC, 0, 7, op::INVOKESTATIC, 0, 6,
                        op::SSPUSH, 0, 99, 0x81, 0, 9,
                        op::ALOAD_0, op::SSPUSH, 0, 99, 0x89, 10,
                    ]);
                    if ending == "commit-throw" {
                        process.extend_from_slice(&[op::SSPUSH, 0x6a, 0x80, op::INVOKESTATIC, 0, 11]);
                    } else { process.extend_from_slice(&[112, 0]); }
                },
                "abort" => process.extend_from_slice(&[op::INVOKESTATIC, 0, 8]),
                "throw" => process.extend_from_slice(&[op::SSPUSH, 0x6a, 0x80, op::INVOKESTATIC, 0, 11]),
                "allocate-abort" => process.extend_from_slice(&[op::NEW, 0, 3, op::ASTORE_0 + 2, op::INVOKESTATIC, 0, 8]),
                "cancel" | "plain-cancel" => process.extend_from_slice(&[112, 0]), // goto itself until cancellation
                "full" | "full-caught" => process.extend_from_slice(&[
                    op::ALOAD_0 + 2, op::SCONST_0, op::ALOAD_0 + 2, op::SCONST_0,
                    op::SSPUSH, 0x20, 0, op::INVOKESTATIC, 0, 12,
                ]),
                _ => {},
            }
            process.push(op::RETURN);
            let handler_offset = process.len() as u16;
            if ending == "full-caught" {
                process.extend_from_slice(&[op::INVOKEVIRTUAL, 0, 14, op::INVOKESTATIC, 0, 8, 0x81, 0, 9, op::RETURN]);
            }
            let mut package = applet(process, 8);
            package.static_bytes = 2;
            package.classes[0].declared_size = 1;
            package.constants.extend_from_slice(&[
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 1],
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 2],
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 0],
                [CONSTANT_STATIC_FIELDREF, 0, 0, 0],
                [crate::cap::CONSTANT_INSTANCE_FIELDREF, 0, 0, 0],
                [CONSTANT_STATIC_METHODREF, 0x81, 7, 1],
                [CONSTANT_STATIC_METHODREF, 0x81, 16, 1],
                [CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 1],
                [CONSTANT_VIRTUAL_METHODREF, 0x81, 14, 1],
            ]);
            if ending == "full-caught" {
                package.handlers.push([0; 8]);
                let bodies = package.extra_offsets();
                package.constants[4] = [CONSTANT_STATIC_METHODREF, 0, (bodies[0] >> 8) as u8, bodies[0] as u8];
                package.classes[0].public[applet_token(MethodId::select).unwrap() as usize] = bodies[1];
                package.classes[0].public[applet_token(MethodId::process).unwrap() as usize] = bodies[2];
                let start = bodies[2] + 2;
                let target = start + handler_offset;
                let length = handler_offset | 0x8000;
                package.handlers[0] = [(start >> 8) as u8, start as u8, (length >> 8) as u8, length as u8,
                    (target >> 8) as u8, target as u8, 0, 0];
            }
            let bytes = package.build();
            let file = LoadFile::parse(&bytes).unwrap();
            let mut card = AppletInstance::new(&file, Sizes { heap_bytes: 16384, ..Sizes::default() }).unwrap();
            card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
            let mut polls = 0;
            let mut host = CheckpointHost { fail_at: match ending { "commit-fail" | "plain-store-fail" => Some(1), _ => None }, ..Default::default() };
            let result = card.process_with_cancel(&file, &mut host, &[0, 1, 0, 0], false, &mut || {
                polls += 1;
                ending.ends_with("cancel") && polls == 100
            });
            if matches!(ending, "commit-fail" | "plain-store-fail") { assert_eq!(result, Err(Error::Storage), "{ending}"); }
            else if ending.ends_with("cancel") { assert_eq!(result, Err(Error::Cancelled)); }
            else {
                assert_eq!(result.unwrap().sw, if matches!(ending, "commit" | "abort" | "full-caught") { SW_SUCCESS } else { SW_UNKNOWN }, "{ending}");
            }
            let expected: u16 = if ending.starts_with("plain-") || ending.starts_with("commit") && ending != "commit-fail" { 12 } else { 9 };
            assert_eq!(card.statics, if ending == "full-caught" { 3u16 } else { expected }.to_be_bytes(), "{ending}");
            let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
            assert_eq!(heap.get_word(card.instance.unwrap(), 0).unwrap(), expected, "{ending}");
            assert_eq!(heap.array_get(card.buffer, 0), Ok(42), "APDU bytes are transient: {ending}");
            if ending.ends_with("cancel") && ending != "commit-cancel"
                || matches!(ending, "commit-fail" | "plain-store-fail") {
                assert!(host.saved.is_empty(), "{ending}");
            } else {
                assert!(!host.saved.is_empty(), "{ending}");
            }
            for (heap, statics, instance) in &host.saved {
                let mut restored = AppletInstance::restore(&file, card.sizes, PersistentState { heap, statics, instance: *instance }).unwrap();
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.array_get(restored.buffer, 0), Ok(0));
            }
            if let Some((heap, statics, instance)) = host.saved.last() {
                let durable_field: u16 = if ending.starts_with("commit")
                    || ending.starts_with("plain-") { 12 } else { 9 };
                let durable_static = if ending == "full-caught" { 3 } else { durable_field };
                let mut restored = AppletInstance::restore(&file, card.sizes,
                    PersistentState { heap, statics, instance: *instance }).unwrap();
                assert_eq!(statics, &durable_static.to_be_bytes(), "{ending}");
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.get_word(*instance, 0), Ok(durable_field), "{ending}");
            }
            if let Some(failed) = host.fail_at { assert_eq!(host.calls, failed, "failed checkpoint must not retry"); }
            if !ending.ends_with("cancel") && ending != "commit-fail" {
                let mut saved = vec![0; card.persistent_heap_bytes()];
                let mut restored = AppletInstance::restore(&file, card.sizes, card.save_into(&mut saved).unwrap()).unwrap();
                assert_eq!(restored.statics, card.statics);
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.get_word(restored.instance.unwrap(), 0), Ok(expected));
                assert_eq!(heap.array_get(restored.buffer, 0), Ok(0));
            }
            if ending == "throw" {
                // Throwing a reserved exception must not invalidate applet references.
                assert!(!card.transaction_aborted);
                assert_eq!(card.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0], false).unwrap().sw, SW_UNKNOWN);
                assert!(!card.transaction_aborted);
            }
            if ending == "allocate-abort" {
                assert_eq!(card.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0], false), Err(Error::TransactionAborted));
                card.reset().unwrap();
                assert!(!card.transaction_aborted);
            }
        }
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
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
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
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[]), Err(Error::Missing));
        assert!(!card.installed());
    }
}
