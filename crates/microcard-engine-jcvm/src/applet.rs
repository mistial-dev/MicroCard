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
            let buffer = heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?;
            let (incoming, remainder) = buffer.split_at_mut(command.len());
            incoming.copy_from_slice(command);
            remainder.fill(0);
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
                // The transport appends the status word, so reserve its space now.
                data.try_reserve_exact(response.len() + 2).map_err(|_| Error::Quota)?;
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
mod tests;
