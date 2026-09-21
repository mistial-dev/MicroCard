//! The instruction dispatch loop.
//!
//! One match dispatches arithmetic, control flow, fields, arrays, and native calls.
//!
//! Java Card arithmetic wraps rather than trapping, JCVM §3.3, so every operation below is
//! a wrapping one. Two of them are worth naming: a shift distance is masked before use, and
//! `sushr` masks its operand to 16 bits before shifting, which is the difference between a
//! logical and an arithmetic shift on a value held in a wider register.
use crate::jcvm_api::{ClassId};
use super::frame::{Frame, NULL, Reference};
use super::heap::{self, Context, Heap};

use crate::cap::Method;
use crate::code::{Limits, constant_pool_index, instruction_length};
use crate::link::Linked;
use crate::host::Host;
use crate::natives::{self, Jcre, Native};
use crate::{Error, Result};

/// How an invocation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Void,
    Short(i16),
    Int(i32),
    Reference(Reference),
    /// It threw, and no handler in that method caught it. The caller searches next.
    Thrown(Reference),
}

/// How deep one command may nest invocations.
///
/// Each level costs a native stack frame, so the bound is what keeps a recursive method
/// from reaching past the card's own stack instead of failing.
pub const MAX_DEPTH: u8 = 16;

/// What a running method is allowed to touch.
pub struct Machine<'a, 'h, 'p, H: Host> {
    pub heap: &'a mut Heap<'h>,
    /// The card, for anything the engine cannot compute itself.
    pub host: &'a mut H,
    /// The package, for resolving what an instruction names.
    pub linked: &'a Linked<'p>,
    /// The Method component, which every method offset counts from.
    pub methods: Method<'p>,
    /// The static field image, indexed in bytes.
    pub statics: &'a mut [u8],
    /// The context this code runs in, which the firewall compares against every object.
    pub context: Context,
    pub limits: Limits,
    /// What the runtime environment knows while this command runs.
    pub jcre: Jcre,
    depth: u8,
    cancel: Option<&'a mut dyn FnMut() -> bool>,
}

impl<'a, 'h, 'p, H: Host> Machine<'a, 'h, 'p, H> {
    /// Everything one command runs against. The pieces are unrelated to each other, which
    /// is why they arrive separately rather than as a struct that would only exist here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        heap: &'a mut Heap<'h>,
        host: &'a mut H,
        linked: &'a Linked<'p>,
        methods: Method<'p>,
        statics: &'a mut [u8],
        context: Context,
        limits: Limits,
        jcre: Jcre,
    ) -> Self {
        Self {
            heap,
            host,
            linked,
            methods,
            statics,
            context,
            limits,
            jcre,
            depth: 0,
            cancel: None,
        }
    }

    /// Every applet callback ends its transaction, including exceptional returns.
    pub fn abort_unfinished_transaction(&mut self) -> Result<bool> {
        if self.heap.transaction_remaining().is_none() { return Ok(false); }
        self.heap.abort_transaction(self.statics)?;
        Ok(true)
    }

    pub fn with_cancel(mut self, cancel: &'a mut dyn FnMut() -> bool) -> Self {
        self.cancel = Some(cancel);
        self
    }
}

/// Words and tags one command's frames are carved out of.
pub struct Arena<'a> {
    pub words: &'a mut [u16],
    pub tags: &'a mut [u8],
}

/// Opcodes this loop understands by name rather than by table.
mod op {
    pub const NOP: u8 = 0;
    pub const ACONST_NULL: u8 = 1;
    pub const SCONST_M1: u8 = 2;
    /// Used by tests, which spell the constants out rather than counting opcodes.
    #[cfg(test)]
    pub const SCONST_0: u8 = 3;
    #[cfg(test)]
    pub const SCONST_1: u8 = 4;
    pub const SCONST_5: u8 = 8;
    pub const ICONST_M1: u8 = 9;
    pub const ICONST_5: u8 = 15;
    pub const BSPUSH: u8 = 16;
    pub const SSPUSH: u8 = 17;
    pub const BIPUSH: u8 = 18;
    pub const SIPUSH: u8 = 19;
    pub const IIPUSH: u8 = 20;
    pub const ALOAD: u8 = 21;
    pub const SLOAD: u8 = 22;
    pub const ILOAD: u8 = 23;
    pub const ALOAD_0: u8 = 24;
    pub const SLOAD_0: u8 = 28;
    pub const ILOAD_0: u8 = 32;
    pub const ASTORE: u8 = 40;
    pub const SSTORE: u8 = 41;
    pub const ISTORE: u8 = 42;
    pub const ASTORE_0: u8 = 43;
    pub const SSTORE_0: u8 = 47;
    pub const ISTORE_0: u8 = 51;
    pub const AALOAD: u8 = 36;
    pub const BALOAD: u8 = 37;
    pub const SALOAD: u8 = 38;
    pub const IALOAD: u8 = 39;
    pub const AASTORE: u8 = 55;
    pub const BASTORE: u8 = 56;
    pub const SASTORE: u8 = 57;
    pub const IASTORE: u8 = 58;
    pub const POP: u8 = 59;
    pub const POP2: u8 = 60;
    pub const DUP: u8 = 61;
    pub const DUP2: u8 = 62;
    pub const DUP_X: u8 = 63;
    pub const SWAP_X: u8 = 64;
    pub const SADD: u8 = 65;
    pub const IADD: u8 = 66;
    pub const SSUB: u8 = 67;
    pub const ISUB: u8 = 68;
    pub const SMUL: u8 = 69;
    pub const IMUL: u8 = 70;
    pub const SDIV: u8 = 71;
    pub const IDIV: u8 = 72;
    pub const SREM: u8 = 73;
    pub const IREM: u8 = 74;
    pub const SNEG: u8 = 75;
    pub const INEG: u8 = 76;
    pub const SSHL: u8 = 77;
    pub const ISHL: u8 = 78;
    pub const SSHR: u8 = 79;
    pub const ISHR: u8 = 80;
    pub const SUSHR: u8 = 81;
    pub const IUSHR: u8 = 82;
    pub const SAND: u8 = 83;
    pub const IAND: u8 = 84;
    pub const SOR: u8 = 85;
    pub const IOR: u8 = 86;
    pub const SXOR: u8 = 87;
    pub const IXOR: u8 = 88;
    pub const SINC: u8 = 89;
    pub const IINC: u8 = 90;
    pub const S2B: u8 = 91;
    pub const S2I: u8 = 92;
    pub const I2B: u8 = 93;
    pub const I2S: u8 = 94;
    pub const ICMP: u8 = 95;
    pub const IFEQ: u8 = 96;
    pub const IFLE: u8 = 101;
    pub const IFNULL: u8 = 102;
    pub const IFNONNULL: u8 = 103;
    pub const IF_ACMPEQ: u8 = 104;
    pub const IF_ACMPNE: u8 = 105;
    pub const IF_SCMPEQ: u8 = 106;
    pub const IF_SCMPLE: u8 = 111;
    pub const GOTO: u8 = 112;
    pub const STABLESWITCH: u8 = 115;
    pub const ITABLESWITCH: u8 = 116;
    pub const SLOOKUPSWITCH: u8 = 117;
    pub const ILOOKUPSWITCH: u8 = 118;
    pub const ARETURN: u8 = 119;
    pub const SRETURN: u8 = 120;
    pub const IRETURN: u8 = 121;
    pub const RETURN: u8 = 122;
    pub const SINC_W: u8 = 150;
    pub const IINC_W: u8 = 151;
    pub const IFEQ_W: u8 = 152;
    pub const IFLE_W: u8 = 157;
    pub const IFNULL_W: u8 = 158;
    pub const IFNONNULL_W: u8 = 159;
    pub const IF_ACMPEQ_W: u8 = 160;
    pub const IF_ACMPNE_W: u8 = 161;
    pub const IF_SCMPEQ_W: u8 = 162;
    pub const IF_SCMPLE_W: u8 = 167;
    pub const GETSTATIC_A: u8 = 123;
    pub const PUTSTATIC_A: u8 = 127;
    pub const GETFIELD_A: u8 = 131;
    pub const PUTFIELD_A: u8 = 135;
    pub const INVOKEVIRTUAL: u8 = 139;
    pub const INVOKESPECIAL: u8 = 140;
    pub const INVOKESTATIC: u8 = 141;
    pub const INVOKEINTERFACE: u8 = 142;
    pub const NEW: u8 = 143;
    pub const NEWARRAY: u8 = 144;
    pub const ANEWARRAY: u8 = 145;
    pub const CHECKCAST: u8 = 148;
    pub const INSTANCEOF: u8 = 149;
    pub const ATHROW: u8 = 147;
    pub const ARRAYLENGTH: u8 = 146;
    // The wide forms come before the this forms, which is the opposite of what the
    // shorter mnemonics suggest. The test below pins each against the generated table.
    pub const GETFIELD_A_W: u8 = 169;
    pub const GETFIELD_A_THIS: u8 = 173;
    pub const PUTFIELD_A_W: u8 = 177;
    pub const PUTFIELD_A_THIS: u8 = 181;
    pub const GOTO_W: u8 = 168;
}

/// Which comparison a conditional branch makes, from its offset within its family.
fn compares(index: u8, left: i32, right: i32) -> bool {
    match index {
        0 => left == right,
        1 => left != right,
        2 => left < right,
        3 => left >= right,
        4 => left > right,
        _ => left <= right,
    }
}

fn word(code: &[u8], at: usize) -> Result<i16> {
    let bytes = code.get(at..at + 2).ok_or(Error::Bounds)?;
    Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
}

fn long(code: &[u8], at: usize) -> Result<i32> {
    let bytes = code.get(at..at + 4).ok_or(Error::Bounds)?;
    Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn byte(code: &[u8], at: usize) -> Result<u8> {
    code.get(at).copied().ok_or(Error::Bounds)
}

/// Run a method body to its return.
///
/// `budget` counts instructions and is what stops a loop in the bytecode from holding the
/// card. It is decremented per instruction and running out is an error rather than a
/// silent stop, so a caller can tell a finished method from an abandoned one.
/// Call a method by its Method component offset, taking its arguments from `caller`.
///
/// The callee's frame comes out of what is left of the arena, so the depth a command can
/// reach is bounded by memory the caller set aside rather than by anything the bytecode
/// says. Its result goes back on the caller's stack with the right tag.
pub fn invoke(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    method: u16,
    caller: &mut Frame,
    arena: &mut Arena,
    budget: &mut u32,
) -> Result<Option<Reference>> {
    if machine.depth >= MAX_DEPTH {
        return Err(Error::Quota);
    }
    let bytes = machine.methods.bytes();
    let at = method as usize;
    if at < machine.methods.methods_start() {
        return Err(Error::Bounds);
    }
    let header = crate::cap::MethodHeader::parse(bytes, at)?;
    if header.abstract_method() {
        // An abstract method has no body, so reaching one means the dispatch was wrong.
        return Err(Error::Missing);
    }
    let locals = header.frame_words() as usize;
    let stack = header.max_stack as usize;
    let words_needed = Frame::words_for(locals, stack);
    let tags_needed = Frame::tag_bytes_for(locals, stack);
    if arena.words.len() < words_needed || arena.tags.len() < tags_needed {
        return Err(Error::Quota);
    }
    let (words, rest_words) = arena.words.split_at_mut(words_needed);
    let (tags, rest_tags) = arena.tags.split_at_mut(tags_needed);
    let mut callee = Frame::new(words, tags, locals, stack)?;
    // Arguments come off the caller's stack in reverse, keeping their tags, so a reference
    // stays a reference across the call.
    for index in (0..header.nargs as usize).rev() {
        let value = caller.pop_raw()?;
        callee.store_raw(index, value)?;
    }
    let body = at + header.length;
    let code = bytes.get(body..).ok_or(Error::Bounds)?;
    let mut inner = Arena {
        words: rest_words,
        tags: rest_tags,
    };
    machine.depth += 1;
    // The handler table records absolute offsets, so the callee has to know where its own
    // body sits before it can find its own handlers.
    let outcome = run_body(machine, code, body, &mut callee, &mut inner, budget);
    machine.depth -= 1;
    match outcome? {
        Outcome::Void => Ok(None),
        Outcome::Short(value) => caller.push_short(value).map(|()| None),
        Outcome::Int(value) => caller.push_int(value).map(|()| None),
        Outcome::Reference(value) => caller.push_reference(value).map(|()| None),
        // Nothing in the callee caught it, so the caller searches its own handlers from
        // wherever the call was made.
        Outcome::Thrown(exception) => Ok(Some(exception)),
    }
}

/// Find the handler for an exception thrown at `pc`, JCVM §3.6 and §6.10.3.
///
/// Handlers are one flat table for the whole package, in order, and each carries a stop
/// bit marking the last handler applicable to an active range. Honouring that bit is what
/// makes the flat table behave like nested try blocks. Ignoring it lets an exception
/// escape one scope too far and be caught by the wrong block, which is hard to see later.
fn find_handler(
    machine: &Machine<'_, '_, '_, impl Host>,
    body: usize,
    code_len: usize,
    pc: usize,
    exception: Reference,
) -> Result<Option<usize>> {
    let at = (body + pc) as u16;
    let class = machine.heap.info(exception)?.class;
    for handler in machine.methods.handlers() {
        if handler.covers(at) {
            if catches(machine, handler.catch_type_index, class)? {
                let target = handler.handler_offset as usize;
                // A handler outside this method would run on the wrong frame.
                if target < body || target - body >= code_len {
                    return Err(Error::Bounds);
                }
                return Ok(Some(target - body));
            }
            // The last handler of this range. Nothing after it covers the same code, so
            // the search stops here and the exception leaves the method.
            if handler.stop {
                return Ok(None);
            }
        }
    }
    Ok(None)
}

/// Whether a handler's catch type matches the thrown class, following the chain up.
fn catches(machine: &Machine<'_, '_, '_, impl Host>, catch_type: u16, thrown: u16) -> Result<bool> {
    // Zero catches everything, which is what a finally block compiles to.
    if catch_type == 0 {
        return Ok(true);
    }
    class_matches(machine, thrown, catch_type)
}

/// Whether a class reaches the class a constant pool entry names.
///
/// A catch and a cast ask the same question, so they are answered in one place. A class
/// the card provides answers through the hierarchy its export file records, and an
/// applet's own class answers by walking what it extends and implements.
fn class_matches(machine: &Machine<'_, '_, '_, impl Host>, class: u16, index: u16) -> Result<bool> {
    machine.linked.class_matches(class, index)
}

/// Whether an object can be used as the type a cast names, JCVM §7.5.16.
///
/// The type code decides what is being asked. For a primitive array the code is the whole
/// answer. Otherwise the constant pool names a class.
fn assignable(
    machine: &Machine<'_, '_, '_, impl Host>,
    object: Reference,
    atype: u8,
    named: Option<(usize, u16)>,
) -> Result<bool> {
    let info = machine.heap.info(object)?;
    if (10..=13).contains(&atype) {
        return Ok(info.is_array() && info.kind == array_kind(atype)?);
    }
    let Some((_, index)) = named else {
        return Err(Error::Format);
    };
    if atype == 14 {
        // An array of references to the named class. The element type is all this engine
        // records, so the element class itself is not checked.
        return Ok(info.is_array() && info.kind == heap::KIND_REFERENCE);
    }
    if info.is_array() {
        return Ok(false);
    }
    class_matches(machine, info.class, index)
}

fn reference_array_accepts(machine: &Machine<'_, '_, '_, impl Host>, array: heap::Info,
        value: Reference) -> Result<bool> {
    if value == NULL || array.class == heap::ANY_REFERENCE_CLASS { return Ok(true); }
    let component = crate::cap::ClassRef::decode(array.class);
    if component == crate::cap::ClassRef::None { return Err(Error::Format); }
    let value_info = machine.heap.info(value)?;
    if !value_info.is_array() {
        return machine.linked.class_matches_target(value_info.class, component);
    }
    // Every array is an Object. Java Card does not expose Cloneable or Serializable,
    // so no other named class can accept an array value here.
    machine.linked.class_reference_is_object(component)
}

/// Run a method body with no arena, which refuses any invocation it meets.
pub fn run(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    code: &[u8],
    frame: &mut Frame,
    budget: &mut u32,
) -> Result<Outcome> {
    let mut arena = Arena {
        words: &mut [],
        tags: &mut [],
    };
    run_with(machine, code, frame, &mut arena, budget)
}

/// Run a method body, using `arena` for anything it calls.
pub fn run_with(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    code: &[u8],
    frame: &mut Frame,
    arena: &mut Arena,
    budget: &mut u32,
) -> Result<Outcome> {
    run_body(machine, code, 0, frame, arena, budget)
}

fn call_native(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    target: crate::link::ApiTarget,
    frame: &mut Frame,
    budget: &mut u32,
) -> Result<Native> {
    let mut native = natives::NativeContext {
        heap: machine.heap,
        host: machine.host,
        frame,
        context: machine.context,
        jcre: &mut machine.jcre,
        budget,
        statics: machine.statics,
    };
    natives::call_with_budget(target, &mut native)
}

/// Run a method body that starts at `body` in the Method component.
///
/// The absolute offset is what the handler table records, so a method needs to know where
/// it sits before it can find its own handlers.
pub fn run_body(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    code: &[u8],
    body: usize,
    frame: &mut Frame,
    arena: &mut Arena,
    budget: &mut u32,
) -> Result<Outcome> {
    let mut pc = 0usize;
    loop {
        if machine.cancel.as_mut().is_some_and(|cancel| cancel()) {
            return Err(Error::Cancelled);
        }
        *budget = budget.checked_sub(1).ok_or(Error::Quota)?;
        let opcode = byte(code, pc)?;
        #[cfg(feature = "diagnostics")]
        if let Err(error) = machine.limits.allows(opcode) {
            extern crate std;
            std::eprintln!(
                "jcvm: rejected opcode {opcode:#04x} at Method.cap offset {:#06x}: {error:?}",
                body + pc
            );
        }
        machine.limits.allows(opcode)?;
        let length = instruction_length(code, pc)?;
        let mut next = pc + length;
        // Convert transaction and firewall violations into catchable Java exceptions
        // at the failing instruction. Other engine errors retain their fail-closed path.
        let step = (|| -> Result<Option<Outcome>> {
        match opcode {
            op::NOP => {}
            op::ACONST_NULL => frame.push_reference(NULL)?,
            op::SCONST_M1..=op::SCONST_5 => {
                frame.push_short(opcode as i16 - op::SCONST_M1 as i16 - 1)?
            }
            op::ICONST_M1..=op::ICONST_5 => {
                frame.push_int(opcode as i32 - op::ICONST_M1 as i32 - 1)?
            }
            op::BSPUSH | op::BIPUSH => {
                let value = byte(code, pc + 1)? as i8 as i32;
                if opcode == op::BSPUSH {
                    frame.push_short(value as i16)?
                } else {
                    frame.push_int(value)?
                }
            }
            op::SSPUSH | op::SIPUSH => {
                let value = word(code, pc + 1)?;
                if opcode == op::SSPUSH {
                    frame.push_short(value)?
                } else {
                    frame.push_int(value as i32)?
                }
            }
            op::IIPUSH => frame.push_int(long(code, pc + 1)?)?,

            op::ALOAD => {
                let value = frame.load_reference(byte(code, pc + 1)? as usize)?;
                frame.push_reference(value)?
            }
            op::SLOAD => {
                let value = frame.load_short(byte(code, pc + 1)? as usize)?;
                frame.push_short(value)?
            }
            op::ILOAD => {
                let value = frame.load_int(byte(code, pc + 1)? as usize)?;
                frame.push_int(value)?
            }
            op::ALOAD_0..=27 => {
                let value = frame.load_reference((opcode - op::ALOAD_0) as usize)?;
                frame.push_reference(value)?
            }
            op::SLOAD_0..=31 => {
                let value = frame.load_short((opcode - op::SLOAD_0) as usize)?;
                frame.push_short(value)?
            }
            op::ILOAD_0..=35 => {
                let value = frame.load_int((opcode - op::ILOAD_0) as usize)?;
                frame.push_int(value)?
            }

            op::ASTORE => {
                let value = frame.pop_reference()?;
                frame.store_reference(byte(code, pc + 1)? as usize, value)?
            }
            op::SSTORE => {
                let value = frame.pop_short()?;
                frame.store_short(byte(code, pc + 1)? as usize, value)?
            }
            op::ISTORE => {
                let value = frame.pop_int()?;
                frame.store_int(byte(code, pc + 1)? as usize, value)?
            }
            op::ASTORE_0..=46 => {
                let value = frame.pop_reference()?;
                frame.store_reference((opcode - op::ASTORE_0) as usize, value)?
            }
            op::SSTORE_0..=50 => {
                let value = frame.pop_short()?;
                frame.store_short((opcode - op::SSTORE_0) as usize, value)?
            }
            op::ISTORE_0..=54 => {
                let value = frame.pop_int()?;
                frame.store_int((opcode - op::ISTORE_0) as usize, value)?
            }

            op::POP => frame.pop_words(1)?,
            op::POP2 => frame.pop_words(2)?,
            op::DUP => frame.duplicate(1, 0)?,
            op::DUP2 => frame.duplicate(2, 0)?,
            op::DUP_X => {
                let mn = byte(code, pc + 1)?;
                frame.duplicate((mn >> 4) as usize, (mn & 0x0f) as usize)?
            }
            op::SWAP_X => {
                let mn = byte(code, pc + 1)?;
                frame.swap((mn >> 4) as usize, (mn & 0x0f) as usize)?
            }

            op::SADD | op::SSUB | op::SMUL | op::SAND | op::SOR | op::SXOR => {
                let right = frame.pop_short()?;
                let left = frame.pop_short()?;
                frame.push_short(match opcode {
                    op::SADD => left.wrapping_add(right),
                    op::SSUB => left.wrapping_sub(right),
                    op::SMUL => left.wrapping_mul(right),
                    op::SAND => left & right,
                    op::SOR => left | right,
                    _ => left ^ right,
                })?
            }
            op::SDIV | op::SREM => {
                let right = frame.pop_short()?;
                let left = frame.pop_short()?;
                if right == 0 {
                    return Err(Error::Arithmetic);
                }
                // Wrapping, because the one case that overflows is the most negative value
                // divided by minus one, and Java Card wraps where Rust would panic.
                frame.push_short(if opcode == op::SDIV {
                    left.wrapping_div(right)
                } else {
                    left.wrapping_rem(right)
                })?
            }
            op::SNEG => {
                let value = frame.pop_short()?;
                frame.push_short(value.wrapping_neg())?
            }
            op::SSHL | op::SSHR | op::SUSHR => {
                // The distance is taken modulo the width, JCVM §7.5.
                let distance = (frame.pop_short()? as u16 & 0x0f) as u32;
                let value = frame.pop_short()?;
                frame.push_short(match opcode {
                    op::SSHL => value.wrapping_shl(distance),
                    op::SSHR => value.wrapping_shr(distance),
                    // Mask to 16 bits first, or the sign bits of a wider register would be
                    // shifted in and the result would be an arithmetic shift.
                    _ => ((value as u16) >> distance) as i16,
                })?
            }

            op::IADD | op::ISUB | op::IMUL | op::IAND | op::IOR | op::IXOR => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                frame.push_int(match opcode {
                    op::IADD => left.wrapping_add(right),
                    op::ISUB => left.wrapping_sub(right),
                    op::IMUL => left.wrapping_mul(right),
                    op::IAND => left & right,
                    op::IOR => left | right,
                    _ => left ^ right,
                })?
            }
            op::IDIV | op::IREM => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                if right == 0 {
                    return Err(Error::Arithmetic);
                }
                frame.push_int(if opcode == op::IDIV {
                    left.wrapping_div(right)
                } else {
                    left.wrapping_rem(right)
                })?
            }
            op::INEG => {
                let value = frame.pop_int()?;
                frame.push_int(value.wrapping_neg())?
            }
            op::ISHL | op::ISHR | op::IUSHR => {
                let distance = (frame.pop_short()? as u16 & 0x1f) as u32;
                let value = frame.pop_int()?;
                frame.push_int(match opcode {
                    op::ISHL => value.wrapping_shl(distance),
                    op::ISHR => value.wrapping_shr(distance),
                    _ => ((value as u32) >> distance) as i32,
                })?
            }

            op::SINC | op::SINC_W => {
                let index = byte(code, pc + 1)? as usize;
                let by = if opcode == op::SINC {
                    byte(code, pc + 2)? as i8 as i16
                } else {
                    word(code, pc + 2)?
                };
                let value = frame.load_short(index)?;
                frame.store_short(index, value.wrapping_add(by))?
            }
            op::IINC | op::IINC_W => {
                let index = byte(code, pc + 1)? as usize;
                let by = if opcode == op::IINC {
                    byte(code, pc + 2)? as i8 as i32
                } else {
                    word(code, pc + 2)? as i32
                };
                let value = frame.load_int(index)?;
                frame.store_int(index, value.wrapping_add(by))?
            }

            op::S2B => {
                // Truncate to a byte and sign extend back, which is what a byte field
                // round trip does.
                let value = frame.pop_short()?;
                frame.push_short(value as i8 as i16)?
            }
            op::S2I => {
                let value = frame.pop_short()?;
                frame.push_int(value as i32)?
            }
            op::I2B => {
                let value = frame.pop_int()?;
                frame.push_short(value as i8 as i16)?
            }
            op::I2S => {
                let value = frame.pop_int()?;
                frame.push_short(value as i16)?
            }
            op::ICMP => {
                let right = frame.pop_int()?;
                let left = frame.pop_int()?;
                frame.push_short(match left.cmp(&right) {
                    core::cmp::Ordering::Less => -1,
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 1,
                })?
            }

            op::IFEQ..=op::IFLE | op::IFEQ_W..=op::IFLE_W => {
                let wide = opcode >= op::IFEQ_W;
                let index = opcode - if wide { op::IFEQ_W } else { op::IFEQ };
                let value = frame.pop_short()? as i32;
                if compares(index, value, 0) {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IFNULL | op::IFNONNULL | op::IFNULL_W | op::IFNONNULL_W => {
                let wide = opcode >= op::IFNULL_W;
                let want_null = opcode == op::IFNULL || opcode == op::IFNULL_W;
                let value = frame.pop_reference()?;
                if (value == NULL) == want_null {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IF_ACMPEQ | op::IF_ACMPNE | op::IF_ACMPEQ_W | op::IF_ACMPNE_W => {
                let wide = opcode >= op::IF_ACMPEQ_W;
                let equal = opcode == op::IF_ACMPEQ || opcode == op::IF_ACMPEQ_W;
                let right = frame.pop_reference()?;
                let left = frame.pop_reference()?;
                if (left == right) == equal {
                    next = branch(code, pc, wide)?;
                }
            }
            op::IF_SCMPEQ..=op::IF_SCMPLE | op::IF_SCMPEQ_W..=op::IF_SCMPLE_W => {
                let wide = opcode >= op::IF_SCMPEQ_W;
                let index = opcode - if wide { op::IF_SCMPEQ_W } else { op::IF_SCMPEQ };
                let right = frame.pop_short()? as i32;
                let left = frame.pop_short()? as i32;
                if compares(index, left, right) {
                    next = branch(code, pc, wide)?;
                }
            }
            op::GOTO => next = branch(code, pc, false)?,
            op::GOTO_W => next = branch(code, pc, true)?,

            op::STABLESWITCH | op::ITABLESWITCH => {
                let wide = opcode == op::ITABLESWITCH;
                let index = if wide {
                    frame.pop_int()?
                } else {
                    frame.pop_short()? as i32
                };
                let (low, high) = if wide {
                    (long(code, pc + 3)?, long(code, pc + 7)?)
                } else {
                    (word(code, pc + 3)? as i32, word(code, pc + 5)? as i32)
                };
                let header = if wide { 1 + 2 + 4 + 4 } else { 1 + 2 + 2 + 2 };
                let offset = if index < low || index > high {
                    word(code, pc + 1)? as i32
                } else {
                    let slot = (index as i64 - low as i64) as usize;
                    word(code, pc + header + slot * 2)? as i32
                };
                next = target(pc, offset, code.len())?;
            }
            op::SLOOKUPSWITCH | op::ILOOKUPSWITCH => {
                let wide = opcode == op::ILOOKUPSWITCH;
                let key = if wide {
                    frame.pop_int()?
                } else {
                    frame.pop_short()? as i32
                };
                let match_width = if wide { 4 } else { 2 };
                let pairs = word(code, pc + 3)? as u16 as usize;
                let mut offset = word(code, pc + 1)? as i32;
                for pair in 0..pairs {
                    let at = pc + 5 + pair * (match_width + 2);
                    let candidate = if wide {
                        long(code, at)?
                    } else {
                        word(code, at)? as i32
                    };
                    if candidate == key {
                        offset = word(code, at + match_width)? as i32;
                        break;
                    }
                }
                next = target(pc, offset, code.len())?;
            }

            op::ARRAYLENGTH => {
                let array = frame.pop_reference()?;
                let info = machine.heap.check_access(array, machine.context)?;
                if !info.is_array() {
                    return Err(Error::Type);
                }
                frame.push_short(info.length as i16)?
            }
            op::CHECKCAST | op::INSTANCEOF => {
                let object = frame.pop_reference()?;
                // A cast of null always succeeds, JCVM §7.5.16, and an instanceof of null
                // is always false.
                let answer = if object == NULL {
                    opcode == op::CHECKCAST
                } else {
                    let atype = byte(code, pc + 1)?;
                    assignable(machine, object, atype, constant_pool_index(code, pc)?)?
                };
                if opcode == op::INSTANCEOF {
                    frame.push_short((answer && object != NULL) as i16)?;
                } else if answer {
                    frame.push_reference(object)?;
                } else {
                    let exception = natives::new_exception(
                        machine.heap,
                        ClassId::ClassCastException,
                        machine.context,
                    )?;
                    return Ok(Some(Outcome::Thrown(exception)));
                }
            }
            op::ANEWARRAY => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                let entry = machine.linked.constants()?.get(index)?;
                if entry.tag != crate::cap::CONSTANT_CLASSREF { return Err(Error::Format); }
                let component = u16::from_be_bytes([entry.info[0], entry.info[1]]);
                if crate::cap::ClassRef::decode(component) == crate::cap::ClassRef::None {
                    return Err(Error::Format);
                }
                let length = frame.pop_short()?;
                if length < 0 {
                    let exception = natives::new_exception(machine.heap, ClassId::NegativeArraySizeException, machine.context)?;
                    return Ok(Some(Outcome::Thrown(exception)));
                }
                let array =
                    machine
                        .heap
                        .new_reference_array(component, length as u16, machine.context)?;
                frame.push_reference(array)?
            }
            op::NEWARRAY => {
                // The instruction numbers its types from 10, JCVM Table 7-2, and the
                // static field component numbers the same types from 2. Passing one
                // through as the other builds an array of a type nothing can read.
                let kind = array_kind(byte(code, pc + 1)?)?;
                let length = frame.pop_short()?;
                if length < 0 {
                    let exception = natives::new_exception(machine.heap, ClassId::NegativeArraySizeException, machine.context)?;
                    return Ok(Some(Outcome::Thrown(exception)));
                }
                let array = machine
                    .heap
                    .new_array(kind, length as u16, machine.context)?;
                frame.push_reference(array)?
            }
            op::BALOAD | op::SALOAD | op::AALOAD => {
                let index = frame.pop_short()?;
                let array = frame.pop_reference()?;
                let info = machine.heap.check_access(array, machine.context)?;
                // The instruction and the array have to agree on the element type, or a
                // reference would be read as a number or the other way round.
                let wanted = match opcode {
                    op::BALOAD => [heap::KIND_BOOLEAN, heap::KIND_BYTE].contains(&info.kind),
                    op::SALOAD => info.kind == heap::KIND_SHORT,
                    _ => info.kind == heap::KIND_REFERENCE,
                };
                if !wanted {
                    return Err(Error::Type);
                }
                let value = machine.heap.array_get(array, bounded_index(index, info.length)?)?;
                if opcode == op::AALOAD {
                    frame.push_reference(value as u16)?
                } else {
                    frame.push_short(value)?
                }
            }
            op::IALOAD => {
                let index = frame.pop_short()?;
                let array = frame.pop_reference()?;
                let info = machine.heap.check_access(array, machine.context)?;
                if info.kind != heap::KIND_INT { return Err(Error::Type); }
                let value = machine.heap.array_get_int(array, bounded_index(index, info.length)?)?;
                frame.push_int(value)?
            }
            op::BASTORE | op::SASTORE | op::AASTORE => {
                let value = if opcode == op::AASTORE {
                    frame.pop_reference()? as i16
                } else {
                    frame.pop_short()?
                };
                let index = frame.pop_short()?;
                let array = frame.pop_reference()?;
                let info = machine.heap.check_access(array, machine.context)?;
                let wanted = match opcode {
                    op::BASTORE => [heap::KIND_BOOLEAN, heap::KIND_BYTE].contains(&info.kind),
                    op::SASTORE => info.kind == heap::KIND_SHORT,
                    _ => info.kind == heap::KIND_REFERENCE,
                };
                if !wanted {
                    return Err(Error::Type);
                }
                if opcode == op::AASTORE {
                    let reference = value as Reference;
                    check_reference_store(machine, reference)?;
                    if !reference_array_accepts(machine, info, reference)? {
                        let exception = natives::new_exception(machine.heap,
                            ClassId::ArrayStoreException, machine.context)?;
                        return Ok(Some(Outcome::Thrown(exception)));
                    }
                    machine.heap.array_put_reference(array,
                        bounded_index(index, info.length)?, reference)?;
                } else {
                    machine.heap.array_put(array, bounded_index(index, info.length)?, value)?;
                }
            }
            op::IASTORE => {
                let value = frame.pop_int()?;
                let index = frame.pop_short()?;
                let array = frame.pop_reference()?;
                let info = machine.heap.check_access(array, machine.context)?;
                if info.kind != heap::KIND_INT { return Err(Error::Type); }
                machine
                    .heap
                    .array_put_int(array, bounded_index(index, info.length)?, value)?
            }

            op::NEW => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                let entry = machine.linked.constants()?.get(index)?;
                let value = u16::from_be_bytes([entry.info[0], entry.info[1]]);
                let object = match crate::cap::ClassRef::decode(value) {
                    crate::cap::ClassRef::Internal(class) => {
                        let words = machine.linked.instance_words(class)?;
                        machine.heap.new_object(class, words, machine.context)?
                    }
                    // A class the card provides. Its state is the card's rather than the
                    // applet's, so the object carries the words this engine needs instead
                    // of fields the applet could name.
                    crate::cap::ClassRef::External { package, class } => {
                        let wanted = machine.linked.api_class(package, class)?;
                        natives::new_api_object(machine.heap, wanted, machine.context)?
                    }
                    crate::cap::ClassRef::None => return Err(Error::Format),
                };
                frame.push_reference(object)?
            }

            op::GETSTATIC_A..=126 => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                let at = machine.linked.static_field(index)? as usize;
                read_static(machine, frame, at, opcode - op::GETSTATIC_A)?
            }
            op::PUTSTATIC_A..=130 => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                let at = machine.linked.static_field(index)? as usize;
                let kind = opcode - op::PUTSTATIC_A;
                let value = take_field_value(frame, kind)?;
                write_static(machine, at, kind, value)?
            }

            // The three field families differ only in where the receiver and the index
            // come from. The type is the position within each family.
            op::GETFIELD_A..=134 => {
                let index = field_index(code, pc, machine)?;
                let object = frame.pop_reference()?;
                read_field(machine, frame, object, index, opcode - op::GETFIELD_A)?
            }
            op::PUTFIELD_A..=138 => {
                let index = field_index(code, pc, machine)?;
                let kind = opcode - op::PUTFIELD_A;
                let value = take_field_value(frame, kind)?;
                let object = frame.pop_reference()?;
                put_field_value(machine, object, index, kind, value)?
            }
            op::GETFIELD_A_THIS..=176 => {
                let index = field_index(code, pc, machine)?;
                // The receiver is local zero, which is what makes these the shortest way
                // for a method to reach its own fields.
                let object = frame.load_reference(0)?;
                read_field(machine, frame, object, index, opcode - op::GETFIELD_A_THIS)?
            }
            op::PUTFIELD_A_THIS..=184 => {
                let index = field_index(code, pc, machine)?;
                let kind = opcode - op::PUTFIELD_A_THIS;
                let value = take_field_value(frame, kind)?;
                let object = frame.load_reference(0)?;
                put_field_value(machine, object, index, kind, value)?
            }
            op::GETFIELD_A_W..=172 => {
                let index = field_index(code, pc, machine)?;
                let object = frame.pop_reference()?;
                read_field(machine, frame, object, index, opcode - op::GETFIELD_A_W)?
            }
            op::PUTFIELD_A_W..=180 => {
                let index = field_index(code, pc, machine)?;
                let kind = opcode - op::PUTFIELD_A_W;
                let value = take_field_value(frame, kind)?;
                let object = frame.pop_reference()?;
                put_field_value(machine, object, index, kind, value)?
            }

            op::INVOKESTATIC | op::INVOKESPECIAL => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                // A call into an imported package is answered by the card rather than by
                // any method in this package, so it is tried first.
                let outcome = match machine.linked.external_static_method(index) {
                    Ok(Some((package, class, method))) => {
                        let target = machine.linked.api_method(package, class, method, true)?;
                        Some(call_native(machine, target, frame, budget)?)
                    }
                    _ => None,
                };
                if let Some(native) = outcome {
                    match native {
                        Native::Returned => {}
                        Native::Unimplemented => return Err(Error::Unsupported),
                        Native::Threw(exception) => {
                            return Ok(Some(Outcome::Thrown(exception)));
                        }
                    }
                    return Ok(None);
                }
                // invokespecial reaches a constructor or a private method through the same
                // constant type as invokestatic, and a superclass method through its own.
                let method = match machine.linked.static_method(index) {
                    Ok(method) => method,
                    Err(Error::Type) if opcode == op::INVOKESPECIAL => {
                        machine.linked.virtual_method(index, 0)?
                    }
                    Err(error) => return Err(error),
                };
                if let Some(exception) = invoke(machine, method, frame, arena, budget)? {
                    return Ok(Some(Outcome::Thrown(exception)));
                }
            }
            op::INVOKEVIRTUAL => {
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                // A method on a class the card provides is answered by the card. The
                // receiver is an object whose class no package defines.
                if let Some((package, class, method)) =
                    machine.linked.external_class_method(index)?
                {
                    let target = machine.linked.api_method(package, class, method, false)?;
                    match call_native(machine, target, frame, budget)? {
                        Native::Returned => {}
                        Native::Unimplemented => return Err(Error::Unsupported),
                        Native::Threw(exception) => {
                            return Ok(Some(Outcome::Thrown(exception)));
                        }
                    }
                    return Ok(None);
                }
                // The receiver sits under the arguments, and its class decides which body
                // runs, which is the whole of dynamic dispatch.
                let (declared, token) = machine.linked.virtual_ref(index)?;
                // The class the compiler saw gives the signature, so the argument count
                // comes from there. An override has the same signature by definition.
                let signature = machine.linked.lookup(declared, token)?;
                let header = crate::cap::MethodHeader::parse(
                    machine.methods.bytes(),
                    signature as usize,
                )?;
                // An instance method takes its receiver as the first argument, so a count
                // of zero means the resolution landed somewhere that is not one.
                let below = (header.nargs as usize).checked_sub(1).ok_or(Error::Type)?;
                let receiver = frame.peek_reference(below)?;
                let info = machine.heap.check_access(receiver, machine.context)?;
                let method = machine.linked.lookup(info.class, token)?;
                if let Some(exception) = invoke(machine, method, frame, arena, budget)? {
                    return Ok(Some(Outcome::Thrown(exception)));
                }
            }
            op::INVOKEINTERFACE => {
                // The argument count is an operand here rather than something to look up,
                // because the interface says nothing about which class will answer.
                let nargs = byte(code, pc + 1)?;
                let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
                let token = byte(code, pc + 4)?;
                let entry = machine.linked.constants()?.get(index)?;
                let interface =
                    crate::cap::ClassRef::decode(u16::from_be_bytes([entry.info[0], entry.info[1]]));
                let below = (nargs as usize).checked_sub(1).ok_or(Error::Type)?;
                let receiver = frame.peek_reference(below)?;
                let info = machine.heap.check_access(receiver, machine.context)?;
                // An object of a class the card provides answers the interface itself,
                // because the card is what implements it.
                if natives::is_native_class(info.class) {
                    let crate::cap::ClassRef::External { package, class } = interface else {
                        return Err(Error::Type);
                    };
                    let target = machine.linked.api_method(package, class, token, false)?;
                    match call_native(machine, target, frame, budget)? {
                        Native::Returned => {}
                        Native::Unimplemented => return Err(Error::Unsupported),
                        Native::Threw(exception) => {
                            return Ok(Some(Outcome::Thrown(exception)));
                        }
                    }
                    return Ok(None);
                }
                let method = machine
                    .linked
                    .interface_method(interface, token, info.class)?;
                if let Some(exception) = invoke(machine, method, frame, arena, budget)? {
                    return Ok(Some(Outcome::Thrown(exception)));
                }
            }
            op::ATHROW => {
                let exception = frame.pop_reference()?;
                // Throwing null is itself a null dereference, JCVM §7.5.
                machine.heap.info(exception)?;
                return Ok(Some(Outcome::Thrown(exception)));
            }

            op::RETURN => return Ok(Some(Outcome::Void)),
            op::SRETURN => return Ok(Some(Outcome::Short(frame.pop_short()?))),
            op::IRETURN => return Ok(Some(Outcome::Int(frame.pop_int()?))),
            op::ARETURN => return Ok(Some(Outcome::Reference(frame.pop_reference()?))),

            _ => return Err(Error::Unsupported),
        }
        Ok(None)
        })();
        let step = match step {
            Err(error @ (Error::Null | Error::Arithmetic | Error::ArrayBounds)) => {
                let class = match error {
                    Error::Null => ClassId::NullPointerException,
                    Error::Arithmetic => ClassId::ArithmeticException,
                    _ => ClassId::ArrayIndexOutOfBoundsException,
                };
                let exception = natives::new_exception(machine.heap, class, machine.context)?;
                Ok(Some(Outcome::Thrown(exception)))
            }
            Err(Error::Quota) if matches!(opcode, op::NEW | op::NEWARRAY | op::ANEWARRAY) => {
                let exception = natives::new_exception(machine.heap, ClassId::SystemException, machine.context)?;
                machine.heap.put_word_unconditional(exception, natives::REASON_FIELD, 5)?; // NO_RESOURCE
                Ok(Some(Outcome::Thrown(exception)))
            }
            Err(error @ (Error::TransactionFull | Error::Firewall)) => {
                let exception = if error == Error::Firewall {
                    natives::new_exception(machine.heap, ClassId::SecurityException, machine.context)?
                } else {
                    let Native::Threw(exception) = natives::transaction_exception(
                        machine.heap, &mut machine.jcre, machine.context, 3,
                    )? else { return Err(Error::Inconsistent); };
                    exception
                };
                Ok(Some(Outcome::Thrown(exception)))
            }
            result => result,
        };
        match step {
            Ok(Some(Outcome::Thrown(exception))) => {
                match find_handler(machine, body, code.len(), pc, exception)? {
                    Some(target) => {
                        enter_handler(frame, exception)?;
                        next = target;
                    }
                    None => return Ok(Outcome::Thrown(exception)),
                }
            }
            Ok(Some(outcome)) => return Ok(outcome),
            Ok(None) => {},
            Err(error) => {
                #[cfg(feature = "diagnostics")]
                {
                    extern crate std;
                    std::eprintln!(
                        "jcvm: instruction {opcode:#04x} at Method.cap offset {:#06x} failed: {error:?}",
                        body + pc
                    );
                }
                return Err(error);
            }
        }
        pc = next;
    }
}

/// The heap's element type for an array type code in the instruction set.
///
/// JCVM Table 7-2 numbers these from 10 while the static field component numbers the same
/// types from 2, so the two have to be translated rather than shared.
fn array_kind(atype: u8) -> Result<u8> {
    Ok(match atype {
        10 => heap::KIND_BOOLEAN,
        11 => heap::KIND_BYTE,
        12 => heap::KIND_SHORT,
        13 => heap::KIND_INT,
        _ => return Err(Error::Format),
    })
}

/// A handler starts with an empty stack holding only the exception, JCVM §3.6.
///
/// Whatever the try block had pushed is gone, which is why a handler cannot be entered by
/// an ordinary branch and why the boundary map alone does not make one reachable.
fn enter_handler(frame: &mut Frame, exception: Reference) -> Result<()> {
    frame.clear_stack();
    frame.push_reference(exception)
}

/// The constant pool index a field instruction names.
fn field_index(code: &[u8], pc: usize, machine: &Machine<'_, '_, '_, impl Host>) -> Result<u16> {
    let (_, index) = constant_pool_index(code, pc)?.ok_or(Error::Format)?;
    machine.linked.instance_field(index)
}

/// Which of the four field types an instruction in a family names.
const KIND_REF: u8 = 0;
const KIND_BYTE: u8 = 1;
const KIND_SHORT: u8 = 2;

fn read_field(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    frame: &mut Frame,
    object: Reference,
    index: u16,
    kind: u8,
) -> Result<()> {
    machine.heap.check_access(object, machine.context)?;
    let word = machine.heap.get_word(object, index as usize)?;
    match kind {
        KIND_REF => frame.push_reference(word),
        KIND_BYTE => frame.push_short(word as i8 as i16),
        KIND_SHORT => frame.push_short(word as i16),
        _ => {
            let low = machine.heap.get_word(object, index as usize + 1)?;
            frame.push_int((((word as u32) << 16) | low as u32) as i32)
        }
    }
}

fn take_field_value(frame: &mut Frame, kind: u8) -> Result<i32> {
    Ok(match kind {
        KIND_REF => frame.pop_reference()? as i32,
        KIND_BYTE | KIND_SHORT => frame.pop_short()? as i32,
        _ => frame.pop_int()?,
    })
}

fn check_reference_store(machine: &Machine<'_, '_, '_, impl Host>, reference: Reference) -> Result<()> {
    if reference == NULL { return Ok(()); }
    let info = machine.heap.info(reference)?;
    if info.owner != machine.context || reference == machine.jcre.buffer
        || natives::is_temporary_native(info.class, info.length) {
        return Err(Error::Firewall);
    }
    Ok(())
}

fn put_field_value(
    machine: &mut Machine<'_, '_, '_, impl Host>,
    object: Reference,
    index: u16,
    kind: u8,
    value: i32,
) -> Result<()> {
    machine.heap.check_access(object, machine.context)?;
    if kind == KIND_REF { check_reference_store(machine, value as Reference)?; }
    match kind {
        // A byte field keeps only the low byte, so reading it back sign extends.
        KIND_BYTE => machine
            .heap
            .put_word(object, index as usize, value as i8 as i16 as u16),
        KIND_REF | KIND_SHORT => machine.heap.put_word(object, index as usize, value as u16),
        _ => machine.heap.put_int(object, index as usize, value),
    }
}

fn write_static(machine: &mut Machine<'_, '_, '_, impl Host>, at: usize, kind: u8, value: i32) -> Result<()> {
    if kind == KIND_REF { check_reference_store(machine, value as Reference)?; }
    let width = if kind == 3 { 4 } else { 2 };
    let bytes = machine.statics.get_mut(at..at + width).ok_or(Error::Bounds)?;
    machine.heap.remember_static(at, bytes)?;
    match kind {
        // A byte field keeps only the low byte, so reading it back sign extends.
        KIND_BYTE => bytes.copy_from_slice(&(value as i8 as i16).to_be_bytes()),
        KIND_REF | KIND_SHORT => bytes.copy_from_slice(&(value as i16).to_be_bytes()),
        _ => bytes.copy_from_slice(&value.to_be_bytes()),
    }
    Ok(())
}

fn read_static(machine: &mut Machine<'_, '_, '_, impl Host>, frame: &mut Frame, at: usize, kind: u8) -> Result<()> {
    let width = if kind == 3 { 4 } else { 2 };
    let bytes = machine
        .statics
        .get(at..at + width)
        .ok_or(Error::Bounds)?;
    match kind {
        KIND_REF => frame.push_reference(u16::from_be_bytes([bytes[0], bytes[1]])),
        KIND_BYTE => frame.push_short(bytes[1] as i8 as i16),
        KIND_SHORT => frame.push_short(i16::from_be_bytes([bytes[0], bytes[1]])),
        _ => frame.push_int(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
    }
}

/// An array index is a signed short, and a negative one is out of bounds rather than a
/// large positive index.
fn bounded_index(index: i16, length: u16) -> Result<usize> {
    if index < 0 || index as u16 >= length {
        return Err(Error::ArrayBounds);
    }
    Ok(index as usize)
}

fn branch(code: &[u8], pc: usize, wide: bool) -> Result<usize> {
    let offset = if wide {
        word(code, pc + 1)? as i32
    } else {
        byte(code, pc + 1)? as i8 as i32
    };
    target(pc, offset, code.len())
}

fn target(pc: usize, offset: i32, length: usize) -> Result<usize> {
    let target = pc as i64 + offset as i64;
    if target < 0 || target as u64 >= length as u64 {
        return Err(Error::Bounds);
    }
    Ok(target as usize)
}

#[cfg(test)]
mod tests;
