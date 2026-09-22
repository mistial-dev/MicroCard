//! Direct interpreter for verified MC04 CIL method bodies.
use crate::{
    assembly::{Assembly, StackType},
    mc04_opcodes, Error, Result,
};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

const MAX_TRANSIENT_BYTES: usize = 16 * 1024;
const MAX_TRANSIENT_OBJECTS: usize = 256;
const MAX_ACTIVE_LOCALS: usize = 32 * 64;
const MAX_EVALUATION_STACK: usize = 256;
const MAX_CALL_FRAMES: usize = 32;
mod heap;
pub use heap::Heap;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExecutionMetrics {
    pub(crate) instructions: u32,
    pub(crate) peak_evaluation_slots: usize,
    pub(crate) peak_local_slots: usize,
    pub(crate) peak_frames: usize,
    pub(crate) peak_transient_bytes: usize,
    pub(crate) peak_transient_objects: usize,
    pub(crate) native_work_units: usize,
    pub(crate) transaction_snapshots: usize,
    pub(crate) transaction_clone_allocations: usize,
}

#[cfg(not(test))]
#[derive(Default)]
pub(crate) struct ExecutionMetrics {
    _private: (),
}

impl ExecutionMetrics {
    fn observe(&mut self, stack: usize, locals: usize, frames: usize, heap: &Heap) {
        #[cfg(test)]
        {
            self.peak_evaluation_slots = self.peak_evaluation_slots.max(stack);
            self.peak_local_slots = self.peak_local_slots.max(locals);
            self.peak_frames = self.peak_frames.max(frames);
            self.peak_transient_bytes = self.peak_transient_bytes.max(heap.used);
            self.peak_transient_objects = self.peak_transient_objects.max(heap.objects.len());
        }
        #[cfg(not(test))]
        let _ = (stack, locals, frames, heap);
    }

    fn instruction(&mut self) {
        #[cfg(test)]
        {
            self.instructions += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeValue {
    Int(i32),
    Ref(usize),
    Opaque(u16),
}

#[derive(Clone, Copy)]
pub struct Unit<'a> {
    pub name: &'a str,
    pub assembly: Assembly<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkedTarget {
    ObjectConstructor,
    CurrentDomain,
    DomainStorage,
    DomainKeys,
    Native(u8),
    Managed { unit: usize, method: u16 },
}

impl Zeroize for RuntimeValue {
    fn zeroize(&mut self) {
        *self = Self::Int(0);
    }
}

impl RuntimeValue {
    pub fn int(self) -> Result<i32> {
        match self {
            Self::Int(value) => Ok(value),
            Self::Ref(_) | Self::Opaque(_) => Err(Error::Format),
        }
    }
    fn truth(self) -> bool {
        match self {
            Self::Int(value) => value != 0,
            Self::Ref(value) => value != 0,
            Self::Opaque(_) => true,
        }
    }
}

struct Frame {
    unit: usize,
    method: u16,
    pc: usize,
    argument_base: usize,
    evaluation_base: usize,
    return_base: usize,
    returns: bool,
    local_base: usize,
    local_count: usize,
}

impl Zeroize for Frame {
    fn zeroize(&mut self) {
        self.unit.zeroize();
        self.method.zeroize();
        self.pc.zeroize();
        self.argument_base.zeroize();
        self.evaluation_base.zeroize();
        self.return_base.zeroize();
        self.returns.zeroize();
        self.local_base.zeroize();
        self.local_count.zeroize();
    }
}

fn default_value(kind: StackType) -> RuntimeValue {
    match kind {
        StackType::Int | StackType::Value(_) => RuntimeValue::Int(0),
        StackType::Ref(_) | StackType::Array(_) | StackType::Null => RuntimeValue::Ref(0),
    }
}

pub trait External {
    fn resolve(&self, unit: usize, member: u16) -> Result<LinkedTarget>;

    fn invoke(
        &mut self,
        unit: usize,
        member: u16,
        id: u8,
        arguments: &[RuntimeValue],
        heap: &mut Heap,
    ) -> Result<Option<RuntimeValue>>;
}

struct Standalone<'a> {
    assembly: &'a Assembly<'a>,
}

impl External for Standalone<'_> {
    fn resolve(&self, unit: usize, member: u16) -> Result<LinkedTarget> {
        if unit != 0 {
            return Err(Error::Bounds);
        }
        match crate::mc04_imports::resolve(self.assembly, member)? {
            Some(crate::mc04_imports::Import::ObjectConstructor) => {
                Ok(LinkedTarget::ObjectConstructor)
            }
            Some(_) => Err(Error::Unauthorized),
            None => Err(Error::Missing),
        }
    }

    fn invoke(
        &mut self,
        _: usize,
        _: u16,
        _: u8,
        _: &[RuntimeValue],
        _: &mut Heap,
    ) -> Result<Option<RuntimeValue>> {
        Err(Error::Unsupported)
    }
}

fn pop(stack: &mut Vec<RuntimeValue>, floor: usize) -> Result<RuntimeValue> {
    if stack.len() <= floor {
        return Err(Error::Stack);
    }
    let slot = stack.last_mut().ok_or(Error::Stack)?;
    let value = *slot;
    slot.zeroize();
    stack.pop();
    Ok(value)
}

fn branch_comparison(kind: u8, left: RuntimeValue, right: RuntimeValue) -> Result<bool> {
    match kind {
        3 => Ok(left == right),
        8 => Ok(left != right),
        4 => Ok(left.int()? >= right.int()?),
        5 => Ok(left.int()? > right.int()?),
        6 => Ok(left.int()? <= right.int()?),
        7 => Ok(left.int()? < right.int()?),
        9 => Ok((left.int()? as u32) >= right.int()? as u32),
        10 => Ok((left.int()? as u32) > right.int()? as u32),
        11 => Ok((left.int()? as u32) <= right.int()? as u32),
        12 => Ok((left.int()? as u32) < right.int()? as u32),
        _ => Err(Error::Unsupported),
    }
}

fn clear(stack: &mut Vec<RuntimeValue>, start: usize) {
    for value in &mut stack[start..] {
        value.zeroize();
    }
    stack.truncate(start);
}

fn i32_at(bytes: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Bounds)?
            .try_into()
            .unwrap(),
    ))
}

fn branch(next: usize, delta: i32) -> Result<usize> {
    let target = i64::try_from(next)
        .map_err(|_| Error::Bounds)?
        .checked_add(i64::from(delta))
        .ok_or(Error::Bounds)?;
    usize::try_from(target).map_err(|_| Error::Bounds)
}

fn instruction_width(code: &[u8], pc: usize, value: u16) -> Result<usize> {
    let opcode = mc04_opcodes::lookup(value).ok_or(Error::Unsupported)?;
    let width = if opcode.fixed_length != 0 {
        usize::from(opcode.fixed_length)
    } else {
        let count = usize::try_from(i32_at(code, pc + 1)?).map_err(|_| Error::Bounds)?;
        5usize
            .checked_add(count.checked_mul(4).ok_or(Error::Bounds)?)
            .ok_or(Error::Bounds)?
    };
    code.get(pc..pc.checked_add(width).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)?;
    Ok(width)
}

fn frame(
    units: &[Unit<'_>],
    unit: usize,
    method: u16,
    argument_base: usize,
    return_base: usize,
    locals: &mut Vec<RuntimeValue>,
    signature_types: &mut Vec<StackType>,
) -> Result<Frame> {
    let assembly = &units.get(unit).ok_or(Error::Bounds)?.assembly;
    let (receiver, result) = assembly.method_types_into(method, signature_types)?;
    let argument_count = signature_types.len() + usize::from(receiver.is_some());
    assembly.method_local_types_into(method, signature_types)?;
    let local_base = locals.len();
    if local_base
        .checked_add(signature_types.len())
        .is_none_or(|total| total > MAX_ACTIVE_LOCALS)
    {
        return Err(Error::Quota);
    }
    locals
        .try_reserve(signature_types.len())
        .map_err(|_| Error::Quota)?;
    locals.extend(signature_types.iter().copied().map(default_value));
    Ok(Frame {
        unit,
        method,
        pc: 0,
        argument_base,
        evaluation_base: argument_base + argument_count,
        return_base,
        returns: result.is_some(),
        local_base,
        local_count: locals.len() - local_base,
    })
}

fn local_index(frame: &Frame, index: usize) -> Result<usize> {
    if index >= frame.local_count {
        return Err(Error::Bounds);
    }
    frame.local_base.checked_add(index).ok_or(Error::Bounds)
}

/// Execute verified MC04 CIL without translating or copying its method bodies.
/// Framework/native MemberRefs and cross-assembly calls are resolved by the
/// domain executor; this core handles the managed profile instruction set.
pub(crate) fn execute_program_with_metrics_and_cancel(
    units: &[Unit<'_>],
    entry_unit: usize,
    entry: u16,
    arguments: &[i32],
    external: &mut impl External,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Result<(Option<i32>, ExecutionMetrics)> {
    let assembly = &units.get(entry_unit).ok_or(Error::Bounds)?.assembly;
    let mut signature_types = Vec::new();
    let (entry_receiver, _) = assembly.method_types_into(entry, &mut signature_types)?;
    if entry_receiver.is_some()
        || signature_types.len() != arguments.len()
        || signature_types.iter().any(|kind| *kind != StackType::Int)
    {
        return Err(Error::Format);
    }
    if arguments.len() > MAX_EVALUATION_STACK {
        return Err(Error::Quota);
    }
    // Reserve the verified stack bound before managed code runs. This makes every
    // instruction-loop push allocation-free, including the two temporary slots
    // used by object construction before the post-instruction quota check.
    let mut stack_values = Vec::new();
    stack_values
        .try_reserve_exact(MAX_EVALUATION_STACK + 2)
        .map_err(|_| Error::Quota)?;
    stack_values.extend(arguments.iter().copied().map(RuntimeValue::Int));
    let mut stack = Zeroizing::new(stack_values);
    let mut locals = Zeroizing::new(Vec::new());
    let first = frame(
        units,
        entry_unit,
        entry,
        0,
        0,
        &mut locals,
        &mut signature_types,
    )?;
    let mut frame_values = Vec::new();
    frame_values
        .try_reserve_exact(MAX_CALL_FRAMES)
        .map_err(|_| Error::Quota)?;
    frame_values.push(first);
    let mut frames = Zeroizing::new(frame_values);
    let mut arena = Zeroizing::new(Heap::new());
    let mut metrics = ExecutionMetrics::default();
    let mut fuel = 100_000u32;
    let mut cancel_poll_countdown = 0u8;
    loop {
        if cancel_poll_countdown == 0 {
            if should_cancel() {
                return Err(Error::Cancelled);
            }
            cancel_poll_countdown = 63;
        } else {
            cancel_poll_countdown -= 1;
        }
        metrics.observe(stack.len(), locals.len(), frames.len(), &arena);
        metrics.instruction();
        fuel = fuel.checked_sub(1).ok_or(Error::Budget)?;
        let current = frames.last_mut().ok_or(Error::Stack)?;
        let unit = current.unit;
        let assembly = &units[unit].assembly;
        let method = assembly.method(current.method)?;
        let pc = current.pc;
        let opcode = *method.code.get(pc).ok_or(Error::Bounds)?;
        let value = if opcode == 0xfe {
            0xfe00 | u16::from(*method.code.get(pc + 1).ok_or(Error::Bounds)?)
        } else {
            u16::from(opcode)
        };
        let width = instruction_width(method.code, pc, value)?;
        let next = pc.checked_add(width).ok_or(Error::Bounds)?;
        current.pc = next;
        let floor = current.evaluation_base;
        match opcode {
            0x00 => {}
            0x02..=0x05 => {
                let value = stack[current.argument_base + usize::from(opcode - 0x02)];
                stack.push(value);
            }
            0x06..=0x09 => {
                let index = local_index(current, usize::from(opcode - 0x06))?;
                stack.push(*locals.get(index).ok_or(Error::Bounds)?);
            }
            0x0a..=0x0d => {
                let index = local_index(current, usize::from(opcode - 0x0a))?;
                let value = pop(&mut stack, floor)?;
                let slot = locals.get_mut(index).ok_or(Error::Bounds)?;
                slot.zeroize();
                *slot = value;
            }
            0x0e => {
                let value = stack[current.argument_base + usize::from(method.code[pc + 1])];
                stack.push(value);
            }
            0x11 => {
                let index = local_index(current, usize::from(method.code[pc + 1]))?;
                stack.push(*locals.get(index).ok_or(Error::Bounds)?);
            }
            0x13 => {
                let index = local_index(current, usize::from(method.code[pc + 1]))?;
                let value = pop(&mut stack, floor)?;
                let slot = locals.get_mut(index).ok_or(Error::Bounds)?;
                slot.zeroize();
                *slot = value;
            }
            0x14 => stack.push(RuntimeValue::Ref(0)),
            0x15..=0x1e => stack.push(RuntimeValue::Int(i32::from(opcode) - 0x16)),
            0x1f => stack.push(RuntimeValue::Int(i32::from(method.code[pc + 1] as i8))),
            0x20 => stack.push(RuntimeValue::Int(i32_at(method.code, pc + 1)?)),
            0x25 => {
                let value = *stack.last().ok_or(Error::Stack)?;
                stack.push(value);
            }
            0x26 => {
                pop(&mut stack, floor)?;
            }
            0x28 | 0x6f => {
                if method.code[pc + 1] == 10 {
                    let index = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                    let (call_receiver, call_result) =
                        assembly.member_types_into(index, &mut signature_types)?;
                    let parameters_empty = signature_types.is_empty();
                    let count = signature_types.len() + usize::from(call_receiver.is_some());
                    let start = stack.len().checked_sub(count).ok_or(Error::Stack)?;
                    if start < floor {
                        return Err(Error::Stack);
                    }
                    let result = match external.resolve(unit, index)? {
                        LinkedTarget::ObjectConstructor
                            if call_receiver.is_some()
                                && parameters_empty
                                && call_result.is_none() =>
                        {
                            None
                        }
                        LinkedTarget::CurrentDomain if stack[start..].is_empty() => {
                            Some(RuntimeValue::Opaque(1))
                        }
                        LinkedTarget::DomainStorage
                            if stack[start..] == [RuntimeValue::Opaque(1)] =>
                        {
                            Some(RuntimeValue::Opaque(3))
                        }
                        LinkedTarget::DomainKeys if stack[start..] == [RuntimeValue::Opaque(1)] => {
                            Some(RuntimeValue::Opaque(2))
                        }
                        LinkedTarget::Native(id) => {
                            external.invoke(unit, index, id, &stack[start..], &mut arena)?
                        }
                        LinkedTarget::Managed {
                            unit: target_unit,
                            method: target_method,
                        } => {
                            if frames.len() >= MAX_CALL_FRAMES {
                                return Err(Error::Quota);
                            }
                            let (target_receiver, target_result) = units[target_unit]
                                .assembly
                                .method_types_into(target_method, &mut signature_types)?;
                            if signature_types.len() + usize::from(target_receiver.is_some())
                                != count
                                || target_result.is_some() != call_result.is_some()
                            {
                                return Err(Error::Format);
                            }
                            frames.push(frame(
                                units,
                                target_unit,
                                target_method,
                                start,
                                start,
                                &mut locals,
                                &mut signature_types,
                            )?);
                            continue;
                        }
                        _ => return Err(Error::Format),
                    };
                    clear(&mut stack, start);
                    if result.is_some() != call_result.is_some() {
                        return Err(Error::Native);
                    }
                    if let Some(result) = result {
                        stack.push(result);
                    }
                    continue;
                }
                if method.code[pc + 1] != 6 {
                    return Err(Error::Unsupported);
                }
                let target = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                let target = target.checked_sub(1).ok_or(Error::Bounds)?;
                let (target_receiver, _) =
                    assembly.method_types_into(target, &mut signature_types)?;
                if (opcode == 0x6f) != target_receiver.is_some() {
                    return Err(Error::Format);
                }
                let count = signature_types.len() + usize::from(target_receiver.is_some());
                let base = stack.len().checked_sub(count).ok_or(Error::Stack)?;
                if base < floor || frames.len() >= MAX_CALL_FRAMES {
                    return Err(Error::Quota);
                }
                frames.push(frame(
                    units,
                    unit,
                    target,
                    base,
                    base,
                    &mut locals,
                    &mut signature_types,
                )?);
            }
            0x73 => {
                if method.code[pc + 1] != 6 {
                    return Err(Error::Unsupported);
                }
                let target = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                let index = target.checked_sub(1).ok_or(Error::Bounds)?;
                let (constructor_receiver, constructor_result) =
                    assembly.method_types_into(index, &mut signature_types)?;
                if constructor_receiver.is_none() || constructor_result.is_some() {
                    return Err(Error::Format);
                }
                let base = stack
                    .len()
                    .checked_sub(signature_types.len())
                    .ok_or(Error::Stack)?;
                if base < floor || frames.len() >= MAX_CALL_FRAMES {
                    return Err(Error::Quota);
                }
                let owner = assembly.method_owner(index)?;
                let object = arena.allocate_struct(
                    unit,
                    owner,
                    usize::from(assembly.type_field_count(owner)?),
                )?;
                stack.insert(base, object);
                stack.insert(base + 1, object);
                frames.push(frame(
                    units,
                    unit,
                    index,
                    base + 1,
                    base + 1,
                    &mut locals,
                    &mut signature_types,
                )?);
            }
            0x7b => {
                if method.code[pc + 1] != 4 {
                    return Err(Error::Format);
                }
                let field = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                let (owner, offset) = assembly.field_layout(field)?;
                let object = pop(&mut stack, floor)?;
                stack.push(arena.field_get(object, unit, owner, offset)?);
            }
            0x7d => {
                if method.code[pc + 1] != 4 {
                    return Err(Error::Format);
                }
                let field = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                let (owner, offset) = assembly.field_layout(field)?;
                let value = pop(&mut stack, floor)?;
                let object = pop(&mut stack, floor)?;
                arena.field_set(object, unit, owner, offset, value)?;
            }
            0x2a => {
                let result = if current.returns {
                    Some(pop(&mut stack, floor)?)
                } else {
                    None
                };
                if stack.len() != floor {
                    return Err(Error::Stack);
                }
                let return_base = current.return_base;
                let local_base = current.local_base;
                clear(&mut stack, return_base);
                clear(&mut locals, local_base);
                frames.pop();
                if frames.is_empty() {
                    return Ok((result.map(RuntimeValue::int).transpose()?, metrics));
                }
                if let Some(value) = result {
                    stack.push(value);
                }
            }
            0x2b..=0x44 => {
                let short = opcode <= 0x37;
                let delta = if short {
                    i32::from(method.code[pc + 1] as i8)
                } else {
                    i32_at(method.code, pc + 1)?
                };
                let kind = if short { opcode - 0x2b } else { opcode - 0x38 };
                let take = match kind {
                    0 => true,
                    1 => !pop(&mut stack, floor)?.truth(),
                    2 => pop(&mut stack, floor)?.truth(),
                    3..=12 => {
                        let right = pop(&mut stack, floor)?;
                        let left = pop(&mut stack, floor)?;
                        branch_comparison(kind, left, right)?
                    }
                    _ => return Err(Error::Unsupported),
                };
                if take {
                    current.pc = branch(next, delta)?;
                }
            }
            0x45 => {
                let index = pop(&mut stack, floor)?.int()?;
                let count =
                    usize::try_from(i32_at(method.code, pc + 1)?).map_err(|_| Error::Bounds)?;
                if let Ok(index) = usize::try_from(index) {
                    if index < count {
                        current.pc = branch(next, i32_at(method.code, pc + 5 + index * 4)?)?;
                    }
                }
            }
            0x58..=0x64 | 0xd6..=0xdb => {
                let right = pop(&mut stack, floor)?.int()?;
                let left = pop(&mut stack, floor)?.int()?;
                let value = match opcode {
                    0x58 => left.wrapping_add(right),
                    0x59 => left.wrapping_sub(right),
                    0x5a => left.wrapping_mul(right),
                    0x5b => left.checked_div(right).ok_or(Error::Arithmetic)?,
                    0x5c => {
                        ((left as u32)
                            .checked_div(right as u32)
                            .ok_or(Error::Arithmetic)?) as i32
                    }
                    0x5d => left.checked_rem(right).ok_or(Error::Arithmetic)?,
                    0x5e => {
                        ((left as u32)
                            .checked_rem(right as u32)
                            .ok_or(Error::Arithmetic)?) as i32
                    }
                    0x5f => left & right,
                    0x60 => left | right,
                    0x61 => left ^ right,
                    0x62 => left.wrapping_shl(right as u32 & 31),
                    0x63 => left.wrapping_shr(right as u32 & 31),
                    0x64 => ((left as u32) >> (right as u32 & 31)) as i32,
                    0xd6 => left.checked_add(right).ok_or(Error::Arithmetic)?,
                    0xd7 => (left as u32)
                        .checked_add(right as u32)
                        .map(|v| v as i32)
                        .ok_or(Error::Arithmetic)?,
                    0xd8 => left.checked_mul(right).ok_or(Error::Arithmetic)?,
                    0xd9 => (left as u32)
                        .checked_mul(right as u32)
                        .map(|v| v as i32)
                        .ok_or(Error::Arithmetic)?,
                    0xda => left.checked_sub(right).ok_or(Error::Arithmetic)?,
                    0xdb => (left as u32)
                        .checked_sub(right as u32)
                        .map(|v| v as i32)
                        .ok_or(Error::Arithmetic)?,
                    _ => return Err(Error::Unsupported),
                };
                stack.push(RuntimeValue::Int(value));
            }
            0x65 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v.wrapping_neg()));
            }
            0x66 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(!v));
            }
            0x67 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v as i8 as i32));
            }
            0x68 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v as i16 as i32));
            }
            0x69 | 0x6d => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v));
            }
            0x82..=0x84 | 0x86..=0x88 | 0xb3..=0xb8 => {
                let value = pop(&mut stack, floor)?.int()?;
                let converted = match opcode {
                    0x82 => i8::try_from(value as u32)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0x83 => i16::try_from(value as u32)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0x84 | 0x88 | 0xb7 => value,
                    0x86 => u8::try_from(value as u32)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0x87 => u16::try_from(value as u32)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0xb3 => i8::try_from(value)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0xb4 => u8::try_from(value)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0xb5 => i16::try_from(value)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0xb6 => u16::try_from(value)
                        .map(i32::from)
                        .map_err(|_| Error::Arithmetic)?,
                    0xb8 => u32::try_from(value)
                        .map(|v| v as i32)
                        .map_err(|_| Error::Arithmetic)?,
                    _ => return Err(Error::Unsupported),
                };
                stack.push(RuntimeValue::Int(converted));
            }
            0xd1 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v as u16 as i32));
            }
            0xd2 => {
                let v = pop(&mut stack, floor)?.int()?;
                stack.push(RuntimeValue::Int(v as u8 as i32));
            }
            0x8d => {
                let length =
                    usize::try_from(pop(&mut stack, floor)?.int()?).map_err(|_| Error::Bounds)?;
                let table = method.code[pc + 1];
                let row = u16::from_le_bytes([method.code[pc + 2], method.code[pc + 3]]);
                if table != 1 {
                    return Err(Error::Unsupported);
                }
                let kind = assembly.type_ref(row)?;
                let bytes = kind.namespace == "System" && kind.name == "Byte";
                if !(bytes || kind.namespace == "System" && kind.name == "Int32") {
                    return Err(Error::Unsupported);
                }
                stack.push(arena.allocate(bytes, length)?);
            }
            0x8e => {
                let length = arena.array_length(pop(&mut stack, floor)?)?;
                stack.push(RuntimeValue::Int(
                    i32::try_from(length).map_err(|_| Error::Quota)?,
                ));
            }
            0x91 | 0x94 => {
                let index =
                    usize::try_from(pop(&mut stack, floor)?.int()?).map_err(|_| Error::Bounds)?;
                let array = pop(&mut stack, floor)?;
                let value = arena.array_get(array, index, opcode == 0x91)?;
                stack.push(RuntimeValue::Int(value));
            }
            0x9c | 0x9e => {
                let value = pop(&mut stack, floor)?.int()?;
                let index =
                    usize::try_from(pop(&mut stack, floor)?.int()?).map_err(|_| Error::Bounds)?;
                let array = pop(&mut stack, floor)?;
                arena.array_set(array, index, opcode == 0x9c, value)?;
            }
            0xfe => {
                let right = pop(&mut stack, floor)?;
                let left = pop(&mut stack, floor)?;
                let result = match value {
                    0xfe01 => left == right,
                    0xfe02 => left.int()? > right.int()?,
                    0xfe03 => (left.int()? as u32) > right.int()? as u32,
                    0xfe04 => left.int()? < right.int()?,
                    0xfe05 => (left.int()? as u32) < right.int()? as u32,
                    _ => return Err(Error::Unsupported),
                };
                stack.push(RuntimeValue::Int(i32::from(result)));
            }
            _ => return Err(Error::Unsupported),
        }
        if stack.len() > MAX_EVALUATION_STACK {
            return Err(Error::Quota);
        }
    }
}

pub(crate) fn execute_program_with_metrics(
    units: &[Unit<'_>],
    entry_unit: usize,
    entry: u16,
    arguments: &[i32],
    external: &mut impl External,
) -> Result<(Option<i32>, ExecutionMetrics)> {
    execute_program_with_metrics_and_cancel(
        units,
        entry_unit,
        entry,
        arguments,
        external,
        &mut || false,
    )
}

pub fn execute_program_with(
    units: &[Unit<'_>],
    entry_unit: usize,
    entry: u16,
    arguments: &[i32],
    external: &mut impl External,
) -> Result<Option<i32>> {
    execute_program_with_metrics(units, entry_unit, entry, arguments, external)
        .map(|(result, _)| result)
}

pub fn execute(assembly: &Assembly<'_>, entry: u16, arguments: &[i32]) -> Result<Option<i32>> {
    execute_with(assembly, entry, arguments, &mut Standalone { assembly })
}

pub fn execute_with(
    assembly: &Assembly<'_>,
    entry: u16,
    arguments: &[i32],
    external: &mut impl External,
) -> Result<Option<i32>> {
    let identity = assembly.identity()?;
    execute_program_with(
        &[Unit {
            name: identity.name,
            assembly: *assembly,
        }],
        0,
        entry,
        arguments,
        external,
    )
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn equality_branches_accept_references_but_ordering_does_not() {
        assert_eq!(
            branch_comparison(3, RuntimeValue::Ref(1), RuntimeValue::Ref(1)),
            Ok(true)
        );
        assert_eq!(
            branch_comparison(8, RuntimeValue::Ref(1), RuntimeValue::Ref(2)),
            Ok(true)
        );
        assert_eq!(
            branch_comparison(3, RuntimeValue::Ref(1), RuntimeValue::Ref(2)),
            Ok(false)
        );
        assert_eq!(
            branch_comparison(4, RuntimeValue::Ref(1), RuntimeValue::Ref(2)),
            Err(Error::Format)
        );
        assert_eq!(
            branch_comparison(9, RuntimeValue::Int(-1), RuntimeValue::Int(1)),
            Ok(true)
        );
    }

    #[test]
    fn cancellation_is_checked_before_execution() {
        let assembly =
            Assembly::parse(include_bytes!("../../../fuzz/fixtures/counter.mca")).unwrap();
        let identity = assembly.identity().unwrap();
        let units = [Unit {
            name: identity.name,
            assembly,
        }];
        let mut external = Standalone {
            assembly: &assembly,
        };
        let mut polls = 0;
        let result =
            execute_program_with_metrics_and_cancel(&units, 0, 1, &[], &mut external, &mut || {
                polls += 1;
                true
            });
        assert_eq!(result, Err(Error::Cancelled));
        assert_eq!(polls, 1);
    }

    #[test]
    fn invocation_state_zeroizes() {
        let mut value = RuntimeValue::Ref(7);
        value.zeroize();
        assert_eq!(value, RuntimeValue::Int(0));

        let mut heap = Heap::new();
        let retired = heap.allocate_bytes(vec![0x5a; 32]).unwrap();
        heap.zeroize();
        assert!(heap.objects.is_empty());
        assert_eq!(heap.used, 0);
        heap.allocate_bytes(vec![0x11; 32]).unwrap();
        assert!(matches!(heap.bytes(retired), Err(Error::Bounds)));

        let mut frame = Frame {
            unit: 1,
            method: 2,
            pc: 3,
            argument_base: 4,
            evaluation_base: 5,
            return_base: 6,
            returns: true,
            local_base: 7,
            local_count: 8,
        };
        frame.zeroize();
        assert_eq!(
            (
                frame.unit,
                frame.method,
                frame.pc,
                frame.argument_base,
                frame.evaluation_base,
                frame.return_base,
                frame.returns,
                frame.local_base,
                frame.local_count,
            ),
            (0, 0, 0, 0, 0, 0, false, 0, 0)
        );
    }

    #[test]
    fn transient_object_count_is_bounded_without_failed_reservation_drift() {
        let mut heap = Heap::new();
        // Quota rejection must precede backing allocations and leave the heap unchanged.
        for length in [MAX_TRANSIENT_BYTES, usize::MAX] {
            assert_eq!(heap.allocate(true, length), Err(Error::Quota));
            assert_eq!(heap.allocate(false, length), Err(Error::Quota));
            assert_eq!(heap.allocate_struct(0, 0, length), Err(Error::Quota));
            assert_eq!(heap.objects.capacity(), 0);
            assert_eq!(heap.used, 0);
        }
        for _ in 0..MAX_TRANSIENT_OBJECTS {
            heap.allocate(true, 0).unwrap();
        }
        assert_eq!(heap.objects.len(), MAX_TRANSIENT_OBJECTS);
        assert_eq!(heap.used, MAX_TRANSIENT_OBJECTS * 8);
        assert_eq!(heap.allocate(true, 0), Err(Error::Quota));
        assert_eq!(heap.objects.len(), MAX_TRANSIENT_OBJECTS);
        assert_eq!(heap.used, MAX_TRANSIENT_OBJECTS * 8);
    }

    #[test]
    fn sealed_object_fields_use_platform_independent_arena_charges() {
        let mut heap = Heap::new();
        let object = heap.allocate_struct(1, 2, 3).unwrap();
        assert_eq!(heap.used, 8 + 3 * 4);
        heap.field_set(object, 1, 2, 2, RuntimeValue::Int(i32::MIN)).unwrap();
        assert_eq!(heap.field_get(object, 1, 2, 2), Ok(RuntimeValue::Int(i32::MIN)));
        assert_eq!(heap.field_get(object, 0, 2, 2), Err(Error::Format));
        assert_eq!(heap.field_get(object, 1, 3, 2), Err(Error::Format));
        assert_eq!(heap.field_get(object, 1, 2, 3), Err(Error::Bounds));
        assert_eq!(heap.bytes(object), Err(Error::Format));
    }

    #[test]
    fn handles_survive_slab_growth_and_native_byte_results() {
        let mut heap = Heap::new();
        let value = heap.allocate_bytes(vec![0x5a; 31]).unwrap();
        assert_eq!(heap.used, 40); // Odd byte payloads include one alignment byte.
        let integers = heap.allocate(false, 128).unwrap();
        heap.array_set(integers, 127, false, i32::MIN).unwrap();
        assert_eq!(heap.array_get(integers, 127, false), Ok(i32::MIN));
        assert_eq!(heap.array_get(integers, 128, false), Err(Error::Bounds));
        assert_eq!(heap.array_get(integers, 0, true), Err(Error::Format));
        assert_eq!(heap.bytes(value).unwrap(), &[0x5a; 31]);
    }

    #[test]
    fn shared_local_storage_is_bounded_without_failed_growth() {
        let assembly =
            Assembly::parse(include_bytes!("../../../fuzz/fixtures/counter.mca")).unwrap();
        let method = (0..assembly
            .row_count(crate::mc04_schema::TABLE_METHODDEF)
            .unwrap())
            .find(|method| !assembly.method_local_types(*method).unwrap().is_empty())
            .unwrap();
        let units = [Unit {
            name: "Counter",
            assembly,
        }];
        let mut locals = vec![RuntimeValue::Opaque(7); MAX_ACTIVE_LOCALS];
        let mut signature_types = Vec::new();
        assert!(matches!(
            frame(
                &units,
                0,
                method,
                0,
                0,
                &mut locals,
                &mut signature_types,
            ),
            Err(Error::Quota)
        ));
        assert_eq!(locals.len(), MAX_ACTIVE_LOCALS);

        let count = assembly.method_local_types(method).unwrap().len();
        locals.truncate(MAX_ACTIVE_LOCALS - count);
        let created = frame(
            &units,
            0,
            method,
            0,
            0,
            &mut locals,
            &mut signature_types,
        )
        .unwrap();
        assert_eq!(created.local_base, MAX_ACTIVE_LOCALS - count);
        assert_eq!(created.local_count, count);
        assert_eq!(locals.len(), MAX_ACTIVE_LOCALS);
    }
}
