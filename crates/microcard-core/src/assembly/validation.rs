use super::*;

pub(super) fn instruction_end(code: &[u8], start: usize, rows: &[u16; 64]) -> Result<usize> {
    let first = *code.get(start).ok_or(Error::Bounds)?;
    let (value, mut cursor) = if first == 0xfe {
        (
            0xfe00 | u16::from(*code.get(start + 1).ok_or(Error::Bounds)?),
            start + 2,
        )
    } else {
        (u16::from(first), start + 1)
    };
    let opcode = opcodes::lookup(value).ok_or(Error::Unsupported)?;
    use opcodes::Operand;
    match opcode.operand {
        Operand::SwitchI32 => {
            let count = u32_at(code, cursor)? as usize;
            if count > 256 {
                return Err(Error::Quota);
            }
            cursor = cursor
                .checked_add(4)
                .and_then(|value| value.checked_add(count.checked_mul(4)?))
                .ok_or(Error::Quota)?;
        }
        Operand::MethodToken | Operand::FieldToken | Operand::TypeToken => {
            let table = *code.get(cursor).ok_or(Error::Bounds)?;
            let row = u16_at(code, cursor + 1)?;
            if table >= 16
                || opcode.token_tables & (1u16 << table) == 0
                || row == 0
                || row > rows[table as usize]
            {
                return Err(Error::Bounds);
            }
            cursor = cursor.checked_add(3).ok_or(Error::Quota)?;
        }
        _ => {
            cursor = start
                .checked_add(usize::from(opcode.fixed_length))
                .ok_or(Error::Quota)?
        }
    }
    if cursor > code.len() {
        return Err(Error::Bounds);
    }
    Ok(cursor)
}

pub(super) fn branch_target(base: usize, delta: i32, code_length: usize) -> Result<usize> {
    let target = i64::try_from(base)
        .map_err(|_| Error::Quota)?
        .checked_add(i64::from(delta))
        .ok_or(Error::Quota)?;
    if target < 0 || target >= i64::try_from(code_length).map_err(|_| Error::Quota)? {
        return Err(Error::Bounds);
    }
    usize::try_from(target).map_err(|_| Error::Bounds)
}

pub(super) fn is_instruction_start(code: &[u8], target: usize, rows: &[u16; 64]) -> Result<bool> {
    let mut cursor = 0;
    while cursor < target {
        cursor = instruction_end(code, cursor, rows)?;
    }
    Ok(cursor == target)
}

#[derive(Clone, Copy)]
pub(super) struct MethodShape {
    pub(super) has_this: bool,
    pub(super) parameters: u16,
    pub(super) returns: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackType {
    Int,
    Value(u32),
    Ref(u32),
    Array(u32),
    Null,
}

impl StackType {
    fn reference(self) -> bool {
        matches!(self, Self::Ref(_) | Self::Array(_) | Self::Null)
    }
}

pub struct MethodTypes {
    pub receiver: Option<StackType>,
    pub parameters: Vec<StackType>,
    pub result: Option<StackType>,
}

pub(super) fn named_type<'a>(
    assembly: &'a Assembly<'a>,
    token: u32,
) -> Result<(&'a str, &'a str, &'a str, [u16; 4])> {
    let table = (token >> 16) as u8;
    let row = token as u16;
    match table {
        schema::TABLE_TYPEDEF => {
            let ty = assembly.type_def(row)?;
            let owner = assembly.identity()?;
            Ok((ty.namespace, ty.name, owner.name, owner.version))
        }
        schema::TABLE_TYPEREF => {
            let ty = assembly.type_ref(row)?;
            let owner = match ty.scope.table {
                schema::TABLE_MODULE => assembly.identity()?,
                schema::TABLE_ASSEMBLYREF => assembly.assembly_ref(ty.scope.row)?,
                schema::TABLE_TYPEREF => {
                    let (_, _, name, version) = named_type(
                        assembly,
                        (u32::from(schema::TABLE_TYPEREF) << 16) | u32::from(ty.scope.row),
                    )?;
                    return Ok((ty.namespace, ty.name, name, version));
                }
                _ => return Err(Error::Unsupported),
            };
            Ok((ty.namespace, ty.name, owner.name, owner.version))
        }
        _ => Err(Error::Bounds),
    }
}

pub(super) fn same_stack_type(
    left_assembly: &Assembly<'_>,
    left: StackType,
    right_assembly: &Assembly<'_>,
    right: StackType,
) -> Result<bool> {
    Ok(match (left, right) {
        (StackType::Int, StackType::Int) | (StackType::Null, StackType::Null) => true,
        (StackType::Array(left), StackType::Array(right)) => left == right,
        (StackType::Ref(0), StackType::Ref(0)) => true,
        (StackType::Ref(left), StackType::Ref(right))
        | (StackType::Value(left), StackType::Value(right)) => {
            named_type(left_assembly, left)? == named_type(right_assembly, right)?
        }
        _ => false,
    })
}

pub(super) fn same_method_types(
    left_assembly: &Assembly<'_>,
    left: &MethodTypes,
    right_assembly: &Assembly<'_>,
    right: &MethodTypes,
) -> Result<bool> {
    if left.parameters.len() != right.parameters.len()
        || left.receiver.is_some() != right.receiver.is_some()
        || left.result.is_some() != right.result.is_some()
    {
        return Ok(false);
    }
    if let (Some(left), Some(right)) = (left.receiver, right.receiver) {
        if !same_stack_type(left_assembly, left, right_assembly, right)? {
            return Ok(false);
        }
    }
    if let (Some(left), Some(right)) = (left.result, right.result) {
        if !same_stack_type(left_assembly, left, right_assembly, right)? {
            return Ok(false);
        }
    }
    for (left, right) in left
        .parameters
        .iter()
        .copied()
        .zip(right.parameters.iter().copied())
    {
        if !same_stack_type(left_assembly, left, right_assembly, right)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn method_shape(bytes: &[u8], rows: &[u16; 64]) -> Result<MethodShape> {
    let mut signature = Signature { bytes, offset: 0 };
    let calling = signature.byte()?;
    if calling != 0 && calling != 0x20 {
        return Err(Error::Format);
    }
    let parameters = u16::try_from(signature.compressed()?).map_err(|_| Error::Quota)?;
    let returns = bytes.get(signature.offset) != Some(&0x01);
    signature.value_type(rows, true, 0)?;
    for _ in 0..parameters {
        signature.value_type(rows, false, 0)?;
    }
    if signature.offset != bytes.len() {
        return Err(Error::Format);
    }
    Ok(MethodShape {
        has_this: calling == 0x20,
        parameters,
        returns,
    })
}

pub(super) fn local_count(bytes: &[u8]) -> Result<u16> {
    let mut signature = Signature { bytes, offset: 0 };
    if signature.byte()? != 0x07 {
        return Err(Error::Format);
    }
    u16::try_from(signature.compressed()?).map_err(|_| Error::Quota)
}

pub(super) fn local_types_into(
    bytes: &[u8],
    rows: &[u16; 64],
    types: &mut Vec<StackType>,
) -> Result<()> {
    types.clear();
    let mut signature = Signature { bytes, offset: 0 };
    if signature.byte()? != 0x07 {
        return Err(Error::Format);
    }
    let count = usize::try_from(signature.compressed()?).map_err(|_| Error::Quota)?;
    if count > 64 {
        return Err(Error::Quota);
    }
    types.try_reserve_exact(count).map_err(|_| Error::Quota)?;
    for _ in 0..count {
        types.push(signature.stack_type(rows, false, 0)?.ok_or(Error::Format)?);
    }
    if signature.offset != bytes.len() {
        return Err(Error::Format);
    }
    Ok(())
}

pub(super) fn referenced_method_shape(
    assembly: &Assembly<'_>,
    table: u8,
    index: u16,
) -> Result<MethodShape> {
    let mut row = Row::new(assembly.row(table, index)?);
    match table {
        schema::TABLE_METHODDEF => {
            row.u32()?;
            row.u16()?;
            row.u16()?;
            row.index(assembly.string_width)?;
        }
        schema::TABLE_MEMBERREF => {
            row.u16()?;
            row.index(assembly.string_width)?;
        }
        _ => return Err(Error::Bounds),
    }
    let offset = row.index(assembly.blob_width)?;
    if !row.finished() {
        return Err(Error::Format);
    }
    method_shape(
        blob_at(assembly.section(schema::SECTION_BLOB)?, offset)?,
        &assembly.rows,
    )
}

pub(super) fn type_lists(assembly: &Assembly<'_>, index: u16) -> Result<(u16, u16)> {
    let mut row = Row::new(assembly.row(schema::TABLE_TYPEDEF, index)?);
    row.u32()?;
    row.index(assembly.string_width)?;
    row.index(assembly.string_width)?;
    row.u16()?;
    let fields = row.index(if assembly.rows[schema::TABLE_FIELD as usize] <= 255 {
        1
    } else {
        2
    })?;
    let methods = row.index(if assembly.rows[schema::TABLE_METHODDEF as usize] <= 255 {
        1
    } else {
        2
    })?;
    if !row.finished() {
        return Err(Error::Format);
    }
    Ok((fields, methods))
}

pub(super) fn list_owner(assembly: &Assembly<'_>, table: u8, target: u16) -> Result<u16> {
    let types = assembly.rows[schema::TABLE_TYPEDEF as usize];
    let total = assembly.rows[table as usize];
    for index in 1..=types {
        let lists = type_lists(assembly, index)?;
        let start = if table == schema::TABLE_FIELD {
            lists.0
        } else {
            lists.1
        };
        let end = if index == types {
            total + 1
        } else {
            let next = type_lists(assembly, index + 1)?;
            if table == schema::TABLE_FIELD {
                next.0
            } else {
                next.1
            }
        };
        if target >= start && target < end {
            return Ok(index);
        }
    }
    Err(Error::Bounds)
}

pub(super) fn metadata_type(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<StackType> {
    if table == schema::TABLE_TYPEDEF {
        return Ok(StackType::Ref(
            (u32::from(schema::TABLE_TYPEDEF) << 16) | u32::from(index),
        ));
    }
    if table != schema::TABLE_TYPEREF {
        return Err(Error::Bounds);
    }
    let mut row = Row::new(assembly.row(table, index)?);
    row.u16()?;
    let name = row.index(assembly.string_width)?;
    let namespace = row.index(assembly.string_width)?;
    if !row.finished() {
        return Err(Error::Format);
    }
    let strings = assembly.section(schema::SECTION_STRINGS)?;
    if string_at(strings, name)? == "Object" && string_at(strings, namespace)? == "System" {
        Ok(StackType::Ref(0))
    } else {
        Ok(StackType::Ref(
            (u32::from(schema::TABLE_TYPEREF) << 16) | u32::from(index),
        ))
    }
}

pub(super) fn method_receiver(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<StackType> {
    match table {
        schema::TABLE_METHODDEF => metadata_type(
            assembly,
            schema::TABLE_TYPEDEF,
            list_owner(assembly, schema::TABLE_METHODDEF, index)?,
        ),
        schema::TABLE_MEMBERREF => {
            let mut row = Row::new(assembly.row(table, index)?);
            let parent = row.u16()?;
            let tag = parent & 7;
            let owner = parent >> 3;
            match tag {
                0 => metadata_type(assembly, schema::TABLE_TYPEDEF, owner),
                1 => metadata_type(assembly, schema::TABLE_TYPEREF, owner),
                3 => method_receiver(assembly, schema::TABLE_METHODDEF, owner),
                _ => Err(Error::Unsupported),
            }
        }
        _ => Err(Error::Bounds),
    }
}

pub(super) fn referenced_method_types(
    assembly: &Assembly<'_>,
    table: u8,
    index: u16,
) -> Result<MethodTypes> {
    let mut parameters = Vec::new();
    let (receiver, result) = referenced_method_types_into(assembly, table, index, &mut parameters)?;
    Ok(MethodTypes {
        receiver,
        parameters,
        result,
    })
}

pub(super) fn referenced_method_types_into(
    assembly: &Assembly<'_>,
    table: u8,
    index: u16,
    parameters: &mut Vec<StackType>,
) -> Result<(Option<StackType>, Option<StackType>)> {
    parameters.clear();
    let mut row = Row::new(assembly.row(table, index)?);
    match table {
        schema::TABLE_METHODDEF => {
            row.u32()?;
            row.u16()?;
            row.u16()?;
            row.index(assembly.string_width)?;
        }
        schema::TABLE_MEMBERREF => {
            row.u16()?;
            row.index(assembly.string_width)?;
        }
        _ => return Err(Error::Bounds),
    }
    let offset = row.index(assembly.blob_width)?;
    let bytes = blob_at(assembly.section(schema::SECTION_BLOB)?, offset)?;
    let mut signature = Signature { bytes, offset: 0 };
    let calling = signature.byte()?;
    if calling != 0 && calling != 0x20 {
        return Err(Error::Format);
    }
    let count = usize::try_from(signature.compressed()?).map_err(|_| Error::Quota)?;
    if count > 32 {
        return Err(Error::Quota);
    }
    let result = signature.stack_type(&assembly.rows, true, 0)?;
    parameters
        .try_reserve_exact(count)
        .map_err(|_| Error::Quota)?;
    for _ in 0..count {
        parameters.push(
            signature
                .stack_type(&assembly.rows, false, 0)?
                .ok_or(Error::Format)?,
        );
    }
    if signature.offset != bytes.len() {
        return Err(Error::Format);
    }
    Ok((
        if calling == 0x20 {
            Some(method_receiver(assembly, table, index)?)
        } else {
            None
        },
        result,
    ))
}

pub(super) fn field_type(assembly: &Assembly<'_>, index: u16) -> Result<(StackType, StackType)> {
    let owner = metadata_type(
        assembly,
        schema::TABLE_TYPEDEF,
        list_owner(assembly, schema::TABLE_FIELD, index)?,
    )?;
    let mut row = Row::new(assembly.row(schema::TABLE_FIELD, index)?);
    row.u16()?;
    row.index(assembly.string_width)?;
    let offset = row.index(assembly.blob_width)?;
    let bytes = blob_at(assembly.section(schema::SECTION_BLOB)?, offset)?;
    let mut signature = Signature { bytes, offset: 0 };
    if signature.byte()? != 0x06 {
        return Err(Error::Format);
    }
    let value = signature
        .stack_type(&assembly.rows, false, 0)?
        .ok_or(Error::Format)?;
    if signature.offset != bytes.len() {
        return Err(Error::Format);
    }
    Ok((owner, value))
}

pub(super) fn merge_height(
    states: &mut [u16],
    pending: &mut Vec<usize>,
    target: usize,
    height: u16,
) -> Result<()> {
    let state = states.get_mut(target).ok_or(Error::Bounds)?;
    if *state == u16::MAX {
        *state = height;
        pending.push(target);
    } else if *state != height {
        return Err(Error::Format);
    }
    Ok(())
}

pub(super) fn validate_cil(code: &[u8], rows: &[u16; 64]) -> Result<()> {
    let mut cursor = 0;
    while cursor < code.len() {
        cursor = instruction_end(code, cursor, rows)?;
    }
    if cursor != code.len() {
        return Err(Error::Bounds);
    }
    let mut branches = 0usize;
    cursor = 0;
    while cursor < code.len() {
        let start = cursor;
        let first = code[start];
        let (value, operand_start) = if first == 0xfe {
            (0xfe00 | u16::from(code[start + 1]), start + 2)
        } else {
            (u16::from(first), start + 1)
        };
        let operand = opcodes::lookup(value).ok_or(Error::Unsupported)?.operand;
        let end = instruction_end(code, start, rows)?;
        use opcodes::Operand;
        match operand {
            Operand::BranchI8 => {
                branches += 1;
                let target = branch_target(end, i32::from(code[operand_start] as i8), code.len())?;
                if !is_instruction_start(code, target, rows)? {
                    return Err(Error::Bounds);
                }
            }
            Operand::BranchI32 => {
                branches += 1;
                let target = branch_target(end, u32_at(code, operand_start)? as i32, code.len())?;
                if !is_instruction_start(code, target, rows)? {
                    return Err(Error::Bounds);
                }
            }
            Operand::SwitchI32 => {
                let count = u32_at(code, operand_start)? as usize;
                branches = branches.checked_add(count).ok_or(Error::Quota)?;
                for index in 0..count {
                    let delta = u32_at(code, operand_start + 4 + index * 4)? as i32;
                    let target = branch_target(end, delta, code.len())?;
                    if !is_instruction_start(code, target, rows)? {
                        return Err(Error::Bounds);
                    }
                }
            }
            _ => {}
        }
        if branches > 256 {
            return Err(Error::Quota);
        }
        cursor = end;
    }
    Ok(())
}

pub(super) fn validate_method_cil(
    assembly: &Assembly<'_>,
    code: &[u8],
    max_stack: u16,
    arguments: u16,
    locals: u16,
    returns: bool,
) -> Result<()> {
    let rows = &assembly.rows;
    validate_cil(code, rows)?;

    let mut states = Vec::new();
    states
        .try_reserve_exact(code.len())
        .map_err(|_| Error::Quota)?;
    states.resize(code.len(), u16::MAX);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(code.len())
        .map_err(|_| Error::Quota)?;
    pending.push(0usize);
    states[0] = 0;
    while let Some(start) = pending.pop() {
        let mut height = states[start];
        let first = code[start];
        let (value, operand_start) = if first == 0xfe {
            (0xfe00 | u16::from(code[start + 1]), start + 2)
        } else {
            (u16::from(first), start + 1)
        };
        let opcode = opcodes::lookup(value).ok_or(Error::Unsupported)?;
        let end = instruction_end(code, start, rows)?;

        let variable = match value {
            0x0002..=0x0005 => Some((true, value - 0x0002)),
            0x0006..=0x0009 => Some((false, value - 0x0006)),
            0x000a..=0x000d => Some((false, value - 0x000a)),
            0x000e => Some((true, u16::from(code[operand_start]))),
            0x0011 | 0x0013 => Some((false, u16::from(code[operand_start]))),
            _ => None,
        };
        if variable
            .is_some_and(|(argument, index)| index >= if argument { arguments } else { locals })
        {
            return Err(Error::Bounds);
        }

        let method = if matches!(value, 0x0028 | 0x006f | 0x0073) {
            let table = code[operand_start];
            let index = u16_at(code, operand_start + 1)?;
            Some(referenced_method_shape(assembly, table, index)?)
        } else {
            None
        };
        use opcodes::{Flow, Pop, Push};
        let popped = match opcode.pop {
            Pop::Pop0 => 0,
            Pop::Pop1 | Pop::Popi | Pop::Popref => 1,
            Pop::Pop1_pop1 | Pop::Popref_pop1 | Pop::Popref_popi => 2,
            Pop::Popref_popi_popi => 3,
            Pop::Varpop if value == 0x002a => u16::from(returns),
            Pop::Varpop if value == 0x0073 => method.ok_or(Error::Format)?.parameters,
            Pop::Varpop => {
                let shape = method.ok_or(Error::Format)?;
                shape.parameters + u16::from(shape.has_this)
            }
        };
        height = height.checked_sub(popped).ok_or(Error::Format)?;
        let pushed = match opcode.push {
            Push::Push0 => 0,
            Push::Push1 | Push::Pushi | Push::Pushref => 1,
            Push::Push1_push1 => 2,
            Push::Varpush => u16::from(method.ok_or(Error::Format)?.returns),
        };
        height = height.checked_add(pushed).ok_or(Error::Quota)?;
        if height > max_stack {
            return Err(Error::Quota);
        }

        let merge_branch = |states: &mut [u16], pending: &mut Vec<usize>| -> Result<()> {
            match opcode.operand {
                opcodes::Operand::BranchI8 => merge_height(
                    states,
                    pending,
                    branch_target(end, i32::from(code[operand_start] as i8), code.len())?,
                    height,
                ),
                opcodes::Operand::BranchI32 => merge_height(
                    states,
                    pending,
                    branch_target(end, u32_at(code, operand_start)? as i32, code.len())?,
                    height,
                ),
                opcodes::Operand::SwitchI32 => {
                    let count = u32_at(code, operand_start)? as usize;
                    for index in 0..count {
                        let delta = u32_at(code, operand_start + 4 + index * 4)? as i32;
                        merge_height(
                            states,
                            pending,
                            branch_target(end, delta, code.len())?,
                            height,
                        )?;
                    }
                    Ok(())
                }
                _ => Err(Error::Format),
            }
        };
        match opcode.flow {
            Flow::Return => {
                if value != 0x002a || height != 0 {
                    return Err(Error::Format);
                }
            }
            Flow::Branch => merge_branch(&mut states, &mut pending)?,
            Flow::Cond_Branch => {
                merge_branch(&mut states, &mut pending)?;
                if end >= code.len() {
                    return Err(Error::Bounds);
                }
                merge_height(&mut states, &mut pending, end, height)?;
            }
            Flow::Next | Flow::Call => {
                if end >= code.len() {
                    return Err(Error::Bounds);
                }
                merge_height(&mut states, &mut pending, end, height)?;
            }
        }
    }
    Ok(())
}

pub(super) fn compatible(actual: StackType, expected: StackType) -> bool {
    actual == expected
        || (actual == StackType::Null && expected.reference())
        || (matches!(actual, StackType::Ref(_)) && expected == StackType::Ref(0))
}

pub(super) fn pop_type(stack: &mut Vec<StackType>, expected: StackType) -> Result<()> {
    let actual = stack.pop().ok_or(Error::Format)?;
    if compatible(actual, expected) {
        Ok(())
    } else {
        Err(Error::Format)
    }
}

pub(super) fn array_element(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<u32> {
    if table == schema::TABLE_TYPEDEF {
        return Ok(0x1000_0000 | (u32::from(table) << 16) | u32::from(index));
    }
    if table != schema::TABLE_TYPEREF {
        return Err(Error::Bounds);
    }
    let mut row = Row::new(assembly.row(table, index)?);
    row.u16()?;
    let name = row.index(assembly.string_width)?;
    let namespace = row.index(assembly.string_width)?;
    let strings = assembly.section(schema::SECTION_STRINGS)?;
    Ok(
        if string_at(strings, namespace)? == "System" && string_at(strings, name)? == "Byte" {
            1
        } else if string_at(strings, namespace)? == "System" && string_at(strings, name)? == "Int32"
        {
            2
        } else {
            0x1000_0000 | (u32::from(table) << 16) | u32::from(index)
        },
    )
}

pub(super) fn merge_types(
    states: &mut Vec<(usize, Vec<StackType>)>,
    pending: &mut Vec<usize>,
    target: usize,
    incoming: &[StackType],
    cells: &mut usize,
) -> Result<()> {
    if let Some((_, current)) = states.iter_mut().find(|(offset, _)| *offset == target) {
        if current.len() != incoming.len() {
            return Err(Error::Format);
        }
        let mut changed = false;
        for (stored, value) in current.iter_mut().zip(incoming) {
            if *stored == *value {
                continue;
            }
            if *stored == StackType::Null && value.reference() {
                *stored = *value;
                changed = true;
            } else if *value != StackType::Null || !stored.reference() {
                return Err(Error::Format);
            }
        }
        if changed {
            pending.try_reserve(1).map_err(|_| Error::Quota)?;
            pending.push(target);
        }
    } else {
        *cells = cells.checked_add(incoming.len()).ok_or(Error::Quota)?;
        if *cells > 4096 || states.len() >= 257 {
            return Err(Error::Quota);
        }
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(incoming.len())
            .map_err(|_| Error::Quota)?;
        copied.extend_from_slice(incoming);
        states.try_reserve(1).map_err(|_| Error::Quota)?;
        states.push((target, copied));
        pending.try_reserve(1).map_err(|_| Error::Quota)?;
        pending.push(target);
    }
    Ok(())
}

pub(super) fn validate_cil_types(
    assembly: &Assembly<'_>,
    code: &[u8],
    receiver: Option<StackType>,
    parameters: &[StackType],
    locals: &[StackType],
    result: Option<StackType>,
) -> Result<()> {
    let mut states = Vec::new();
    states.try_reserve_exact(257).map_err(|_| Error::Quota)?;
    states.push((0usize, Vec::new()));
    let mut pending = Vec::new();
    pending.try_reserve_exact(257).map_err(|_| Error::Quota)?;
    pending.push(0usize);
    let mut stack = Vec::new();
    stack.try_reserve_exact(256).map_err(|_| Error::Quota)?;
    let mut called_parameters = Vec::new();
    let mut cells = 0usize;
    while let Some(start) = pending.pop() {
        stack.clear();
        let (_, initial) = states
            .iter()
            .find(|(offset, _)| *offset == start)
            .ok_or(Error::Format)?;
        stack.extend_from_slice(initial);
        let mut pc = start;
        loop {
            if pc != start && states.iter().any(|(offset, _)| *offset == pc) {
                merge_types(&mut states, &mut pending, pc, &stack, &mut cells)?;
                break;
            }
            let first = code[pc];
            let (value, operand) = if first == 0xfe {
                (0xfe00 | u16::from(code[pc + 1]), pc + 2)
            } else {
                (u16::from(first), pc + 1)
            };
            let end = instruction_end(code, pc, &assembly.rows)?;
            let variable = |argument: bool, index: usize| -> Result<StackType> {
                if !argument {
                    return locals.get(index).copied().ok_or(Error::Bounds);
                }
                match receiver {
                    Some(value) if index == 0 => Ok(value),
                    Some(_) => parameters.get(index - 1).copied().ok_or(Error::Bounds),
                    None => parameters.get(index).copied().ok_or(Error::Bounds),
                }
            };
            match value {
                0x0000 => {}
                0x0002..=0x0005 => stack.push(variable(true, usize::from(value - 2))?),
                0x0006..=0x0009 => stack.push(variable(false, usize::from(value - 6))?),
                0x000a..=0x000d => pop_type(&mut stack, variable(false, usize::from(value - 10))?)?,
                0x000e => stack.push(variable(true, usize::from(code[operand]))?),
                0x0011 => stack.push(variable(false, usize::from(code[operand]))?),
                0x0013 => pop_type(&mut stack, variable(false, usize::from(code[operand]))?)?,
                0x0014 => stack.push(StackType::Null),
                0x0015..=0x0020 => stack.push(StackType::Int),
                0x0025 => {
                    let top = *stack.last().ok_or(Error::Format)?;
                    stack.push(top);
                }
                0x0026 => {
                    stack.pop().ok_or(Error::Format)?;
                }
                0x0028 | 0x006f => {
                    let table = code[operand];
                    let index = u16_at(code, operand + 1)?;
                    let (target_receiver, target_result) = referenced_method_types_into(
                        assembly,
                        table,
                        index,
                        &mut called_parameters,
                    )?;
                    for parameter in called_parameters.iter().rev() {
                        pop_type(&mut stack, *parameter)?;
                    }
                    if let Some(target_receiver) = target_receiver {
                        pop_type(&mut stack, target_receiver)?;
                    }
                    if let Some(returned) = target_result {
                        stack.push(returned);
                    }
                }
                0x002a => {
                    if let Some(expected) = result {
                        pop_type(&mut stack, expected)?;
                    }
                    if !stack.is_empty() {
                        return Err(Error::Format);
                    }
                    break;
                }
                0x002b | 0x0038 => {
                    let target = match value {
                        0x002b => branch_target(end, i32::from(code[operand] as i8), code.len())?,
                        _ => branch_target(end, u32_at(code, operand)? as i32, code.len())?,
                    };
                    merge_types(&mut states, &mut pending, target, &stack, &mut cells)?;
                    break;
                }
                0x002c | 0x002d | 0x0039 | 0x003a => {
                    let condition = stack.pop().ok_or(Error::Format)?;
                    if condition != StackType::Int && !condition.reference() {
                        return Err(Error::Format);
                    }
                    let target = if matches!(value, 0x002c | 0x002d) {
                        branch_target(end, i32::from(code[operand] as i8), code.len())?
                    } else {
                        branch_target(end, u32_at(code, operand)? as i32, code.len())?
                    };
                    merge_types(&mut states, &mut pending, target, &stack, &mut cells)?;
                }
                0x002e | 0x0033 | 0x003b | 0x0040 => {
                    let right = stack.pop().ok_or(Error::Format)?;
                    let left = stack.pop().ok_or(Error::Format)?;
                    if !compatible(left, right) && !compatible(right, left) {
                        return Err(Error::Format);
                    }
                    let target = if matches!(value, 0x002e | 0x0033) {
                        branch_target(end, i32::from(code[operand] as i8), code.len())?
                    } else {
                        branch_target(end, u32_at(code, operand)? as i32, code.len())?
                    };
                    merge_types(&mut states, &mut pending, target, &stack, &mut cells)?;
                }
                0x002f..=0x0032 | 0x0034..=0x0037 | 0x003c..=0x003f | 0x0041..=0x0044 => {
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(&mut stack, StackType::Int)?;
                    let target = if value <= 0x0037 {
                        branch_target(end, i32::from(code[operand] as i8), code.len())?
                    } else {
                        branch_target(end, u32_at(code, operand)? as i32, code.len())?
                    };
                    merge_types(&mut states, &mut pending, target, &stack, &mut cells)?;
                }
                0x0045 => {
                    pop_type(&mut stack, StackType::Int)?;
                    let count = u32_at(code, operand)? as usize;
                    for index in 0..count {
                        let target = branch_target(
                            end,
                            u32_at(code, operand + 4 + index * 4)? as i32,
                            code.len(),
                        )?;
                        merge_types(&mut states, &mut pending, target, &stack, &mut cells)?;
                    }
                }
                0x0058..=0x0064 | 0x00d6..=0x00db => {
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(&mut stack, StackType::Int)?;
                    stack.push(StackType::Int);
                }
                0x0065..=0x0069 | 0x006d | 0x0082..=0x0088 | 0x00b3..=0x00b8 | 0x00d1..=0x00d2 => {
                    pop_type(&mut stack, StackType::Int)?;
                    stack.push(StackType::Int);
                }
                0x0073 => {
                    let table = code[operand];
                    let index = u16_at(code, operand + 1)?;
                    let (target_receiver, _) = referenced_method_types_into(
                        assembly,
                        table,
                        index,
                        &mut called_parameters,
                    )?;
                    for parameter in called_parameters.iter().rev() {
                        pop_type(&mut stack, *parameter)?;
                    }
                    stack.push(target_receiver.ok_or(Error::Format)?);
                }
                0x007b | 0x007d => {
                    let (owner, field) = field_type(assembly, u16_at(code, operand + 1)?)?;
                    if value == 0x007d {
                        pop_type(&mut stack, field)?;
                    }
                    pop_type(&mut stack, owner)?;
                    if value == 0x007b {
                        stack.push(field);
                    }
                }
                0x008d => {
                    pop_type(&mut stack, StackType::Int)?;
                    stack.push(StackType::Array(array_element(
                        assembly,
                        code[operand],
                        u16_at(code, operand + 1)?,
                    )?));
                }
                0x008e => {
                    let array = stack.pop().ok_or(Error::Format)?;
                    if !matches!(array, StackType::Array(_)) {
                        return Err(Error::Format);
                    }
                    stack.push(StackType::Int);
                }
                0x0091 | 0x0094 => {
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(
                        &mut stack,
                        StackType::Array(if value == 0x0091 { 1 } else { 2 }),
                    )?;
                    stack.push(StackType::Int);
                }
                0x009c | 0x009e => {
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(
                        &mut stack,
                        StackType::Array(if value == 0x009c { 1 } else { 2 }),
                    )?;
                }
                0xfe01 => {
                    let right = stack.pop().ok_or(Error::Format)?;
                    let left = stack.pop().ok_or(Error::Format)?;
                    if !compatible(left, right) && !compatible(right, left) {
                        return Err(Error::Format);
                    }
                    stack.push(StackType::Int);
                }
                0xfe02..=0xfe05 => {
                    pop_type(&mut stack, StackType::Int)?;
                    pop_type(&mut stack, StackType::Int)?;
                    stack.push(StackType::Int);
                }
                _ => return Err(Error::Unsupported),
            }
            pc = end;
            if pc >= code.len() {
                return Err(Error::Bounds);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum SignatureKind {
    Field,
    Method,
    Locals,
}

pub(super) fn validate_signature(
    bytes: &[u8],
    kind: SignatureKind,
    rows: &[u16; 64],
) -> Result<()> {
    let mut signature = Signature { bytes, offset: 0 };
    let calling = signature.byte()?;
    match kind {
        SignatureKind::Field if calling == 0x06 => signature.value_type(rows, false, 0)?,
        SignatureKind::Locals if calling == 0x07 => {
            let count = signature.compressed()?;
            if count > 64 {
                return Err(Error::Quota);
            }
            for _ in 0..count {
                signature.value_type(rows, false, 0)?;
            }
        }
        SignatureKind::Method if calling == 0 || calling == 0x20 => {
            let count = signature.compressed()?;
            if count > 32 {
                return Err(Error::Quota);
            }
            signature.value_type(rows, true, 0)?;
            for _ in 0..count {
                signature.value_type(rows, false, 0)?;
            }
        }
        _ => return Err(Error::Format),
    }
    if signature.offset != bytes.len() {
        return Err(Error::Format);
    }
    Ok(())
}

struct Signature<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Signature<'_> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self.bytes.get(self.offset).ok_or(Error::Format)?;
        self.offset += 1;
        Ok(value)
    }

    fn compressed(&mut self) -> Result<u32> {
        let first = self.byte()?;
        if first < 0x80 {
            return Ok(u32::from(first));
        }
        if first < 0xc0 {
            let value = (u32::from(first & 0x3f) << 8) | u32::from(self.byte()?);
            return if value >= 0x80 {
                Ok(value)
            } else {
                Err(Error::Format)
            };
        }
        if first < 0xe0 {
            let value = (u32::from(first & 0x1f) << 24)
                | (u32::from(self.byte()?) << 16)
                | (u32::from(self.byte()?) << 8)
                | u32::from(self.byte()?);
            return if value >= 0x4000 {
                Ok(value)
            } else {
                Err(Error::Format)
            };
        }
        Err(Error::Format)
    }

    fn stack_type(&mut self, rows: &[u16; 64], void: bool, depth: u8) -> Result<Option<StackType>> {
        if depth >= 8 {
            return Err(Error::Quota);
        }
        Ok(match self.byte()? {
            0x01 if void => None,
            0x02 | 0x04..=0x09 => Some(StackType::Int),
            0x0e => Some(StackType::Ref(1)),
            0x1c => Some(StackType::Ref(0)),
            0x1d => {
                let element = match *self.bytes.get(self.offset).ok_or(Error::Format)? {
                    0x04 | 0x05 => 1,
                    0x08 | 0x09 => 2,
                    0x0e => 3,
                    0x1c => 4,
                    0x12 => {
                        let value = self
                            .stack_type(rows, false, depth + 1)?
                            .ok_or(Error::Format)?;
                        let StackType::Ref(token) = value else {
                            return Err(Error::Format);
                        };
                        return Ok(Some(StackType::Array(0x1000_0000 | token)));
                    }
                    _ => return Err(Error::Unsupported),
                };
                self.byte()?;
                Some(StackType::Array(element))
            }
            kind @ (0x11 | 0x12) => {
                let coded = self.compressed()?;
                let tag = coded & 3;
                let row = coded >> 2;
                let table = match tag {
                    0 => schema::TABLE_TYPEDEF,
                    1 => schema::TABLE_TYPEREF,
                    _ => return Err(Error::Format),
                };
                if row == 0 || row > u32::from(rows[table as usize]) {
                    return Err(Error::Bounds);
                }
                Some(if kind == 0x11 {
                    StackType::Value((u32::from(table) << 16) | row)
                } else {
                    StackType::Ref((u32::from(table) << 16) | row)
                })
            }
            _ => return Err(Error::Unsupported),
        })
    }

    fn value_type(&mut self, rows: &[u16; 64], void: bool, depth: u8) -> Result<()> {
        self.stack_type(rows, void, depth).map(|_| ())
    }
}
