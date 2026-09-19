//! Zero-copy structural parser for the MC04 embedded ECMA-335 profile.
use crate::{mc04_opcodes as opcodes, mc04_schema as schema, Error, Result};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Section {
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Assembly<'a> {
    bytes: &'a [u8],
    sections: [Section; 4],
    rows: [u16; 64],
    table_offsets: [u32; 64],
    string_width: usize,
    blob_width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataToken {
    pub table: u8,
    pub row: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodView<'a> {
    pub name: &'a str,
    pub signature: &'a [u8],
    pub local_signature: &'a [u8],
    pub code: &'a [u8],
    pub flags: u16,
    pub implementation_flags: u16,
    pub body_flags: u8,
    pub max_stack: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRefView<'a> {
    pub parent: MetadataToken,
    pub name: &'a str,
    pub signature: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeRefView<'a> {
    pub scope: MetadataToken,
    pub name: &'a str,
    pub namespace: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssemblyRefView<'a> {
    pub version: [u16; 4],
    pub flags: u32,
    pub public_key_or_token: &'a [u8],
    pub name: &'a str,
    pub culture: &'a str,
    pub hash_value: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeDefView<'a> {
    pub name: &'a str,
    pub namespace: &'a str,
    pub flags: u32,
}

const TYPE_ALLOWED_FLAGS: u32 = 0x0010_0181;
const TYPE_SEALED: u32 = 0x0000_0100;
const FIELD_ALLOWED_FLAGS: u16 = 0x0027;
const METHOD_ALLOWED_FLAGS: u16 = 0x1897;

fn validate_type_flags(name: &str, flags: u32) -> Result<()> {
    if name == "<Module>" {
        return if flags == 0 {
            Ok(())
        } else {
            Err(Error::Format)
        };
    }
    if flags & !TYPE_ALLOWED_FLAGS != 0 || flags & TYPE_SEALED == 0 {
        return Err(Error::Format);
    }
    Ok(())
}

fn validate_base_type(assembly: &Assembly<'_>, name: &str, extends: u16) -> Result<()> {
    if name == "<Module>" || extends == 0 {
        return if extends == 0 {
            Ok(())
        } else {
            Err(Error::Format)
        };
    }
    if extends & 3 != 1 || extends >> 2 == 0 {
        return Err(Error::Format);
    }
    let base = assembly.type_ref(extends >> 2)?;
    if base.scope.table != schema::TABLE_ASSEMBLYREF
        || base.name != "Object"
        || base.namespace != "System"
    {
        return Err(Error::Format);
    }
    Ok(())
}

fn validate_field_flags(flags: u16) -> Result<()> {
    if flags & !FIELD_ALLOWED_FLAGS != 0 {
        return Err(Error::Format);
    }
    Ok(())
}

fn validate_method_flags(implementation: u16, flags: u16) -> Result<()> {
    if implementation != 0 || flags & !METHOD_ALLOWED_FLAGS != 0 {
        return Err(Error::Format);
    }
    Ok(())
}

fn externally_visible(owner: &TypeDefView<'_>, method: &MethodView<'_>) -> bool {
    owner.flags & 0x0000_0007 == 0x0000_0001 && method.flags & 0x0007 == 0x0006
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(Error::Format)?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Format)?
            .try_into()
            .unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(Error::Format)?
            .try_into()
            .unwrap(),
    ))
}

impl<'a> Assembly<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        const FIXED_HEADER: usize = 16;
        const DIRECTORY_ENTRY: usize = 10;
        if bytes.len() < FIXED_HEADER + 4 * DIRECTORY_ENTRY
            || bytes.get(..4) != Some(b"MC04")
            || bytes[4] != 4
            || bytes[5] != 0
            || u16_at(bytes, 6)? != 0
            || bytes[8] != 4
            || bytes[9] != 2
        {
            return Err(Error::Format);
        }
        let header_size = usize::from(u16_at(bytes, 10)?);
        if header_size != FIXED_HEADER + 4 * DIRECTORY_ENTRY
            || u32_at(bytes, 12)? as usize != bytes.len()
        {
            return Err(Error::Format);
        }

        let mut sections = [Section::default(); 4];
        let mut expected_offset = header_size;
        for (index, section) in sections.iter_mut().enumerate() {
            let at = FIXED_HEADER + index * DIRECTORY_ENTRY;
            if bytes[at] != index as u8 + 1 || bytes[at + 1] != 0 {
                return Err(Error::Format);
            }
            let offset = u32_at(bytes, at + 2)?;
            let length = u32_at(bytes, at + 6)?;
            let end = (offset as usize)
                .checked_add(length as usize)
                .ok_or(Error::Format)?;
            if offset as usize != expected_offset || end > bytes.len() {
                return Err(Error::Format);
            }
            *section = Section { offset, length };
            expected_offset = end;
        }
        if expected_offset != bytes.len() {
            return Err(Error::Format);
        }

        let strings = slice(bytes, sections[1])?;
        let blobs = slice(bytes, sections[2])?;
        let code = slice(bytes, sections[3])?;
        validate_strings(strings)?;
        validate_blobs(blobs)?;
        if code.is_empty() {
            return Err(Error::Format);
        }
        let string_width = if strings.len() <= 256 { 1 } else { 2 };
        let blob_width = if blobs.len() <= 256 { 1 } else { 2 };

        let tables = slice(bytes, sections[0])?;
        if tables.len() < 12
            || tables[0] != 2
            || tables[1] != 0
            || tables[3] != 0
            || tables[2] & !3 != 0
            || (tables[2] & 1 != 0) != (string_width == 2)
            || (tables[2] & 2 != 0) != (blob_width == 2)
        {
            return Err(Error::Format);
        }
        let valid = u64_at(tables, 4)?;
        let required = (1u64 << schema::TABLE_MODULE)
            | (1u64 << schema::TABLE_TYPEDEF)
            | (1u64 << schema::TABLE_METHODDEF)
            | (1u64 << schema::TABLE_ASSEMBLY);
        if valid & !schema::ALLOWED_TABLES != 0 || valid & required != required {
            return Err(Error::Format);
        }
        let mut rows = [0u16; 64];
        let mut cursor = 12usize;
        for table in 0..64u8 {
            if valid & (1u64 << table) == 0 {
                continue;
            }
            let count = u16_at(tables, cursor)?;
            cursor += 2;
            if count == 0 || count > schema::max_rows(table).ok_or(Error::Format)? {
                return Err(Error::Quota);
            }
            rows[table as usize] = count;
        }
        if rows[schema::TABLE_MODULE as usize] != 1 || rows[schema::TABLE_ASSEMBLY as usize] != 1 {
            return Err(Error::Format);
        }

        let mut table_offsets = [0u32; 64];
        for table in 0..64u8 {
            let count = rows[table as usize];
            if count == 0 {
                continue;
            }
            table_offsets[table as usize] = u32::try_from(cursor).map_err(|_| Error::Quota)?;
            let width =
                schema::row_width(table, string_width, blob_width, &rows).ok_or(Error::Format)?;
            cursor = cursor
                .checked_add(width.checked_mul(count as usize).ok_or(Error::Quota)?)
                .ok_or(Error::Quota)?;
            if cursor > tables.len() {
                return Err(Error::Format);
            }
        }
        if cursor != tables.len() {
            return Err(Error::Format);
        }

        let assembly = Self {
            bytes,
            sections,
            rows,
            table_offsets,
            string_width,
            blob_width,
        };
        assembly.validate_metadata()?;
        Ok(assembly)
    }

    pub fn section(&self, kind: u8) -> Result<&'a [u8]> {
        let index = usize::from(kind.checked_sub(1).ok_or(Error::Bounds)?);
        slice(self.bytes, *self.sections.get(index).ok_or(Error::Bounds)?)
    }

    pub fn table(&self, table: u8) -> Result<&'a [u8]> {
        let count = *self.rows.get(table as usize).ok_or(Error::Bounds)?;
        if count == 0 {
            return Ok(&[]);
        }
        let width = schema::row_width(table, self.string_width, self.blob_width, &self.rows)
            .ok_or(Error::Bounds)?;
        let tables = self.section(schema::SECTION_TABLES)?;
        let start = self.table_offsets[table as usize] as usize;
        tables
            .get(start..start + width * count as usize)
            .ok_or(Error::Bounds)
    }

    pub fn row(&self, table: u8, row: u16) -> Result<&'a [u8]> {
        let count = self.row_count(table)?;
        if row == 0 || row > count {
            return Err(Error::Bounds);
        }
        let width = schema::row_width(table, self.string_width, self.blob_width, &self.rows)
            .ok_or(Error::Bounds)?;
        let start = (row as usize - 1) * width;
        self.table(table)?
            .get(start..start + width)
            .ok_or(Error::Bounds)
    }

    pub fn row_count(&self, table: u8) -> Result<u16> {
        self.rows.get(table as usize).copied().ok_or(Error::Bounds)
    }

    /// Return a borrowed execution view. `index` is the compact zero-based
    /// MethodDef index used by manifests; code and heap data stay in the image.
    pub fn method(&self, index: u16) -> Result<MethodView<'a>> {
        let mut row = Row::new(self.row(
            schema::TABLE_METHODDEF,
            index.checked_add(1).ok_or(Error::Bounds)?,
        )?);
        let offset = row.u32()? as usize;
        let implementation_flags = row.u16()?;
        let flags = row.u16()?;
        let name = row.index(self.string_width)?;
        let signature = row.index(self.blob_width)?;
        if !row.finished() {
            return Err(Error::Format);
        }
        let strings = self.section(schema::SECTION_STRINGS)?;
        let blobs = self.section(schema::SECTION_BLOB)?;
        let code = self.section(schema::SECTION_CODE)?;
        let header = code.get(offset..offset + 12).ok_or(Error::Bounds)?;
        let length = u32_at(header, 4)? as usize;
        let body = code
            .get(offset + 12..offset + 12 + length)
            .ok_or(Error::Bounds)?;
        let locals = u16_at(header, 8)?;
        Ok(MethodView {
            name: string_at(strings, name)?,
            signature: blob_at(blobs, signature)?,
            local_signature: if locals == 0 {
                &[]
            } else {
                blob_at(blobs, locals)?
            },
            code: body,
            flags,
            implementation_flags,
            body_flags: header[0],
            max_stack: u16_at(header, 2)?,
        })
    }

    pub fn method_types(&self, index: u16) -> Result<MethodTypes> {
        let mut parameters = Vec::new();
        let (receiver, result) = self.method_types_into(index, &mut parameters)?;
        Ok(MethodTypes {
            receiver,
            parameters,
            result,
        })
    }

    pub(crate) fn method_types_into(
        &self,
        index: u16,
        parameters: &mut Vec<StackType>,
    ) -> Result<(Option<StackType>, Option<StackType>)> {
        referenced_method_types_into(
            self,
            schema::TABLE_METHODDEF,
            index.checked_add(1).ok_or(Error::Bounds)?,
            parameters,
        )
    }

    pub fn member_types(&self, index: u16) -> Result<MethodTypes> {
        let mut parameters = Vec::new();
        let (receiver, result) = self.member_types_into(index, &mut parameters)?;
        Ok(MethodTypes {
            receiver,
            parameters,
            result,
        })
    }

    pub(crate) fn member_types_into(
        &self,
        index: u16,
        parameters: &mut Vec<StackType>,
    ) -> Result<(Option<StackType>, Option<StackType>)> {
        referenced_method_types_into(self, schema::TABLE_MEMBERREF, index, parameters)
    }

    pub fn method_local_types(&self, index: u16) -> Result<Vec<StackType>> {
        let mut types = Vec::new();
        self.method_local_types_into(index, &mut types)?;
        Ok(types)
    }

    pub(crate) fn method_local_types_into(
        &self,
        index: u16,
        types: &mut Vec<StackType>,
    ) -> Result<()> {
        let method = self.method(index)?;
        if method.local_signature.is_empty() {
            types.clear();
            Ok(())
        } else {
            local_types_into(method.local_signature, &self.rows, types)
        }
    }

    pub fn method_owner(&self, index: u16) -> Result<u16> {
        list_owner(
            self,
            schema::TABLE_METHODDEF,
            index.checked_add(1).ok_or(Error::Bounds)?,
        )
    }

    pub fn type_def(&self, index: u16) -> Result<TypeDefView<'a>> {
        let mut row = Row::new(self.row(schema::TABLE_TYPEDEF, index)?);
        let flags = row.u32()?;
        let name = row.index(self.string_width)?;
        let namespace = row.index(self.string_width)?;
        row.u16()?;
        row.index(if self.rows[schema::TABLE_FIELD as usize] <= 255 {
            1
        } else {
            2
        })?;
        row.index(if self.rows[schema::TABLE_METHODDEF as usize] <= 255 {
            1
        } else {
            2
        })?;
        if !row.finished() {
            return Err(Error::Format);
        }
        let strings = self.section(schema::SECTION_STRINGS)?;
        Ok(TypeDefView {
            name: string_at(strings, name)?,
            namespace: string_at(strings, namespace)?,
            flags,
        })
    }

    pub fn find_method(
        &self,
        namespace: &str,
        type_name: &str,
        method_name: &str,
        signature: &[u8],
    ) -> Result<u16> {
        let mut found = None;
        for index in 0..self.row_count(schema::TABLE_METHODDEF)? {
            let owner = self.type_def(self.method_owner(index)?)?;
            let method = self.method(index)?;
            if externally_visible(&owner, &method)
                && owner.namespace == namespace
                && owner.name == type_name
                && method.name == method_name
                && method.signature == signature
                && found.replace(index).is_some()
            {
                return Err(Error::Format);
            }
        }
        found.ok_or(Error::Missing)
    }

    pub fn find_method_for(
        &self,
        namespace: &str,
        type_name: &str,
        method_name: &str,
        caller: &Assembly<'_>,
        member_index: u16,
    ) -> Result<u16> {
        let expected = caller.member_types(member_index)?;
        let mut found = None;
        for index in 0..self.row_count(schema::TABLE_METHODDEF)? {
            let owner = self.type_def(self.method_owner(index)?)?;
            let method = self.method(index)?;
            if externally_visible(&owner, &method)
                && owner.namespace == namespace
                && owner.name == type_name
                && method.name == method_name
                && same_method_types(caller, &expected, self, &self.method_types(index)?)?
                && found.replace(index).is_some()
            {
                return Err(Error::Format);
            }
        }
        found.ok_or(Error::Missing)
    }

    pub fn type_field_count(&self, type_row: u16) -> Result<u16> {
        let start = type_lists(self, type_row)?.0;
        let end = if type_row == self.rows[schema::TABLE_TYPEDEF as usize] {
            self.rows[schema::TABLE_FIELD as usize] + 1
        } else {
            type_lists(self, type_row + 1)?.0
        };
        end.checked_sub(start).ok_or(Error::Format)
    }

    pub fn field_layout(&self, field_row: u16) -> Result<(u16, u16)> {
        let owner = list_owner(self, schema::TABLE_FIELD, field_row)?;
        let start = type_lists(self, owner)?.0;
        Ok((owner, field_row.checked_sub(start).ok_or(Error::Format)?))
    }

    /// Verify every framework MemberRef against the immutable device ABI and
    /// require its numeric native capability in the signed manifest.
    pub fn validate_imports(&self, capabilities: &[u8]) -> Result<()> {
        for (_, import) in self.framework_imports()? {
            if let crate::mc04_imports::Import::Native(id) = import {
                if !capabilities.contains(&id) {
                    return Err(Error::Unauthorized);
                }
            }
        }
        Ok(())
    }

    /// Return the canonical sorted set of framework MemberRef link targets.
    pub fn framework_imports(&self) -> Result<Vec<(u16, crate::mc04_imports::Import)>> {
        let uses = self.member_ref_uses()?;
        let mut imports = Vec::new();
        imports
            .try_reserve_exact(uses.len())
            .map_err(|_| Error::Quota)?;
        for (member, _) in uses {
            if let Some(import) = crate::mc04_imports::resolve(self, member)? {
                imports.push((member, import));
            }
        }
        Ok(imports)
    }

    /// Return every externally referenced method and its call opcode. The
    /// result is canonical and rejects one MemberRef used with conflicting
    /// invocation forms.
    pub fn member_ref_uses(&self) -> Result<Vec<(u16, u16)>> {
        let mut uses = Vec::new();
        uses
            .try_reserve_exact(usize::from(self.row_count(schema::TABLE_MEMBERREF)?))
            .map_err(|_| Error::Quota)?;
        for index in 0..self.row_count(schema::TABLE_METHODDEF)? {
            let code = self.method(index)?.code;
            let mut pc = 0usize;
            while pc < code.len() {
                let first = code[pc];
                let (value, operand) = if first == 0xfe {
                    (
                        0xfe00 | u16::from(*code.get(pc + 1).ok_or(Error::Bounds)?),
                        pc + 2,
                    )
                } else {
                    (u16::from(first), pc + 1)
                };
                let end = instruction_end(code, pc, &self.rows)?;
                if matches!(value, 0x0028 | 0x006f | 0x0073)
                    && code.get(operand) == Some(&schema::TABLE_MEMBERREF)
                {
                    let member = u16_at(code, operand + 1)?;
                    if let Some((_, prior)) = uses.iter().find(|(seen, _)| *seen == member) {
                        if *prior != value {
                            return Err(Error::Format);
                        }
                    } else {
                        uses.push((member, value));
                    }
                }
                pc = end;
            }
        }
        uses.sort_unstable_by_key(|(member, _)| *member);
        Ok(uses)
    }

    /// Return direct managed-call tokens from one method. Tokens retain compact
    /// table/row indices, so linked verification does not copy method bodies.
    pub fn method_calls(&self, index: u16) -> Result<Vec<MetadataToken>> {
        let code = self.method(index)?.code;
        let mut calls = Vec::new();
        let mut pc = 0usize;
        while pc < code.len() {
            let first = code[pc];
            let (value, operand) = if first == 0xfe {
                (
                    0xfe00 | u16::from(*code.get(pc + 1).ok_or(Error::Bounds)?),
                    pc + 2,
                )
            } else {
                (u16::from(first), pc + 1)
            };
            let end = instruction_end(code, pc, &self.rows)?;
            if matches!(value, 0x0028 | 0x006f | 0x0073) {
                let table = *code.get(operand).ok_or(Error::Bounds)?;
                if matches!(table, schema::TABLE_METHODDEF | schema::TABLE_MEMBERREF) {
                    calls.try_reserve(1).map_err(|_| Error::Quota)?;
                    calls.push(MetadataToken {
                        table,
                        row: u16_at(code, operand + 1)?,
                    });
                }
            }
            pc = end;
        }
        Ok(calls)
    }

    /// Resolve a one-based MemberRef row without copying its heap values.
    pub fn member_ref(&self, index: u16) -> Result<MemberRefView<'a>> {
        let mut row = Row::new(self.row(schema::TABLE_MEMBERREF, index)?);
        let parent = decode_coded(
            row.u16()?,
            3,
            &[Some(2), Some(1), None, Some(6), None, None, None, None],
        )?;
        let name = row.index(self.string_width)?;
        let signature = row.index(self.blob_width)?;
        if !row.finished() {
            return Err(Error::Format);
        }
        Ok(MemberRefView {
            parent,
            name: string_at(self.section(schema::SECTION_STRINGS)?, name)?,
            signature: blob_at(self.section(schema::SECTION_BLOB)?, signature)?,
        })
    }

    /// Resolve a one-based TypeRef row and its ResolutionScope.
    pub fn type_ref(&self, index: u16) -> Result<TypeRefView<'a>> {
        let mut row = Row::new(self.row(schema::TABLE_TYPEREF, index)?);
        let scope = decode_coded(row.u16()?, 2, &[Some(0), None, Some(35), Some(1)])?;
        let name = row.index(self.string_width)?;
        let namespace = row.index(self.string_width)?;
        if !row.finished() {
            return Err(Error::Format);
        }
        let strings = self.section(schema::SECTION_STRINGS)?;
        Ok(TypeRefView {
            scope,
            name: string_at(strings, name)?,
            namespace: string_at(strings, namespace)?,
        })
    }

    /// Resolve a one-based AssemblyRef row; identity data remains borrowed.
    pub fn assembly_ref(&self, index: u16) -> Result<AssemblyRefView<'a>> {
        let mut row = Row::new(self.row(schema::TABLE_ASSEMBLYREF, index)?);
        let version = [row.u16()?, row.u16()?, row.u16()?, row.u16()?];
        let flags = row.u32()?;
        let public_key_or_token = row.index(self.blob_width)?;
        let name = row.index(self.string_width)?;
        let culture = row.index(self.string_width)?;
        let hash_value = row.index(self.blob_width)?;
        if !row.finished() {
            return Err(Error::Format);
        }
        Ok(AssemblyRefView {
            version,
            flags,
            public_key_or_token: blob_at(
                self.section(schema::SECTION_BLOB)?,
                public_key_or_token,
            )?,
            name: string_at(self.section(schema::SECTION_STRINGS)?, name)?,
            culture: string_at(self.section(schema::SECTION_STRINGS)?, culture)?,
            hash_value: blob_at(self.section(schema::SECTION_BLOB)?, hash_value)?,
        })
    }

    pub fn identity(&self) -> Result<AssemblyRefView<'a>> {
        let mut row = Row::new(self.row(schema::TABLE_ASSEMBLY, 1)?);
        let version = [row.u16()?, row.u16()?, row.u16()?, row.u16()?];
        let flags = row.u32()?;
        let name = row.index(self.string_width)?;
        if !row.finished() {
            return Err(Error::Format);
        }
        Ok(AssemblyRefView {
            version,
            flags,
            public_key_or_token: &[],
            name: string_at(self.section(schema::SECTION_STRINGS)?, name)?,
            culture: "",
            hash_value: &[],
        })
    }

    /// Lifecycle indices are compact zero-based MethodDef indices from the signed manifest.
    pub fn validate_lifecycle(&self, index: u16) -> Result<()> {
        let row_index = index.checked_add(1).ok_or(Error::Bounds)?;
        let mut row = Row::new(self.row(schema::TABLE_METHODDEF, row_index)?);
        row.u32()?;
        row.u16()?;
        let flags = row.u16()?;
        row.index(self.string_width)?;
        row.index(self.blob_width)?;
        if !row.finished() || flags & 0x0010 == 0 {
            return Err(Error::Format);
        }
        let method = referenced_method_types(self, schema::TABLE_METHODDEF, row_index)?;
        if method.receiver.is_some() || !method.parameters.is_empty() || method.result.is_some() {
            return Err(Error::Format);
        }
        Ok(())
    }

    fn validate_metadata(&self) -> Result<()> {
        let strings = self.section(schema::SECTION_STRINGS)?;
        let blobs = self.section(schema::SECTION_BLOB)?;
        let code = self.section(schema::SECTION_CODE)?;
        let string = |row: &mut Row<'_>, required: bool| -> Result<()> {
            let offset = row.index(self.string_width)?;
            let value = string_at(strings, offset)?;
            if required && value.is_empty() {
                return Err(Error::Format);
            }
            Ok(())
        };
        let blob = |row: &mut Row<'_>, required: bool| -> Result<()> {
            let offset = row.index(self.blob_width)?;
            let value = blob_at(blobs, offset)?;
            if required && value.is_empty() {
                return Err(Error::Format);
            }
            Ok(())
        };

        let mut previous_attribute: Option<(u16, u16, u16)> = None;
        let mut next_code_offset = 0usize;
        let mut method_parameters = Vec::new();
        let mut method_locals = Vec::new();
        for table in 0..64u8 {
            for index in 1..=self.rows[table as usize] {
                let mut row = Row::new(self.row(table, index)?);
                match table {
                    schema::TABLE_MODULE => string(&mut row, true)?,
                    schema::TABLE_TYPEREF => {
                        coded(
                            row.u16()?,
                            2,
                            &[Some(0), None, Some(35), Some(1)],
                            &self.rows,
                            false,
                        )?;
                        string(&mut row, true)?;
                        string(&mut row, false)?;
                    }
                    schema::TABLE_TYPEDEF => {
                        let flags = row.u32()?;
                        let name = string_at(strings, row.index(self.string_width)?)?;
                        if name.is_empty() {
                            return Err(Error::Format);
                        }
                        validate_type_flags(name, flags)?;
                        string(&mut row, false)?;
                        let extends = row.u16()?;
                        coded(
                            extends,
                            2,
                            &[Some(2), Some(1), None, None],
                            &self.rows,
                            true,
                        )?;
                        validate_base_type(self, name, extends)?;
                        table_list(&mut row, self.rows[4])?;
                        table_list(&mut row, self.rows[6])?;
                    }
                    schema::TABLE_FIELD => {
                        validate_field_flags(row.u16()?)?;
                        string(&mut row, true)?;
                        let signature = blob_at(blobs, row.index(self.blob_width)?)?;
                        validate_signature(signature, SignatureKind::Field, &self.rows)?;
                        if signature != [0x06, 0x08] {
                            return Err(Error::Format);
                        }
                    }
                    schema::TABLE_METHODDEF => {
                        let offset = row.u32()? as usize;
                        let implementation = row.u16()?;
                        let flags = row.u16()?;
                        validate_method_flags(implementation, flags)?;
                        string(&mut row, true)?;
                        let signature = blob_at(blobs, row.index(self.blob_width)?)?;
                        validate_signature(signature, SignatureKind::Method, &self.rows)?;
                        let shape = method_shape(signature, &self.rows)?;
                        let (method_receiver, method_result) = referenced_method_types_into(
                            self,
                            schema::TABLE_METHODDEF,
                            index,
                            &mut method_parameters,
                        )?;
                        if offset != next_code_offset || offset + 12 > code.len() {
                            return Err(Error::Bounds);
                        }
                        let header = &code[offset..offset + 12];
                        if header[0] & !3 != 0
                            || header[1] != 0
                            || u16_at(header, 2)? == 0
                            || u16_at(header, 2)? > 256
                            || u16_at(header, 10)? != 0
                        {
                            return Err(Error::Format);
                        }
                        let length = u32_at(header, 4)? as usize;
                        let local_signature = u16_at(header, 8)?;
                        let locals = if local_signature != 0 {
                            let local_blob = blob_at(blobs, local_signature)?;
                            validate_signature(local_blob, SignatureKind::Locals, &self.rows)?;
                            let locals = local_count(local_blob)?;
                            local_types_into(local_blob, &self.rows, &mut method_locals)?;
                            locals
                        } else {
                            method_locals.clear();
                            0
                        };
                        next_code_offset = offset
                            .checked_add(12)
                            .and_then(|start| start.checked_add(length))
                            .ok_or(Error::Quota)?;
                        if length == 0 || next_code_offset > code.len() {
                            return Err(Error::Bounds);
                        }
                        validate_method_cil(
                            self,
                            &code[offset + 12..next_code_offset],
                            u16_at(header, 2)?,
                            shape.parameters + u16::from(shape.has_this),
                            locals,
                            shape.returns,
                        )?;
                        validate_cil_types(
                            self,
                            &code[offset + 12..next_code_offset],
                            method_receiver,
                            &method_parameters,
                            &method_locals,
                            method_result,
                        )?;
                    }
                    schema::TABLE_MEMBERREF => {
                        coded(
                            row.u16()?,
                            3,
                            &[Some(2), Some(1), None, Some(6), None, None, None, None],
                            &self.rows,
                            false,
                        )?;
                        string(&mut row, true)?;
                        let signature = blob_at(blobs, row.index(self.blob_width)?)?;
                        validate_signature(signature, SignatureKind::Method, &self.rows)?;
                    }
                    schema::TABLE_CUSTOMATTRIBUTE => {
                        let parent = row.u16()?;
                        let attribute_type = row.u16()?;
                        coded(
                            parent,
                            5,
                            &[
                                Some(6),
                                Some(4),
                                Some(1),
                                Some(2),
                                None,
                                None,
                                Some(10),
                                Some(0),
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                Some(32),
                                Some(35),
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                                None,
                            ],
                            &self.rows,
                            false,
                        )?;
                        coded(
                            attribute_type,
                            3,
                            &[None, None, Some(6), Some(10), None, None, None, None],
                            &self.rows,
                            false,
                        )?;
                        let value_offset = row.index(self.blob_width)?;
                        let value = blob_at(blobs, value_offset)?;
                        if value.is_empty() {
                            return Err(Error::Format);
                        }
                        if let Some(previous) = previous_attribute {
                            let order = (previous.0, previous.1).cmp(&(parent, attribute_type));
                            if order.is_gt()
                                || (order.is_eq() && blob_at(blobs, previous.2)? >= value)
                            {
                                return Err(Error::Format);
                            }
                        }
                        previous_attribute = Some((parent, attribute_type, value_offset));
                    }
                    schema::TABLE_ASSEMBLY => {
                        for _ in 0..4 {
                            row.u16()?;
                        }
                        row.u32()?;
                        string(&mut row, true)?;
                    }
                    schema::TABLE_ASSEMBLYREF => {
                        for _ in 0..4 {
                            row.u16()?;
                        }
                        row.u32()?;
                        blob(&mut row, false)?;
                        string(&mut row, true)?;
                        string(&mut row, false)?;
                        blob(&mut row, false)?;
                    }
                    _ => return Err(Error::Format),
                }
                if !row.finished() {
                    return Err(Error::Format);
                }
            }
        }
        if next_code_offset != code.len() {
            return Err(Error::Format);
        }
        self.validate_local_call_graph()?;
        Ok(())
    }

    fn validate_local_call_graph(&self) -> Result<()> {
        fn visit(
            assembly: &Assembly<'_>,
            method_index: u16,
            states: &mut [u8],
            depths: &mut [u16],
        ) -> Result<u16> {
            let slot = usize::from(method_index);
            match *states.get(slot).ok_or(Error::Bounds)? {
                1 => return Err(Error::Quota),
                2 => return depths.get(slot).copied().ok_or(Error::Bounds),
                _ => {}
            }
            states[slot] = 1;
            let method = assembly.method(method_index)?;
            let mut offset = 0usize;
            let mut max_depth = 1u16;
            while offset < method.code.len() {
                let end = instruction_end(method.code, offset, &assembly.rows)?;
                if matches!(method.code[offset], 0x28 | 0x6f | 0x73)
                    && *method.code.get(offset + 1).ok_or(Error::Bounds)? == schema::TABLE_METHODDEF
                {
                    let row = u16_at(method.code, offset + 2)?;
                    let target = row.checked_sub(1).ok_or(Error::Bounds)?;
                    let child_depth = visit(assembly, target, states, depths)?;
                    max_depth = max_depth.max(child_depth.checked_add(1).ok_or(Error::Quota)?);
                    if max_depth > 32 {
                        return Err(Error::Quota);
                    }
                }
                offset = end;
            }
            depths[slot] = max_depth;
            states[slot] = 2;
            Ok(max_depth)
        }

        let count = usize::from(self.row_count(schema::TABLE_METHODDEF)?);
        let mut states = Vec::new();
        states
            .try_reserve_exact(count)
            .map_err(|_| Error::Quota)?;
        states.resize(count, 0u8);
        let mut depths = Vec::new();
        depths
            .try_reserve_exact(count)
            .map_err(|_| Error::Quota)?;
        depths.resize(count, 0u16);
        for index in 0..count {
            visit(self, index as u16, &mut states, &mut depths)?;
        }
        Ok(())
    }
}

struct Row<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Row<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn u16(&mut self) -> Result<u16> {
        let value = u16_at(self.bytes, self.offset)?;
        self.offset += 2;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32> {
        let value = u32_at(self.bytes, self.offset)?;
        self.offset += 4;
        Ok(value)
    }
    fn index(&mut self, width: usize) -> Result<u16> {
        let value = match width {
            1 => u16::from(*self.bytes.get(self.offset).ok_or(Error::Format)?),
            2 => u16_at(self.bytes, self.offset)?,
            _ => return Err(Error::Format),
        };
        self.offset += width;
        Ok(value)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn table_list(row: &mut Row<'_>, count: u16) -> Result<()> {
    let width = if count <= 255 { 1 } else { 2 };
    let index = row.index(width)?;
    if index == 0 || index > count.saturating_add(1) {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn coded(
    value: u16,
    tag_bits: u8,
    tables: &[Option<u8>],
    rows: &[u16; 64],
    nil: bool,
) -> Result<()> {
    if value == 0 {
        return if nil { Ok(()) } else { Err(Error::Bounds) };
    }
    let tag_mask = (1u16 << tag_bits) - 1;
    let table = tables
        .get((value & tag_mask) as usize)
        .and_then(|table| *table)
        .ok_or(Error::Format)?;
    let index = value >> tag_bits;
    if index == 0 || index > rows[table as usize] {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn decode_coded(value: u16, tag_bits: u8, tables: &[Option<u8>]) -> Result<MetadataToken> {
    if value == 0 {
        return Err(Error::Bounds);
    }
    let tag_mask = (1u16 << tag_bits) - 1;
    let table = tables
        .get((value & tag_mask) as usize)
        .and_then(|table| *table)
        .ok_or(Error::Format)?;
    let row = value >> tag_bits;
    if row == 0 {
        return Err(Error::Bounds);
    }
    Ok(MetadataToken { table, row })
}

fn slice(bytes: &[u8], section: Section) -> Result<&[u8]> {
    let start = section.offset as usize;
    let end = start
        .checked_add(section.length as usize)
        .ok_or(Error::Format)?;
    bytes.get(start..end).ok_or(Error::Format)
}

fn validate_strings(bytes: &[u8]) -> Result<()> {
    if bytes.first() != Some(&0) || bytes.last() != Some(&0) {
        return Err(Error::Format);
    }
    for string in bytes[1..].split_inclusive(|byte| *byte == 0) {
        let text = string.strip_suffix(&[0]).ok_or(Error::Format)?;
        if text.is_empty() || core::str::from_utf8(text).is_err() {
            return Err(Error::Format);
        }
    }
    Ok(())
}

fn string_at(bytes: &[u8], offset: u16) -> Result<&str> {
    let offset = offset as usize;
    if offset == 0 {
        return Ok("");
    }
    if offset >= bytes.len() || bytes.get(offset.wrapping_sub(1)) != Some(&0) {
        return Err(Error::Bounds);
    }
    let end = bytes[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|length| offset + length)
        .ok_or(Error::Format)?;
    core::str::from_utf8(&bytes[offset..end]).map_err(|_| Error::Format)
}

fn validate_blobs(bytes: &[u8]) -> Result<()> {
    if bytes.first() != Some(&0) {
        return Err(Error::Format);
    }
    let mut cursor = 1usize;
    while cursor < bytes.len() {
        let first = bytes[cursor];
        let (header, length) = if first & 0x80 == 0 {
            (1, first as usize)
        } else if first & 0xc0 == 0x80 {
            let second = *bytes.get(cursor + 1).ok_or(Error::Format)?;
            let length = (usize::from(first & 0x3f) << 8) | usize::from(second);
            if length < 128 {
                return Err(Error::Format);
            }
            (2, length)
        } else {
            return Err(Error::Format);
        };
        cursor = cursor.checked_add(header + length).ok_or(Error::Format)?;
        if cursor > bytes.len() {
            return Err(Error::Format);
        }
    }
    Ok(())
}

fn blob_at(bytes: &[u8], offset: u16) -> Result<&[u8]> {
    let target = offset as usize;
    if target == 0 {
        return Ok(&[]);
    }
    let mut cursor = 1usize;
    while cursor < bytes.len() {
        let entry = cursor;
        let first = bytes[cursor];
        let (header, length) = if first & 0x80 == 0 {
            (1, first as usize)
        } else if first & 0xc0 == 0x80 {
            let second = *bytes.get(cursor + 1).ok_or(Error::Format)?;
            (2, (usize::from(first & 0x3f) << 8) | usize::from(second))
        } else {
            return Err(Error::Format);
        };
        let start = entry + header;
        let end = start.checked_add(length).ok_or(Error::Format)?;
        if end > bytes.len() {
            return Err(Error::Format);
        }
        if entry == target {
            return Ok(&bytes[start..end]);
        }
        if entry > target {
            return Err(Error::Bounds);
        }
        cursor = end;
    }
    Err(Error::Bounds)
}

fn instruction_end(code: &[u8], start: usize, rows: &[u16; 64]) -> Result<usize> {
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

fn branch_target(base: usize, delta: i32, code_length: usize) -> Result<usize> {
    let target = i64::try_from(base)
        .map_err(|_| Error::Quota)?
        .checked_add(i64::from(delta))
        .ok_or(Error::Quota)?;
    if target < 0 || target >= i64::try_from(code_length).map_err(|_| Error::Quota)? {
        return Err(Error::Bounds);
    }
    usize::try_from(target).map_err(|_| Error::Bounds)
}

fn is_instruction_start(code: &[u8], target: usize, rows: &[u16; 64]) -> Result<bool> {
    let mut cursor = 0;
    while cursor < target {
        cursor = instruction_end(code, cursor, rows)?;
    }
    Ok(cursor == target)
}

#[derive(Clone, Copy)]
struct MethodShape {
    has_this: bool,
    parameters: u16,
    returns: bool,
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

fn named_type<'a>(
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

fn same_stack_type(
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

fn same_method_types(
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

fn method_shape(bytes: &[u8], rows: &[u16; 64]) -> Result<MethodShape> {
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

fn local_count(bytes: &[u8]) -> Result<u16> {
    let mut signature = Signature { bytes, offset: 0 };
    if signature.byte()? != 0x07 {
        return Err(Error::Format);
    }
    u16::try_from(signature.compressed()?).map_err(|_| Error::Quota)
}

fn local_types_into(
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

fn referenced_method_shape(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<MethodShape> {
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

fn type_lists(assembly: &Assembly<'_>, index: u16) -> Result<(u16, u16)> {
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

fn list_owner(assembly: &Assembly<'_>, table: u8, target: u16) -> Result<u16> {
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

fn metadata_type(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<StackType> {
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

fn method_receiver(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<StackType> {
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

fn referenced_method_types(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<MethodTypes> {
    let mut parameters = Vec::new();
    let (receiver, result) = referenced_method_types_into(assembly, table, index, &mut parameters)?;
    Ok(MethodTypes {
        receiver,
        parameters,
        result,
    })
}

fn referenced_method_types_into(
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

fn field_type(assembly: &Assembly<'_>, index: u16) -> Result<(StackType, StackType)> {
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

fn merge_height(
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

fn validate_cil(code: &[u8], rows: &[u16; 64]) -> Result<()> {
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

fn validate_method_cil(
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

fn compatible(actual: StackType, expected: StackType) -> bool {
    actual == expected
        || (actual == StackType::Null && expected.reference())
        || (matches!(actual, StackType::Ref(_)) && expected == StackType::Ref(0))
}

fn pop_type(stack: &mut Vec<StackType>, expected: StackType) -> Result<()> {
    let actual = stack.pop().ok_or(Error::Format)?;
    if compatible(actual, expected) {
        Ok(())
    } else {
        Err(Error::Format)
    }
}

fn array_element(assembly: &Assembly<'_>, table: u8, index: u16) -> Result<u32> {
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

fn merge_types(
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

fn validate_cil_types(
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
enum SignatureKind {
    Field,
    Method,
    Locals,
}

fn validate_signature(bytes: &[u8], kind: SignatureKind, rows: &[u16; 64]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn minimal() -> Vec<u8> {
        let valid = (1u64 << schema::TABLE_MODULE)
            | (1u64 << schema::TABLE_TYPEDEF)
            | (1u64 << schema::TABLE_METHODDEF)
            | (1u64 << schema::TABLE_ASSEMBLY);
        let mut tables = alloc::vec![2, 0, 0, 0];
        tables.extend(valid.to_le_bytes());
        for _ in 0..4 {
            tables.extend(1u16.to_le_bytes());
        }
        tables.push(1); // Module.Name
        tables.extend([1, 1, 0, 0, 3, 0, 0, 0, 1, 1]); // public sealed TypeDef
        tables.extend([0, 0, 0, 0, 0, 0, 0x16, 0, 5, 1]); // public static MethodDef
        tables.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]); // Assembly
        let code = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a];
        let sections: [&[u8]; 4] = [&tables, b"\0M\0T\0Run\0A\0", &[0, 3, 0, 0, 1], &code];
        let header_size = 56usize;
        let file_size = header_size + sections.iter().map(|section| section.len()).sum::<usize>();
        let mut bytes = b"MC04".to_vec();
        bytes.extend([4, 0, 0, 0, 4, 2]);
        bytes.extend((header_size as u16).to_le_bytes());
        bytes.extend((file_size as u32).to_le_bytes());
        let mut offset = header_size;
        for (index, section) in sections.iter().enumerate() {
            bytes.extend([index as u8 + 1, 0]);
            bytes.extend((offset as u32).to_le_bytes());
            bytes.extend((section.len() as u32).to_le_bytes());
            offset += section.len();
        }
        for section in sections {
            bytes.extend(section);
        }
        bytes
    }

    fn minimal_body(body: &[u8], max_stack: u16) -> Vec<u8> {
        let mut bytes = minimal();
        let code_offset = u32_at(&bytes, 48).unwrap() as usize;
        bytes.truncate(code_offset + 12);
        bytes.extend(body);
        bytes[code_offset + 2..code_offset + 4].copy_from_slice(&max_stack.to_le_bytes());
        bytes[code_offset + 4..code_offset + 8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        bytes[52..56].copy_from_slice(&(12u32 + body.len() as u32).to_le_bytes());
        let total = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&total.to_le_bytes());
        bytes
    }

    #[test]
    fn mc04_sections_and_tables_are_borrowed() {
        let bytes = minimal();
        let assembly = Assembly::parse(&bytes).unwrap();
        assert_eq!(assembly.row_count(schema::TABLE_METHODDEF), Ok(1));
        assert_eq!(assembly.validate_lifecycle(0), Ok(()));
        assert_eq!(assembly.validate_lifecycle(1), Err(Error::Bounds));
        let method = assembly.method(0).unwrap();
        assert_eq!(method.name, "Run");
        assert_eq!(method.signature, [0, 0, 1]);
        assert!(method.local_signature.is_empty());
        assert_eq!(method.code, [0x2a]);
        assert_eq!(method.max_stack, 1);
        assert_eq!(method.flags & 0x10, 0x10);
        let code_section = assembly.section(schema::SECTION_CODE).unwrap();
        assert_eq!(method.code.as_ptr(), code_section[12..].as_ptr());
        assert_eq!(assembly.table(schema::TABLE_METHODDEF).unwrap().len(), 10);
        let code = assembly.section(schema::SECTION_CODE).unwrap();
        assert_eq!(code.last(), Some(&0x2a));
        assert_eq!(code.as_ptr(), bytes[bytes.len() - code.len()..].as_ptr());
    }

    #[test]
    fn mc04_rejects_recursive_local_call_graphs_before_execution() {
        let bytes = minimal_body(&[0x28, schema::TABLE_METHODDEF, 1, 0, 0x2a], 1);
        assert!(matches!(Assembly::parse(&bytes), Err(Error::Quota)));
    }

    #[test]
    fn mc04_lifecycle_requires_static_parameterless_void_method() {
        let mut bytes = minimal();
        let tables_offset = u32_at(&bytes, 18).unwrap() as usize;
        let method_flags = tables_offset + 4 + 8 + 8 + 1 + 10 + 6;
        bytes[method_flags] = 0;
        let assembly = Assembly::parse(&bytes).unwrap();
        assert_eq!(assembly.validate_lifecycle(0), Err(Error::Format));
    }

    #[test]
    fn cross_assembly_lookup_requires_public_type_and_method() {
        let bytes = minimal();
        let assembly = Assembly::parse(&bytes).unwrap();
        assert_eq!(assembly.find_method("", "T", "Run", &[0, 0, 1]), Ok(0));

        let tables_offset = u32_at(&bytes, 18).unwrap() as usize;
        let type_flags = tables_offset + 4 + 8 + 8 + 1;
        let method_flags = type_flags + 10 + 6;
        let mut hidden_method = bytes.clone();
        hidden_method[method_flags] = 0x10;
        let assembly = Assembly::parse(&hidden_method).unwrap();
        assert_eq!(
            assembly.find_method("", "T", "Run", &[0, 0, 1]),
            Err(Error::Missing)
        );

        let mut hidden_type = bytes;
        hidden_type[type_flags] = 0;
        let assembly = Assembly::parse(&hidden_type).unwrap();
        assert_eq!(
            assembly.find_method("", "T", "Run", &[0, 0, 1]),
            Err(Error::Missing)
        );
    }

    #[test]
    fn mc04_rejects_noncanonical_structure() {
        let valid = minimal();
        for offset in [0usize, 4, 5, 8, 9, 16, valid.len() - 4] {
            let mut bad = valid.clone();
            bad[offset] ^= 1;
            assert!(Assembly::parse(&bad).is_err(), "offset {offset}");
        }
        for length in 0..valid.len() {
            assert!(
                Assembly::parse(&valid[..length]).is_err(),
                "length {length}"
            );
        }
        let blob_offset = u32_at(&valid, 38).unwrap() as usize;
        let mut unsupported_signature = valid.clone();
        unsupported_signature[blob_offset + 4] = 0x0a;
        assert_eq!(
            Assembly::parse(&unsupported_signature).unwrap_err(),
            Error::Unsupported
        );
        let mut truncated_compressed_signature = valid;
        truncated_compressed_signature[blob_offset + 3] = 0x80;
        assert!(Assembly::parse(&truncated_compressed_signature).is_err());
    }

    #[test]
    fn mc04_rejects_forged_declaration_shapes() {
        let valid = include_bytes!("../../../fuzz/fixtures/counter.mca");
        let row_offset = |table, row| {
            let assembly = Assembly::parse(valid).unwrap();
            assembly.row(table, row).unwrap().as_ptr() as usize - valid.as_ptr() as usize
        };
        let type_row = {
            let assembly = Assembly::parse(valid).unwrap();
            (1..=assembly.row_count(schema::TABLE_TYPEDEF).unwrap())
                .find(|index| assembly.type_def(*index).unwrap().name != "<Module>")
                .unwrap()
        };

        let type_offset = row_offset(schema::TABLE_TYPEDEF, type_row);
        let mut interface_type = valid.to_vec();
        let flags = u32_at(&interface_type, type_offset).unwrap() | 0x20;
        interface_type[type_offset..type_offset + 4].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(Assembly::parse(&interface_type).unwrap_err(), Error::Format);

        let mut unsealed_type = valid.to_vec();
        let flags = u32_at(&unsealed_type, type_offset).unwrap() & !TYPE_SEALED;
        unsealed_type[type_offset..type_offset + 4].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(Assembly::parse(&unsealed_type).unwrap_err(), Error::Format);

        let extends_offset = {
            let assembly = Assembly::parse(valid).unwrap();
            let mut row = Row::new(assembly.row(schema::TABLE_TYPEDEF, type_row).unwrap());
            row.u32().unwrap();
            row.index(assembly.string_width).unwrap();
            row.index(assembly.string_width).unwrap();
            type_offset + row.offset
        };
        let mut inherited_type = valid.to_vec();
        inherited_type[extends_offset..extends_offset + 2]
            .copy_from_slice(&(type_row << 2).to_le_bytes());
        assert_eq!(Assembly::parse(&inherited_type).unwrap_err(), Error::Format);

        let field_offset = row_offset(schema::TABLE_FIELD, 1);
        let mut static_field = valid.to_vec();
        let flags = u16_at(&static_field, field_offset).unwrap() | 0x10;
        static_field[field_offset..field_offset + 2].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(Assembly::parse(&static_field).unwrap_err(), Error::Format);

        let field_signature_offset = {
            let assembly = Assembly::parse(valid).unwrap();
            let mut row = Row::new(assembly.row(schema::TABLE_FIELD, 1).unwrap());
            row.u16().unwrap();
            row.index(assembly.string_width).unwrap();
            let blob = row.index(assembly.blob_width).unwrap();
            blob_at(assembly.section(schema::SECTION_BLOB).unwrap(), blob)
                .unwrap()
                .as_ptr() as usize
                - valid.as_ptr() as usize
        };
        let mut byte_field = valid.to_vec();
        byte_field[field_signature_offset + 1] = 0x05;
        assert_eq!(Assembly::parse(&byte_field).unwrap_err(), Error::Format);

        let method_offset = row_offset(schema::TABLE_METHODDEF, 1);
        let mut virtual_method = valid.to_vec();
        let flags = u16_at(&virtual_method, method_offset + 6).unwrap() | 0x40;
        virtual_method[method_offset + 6..method_offset + 8].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(Assembly::parse(&virtual_method).unwrap_err(), Error::Format);

        let mut native_method = valid.to_vec();
        native_method[method_offset + 4..method_offset + 6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(Assembly::parse(&native_method).unwrap_err(), Error::Format);
    }

    #[test]
    fn mc04_signatures_enforce_profile_and_remapped_type_tokens() {
        let mut rows = [0u16; 64];
        rows[schema::TABLE_TYPEDEF as usize] = 1;
        rows[schema::TABLE_TYPEREF as usize] = 1;
        assert_eq!(
            validate_signature(&[0, 0, 0x12, 4], SignatureKind::Method, &rows),
            Ok(())
        );
        assert_eq!(
            validate_signature(&[6, 8], SignatureKind::Field, &rows),
            Ok(())
        );
        assert_eq!(
            validate_signature(&[7, 1, 8], SignatureKind::Locals, &rows),
            Ok(())
        );
        assert_eq!(
            validate_signature(&[0, 0, 0x12, 8], SignatureKind::Method, &rows),
            Err(Error::Bounds)
        );
        assert_eq!(
            validate_signature(&[0, 0, 0x12, 0x80, 4], SignatureKind::Method, &rows),
            Err(Error::Format)
        );
        assert_eq!(
            validate_signature(&[0, 0, 0x0a], SignatureKind::Method, &rows),
            Err(Error::Unsupported)
        );
        assert_eq!(
            validate_signature(&[0x80, 0, 1], SignatureKind::Method, &rows),
            Err(Error::Format)
        );
        let mut maximum_parameters = alloc::vec![0, 32, 1];
        maximum_parameters.extend(core::iter::repeat_n(0x08, 32));
        assert_eq!(
            validate_signature(&maximum_parameters, SignatureKind::Method, &rows),
            Ok(())
        );
        assert_eq!(
            validate_signature(&[0, 33, 1], SignatureKind::Method, &rows),
            Err(Error::Quota)
        );
    }

    #[test]
    fn mc04_cil_enforces_opcode_operands_tokens_and_branch_boundaries() {
        let mut rows = [0u16; 64];
        rows[schema::TABLE_MEMBERREF as usize] = 1;
        assert_eq!(validate_cil(&[0x16, 0x2b, 0xfd], &rows), Ok(()));
        assert_eq!(validate_cil(&[0x28, 10, 1, 0, 0x2a], &rows), Ok(()));
        assert_eq!(validate_cil(&[0x28, 10, 2, 0], &rows), Err(Error::Bounds));
        assert_eq!(validate_cil(&[0x28, 4, 1, 0], &rows), Err(Error::Bounds));
        assert_eq!(
            validate_cil(&[0x20, 0, 0, 0, 0, 0x2b, 0xfa], &rows),
            Err(Error::Bounds)
        );
        assert_eq!(validate_cil(&[0x20, 0, 0], &rows), Err(Error::Bounds));
        let mut bounded_switch = alloc::vec![0x45];
        bounded_switch.extend_from_slice(&256u32.to_le_bytes());
        bounded_switch.resize(1 + 4 + 256 * 4, 0);
        bounded_switch.push(0x2a);
        assert_eq!(validate_cil(&bounded_switch, &rows), Ok(()));
        let mut oversized_switch = alloc::vec![0x45];
        oversized_switch.extend_from_slice(&257u32.to_le_bytes());
        oversized_switch.resize(1 + 4 + 257 * 4, 0);
        oversized_switch.push(0x2a);
        assert_eq!(validate_cil(&oversized_switch, &rows), Err(Error::Quota));
        assert_eq!(validate_cil(&[0x01], &rows), Err(Error::Unsupported));
        assert_eq!(validate_cil(&[0xe0], &rows), Err(Error::Unsupported));
        assert_eq!(validate_cil(&[0xfe, 1], &rows), Ok(()));
        assert_eq!(validate_cil(&[0xfe], &rows), Err(Error::Bounds));
        for suffix in [0, 6, 255] {
            assert_eq!(validate_cil(&[0xfe, suffix], &rows), Err(Error::Unsupported));
        }
    }

    #[test]
    fn mc04_method_stack_control_flow_and_variable_bounds_are_verified() {
        Assembly::parse(&minimal_body(&[0x16, 0x26, 0x2a], 1)).unwrap();
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x26, 0x2a], 1)).unwrap_err(),
            Error::Format
        );
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x16, 0x17, 0x2a], 1)).unwrap_err(),
            Error::Quota
        );
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x16, 0x2d, 3, 0x16, 0x2b, 0, 0x2a], 1)).unwrap_err(),
            Error::Format
        );
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x02, 0x26, 0x2a], 1)).unwrap_err(),
            Error::Bounds
        );
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x16, 0x2a], 1)).unwrap_err(),
            Error::Format
        );
        assert_eq!(
            Assembly::parse(&minimal_body(&[0x00], 1)).unwrap_err(),
            Error::Bounds
        );
    }

    #[test]
    fn mc04_direct_executor_uses_verified_borrowed_cil() {
        let mut bytes = minimal_body(&[0x18, 0x19, 0x58, 0x2a], 2);
        let blob_offset = u32_at(&bytes, 38).unwrap() as usize;
        bytes[blob_offset + 4] = 0x08; // int32 return type
        let assembly = Assembly::parse(&bytes).unwrap();
        assert_eq!(crate::mc04_vm::execute(&assembly, 0, &[]), Ok(Some(5)));
    }

    #[test]
    fn mc04_stack_types_reject_scalar_reference_array_and_merge_confusion() {
        let bytes = minimal();
        let assembly = Assembly::parse(&bytes).unwrap();
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x16, 0x17, 0x58, 0x26, 0x2a],
                None,
                &[],
                &[],
                None,
            ),
            Ok(())
        );
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x02, 0x16, 0x58, 0x26, 0x2a],
                Some(StackType::Ref(9)),
                &[],
                &[],
                None,
            ),
            Err(Error::Format)
        );
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x16, 0x0a, 0x2a],
                None,
                &[],
                &[StackType::Array(1)],
                None,
            ),
            Err(Error::Format)
        );
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x16, 0x2a],
                None,
                &[],
                &[],
                Some(StackType::Array(1)),
            ),
            Err(Error::Format)
        );
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x16, 0x16, 0x2d, 4, 0x26, 0x02, 0x2b, 0, 0x26, 0x2a],
                Some(StackType::Ref(9)),
                &[],
                &[],
                None,
            ),
            Err(Error::Format)
        );
        assert_eq!(
            validate_cil_types(
                &assembly,
                &[0x02, 0x16, 0x94, 0x26, 0x2a],
                None,
                &[StackType::Array(1)],
                &[],
                None,
            ),
            Err(Error::Format)
        );
    }

    #[test]
    fn local_signature_scratch_is_reused_and_cleared_on_rejection() {
        let rows = [0u16; 64];
        let mut types = Vec::new();
        local_types_into(&[0x07, 2, 0x08, 0x1d, 0x05], &rows, &mut types).unwrap();
        assert_eq!(types, [StackType::Int, StackType::Array(1)]);
        let allocation = types.as_ptr();
        let capacity = types.capacity();

        local_types_into(&[0x07, 1, 0x08], &rows, &mut types).unwrap();
        assert_eq!(types, [StackType::Int]);
        assert_eq!(types.as_ptr(), allocation);
        assert_eq!(types.capacity(), capacity);

        assert_eq!(
            local_types_into(&[0x07, 65], &rows, &mut types),
            Err(Error::Quota)
        );
        assert!(types.is_empty());
        assert_eq!(types.as_ptr(), allocation);
        assert_eq!(types.capacity(), capacity);
    }
}
