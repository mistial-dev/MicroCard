//! Zero-copy structural parser for the MC04 embedded ECMA-335 profile.
use crate::{mc04_opcodes as opcodes, mc04_schema as schema, Error, Result};
use alloc::vec::Vec;

mod metadata;
mod validation;

use metadata::*;
use validation::*;

pub use validation::{MethodTypes, StackType};

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
                if !capabilities.contains(&crate::native_abi::capability(id)) {
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
        uses.try_reserve_exact(usize::from(self.row_count(schema::TABLE_MEMBERREF)?))
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
            public_key_or_token: blob_at(self.section(schema::SECTION_BLOB)?, public_key_or_token)?,
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
        states.try_reserve_exact(count).map_err(|_| Error::Quota)?;
        states.resize(count, 0u8);
        let mut depths = Vec::new();
        depths.try_reserve_exact(count).map_err(|_| Error::Quota)?;
        depths.resize(count, 0u16);
        for index in 0..count {
            visit(self, index as u16, &mut states, &mut depths)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
