use super::{u16_at, u32_at, MetadataToken, Section};
use crate::{Error, Result};

pub(super) struct Row<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> Row<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(super) fn u16(&mut self) -> Result<u16> {
        let value = u16_at(self.bytes, self.offset)?;
        self.offset += 2;
        Ok(value)
    }
    pub(super) fn u32(&mut self) -> Result<u32> {
        let value = u32_at(self.bytes, self.offset)?;
        self.offset += 4;
        Ok(value)
    }
    pub(super) fn index(&mut self, width: usize) -> Result<u16> {
        let value = match width {
            1 => u16::from(*self.bytes.get(self.offset).ok_or(Error::Format)?),
            2 => u16_at(self.bytes, self.offset)?,
            _ => return Err(Error::Format),
        };
        self.offset += width;
        Ok(value)
    }
    pub(super) fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

pub(super) fn table_list(row: &mut Row<'_>, count: u16) -> Result<()> {
    let width = if count <= 255 { 1 } else { 2 };
    let index = row.index(width)?;
    if index == 0 || index > count.saturating_add(1) {
        return Err(Error::Bounds);
    }
    Ok(())
}

pub(super) fn coded(
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

pub(super) fn decode_coded(
    value: u16,
    tag_bits: u8,
    tables: &[Option<u8>],
) -> Result<MetadataToken> {
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

pub(super) fn slice(bytes: &[u8], section: Section) -> Result<&[u8]> {
    let start = section.offset as usize;
    let end = start
        .checked_add(section.length as usize)
        .ok_or(Error::Format)?;
    bytes.get(start..end).ok_or(Error::Format)
}

pub(super) fn validate_strings(bytes: &[u8]) -> Result<()> {
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

pub(super) fn string_at(bytes: &[u8], offset: u16) -> Result<&str> {
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

pub(super) fn validate_blobs(bytes: &[u8]) -> Result<()> {
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

pub(super) fn blob_at(bytes: &[u8], offset: u16) -> Result<&[u8]> {
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
