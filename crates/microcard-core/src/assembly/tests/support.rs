use super::super::*;
use alloc::vec::Vec;

pub(super) fn minimal() -> Vec<u8> {
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

pub(super) fn minimal_body(body: &[u8], max_stack: u16) -> Vec<u8> {
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
