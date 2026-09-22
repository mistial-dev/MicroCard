use super::super::*;
use super::support::{minimal, minimal_body};

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
    let valid = include_bytes!("../../../../../fuzz/fixtures/counter.mca");
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
