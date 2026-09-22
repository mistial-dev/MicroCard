use super::super::*;
use super::support::{minimal, minimal_body};

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
        assert_eq!(
            validate_cil(&[0xfe, suffix], &rows),
            Err(Error::Unsupported)
        );
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
