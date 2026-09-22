use super::super::*;
use alloc::vec::Vec;

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
