//! Checked storage arithmetic shared by the independent firmware engines.
#![no_std]

use core::ops::Range;

/// Plan a bump allocation without changing storage or the allocation cursor.
/// Engines commit the returned end only after allocation and initialization succeed.
pub fn allocation_range(
    used: usize,
    header: usize,
    count: usize,
    element_bytes: usize,
    alignment: usize,
    limit: usize,
) -> Option<Range<usize>> {
    if !alignment.is_power_of_two() || !used.is_multiple_of(alignment) || element_bytes == 0 {
        return None;
    }
    let size = count.checked_mul(element_bytes)?.checked_add(header)?;
    let size = size.checked_add(alignment - 1)? & !(alignment - 1);
    let end = used.checked_add(size)?;
    (end <= limit).then_some(used..end)
}

/// Validate a complete slice range, including empty ranges at its end.
pub fn byte_range(size: usize, offset: usize, length: usize) -> Option<Range<usize>> {
    let end = offset.checked_add(length)?;
    (end <= size).then_some(offset..end)
}

/// Copy validated ranges in one slab using the CPU's overlap-safe memory operation.
pub fn copy_bytes(
    bytes: &mut [u8],
    source: usize,
    destination: usize,
    length: usize,
) -> Option<()> {
    let source = byte_range(bytes.len(), source, length)?;
    byte_range(bytes.len(), destination, length)?;
    bytes.copy_within(source, destination);
    Some(())
}
