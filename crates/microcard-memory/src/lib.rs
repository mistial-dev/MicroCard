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
