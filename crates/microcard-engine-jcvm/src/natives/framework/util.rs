//! `javacard.framework.Util` checked array operations.

use super::super::Native;
use crate::jcvm_api::MethodId;
use crate::vm::frame::Frame;
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};

pub(in crate::natives) fn call(
    name: MethodId,
    heap: &mut Heap,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Native> {
    match name {
        MethodId::makeShort => {
            let low = frame.pop_short()?;
            let high = frame.pop_short()?;
            frame.push_short((((high as u16) << 8) | (low as u8 as u16)) as i16)?;
        }
        MethodId::getShort => {
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            let bytes = heap.byte_slice(array, index(offset)?, 2)?;
            frame.push_short(i16::from_be_bytes([bytes[0], bytes[1]]))?;
        }
        MethodId::setShort => {
            let value = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            heap.byte_slice_mut(array, index(offset)?, 2)?
                .copy_from_slice(&value.to_be_bytes());
            frame.push_short(offset.wrapping_add(2))?;
        }
        MethodId::arrayCopy | MethodId::arrayCopyNonAtomic => {
            let length = frame.pop_short()?;
            let destination_offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let source_offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            heap.check_access(source, context)?;
            heap.check_access(destination, context)?;
            let length = index(length)?;
            heap.byte_slice(source, index(source_offset)?, length)?;
            heap.byte_slice(destination, index(destination_offset)?, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            if name == MethodId::arrayCopy {
                heap.copy_bytes(
                    source,
                    index(source_offset)?,
                    destination,
                    index(destination_offset)?,
                    length,
                )?;
            } else {
                heap.copy_bytes_unconditional(
                    source,
                    index(source_offset)?,
                    destination,
                    index(destination_offset)?,
                    length,
                )?;
            }
            frame.push_short(destination_offset.wrapping_add(length as i16))?;
        }
        MethodId::arrayFill | MethodId::arrayFillNonAtomic => {
            let value = frame.pop_short()?;
            let length = index(frame.pop_short()?)?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            heap.check_access(array, context)?;
            let start = index(offset)?;
            heap.byte_slice(array, start, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            if name == MethodId::arrayFill {
                heap.byte_slice_mut(array, start, length)?.fill(value as u8);
            } else {
                heap.fill_bytes_unconditional(array, start, length, value as u8)?;
            }
            frame.push_short(offset.wrapping_add(length as i16))?;
        }
        MethodId::arrayCompare => {
            let length = frame.pop_short()?;
            let right_offset = frame.pop_short()?;
            let right = frame.pop_reference()?;
            let left_offset = frame.pop_short()?;
            let left = frame.pop_reference()?;
            heap.check_access(left, context)?;
            heap.check_access(right, context)?;
            let length = index(length)?;
            // Validate both full ranges even when comparison stops at the first byte.
            let left = heap.byte_slice(left, index(left_offset)?, length)?;
            let right = heap.byte_slice(right, index(right_offset)?, length)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let answer = match left.cmp(right) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            };
            frame.push_short(answer)?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}

fn index(value: i16) -> Result<usize> {
    if value < 0 {
        return Err(Error::Bounds);
    }
    Ok(value as usize)
}
