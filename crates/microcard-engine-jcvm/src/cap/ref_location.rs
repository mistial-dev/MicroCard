//! The Reference Location component, JCVM 3.x §6.12.
//!
//! Two lists of offsets into the Method component, one for every one-byte constant pool
//! index in the bytecode and one for every two-byte index. A linker that rewrites indices
//! into addresses walks these to find what to patch.
//!
//! This engine does not rewrite anything. The loader validates both lists and their Method
//! component bounds, then discards the component before constructing the runtime view.
use crate::{Error, Result};

/// Offsets are stored as distances from the previous one, JCVM §6.12.
///
/// A distance of 255 or more is written as that many entries of 255 followed by the
/// remainder, so a single entry of 255 never ends a run. Decoding therefore has to
/// accumulate rather than take each byte as an offset.
fn offsets(jumps: &[u8]) -> impl Iterator<Item = Result<usize>> + use<'_> {
    let mut at: usize = 0;
    let mut rest = jumps;
    core::iter::from_fn(move || {
        let mut distance: usize = 0;
        loop {
            let (&jump, remainder) = rest.split_first()?;
            rest = remainder;
            distance += jump as usize;
            if jump != 255 {
                break;
            }
        }
        at = match at.checked_add(distance) {
            Some(value) => value,
            None => return Some(Err(Error::Bounds)),
        };
        Some(Ok(at))
    })
}

fn lists(info: &[u8]) -> Result<(&[u8], &[u8])> {
    let head = info.get(..2).ok_or(Error::Bounds)?;
    let one_byte_count = u16::from_be_bytes([head[0], head[1]]) as usize;
    let one_byte_end = 2usize.checked_add(one_byte_count).ok_or(Error::Bounds)?;
    let one_byte = info.get(2..one_byte_end).ok_or(Error::Bounds)?;
    let tail = info
        .get(one_byte_end..one_byte_end + 2)
        .ok_or(Error::Bounds)?;
    let two_byte_count = u16::from_be_bytes([tail[0], tail[1]]) as usize;
    let two_byte_start = one_byte_end + 2;
    let two_byte_end = two_byte_start
        .checked_add(two_byte_count)
        .ok_or(Error::Bounds)?;
    let two_byte = info
        .get(two_byte_start..two_byte_end)
        .ok_or(Error::Bounds)?;
    if two_byte_end != info.len() {
        return Err(Error::Format);
    }
    Ok((one_byte, two_byte))
}

fn validate_offsets(jumps: &[u8], method_size: usize, width: usize) -> Result<()> {
    if jumps.last() == Some(&255) {
        return Err(Error::Format);
    }
    let mut previous = None;
    for offset in offsets(jumps) {
        let offset = offset?;
        if previous.is_some_and(|last| last >= offset) {
            return Err(Error::Format);
        }
        if offset.checked_add(width).is_none_or(|end| end > method_size) {
            return Err(Error::Bounds);
        }
        previous = Some(offset);
    }
    Ok(())
}

/// Validate a Reference Location component without retaining a runtime representation.
pub(super) fn validate(info: &[u8], method_size: usize) -> Result<()> {
    let (one_byte, two_byte) = lists(info)?;
    validate_offsets(one_byte, method_size, 1)?;
    validate_offsets(two_byte, method_size, 2)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn component(one: &[u8], two: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from((one.len() as u16).to_be_bytes());
        bytes.extend_from_slice(one);
        bytes.extend_from_slice(&(two.len() as u16).to_be_bytes());
        bytes.extend_from_slice(two);
        bytes
    }

    #[test]
    fn the_example_from_the_specification_decodes_to_its_offsets() {
        // JCVM Table 6-16, which is the case that shows a distance of 255 is a continuation
        // and never an offset on its own.
        let info = component(&[10, 55, 255, 255, 5, 255, 0, 8], &[]);
        let (one_byte, _) = lists(&info).unwrap();
        let decoded: Vec<usize> = offsets(one_byte).map(Result::unwrap).collect();
        assert_eq!(decoded, [10, 65, 580, 835, 843]);
        validate(&info, 844).unwrap();
    }

    #[test]
    fn the_two_lists_are_kept_apart() {
        let info = component(&[4, 4], &[9]);
        let (one_byte, two_byte) = lists(&info).unwrap();
        let one: Vec<usize> = offsets(one_byte).map(Result::unwrap).collect();
        let two: Vec<usize> = offsets(two_byte).map(Result::unwrap).collect();
        assert_eq!(one, [4, 8]);
        // The second list counts from its own start, because it describes different
        // operands rather than continuing the first.
        assert_eq!(two, [9]);
    }

    #[test]
    fn a_list_longer_than_the_component_is_refused() {
        let mut info = component(&[1, 2], &[3]);
        info[1] = 9;
        assert_eq!(validate(&info, 10), Err(Error::Bounds));
        // Trailing bytes mean a layout this parser cannot read.
        let mut longer = component(&[1], &[2]);
        longer.push(0);
        assert_eq!(validate(&longer, 10), Err(Error::Format));
        assert_eq!(validate(&[0], 10), Err(Error::Bounds));
        // Both lists empty is legal for a package that references nothing.
        assert_eq!(
            validate(&[0, 0, 0, 0], 0),
            Ok(())
        );
    }

    #[test]
    fn a_run_of_continuations_with_no_end_is_refused() {
        let info = component(&[10, 255, 255], &[]);
        assert_eq!(validate(&info, 1024), Err(Error::Format));
    }
}
