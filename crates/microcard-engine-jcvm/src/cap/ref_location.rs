//! The Reference Location component, JCVM 3.x §6.12.
//!
//! Two lists of offsets into the Method component, one for every one-byte constant pool
//! index in the bytecode and one for every two-byte index. A linker that rewrites indices
//! into addresses walks these to find what to patch.
//!
//! This engine does not rewrite anything. It keeps the image position independent and uses
//! the lists as proof instead. Every listed offset must be the operand of an instruction
//! that really does take a constant pool index, and every index must be in range. That
//! turns the component from a list of places to patch into a statement the card can check.
use crate::{Error, Result};

/// The offset lists of one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefLocation<'a> {
    one_byte: &'a [u8],
    two_byte: &'a [u8],
}

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

impl<'a> RefLocation<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let head = info.get(..2).ok_or(Error::Bounds)?;
        let one_byte_count = u16::from_be_bytes([head[0], head[1]]) as usize;
        let one_byte = info.get(2..2 + one_byte_count).ok_or(Error::Bounds)?;
        let at = 2 + one_byte_count;
        let tail = info.get(at..at + 2).ok_or(Error::Bounds)?;
        let two_byte_count = u16::from_be_bytes([tail[0], tail[1]]) as usize;
        let two_byte = info
            .get(at + 2..at + 2 + two_byte_count)
            .ok_or(Error::Bounds)?;
        if at + 2 + two_byte_count != info.len() {
            return Err(Error::Format);
        }
        Ok(Self { one_byte, two_byte })
    }

    /// Offsets into the Method component of every one-byte constant pool index.
    pub fn one_byte_indices(&self) -> impl Iterator<Item = Result<usize>> + use<'a> {
        offsets(self.one_byte)
    }

    /// Offsets into the Method component of every two-byte constant pool index.
    pub fn two_byte_indices(&self) -> impl Iterator<Item = Result<usize>> + use<'a> {
        offsets(self.two_byte)
    }
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
        let decoded: Vec<usize> = RefLocation::parse(&info)
            .unwrap()
            .one_byte_indices()
            .map(Result::unwrap)
            .collect();
        assert_eq!(decoded, [10, 65, 580, 835, 843]);
    }

    #[test]
    fn the_two_lists_are_kept_apart() {
        let info = component(&[4, 4], &[9]);
        let location = RefLocation::parse(&info).unwrap();
        let one: Vec<usize> = location.one_byte_indices().map(Result::unwrap).collect();
        let two: Vec<usize> = location.two_byte_indices().map(Result::unwrap).collect();
        assert_eq!(one, [4, 8]);
        // The second list counts from its own start, because it describes different
        // operands rather than continuing the first.
        assert_eq!(two, [9]);
    }

    #[test]
    fn a_list_longer_than_the_component_is_refused() {
        let mut info = component(&[1, 2], &[3]);
        info[1] = 9;
        assert_eq!(RefLocation::parse(&info), Err(Error::Bounds));
        // Trailing bytes mean a layout this parser cannot read.
        let mut longer = component(&[1], &[2]);
        longer.push(0);
        assert_eq!(RefLocation::parse(&longer), Err(Error::Format));
        assert_eq!(RefLocation::parse(&[0]), Err(Error::Bounds));
        // Both lists empty is legal for a package that references nothing.
        assert_eq!(
            RefLocation::parse(&[0, 0, 0, 0]).unwrap().one_byte_indices().count(),
            0
        );
    }

    #[test]
    fn a_run_of_continuations_with_no_end_yields_nothing_further() {
        // The list stops mid distance, so there is no offset to report rather than a
        // partial one.
        let info = component(&[10, 255, 255], &[]);
        let decoded: Vec<Result<usize>> = RefLocation::parse(&info)
            .unwrap()
            .one_byte_indices()
            .collect();
        assert_eq!(decoded, [Ok(10)]);
    }
}
