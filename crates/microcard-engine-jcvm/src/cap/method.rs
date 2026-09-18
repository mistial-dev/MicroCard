//! The Method component, JCVM 3.x §6.10.
//!
//! One handler table for the whole package, then every method laid end to end. A method
//! carries no length of its own, so where one ends is only known from where the next
//! begins. That is why walking this component needs the method offsets the Class and Applet
//! components hold, and why nothing here guesses at extents.
use crate::{Error, Result};

/// Method header flags, JCVM Table 6-12.
pub const ACC_EXTENDED: u8 = 0x8;
pub const ACC_ABSTRACT: u8 = 0x4;

/// One entry of the package-wide exception handler table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler {
    /// Start of the range this handler covers, as an offset into the Method component.
    pub start_offset: u16,
    /// Length of that range. Zero covers nothing, which the specification allows.
    pub active_length: u16,
    /// Where control goes, as an offset into the Method component.
    pub handler_offset: u16,
    /// Class reference of the caught type, or zero for a finally block that catches all.
    pub catch_type_index: u16,
    /// Last handler of a nested group.
    ///
    /// This is what makes a flat table behave like nested `try` blocks. A search walks
    /// handlers in order and stops at the one carrying this bit, so getting it wrong lets
    /// an exception escape one scope too far and be caught by the wrong block.
    pub stop: bool,
}

impl Handler {
    /// Whether this handler covers a given offset in the Method component.
    pub fn covers(&self, offset: u16) -> bool {
        offset >= self.start_offset
            && (offset as u32) < self.start_offset as u32 + self.active_length as u32
    }
}

/// A method header, JCVM §6.10.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodHeader {
    pub flags: u8,
    /// Words of operand stack the method needs at its deepest.
    pub max_stack: u8,
    /// Words of argument, including the receiver for an instance method.
    pub nargs: u8,
    /// Words of local variable declared by the method, which excludes its parameters,
    /// JCVM §6.10.4. A frame holds `nargs + max_locals` words of locals.
    pub max_locals: u8,
    /// Bytes the header itself occupies, which is where the bytecode starts.
    pub length: usize,
}

impl MethodHeader {
    pub fn abstract_method(&self) -> bool {
        self.flags & ACC_ABSTRACT != 0
    }

    /// Words a frame needs for this method's locals.
    ///
    /// Parameters arrive in the same array as the declared locals and are counted
    /// separately in the header, so a frame sized from `max_locals` alone would let a
    /// method write past its own locals into whatever the frame arena held next.
    pub fn frame_words(&self) -> u16 {
        self.nargs as u16 + self.max_locals as u16
    }

    /// Read the header at an offset into the Method component.
    pub fn parse(component: &[u8], at: usize) -> Result<Self> {
        let first = *component.get(at).ok_or(Error::Bounds)?;
        let flags = first >> 4;
        // Every other flag is reserved and must be zero, JCVM Table 6-12. A package setting
        // one is refused here instead of having it silently ignored.
        if flags & !(ACC_EXTENDED | ACC_ABSTRACT) != 0 {
            return Err(Error::Format);
        }
        if flags & ACC_EXTENDED != 0 {
            let bytes = component.get(at..at + 4).ok_or(Error::Bounds)?;
            // The low nibble of the first byte is padding and has to be zero.
            if bytes[0] & 0x0f != 0 {
                return Err(Error::Format);
            }
            Ok(Self {
                flags,
                max_stack: bytes[1],
                nargs: bytes[2],
                max_locals: bytes[3],
                length: 4,
            })
        } else {
            let bytes = component.get(at..at + 2).ok_or(Error::Bounds)?;
            Ok(Self {
                flags,
                max_stack: bytes[0] & 0x0f,
                nargs: bytes[1] >> 4,
                max_locals: bytes[1] & 0x0f,
                length: 2,
            })
        }
    }
}

/// The Method component of one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method<'a> {
    info: &'a [u8],
    handler_count: u8,
}

impl<'a> Method<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let &handler_count = info.first().ok_or(Error::Bounds)?;
        let table = 1 + handler_count as usize * 8;
        if info.len() < table {
            return Err(Error::Bounds);
        }
        let method = Self {
            info,
            handler_count,
        };
        for handler in method.handlers() {
            // A handler pointing outside the component could send control anywhere, and its
            // range has to stay inside as well.
            let end = handler.start_offset as u32 + handler.active_length as u32;
            if end > info.len() as u32 || handler.handler_offset as usize >= info.len() {
                return Err(Error::Bounds);
            }
        }
        Ok(method)
    }

    pub fn handler_count(&self) -> usize {
        self.handler_count as usize
    }

    pub fn handlers(&self) -> impl Iterator<Item = Handler> + use<'a> {
        let info = self.info;
        (0..self.handler_count as usize).map(move |index| {
            let at = 1 + index * 8;
            let word = |offset: usize| u16::from_be_bytes([info[at + offset], info[at + offset + 1]]);
            let bitfield = word(2);
            Handler {
                start_offset: word(0),
                stop: bitfield & 0x8000 != 0,
                active_length: bitfield & 0x7fff,
                handler_offset: word(4),
                catch_type_index: word(6),
            }
        })
    }

    /// Where the method area starts, which is the first offset a method may sit at.
    pub fn methods_start(&self) -> usize {
        1 + self.handler_count as usize * 8
    }

    /// The whole component, which every offset in the Class and Applet components counts
    /// from. Bytecode offsets inside a method count from its own header instead.
    pub fn bytes(&self) -> &'a [u8] {
        self.info
    }

    /// The header and the bytecode of the method starting at `at` and ending at `end`.
    ///
    /// The caller supplies `end`, because a method records no length. It comes from the next
    /// method in offset order, or from the end of the component for the last one.
    pub fn method(&self, at: usize, end: usize) -> Result<(MethodHeader, &'a [u8])> {
        if at < self.methods_start() || end > self.info.len() || at >= end {
            return Err(Error::Bounds);
        }
        let header = MethodHeader::parse(self.info, at)?;
        let code = self.info.get(at + header.length..end).ok_or(Error::Bounds)?;
        // An abstract method declares no body, JCVM §6.10.4.
        if header.abstract_method() && !code.is_empty() {
            return Err(Error::Format);
        }
        Ok((header, code))
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn handler(start: u16, length: u16, target: u16, catch: u16, stop: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&start.to_be_bytes());
        bytes.extend_from_slice(&(length | if stop { 0x8000 } else { 0 }).to_be_bytes());
        bytes.extend_from_slice(&target.to_be_bytes());
        bytes.extend_from_slice(&catch.to_be_bytes());
        bytes
    }

    fn component(handlers: &[Vec<u8>], methods: &[u8]) -> Vec<u8> {
        let mut bytes = alloc::vec![handlers.len() as u8];
        for entry in handlers {
            bytes.extend_from_slice(entry);
        }
        bytes.extend_from_slice(methods);
        bytes
    }

    #[test]
    fn a_standard_header_packs_four_fields_into_two_bytes() {
        // max_stack 3, nargs 2, max_locals 5.
        let bytes = alloc::vec![0x03, 0x25, 0x00];
        let header = MethodHeader::parse(&bytes, 0).unwrap();
        assert_eq!(header.flags, 0);
        assert_eq!((header.max_stack, header.nargs, header.max_locals), (3, 2, 5));
        // Parameters sit in the same array as the declared locals, so a frame needs both.
        assert_eq!(header.frame_words(), 7);
        assert_eq!(header.length, 2);
        assert!(!header.abstract_method());
    }

    #[test]
    fn an_extended_header_gives_each_field_a_whole_byte() {
        let bytes = alloc::vec![0x80, 40, 9, 60];
        let header = MethodHeader::parse(&bytes, 0).unwrap();
        assert_eq!(header.flags, ACC_EXTENDED);
        // These are the values a standard header cannot express, which is the only reason
        // the extended form exists.
        assert_eq!((header.max_stack, header.nargs, header.max_locals), (40, 9, 60));
        assert_eq!(header.length, 4);
    }

    #[test]
    fn reserved_flag_bits_and_padding_have_to_be_zero() {
        // A reserved flag would silently change the meaning of the header.
        assert_eq!(MethodHeader::parse(&[0x13, 0x00], 0), Err(Error::Format));
        assert_eq!(MethodHeader::parse(&[0x23, 0x00], 0), Err(Error::Format));
        // Padding in an extended header.
        assert_eq!(MethodHeader::parse(&[0x81, 1, 1, 1], 0), Err(Error::Format));
        // A header that does not fit.
        assert_eq!(MethodHeader::parse(&[0x03], 0), Err(Error::Bounds));
        assert_eq!(MethodHeader::parse(&[0x80, 1, 1], 0), Err(Error::Bounds));
    }

    #[test]
    fn the_handler_table_reads_back_with_its_nesting_marked() {
        // Two handlers over the same range, the inner one first, the outer one closing the
        // group. This is how a nested try reaches a flat table. Every offset counts from
        // the start of the component, so they all land inside the method area below.
        let info = component(
            &[handler(19, 2, 20, 7, false), handler(19, 2, 21, 0, true)],
            &[0x03, 0x25, 0x11, 0x22, 0x7a],
        );
        let method = Method::parse(&info).unwrap();
        assert_eq!(method.handler_count(), 2);
        assert_eq!(method.methods_start(), 17);
        let all: Vec<Handler> = method.handlers().collect();
        assert_eq!(all[0].handler_offset, 20);
        assert_eq!(all[0].catch_type_index, 7);
        assert!(!all[0].stop);
        // The second handler catches everything, which is what a finally block compiles to,
        // and closes the group so an exception stops escaping here.
        assert_eq!(all[1].catch_type_index, 0);
        assert!(all[1].stop);
        assert_eq!(all[1].active_length, 2);

        // The range is half open, so the byte at start plus length belongs to no handler.
        assert!(all[0].covers(19));
        assert!(all[0].covers(20));
        assert!(!all[0].covers(21));
        assert!(!all[0].covers(18));
    }

    #[test]
    fn a_handler_reaching_outside_the_component_is_refused() {
        let body = [0x03, 0x00, 0x7a];
        // A target past the end would send control anywhere.
        let info = component(&[handler(9, 1, 900, 0, true)], &body);
        assert_eq!(Method::parse(&info), Err(Error::Bounds));
        // A range running past the end covers bytes that are not there.
        let info = component(&[handler(9, 900, 9, 0, true)], &body);
        assert_eq!(Method::parse(&info), Err(Error::Bounds));
        // A table longer than the component it sits in.
        assert_eq!(Method::parse(&[2, 0, 0]), Err(Error::Bounds));
        assert_eq!(Method::parse(&[]), Err(Error::Bounds));
    }

    #[test]
    fn a_method_body_runs_from_its_header_to_where_the_next_method_starts() {
        // Two methods, the first three bytecodes long.
        let body = [0x03, 0x25, 0x11, 0x22, 0x7a, 0x02, 0x00, 0x7a];
        let info = component(&[], &body);
        let method = Method::parse(&info).unwrap();
        let start = method.methods_start();
        let (header, code) = method.method(start, start + 5).unwrap();
        assert_eq!(header.max_stack, 3);
        assert_eq!(code, &[0x11, 0x22, 0x7a]);
        let (_, code) = method.method(start + 5, info.len()).unwrap();
        assert_eq!(code, &[0x7a]);

        // A method may not start inside the handler table or end past the component.
        assert_eq!(method.method(0, 4), Err(Error::Bounds));
        assert_eq!(method.method(start, info.len() + 1), Err(Error::Bounds));
        assert_eq!(method.method(start, start), Err(Error::Bounds));
    }

    #[test]
    fn an_abstract_method_carries_no_body() {
        let body = [0x43, 0x25, 0x11];
        let info = component(&[], &body);
        let method = Method::parse(&info).unwrap();
        let start = method.methods_start();
        let (header, code) = method.method(start, start + 2).unwrap();
        assert!(header.abstract_method());
        assert!(code.is_empty());
        // Bytes after an abstract header belong to the next method, so claiming them for
        // this one is a contradiction the specification rules out.
        assert_eq!(method.method(start, start + 3), Err(Error::Format));
    }
}
