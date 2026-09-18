//! The object heap, JCVM 3.x §3.1 and JCRE §6.
//!
//! A reference is a byte offset into one slab, so the heap is position independent and can
//! be written to flash verbatim and read back without relocating anything. Offset zero is
//! never an object, which is what makes the null reference a zero word.
//!
//! Every object carries the context that owns it. The firewall check is a comparison of
//! that byte against the context of the code doing the access, JCRE §6.2, so isolation
//! costs one load and one compare rather than a table walk.
use super::frame::{NULL, Reference};
use crate::{Error, Result};

/// Object kinds, which is the element type for an array.
pub const KIND_OBJECT: u8 = 0;
pub const KIND_BOOLEAN: u8 = 2;
pub const KIND_BYTE: u8 = 3;
pub const KIND_SHORT: u8 = 4;
pub const KIND_INT: u8 = 5;
pub const KIND_REFERENCE: u8 = 6;

/// Bytes of header every object carries: class or element type, length, kind and owner.
pub const HEADER: usize = 6;

/// The context that owns an object. Zero is the runtime environment itself, JCRE §6.1.3.
pub type Context = u8;

/// One slab of objects, allocated from the front.
///
/// There is no collector. Java Card makes object deletion a request the runtime may ignore,
/// and every call to it in the applets this engine targets is guarded by a check that the
/// card supports it, so a bump allocator is a complete implementation of the contract.
pub struct Heap<'a> {
    bytes: &'a mut [u8],
    next: usize,
}

/// What an object is, read back from its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// The Class component offset for an object, or zero for an array.
    pub class: u16,
    /// Field words for an object, elements for an array.
    pub length: u16,
    pub kind: u8,
    pub owner: Context,
}

impl Info {
    pub fn is_array(&self) -> bool {
        self.kind != KIND_OBJECT
    }

    /// Bytes one element occupies.
    pub fn element_size(&self) -> usize {
        match self.kind {
            KIND_BOOLEAN | KIND_BYTE => 1,
            KIND_INT => 4,
            // An object's fields are words, and so are short and reference elements.
            _ => 2,
        }
    }
}

impl<'a> Heap<'a> {
    /// Take a slab. The first two bytes are reserved so that no object can sit at offset
    /// zero, which is the null reference.
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        if bytes.len() < HEADER + 2 {
            return Err(Error::Quota);
        }
        Ok(Self { bytes, next: 2 })
    }

    /// Bytes handed out so far, which is what a writeback has to persist.
    pub fn used(&self) -> usize {
        self.next
    }

    /// The bytes themselves, for sealing and writing back.
    pub fn image(&self) -> &[u8] {
        &self.bytes[..self.next]
    }

    fn allocate(&mut self, class: u16, length: u16, kind: u8, owner: Context) -> Result<Reference> {
        let info = Info {
            class,
            length,
            kind,
            owner,
        };
        let data = (length as usize)
            .checked_mul(info.element_size())
            .ok_or(Error::Quota)?;
        // Objects stay word aligned so a short field never straddles two words.
        let size = (HEADER + data).next_multiple_of(2);
        let at = self.next;
        let end = at.checked_add(size).ok_or(Error::Quota)?;
        if end > self.bytes.len() || end > u16::MAX as usize {
            return Err(Error::Quota);
        }
        self.bytes[at..end].fill(0);
        self.bytes[at..at + 2].copy_from_slice(&class.to_be_bytes());
        self.bytes[at + 2..at + 4].copy_from_slice(&length.to_be_bytes());
        self.bytes[at + 4] = kind;
        self.bytes[at + 5] = owner;
        self.next = end;
        Ok(at as Reference)
    }

    /// An instance of a class, with `words` words of field, all zero.
    pub fn new_object(&mut self, class: u16, words: u16, owner: Context) -> Result<Reference> {
        self.allocate(class, words, KIND_OBJECT, owner)
    }

    /// An array of `length` elements, all zero or null.
    pub fn new_array(&mut self, kind: u8, length: u16, owner: Context) -> Result<Reference> {
        if kind == KIND_OBJECT {
            return Err(Error::Format);
        }
        self.allocate(0, length, kind, owner)
    }

    /// Read an object's header.
    ///
    /// A reference that is null, misaligned or outside what has been allocated is refused
    /// here, so nothing downstream has to repeat the check.
    pub fn info(&self, reference: Reference) -> Result<Info> {
        let at = reference as usize;
        if reference == NULL {
            return Err(Error::Null);
        }
        if at % 2 != 0 || at + HEADER > self.next {
            return Err(Error::Bounds);
        }
        Ok(Info {
            class: u16::from_be_bytes([self.bytes[at], self.bytes[at + 1]]),
            length: u16::from_be_bytes([self.bytes[at + 2], self.bytes[at + 3]]),
            kind: self.bytes[at + 4],
            owner: self.bytes[at + 5],
        })
    }

    /// Check that `context` may touch this object, JCRE §6.2.
    pub fn check_access(&self, reference: Reference, context: Context) -> Result<Info> {
        let info = self.info(reference)?;
        // The runtime environment context reaches everything, which is how the API works on
        // an applet's own objects.
        if context != 0 && info.owner != context {
            return Err(Error::Firewall);
        }
        Ok(info)
    }

    fn slot(&self, reference: Reference, index: usize, want_array: bool) -> Result<(usize, Info)> {
        let info = self.info(reference)?;
        if info.is_array() != want_array {
            return Err(Error::Type);
        }
        if index >= info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + index * info.element_size();
        Ok((at, info))
    }

    pub fn get_word(&self, reference: Reference, index: usize) -> Result<u16> {
        let (at, _) = self.slot(reference, index, false)?;
        Ok(u16::from_be_bytes([self.bytes[at], self.bytes[at + 1]]))
    }

    pub fn put_word(&mut self, reference: Reference, index: usize, value: u16) -> Result<()> {
        let (at, _) = self.slot(reference, index, false)?;
        self.bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Read one array element, widened to a short.
    ///
    /// A byte element sign extends and a boolean does not, which is the difference between
    /// `baload` on a `byte[]` and on a `boolean[]`.
    pub fn array_get(&self, reference: Reference, index: usize) -> Result<i16> {
        let (at, info) = self.slot(reference, index, true)?;
        Ok(match info.kind {
            KIND_BOOLEAN => (self.bytes[at] != 0) as i16,
            KIND_BYTE => self.bytes[at] as i8 as i16,
            KIND_INT => return Err(Error::Type),
            _ => i16::from_be_bytes([self.bytes[at], self.bytes[at + 1]]),
        })
    }

    pub fn array_put(&mut self, reference: Reference, index: usize, value: i16) -> Result<()> {
        let (at, info) = self.slot(reference, index, true)?;
        match info.kind {
            KIND_BOOLEAN => self.bytes[at] = (value != 0) as u8,
            KIND_BYTE => self.bytes[at] = value as u8,
            KIND_INT => return Err(Error::Type),
            _ => self.bytes[at..at + 2].copy_from_slice(&value.to_be_bytes()),
        }
        Ok(())
    }

    pub fn array_get_int(&self, reference: Reference, index: usize) -> Result<i32> {
        let (at, info) = self.slot(reference, index, true)?;
        if info.kind != KIND_INT {
            return Err(Error::Type);
        }
        Ok(i32::from_be_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ]))
    }

    pub fn array_put_int(&mut self, reference: Reference, index: usize, value: i32) -> Result<()> {
        let (at, info) = self.slot(reference, index, true)?;
        if info.kind != KIND_INT {
            return Err(Error::Type);
        }
        self.bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// The bytes of a byte or boolean array, which is what the API layer works on.
    pub fn byte_slice(&self, reference: Reference, offset: usize, length: usize) -> Result<&[u8]> {
        let info = self.info(reference)?;
        if info.element_size() != 1 || !info.is_array() {
            return Err(Error::Type);
        }
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if end > info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + offset;
        Ok(&self.bytes[at..at + length])
    }

    pub fn byte_slice_mut(
        &mut self,
        reference: Reference,
        offset: usize,
        length: usize,
    ) -> Result<&mut [u8]> {
        let info = self.info(reference)?;
        if info.element_size() != 1 || !info.is_array() {
            return Err(Error::Type);
        }
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if end > info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + offset;
        Ok(&mut self.bytes[at..at + length])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    #[test]
    fn an_object_reads_back_what_it_was_made_with() {
        let mut bytes = vec![0xaa; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(0x1234, 3, 7).unwrap();
        // Nothing sits at offset zero, so a zero word is always null and never an object.
        assert_ne!(object, NULL);
        let info = heap.info(object).unwrap();
        assert_eq!(info.class, 0x1234);
        assert_eq!(info.length, 3);
        assert_eq!(info.owner, 7);
        assert!(!info.is_array());
        // Fields start zero whatever the slab held, so a fresh object never shows the last
        // one's contents.
        assert_eq!(heap.get_word(object, 0).unwrap(), 0);
        heap.put_word(object, 2, 0x4321).unwrap();
        assert_eq!(heap.get_word(object, 2).unwrap(), 0x4321);
    }

    #[test]
    fn a_field_index_past_the_object_is_refused() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 2, 1).unwrap();
        assert_eq!(heap.get_word(object, 2), Err(Error::Bounds));
        assert_eq!(heap.put_word(object, 9, 0), Err(Error::Bounds));
    }

    #[test]
    fn the_null_reference_is_refused_before_anything_reads_it() {
        let mut bytes = vec![0; 64];
        let heap = Heap::new(&mut bytes).unwrap();
        assert_eq!(heap.info(NULL), Err(Error::Null));
        assert_eq!(heap.get_word(NULL, 0), Err(Error::Null));
    }

    #[test]
    fn a_reference_outside_what_was_allocated_is_refused() {
        let mut bytes = vec![0; 64];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 1, 1).unwrap();
        // Past the allocation point, and misaligned, which would read a header from the
        // middle of an object.
        assert_eq!(heap.info(heap.used() as u16), Err(Error::Bounds));
        assert_eq!(heap.info(object + 1), Err(Error::Bounds));
    }

    #[test]
    fn element_width_follows_the_array_type() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let bytes_array = heap.new_array(KIND_BYTE, 4, 1).unwrap();
        let shorts = heap.new_array(KIND_SHORT, 4, 1).unwrap();
        // A byte element sign extends on the way out. A boolean does not.
        heap.array_put(bytes_array, 0, -1).unwrap();
        assert_eq!(heap.array_get(bytes_array, 0).unwrap(), -1);
        heap.array_put(shorts, 3, -300).unwrap();
        assert_eq!(heap.array_get(shorts, 3).unwrap(), -300);
        let booleans = heap.new_array(KIND_BOOLEAN, 2, 1).unwrap();
        heap.array_put(booleans, 0, -1).unwrap();
        assert_eq!(heap.array_get(booleans, 0).unwrap(), 1);
    }

    #[test]
    fn an_int_array_is_read_as_ints_and_nothing_else() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let array = heap.new_array(KIND_INT, 2, 1).unwrap();
        heap.array_put_int(array, 1, -70_000).unwrap();
        assert_eq!(heap.array_get_int(array, 1).unwrap(), -70_000);
        // Reading it as a short would take half of one element.
        assert_eq!(heap.array_get(array, 1), Err(Error::Type));
        let shorts = heap.new_array(KIND_SHORT, 2, 1).unwrap();
        assert_eq!(heap.array_get_int(shorts, 0), Err(Error::Type));
    }

    #[test]
    fn an_array_and_an_object_are_not_interchangeable() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 2, 1).unwrap();
        let array = heap.new_array(KIND_SHORT, 2, 1).unwrap();
        // getfield on an array and an array load on an object are both type confusion.
        assert_eq!(heap.array_get(object, 0), Err(Error::Type));
        assert_eq!(heap.get_word(array, 0), Err(Error::Type));
        assert_eq!(heap.new_array(KIND_OBJECT, 1, 1), Err(Error::Format));
    }

    #[test]
    fn the_firewall_compares_the_owner_with_the_caller() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let mine = heap.new_object(1, 1, 3).unwrap();
        heap.check_access(mine, 3).unwrap();
        // Another applet's context cannot reach it, which is the whole firewall.
        assert_eq!(heap.check_access(mine, 4), Err(Error::Firewall));
        // The runtime environment reaches everything, which is how the API works on an
        // applet's own objects.
        heap.check_access(mine, 0).unwrap();
    }

    #[test]
    fn a_byte_array_hands_out_a_bounded_slice() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let array = heap.new_array(KIND_BYTE, 8, 1).unwrap();
        heap.byte_slice_mut(array, 2, 3).unwrap().copy_from_slice(&[1, 2, 3]);
        assert_eq!(heap.byte_slice(array, 0, 8).unwrap(), &[0, 0, 1, 2, 3, 0, 0, 0]);
        assert_eq!(heap.byte_slice(array, 6, 3), Err(Error::Bounds));
        // A short array is not a byte array, whatever its length.
        let shorts = heap.new_array(KIND_SHORT, 8, 1).unwrap();
        assert_eq!(heap.byte_slice(shorts, 0, 1), Err(Error::Type));
    }

    #[test]
    fn a_heap_that_runs_out_refuses_rather_than_overwriting() {
        let mut bytes = vec![0; 32];
        let mut heap = Heap::new(&mut bytes).unwrap();
        heap.new_array(KIND_BYTE, 16, 1).unwrap();
        assert_eq!(heap.new_array(KIND_BYTE, 16, 1), Err(Error::Quota));
        // The slab has to hold at least one header.
        let mut tiny = vec![0; 4];
        assert!(Heap::new(&mut tiny).is_err());
    }
}
