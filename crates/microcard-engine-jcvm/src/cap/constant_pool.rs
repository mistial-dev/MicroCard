//! The Constant Pool component, JCVM 3.x §6.8.
//!
//! Every entry is four bytes: a tag and three bytes whose meaning the tag decides. A
//! bytecode operand that names a class, field or method is an index into this array.
//!
//! Static method references matter twice over. They are how `invokestatic` and constructor
//! calls reach their target, and they are the only place the offsets of static methods
//! appear. The class method tables hold virtual methods alone, so a verifier that walks
//! only those cannot tell where one method ends and the next begins.
use crate::{Error, Result};

/// Constant pool tags, JCVM Table 6-4.
pub const CONSTANT_CLASSREF: u8 = 1;
pub const CONSTANT_INSTANCE_FIELDREF: u8 = 2;
pub const CONSTANT_VIRTUAL_METHODREF: u8 = 3;
pub const CONSTANT_SUPER_METHODREF: u8 = 4;
pub const CONSTANT_STATIC_FIELDREF: u8 = 5;
pub const CONSTANT_STATIC_METHODREF: u8 = 6;

/// One constant pool entry, left in the form the component stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub tag: u8,
    pub info: [u8; 3],
}

impl Entry {
    /// The Method component offset of a static method defined in this package.
    ///
    /// Returns nothing for a method in an imported package, which is resolved through its
    /// export file, and nothing for any other kind of entry.
    pub fn internal_static_method(&self) -> Option<u16> {
        // The high bit of the structure says where the target lives, JCVM §6.8.3.
        if self.tag != CONSTANT_STATIC_METHODREF || self.info[0] & 0x80 != 0 {
            return None;
        }
        Some(u16::from_be_bytes([self.info[1], self.info[2]]))
    }

    /// The class this entry names, when it names one in this package.
    pub fn internal_class(&self) -> Option<u16> {
        if self.tag != CONSTANT_CLASSREF {
            return None;
        }
        let value = u16::from_be_bytes([self.info[0], self.info[1]]);
        (value & 0x8000 == 0).then_some(value)
    }
}

/// The constant pool of one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstantPool<'a> {
    entries: &'a [u8],
    count: u16,
}

impl<'a> ConstantPool<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let head = info.get(..2).ok_or(Error::Bounds)?;
        let count = u16::from_be_bytes([head[0], head[1]]);
        let entries = info.get(2..).ok_or(Error::Bounds)?;
        if entries.len() != count as usize * 4 {
            return Err(Error::Format);
        }
        for entry in entries.chunks_exact(4) {
            // An unknown tag would make the three bytes after it mean nothing, and the
            // bytecode indexing this entry would act on whatever they happened to hold.
            if !(CONSTANT_CLASSREF..=CONSTANT_STATIC_METHODREF).contains(&entry[0]) {
                return Err(Error::Format);
            }
        }
        Ok(Self { entries, count })
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// The entry a bytecode operand names.
    pub fn get(&self, index: u16) -> Result<Entry> {
        let at = index as usize * 4;
        let bytes = self.entries.get(at..at + 4).ok_or(Error::Bounds)?;
        Ok(Entry {
            tag: bytes[0],
            info: [bytes[1], bytes[2], bytes[3]],
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = Entry> + use<'a> {
        self.entries.chunks_exact(4).map(|bytes| Entry {
            tag: bytes[0],
            info: [bytes[1], bytes[2], bytes[3]],
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn pool(entries: &[[u8; 4]]) -> Vec<u8> {
        let mut bytes = Vec::from((entries.len() as u16).to_be_bytes());
        for entry in entries {
            bytes.extend_from_slice(entry);
        }
        bytes
    }

    #[test]
    fn entries_are_four_bytes_and_are_found_by_index() {
        let info = pool(&[
            [CONSTANT_CLASSREF, 0x00, 0x2a, 0],
            [CONSTANT_STATIC_METHODREF, 0x00, 0x07, 0x0e],
        ]);
        let constants = ConstantPool::parse(&info).unwrap();
        assert_eq!(constants.count(), 2);
        assert_eq!(constants.get(0).unwrap().tag, CONSTANT_CLASSREF);
        assert_eq!(constants.get(1).unwrap().internal_static_method(), Some(0x070e));
        // Past the end is a bounds error, so a bytecode operand cannot reach outside.
        assert_eq!(constants.get(2), Err(Error::Bounds));
    }

    #[test]
    fn a_static_method_in_another_package_has_no_offset_here() {
        // The high bit marks an external reference, whose three bytes are package, class
        // and method tokens. Reading them as an offset would land anywhere in the method
        // component.
        let info = pool(&[[CONSTANT_STATIC_METHODREF, 0x80, 0x03, 0x05]]);
        let constants = ConstantPool::parse(&info).unwrap();
        assert_eq!(constants.get(0).unwrap().internal_static_method(), None);
        // So does every other kind of entry.
        let info = pool(&[[CONSTANT_VIRTUAL_METHODREF, 0x00, 0x03, 0x05]]);
        let constants = ConstantPool::parse(&info).unwrap();
        assert_eq!(constants.get(0).unwrap().internal_static_method(), None);
    }

    #[test]
    fn a_class_reference_reads_back_only_when_it_is_internal() {
        let info = pool(&[
            [CONSTANT_CLASSREF, 0x01, 0x23, 0],
            [CONSTANT_CLASSREF, 0x83, 0x05, 0],
        ]);
        let constants = ConstantPool::parse(&info).unwrap();
        assert_eq!(constants.get(0).unwrap().internal_class(), Some(0x0123));
        assert_eq!(constants.get(1).unwrap().internal_class(), None);
    }

    #[test]
    fn a_count_that_disagrees_with_the_component_is_refused() {
        let mut info = pool(&[[CONSTANT_CLASSREF, 0, 0, 0]]);
        info[1] = 2;
        assert_eq!(ConstantPool::parse(&info), Err(Error::Format));
        info.push(0);
        assert_eq!(ConstantPool::parse(&info), Err(Error::Format));
        assert_eq!(ConstantPool::parse(&[0]), Err(Error::Bounds));
        // An empty pool is legal and says so.
        assert_eq!(ConstantPool::parse(&[0, 0]).unwrap().count(), 0);
    }

    #[test]
    fn an_unknown_tag_is_refused() {
        for tag in [0u8, 7, 0xff] {
            let info = pool(&[[tag, 0, 0, 0]]);
            assert_eq!(ConstantPool::parse(&info), Err(Error::Format), "{tag}");
        }
    }
}
