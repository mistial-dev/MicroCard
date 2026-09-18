//! The Class component, JCVM 3.x §6.9.
//!
//! Interfaces first, then classes, laid end to end with no index. A class is addressed by
//! its byte offset into this component, which is what a class reference carries, so the
//! layout is walked rather than looked up.
//!
//! This is also where the method offsets live. The virtual method tables point into the
//! Method component, and together with the applet install offsets they are the only way to
//! know where each method in a package begins.
use super::header::Header;
use crate::{Error, Result};

/// Interface and class flags, JCVM Table 6-11.
pub const ACC_INTERFACE: u8 = 0x8;
pub const ACC_SHAREABLE: u8 = 0x4;
pub const ACC_REMOTE: u8 = 0x2;

/// A reference to a class or interface, JCVM §6.8.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassRef {
    /// A byte offset into the Class component of this package.
    Internal(u16),
    /// A class token in one of the imported packages.
    External { package: u8, class: u8 },
    /// No superclass, which only `java.lang.Object` itself has.
    None,
}

impl ClassRef {
    pub fn decode(value: u16) -> Self {
        // The high bit says where the class lives, JCVM §6.8.1.
        match value {
            0xffff => Self::None,
            _ if value & 0x8000 != 0 => Self::External {
                package: (value >> 8) as u8 & 0x7f,
                class: value as u8,
            },
            _ => Self::Internal(value),
        }
    }
}

/// One class or interface, borrowed from the component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassInfo<'a> {
    /// Offset of this entry, which is what an internal class reference carries.
    pub offset: u16,
    pub flags: u8,
    pub super_class: ClassRef,
    /// Words an instance of this class declares, on top of its superclass.
    pub declared_instance_size: u8,
    pub first_reference_token: u8,
    pub reference_count: u8,
    pub public_method_table_base: u8,
    pub package_method_table_base: u8,
    /// Method component offsets of the public virtual methods, in token order.
    public_methods: &'a [u8],
    /// Method component offsets of the package virtual methods, in token order.
    package_methods: &'a [u8],
    /// The implemented interface table, each entry a class reference, a count and that
    /// many virtual method tokens.
    interfaces: &'a [u8],
    interface_count: u8,
    /// Total size of this entry, which is where the next one starts.
    length: usize,
}

impl<'a> ClassInfo<'a> {
    /// The public virtual method table, two bytes per entry in token order.
    pub fn public_methods(&self) -> &'a [u8] {
        self.public_methods
    }

    /// The package-visible virtual method table, which is a separate namespace.
    pub fn package_methods(&self) -> &'a [u8] {
        self.package_methods
    }

    /// The interfaces this class implements, with the mapping each one needs.
    ///
    /// An interface method token indexes the mapping, and what it finds is a virtual
    /// method token in this class's own hierarchy, JCVM §6.9.2.5. That is the whole of
    /// interface dispatch: one table lookup to change namespace, then an ordinary virtual
    /// method search.
    pub fn interfaces(&self) -> impl Iterator<Item = (ClassRef, &'a [u8])> + use<'a> {
        let mut rest = self.interfaces;
        (0..self.interface_count).filter_map(move |_| {
            let head = rest.get(..3)?;
            let count = head[2] as usize;
            let tokens = rest.get(3..3 + count)?;
            rest = &rest[3 + count..];
            Some((
                ClassRef::decode(u16::from_be_bytes([head[0], head[1]])),
                tokens,
            ))
        })
    }

    pub fn is_interface(&self) -> bool {
        self.flags & ACC_INTERFACE != 0
    }

    /// Method component offsets this class names, skipping the ones it inherits.
    ///
    /// An entry of `0xffff` means the method is defined in an imported package, JCVM §6.9.
    /// Those are resolved through the export files instead of through this table.
    pub fn method_offsets(&self) -> impl Iterator<Item = u16> + use<'a> {
        let tables = [self.public_methods, self.package_methods];
        tables.into_iter().flat_map(|table| {
            table
                .chunks_exact(2)
                .map(|entry| u16::from_be_bytes([entry[0], entry[1]]))
                .filter(|offset| *offset != 0xffff)
        })
    }
}

/// Every class and interface of one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class<'a> {
    info: &'a [u8],
    /// Where the interface and class entries start, after any signature pool.
    entries: usize,
}

impl<'a> Class<'a> {
    /// Parse the component, which needs the CAP version to know its own shape.
    ///
    /// The signature pool exists only from CAP format 2.2, JCVM §6.9. Reading a 2.1
    /// component as though it had one would take the first interface entry for a pool
    /// length and mislay every class in the package.
    pub fn parse(info: &'a [u8], header: &Header) -> Result<Self> {
        let entries = if (header.cap_major, header.cap_minor) >= (2, 2) {
            let length = info
                .get(..2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
                .ok_or(Error::Bounds)?;
            2 + length
        } else {
            0
        };
        if entries > info.len() {
            return Err(Error::Bounds);
        }
        let class = Self { info, entries };
        // Walk once, so every later read is over checked bytes and an entry claiming more
        // than the component holds cannot be reached.
        let mut at = entries;
        while at < info.len() {
            at += class.entry(at)?.length;
        }
        Ok(class)
    }

    /// The class or interface at a byte offset, which is what a class reference carries.
    pub fn at(&self, offset: u16) -> Result<ClassInfo<'a>> {
        let at = offset as usize;
        if at < self.entries {
            return Err(Error::Bounds);
        }
        self.entry(at)
    }

    /// Every class and interface, in the order they appear.
    pub fn iter(&self) -> impl Iterator<Item = ClassInfo<'a>> + use<'a, '_> {
        let mut at = self.entries;
        core::iter::from_fn(move || {
            if at >= self.info.len() {
                return None;
            }
            let entry = self.entry(at).expect("checked during parse");
            at += entry.length;
            Some(entry)
        })
    }

    fn entry(&self, at: usize) -> Result<ClassInfo<'a>> {
        let info = self.info;
        let first = *info.get(at).ok_or(Error::Bounds)?;
        let flags = first >> 4;
        let interface_count = (first & 0x0f) as usize;
        if flags & ACC_INTERFACE != 0 {
            // An interface carries its superinterfaces and, when remote, its name.
            let mut end = at + 1 + interface_count * 2;
            if flags & ACC_REMOTE != 0 {
                let length = *info.get(end).ok_or(Error::Bounds)? as usize;
                end += 1 + length;
            }
            if end > info.len() {
                return Err(Error::Bounds);
            }
            return Ok(ClassInfo {
                offset: at as u16,
                flags,
                super_class: ClassRef::None,
                declared_instance_size: 0,
                first_reference_token: 0,
                reference_count: 0,
                public_method_table_base: 0,
                package_method_table_base: 0,
                public_methods: &[],
                package_methods: &[],
                interfaces: &[],
                interface_count: 0,
                length: end - at,
            });
        }
        // Ten fixed bytes, JCVM §6.9: the flags, the superclass reference, three sizing
        // values and a base and a count for each of the two method tables.
        let fixed = info.get(at..at + 10).ok_or(Error::Bounds)?;
        let super_class = ClassRef::decode(u16::from_be_bytes([fixed[1], fixed[2]]));
        let public_count = fixed[7] as usize;
        let package_count = fixed[9] as usize;
        let public_start = at + 10;
        let package_start = public_start + public_count * 2;
        let interfaces_start = package_start + package_count * 2;
        let public_methods = info
            .get(public_start..package_start)
            .ok_or(Error::Bounds)?;
        let package_methods = info
            .get(package_start..interfaces_start)
            .ok_or(Error::Bounds)?;
        // Each implemented interface names itself and lists one index per method it maps.
        let mut end = interfaces_start;
        for _ in 0..interface_count {
            let count = *info.get(end + 2).ok_or(Error::Bounds)? as usize;
            end += 3 + count;
        }
        if end > info.len() {
            return Err(Error::Bounds);
        }
        Ok(ClassInfo {
            offset: at as u16,
            flags,
            super_class,
            declared_instance_size: fixed[3],
            first_reference_token: fixed[4],
            reference_count: fixed[5],
            public_method_table_base: fixed[6],
            package_method_table_base: fixed[8],
            public_methods,
            package_methods,
            interfaces: info.get(interfaces_start..end).ok_or(Error::Bounds)?,
            interface_count: interface_count as u8,
            length: end - at,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn header(major: u8, minor: u8) -> Header<'static> {
        Header {
            cap_major: major,
            cap_minor: minor,
            flags: 0x04,
            package_major: 1,
            package_minor: 0,
            package_aid: &[0xa0, 0, 0, 0, 1],
        }
    }

    /// One class with the given virtual method tables and no interfaces.
    fn class(super_class: u16, public: &[u16], package: &[u16]) -> Vec<u8> {
        let mut bytes = alloc::vec![0x00];
        bytes.extend_from_slice(&super_class.to_be_bytes());
        bytes.extend_from_slice(&[4, 0, 2]);
        bytes.push(1);
        bytes.push(public.len() as u8);
        bytes.push(0);
        bytes.push(package.len() as u8);
        for offset in public.iter().chain(package) {
            bytes.extend_from_slice(&offset.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn a_class_reference_says_where_the_class_lives() {
        assert_eq!(ClassRef::decode(0x0123), ClassRef::Internal(0x0123));
        // The high bit marks a class in an imported package, named by two tokens.
        assert_eq!(
            ClassRef::decode(0x8305),
            ClassRef::External { package: 3, class: 5 }
        );
        // Only java.lang.Object has no superclass at all.
        assert_eq!(ClassRef::decode(0xffff), ClassRef::None);
    }

    #[test]
    fn classes_are_found_by_the_offset_a_reference_carries() {
        let mut info = Vec::new();
        let first = class(0xffff, &[10, 20], &[]);
        let second = class(0, &[30], &[40]);
        info.extend_from_slice(&first);
        let second_offset = info.len() as u16;
        info.extend_from_slice(&second);

        let classes = Class::parse(&info, &header(2, 1)).unwrap();
        assert_eq!(classes.iter().count(), 2);
        let entry = classes.at(0).unwrap();
        assert_eq!(entry.super_class, ClassRef::None);
        assert_eq!(entry.declared_instance_size, 4);
        assert_eq!(entry.method_offsets().collect::<Vec<u16>>(), [10, 20]);

        let entry = classes.at(second_offset).unwrap();
        // The second class extends the first, by the offset the first one sits at.
        assert_eq!(entry.super_class, ClassRef::Internal(0));
        // Public and package tables are both method offsets into the Method component.
        assert_eq!(entry.method_offsets().collect::<Vec<u16>>(), [30, 40]);
    }

    #[test]
    fn a_method_defined_in_an_imported_package_has_no_offset_here() {
        // 0xffff marks an inherited method, JCVM section 6.9. Treating it as an offset
        // would send the verifier to the last byte of the Method component.
        let info = class(0xffff, &[0xffff, 12, 0xffff], &[]);
        let classes = Class::parse(&info, &header(2, 1)).unwrap();
        let entry = classes.at(0).unwrap();
        assert_eq!(entry.method_offsets().collect::<Vec<u16>>(), [12]);
    }

    #[test]
    fn a_signature_pool_is_read_only_from_the_version_that_has_one() {
        let body = class(0xffff, &[10], &[]);
        // A 2.2 component puts a signature pool first.
        let mut with_pool = alloc::vec![0, 3, 1, 2, 3];
        with_pool.extend_from_slice(&body);
        let classes = Class::parse(&with_pool, &header(2, 2)).unwrap();
        assert_eq!(classes.iter().count(), 1);
        assert_eq!(classes.at(5).unwrap().method_offsets().count(), 1);

        // Reading the same bytes as 2.1 takes the pool for a class entry, so the version
        // has to come from the header rather than from a guess.
        let as_21 = Class::parse(&with_pool, &header(2, 1));
        assert!(as_21.is_err() || as_21.unwrap().iter().count() != 1);

        // A pool longer than the component it sits in.
        assert_eq!(Class::parse(&[0xff, 0xff, 1], &header(2, 2)), Err(Error::Bounds));
    }

    #[test]
    fn an_interface_carries_its_superinterfaces_and_no_method_table() {
        // Two superinterfaces, then a class after it.
        let mut info = alloc::vec![0x82, 0x00, 0x00, 0x00, 0x00];
        let class_offset = info.len() as u16;
        info.extend_from_slice(&class(0xffff, &[7], &[]));
        let classes = Class::parse(&info, &header(2, 1)).unwrap();
        let entries: Vec<ClassInfo> = classes.iter().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_interface());
        assert_eq!(entries[0].method_offsets().count(), 0);
        assert!(!entries[1].is_interface());
        assert_eq!(entries[1].offset, class_offset);
    }

    #[test]
    fn a_remote_interface_carries_its_name() {
        // ACC_INTERFACE and ACC_REMOTE, no superinterfaces, then a four byte name.
        let mut info = alloc::vec![0xa0, 4, b'n', b'a', b'm', b'e'];
        info.extend_from_slice(&class(0xffff, &[7], &[]));
        let classes = Class::parse(&info, &header(2, 1)).unwrap();
        assert_eq!(classes.iter().count(), 2);
        // A name length past the end of the component is refused.
        assert_eq!(Class::parse(&[0xa0, 40, 1], &header(2, 1)), Err(Error::Bounds));
    }

    #[test]
    fn an_entry_claiming_more_than_the_component_holds_is_refused() {
        // A method table claiming more entries than the bytes that follow it.
        let mut info = class(0xffff, &[10], &[]);
        info[7] = 40;
        assert_eq!(Class::parse(&info, &header(2, 1)), Err(Error::Bounds));
        assert_eq!(Class::parse(&[], &header(2, 1)).map(|c| c.iter().count()), Ok(0));
        assert_eq!(Class::parse(&[0x00], &header(2, 1)), Err(Error::Bounds));
    }
}
