//! Turning constant pool entries into the offsets an instruction needs, JCVM 3.x §4.3.7.
//!
//! Nothing is rewritten. Every resolution below is computed when the instruction runs, from
//! the components as they arrived, which keeps the image position independent and lets the
//! same bytes be re-verified after a reset.
//!
//! Two token namespaces meet here. An instance field token counts from zero within the
//! class that declares the field, so its offset in an object is that token plus the size of
//! everything the superclasses declared. A virtual method token is either public or
//! package-visible, the high bit says which, and the two are separate tables.
use crate::cap::{
    CONSTANT_INSTANCE_FIELDREF, CONSTANT_STATIC_FIELDREF, CONSTANT_STATIC_METHODREF,
    CONSTANT_SUPER_METHODREF, CONSTANT_VIRTUAL_METHODREF, Class, ClassInfo, ClassRef, LoadFile,
};
use crate::{Error, Result};

/// The high bit of a virtual method token marks the package-visible namespace, §4.3.7.6.
const PRIVATE_TOKEN: u8 = 0x80;

/// A package, with the resolutions its bytecode needs.
pub struct Linked<'a> {
    file: &'a LoadFile<'a>,
    classes: Class<'a>,
}

impl<'a> Linked<'a> {
    pub fn new(file: &'a LoadFile<'a>) -> Result<Self> {
        Ok(Self {
            file,
            classes: file.classes()?,
        })
    }

    pub fn classes(&self) -> Class<'a> {
        self.classes
    }

    /// Words an instance of this class occupies, including what it inherits.
    ///
    /// A class declares only its own fields, so the size of an object is the sum down the
    /// chain. The walk is bounded because verification already refused any cycle.
    pub fn instance_words(&self, class: u16) -> Result<u16> {
        let mut total: u16 = 0;
        let mut at = ClassRef::Internal(class);
        for _ in 0..=u8::MAX {
            let ClassRef::Internal(offset) = at else {
                return Ok(total);
            };
            let info = self.classes.at(offset)?;
            total = total
                .checked_add(info.declared_instance_size as u16)
                .ok_or(Error::Quota)?;
            at = info.super_class;
        }
        Err(Error::Format)
    }

    /// Words of field the superclasses of this class declare, which is where its own start.
    fn inherited_words(&self, class: u16) -> Result<u16> {
        let info = self.classes.at(class)?;
        match info.super_class {
            ClassRef::Internal(offset) => self.instance_words(offset),
            // A class whose superclass is in another package inherits nothing this engine
            // can see. java.lang.Object declares no fields, which is the usual case.
            _ => Ok(0),
        }
    }

    fn entry(&self, index: u16, tag: u8) -> Result<[u8; 3]> {
        let entry = self.file.constants()?.get(index)?;
        if entry.tag != tag {
            return Err(Error::Type);
        }
        Ok(entry.info)
    }

    /// The word offset of an instance field inside an object.
    ///
    /// The field is named by the class that declares it, so the offset does not depend on
    /// the object's own class. That is what lets a superclass method reach its own field on
    /// an instance of a subclass.
    pub fn instance_field(&self, index: u16) -> Result<u16> {
        let info = self.entry(index, CONSTANT_INSTANCE_FIELDREF)?;
        let ClassRef::Internal(class) = ClassRef::decode(u16::from_be_bytes([info[0], info[1]]))
        else {
            // A field of a class in another package needs that package's export file.
            return Err(Error::Unsupported);
        };
        let token = info[2] & !PRIVATE_TOKEN;
        self.inherited_words(class)?
            .checked_add(token as u16)
            .ok_or(Error::Bounds)
    }

    /// The byte offset of a static field in the static field image.
    pub fn static_field(&self, index: u16) -> Result<u16> {
        let info = self.entry(index, CONSTANT_STATIC_FIELDREF)?;
        if info[0] & 0x80 != 0 {
            return Err(Error::Unsupported);
        }
        // The first byte is padding for an internal reference, JCVM §6.8.3.
        if info[0] != 0 {
            return Err(Error::Format);
        }
        Ok(u16::from_be_bytes([info[1], info[2]]))
    }

    /// The Method component offset of a statically resolved method.
    ///
    /// This covers `invokestatic` and the `invokespecial` that calls a constructor or a
    /// private instance method, which is why those two share one constant type.
    pub fn static_method(&self, index: u16) -> Result<u16> {
        let info = self.entry(index, CONSTANT_STATIC_METHODREF)?;
        if info[0] & 0x80 != 0 {
            return Err(Error::Unsupported);
        }
        // Before CAP 2.3 the first byte is padding. From 2.3 it indexes a method block,
        // and this engine reads the single block form only.
        if info[0] != 0 {
            return Err(Error::Unsupported);
        }
        Ok(u16::from_be_bytes([info[1], info[2]]))
    }

    /// The class a `CONSTANT_Classref` names, when it names one in this package.
    pub fn class_ref(&self, index: u16) -> Result<u16> {
        let entry = self.file.constants()?.get(index)?;
        entry.internal_class().ok_or(Error::Unsupported)
    }

    /// The class and token a virtual or super method reference names.
    ///
    /// The class here is the one the compiler saw, which is what gives the signature. The
    /// body that runs comes from the receiver's own class, so this is only the starting
    /// point for the search.
    pub fn virtual_ref(&self, index: u16) -> Result<(u16, u8)> {
        let tag = self.file.constants()?.get(index)?.tag;
        if tag != CONSTANT_VIRTUAL_METHODREF && tag != CONSTANT_SUPER_METHODREF {
            return Err(Error::Type);
        }
        let info = self.entry(index, tag)?;
        match ClassRef::decode(u16::from_be_bytes([info[0], info[1]])) {
            ClassRef::Internal(class) => Ok((class, info[2])),
            _ => Err(Error::Unsupported),
        }
    }

    /// Find a virtual method by token, starting from the object's own class.
    ///
    /// The table entry for a method a class inherits without overriding is `0xffff`, so the
    /// search walks up until it finds the class that actually defines the body. That walk
    /// is what makes overriding work.
    pub fn virtual_method(&self, index: u16, class: u16) -> Result<u16> {
        let tag = self.file.constants()?.get(index)?.tag;
        if tag != CONSTANT_VIRTUAL_METHODREF && tag != CONSTANT_SUPER_METHODREF {
            return Err(Error::Type);
        }
        let info = self.entry(index, tag)?;
        let token = info[2];
        // A super method reference names the class to start from. A virtual one dispatches
        // on the object, so the caller supplies the class.
        let start = if tag == CONSTANT_SUPER_METHODREF {
            match ClassRef::decode(u16::from_be_bytes([info[0], info[1]])) {
                ClassRef::Internal(offset) => self.super_of(offset)?,
                _ => return Err(Error::Unsupported),
            }
        } else {
            class
        };
        self.lookup(start, token)
    }

    fn super_of(&self, class: u16) -> Result<u16> {
        match self.classes.at(class)?.super_class {
            ClassRef::Internal(offset) => Ok(offset),
            _ => Err(Error::Unsupported),
        }
    }

    /// Resolve an interface method on a receiver's class, JCVM §7.5.54.1.
    ///
    /// An interface method token is numbered within the interface, so it means nothing in
    /// the class. The class carries one mapping per interface it implements, and the token
    /// indexes that mapping to get a virtual method token in the class's own hierarchy.
    /// The search then proceeds as any virtual call does.
    ///
    /// A class inherits the interfaces its superclasses implement, so the mapping is
    /// looked for up the chain rather than on the receiver's class alone.
    pub fn interface_method(&self, interface: u16, token: u8, class: u16) -> Result<u16> {
        let mut at = ClassRef::Internal(class);
        for _ in 0..=u8::MAX {
            let ClassRef::Internal(offset) = at else {
                return Err(Error::Missing);
            };
            let info = self.classes.at(offset)?;
            for (implemented, tokens) in info.interfaces() {
                if implemented != ClassRef::Internal(interface) {
                    continue;
                }
                let virtual_token = *tokens.get(token as usize).ok_or(Error::Bounds)?;
                return self.lookup(class, virtual_token);
            }
            at = info.super_class;
        }
        Err(Error::Missing)
    }

    /// Walk the class chain for the body of a virtual method token.
    pub fn lookup(&self, class: u16, token: u8) -> Result<u16> {
        let private = token & PRIVATE_TOKEN != 0;
        let token = token & !PRIVATE_TOKEN;
        let mut at = ClassRef::Internal(class);
        for _ in 0..=u8::MAX {
            let ClassRef::Internal(offset) = at else {
                return Err(Error::Missing);
            };
            let info = self.classes.at(offset)?;
            if let Some(method) = table_entry(&info, token, private) {
                if method != 0xffff {
                    return Ok(method);
                }
            }
            at = info.super_class;
        }
        Err(Error::Format)
    }
}

/// The entry a token names in one of a class's two method tables, if it is in range.
fn table_entry(info: &ClassInfo, token: u8, private: bool) -> Option<u16> {
    let (base, table) = if private {
        (info.package_method_table_base, info.package_methods())
    } else {
        (info.public_method_table_base, info.public_methods())
    };
    let index = token.checked_sub(base)? as usize;
    let entry = table.get(index * 2..index * 2 + 2)?;
    Some(u16::from_be_bytes([entry[0], entry[1]]))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::test_support::{ClassSpec, Package};
    use alloc::vec;

    #[test]
    fn an_instance_field_offset_counts_from_the_declaring_class() {
        // Two classes, the second extending the first, each declaring two words. A field
        // token of one in the subclass is the third word of the object.
        let mut package = Package {
            classes: vec![
                ClassSpec {
                    declared_size: 2,
                    ..ClassSpec::default()
                },
                ClassSpec {
                    super_class: 0,
                    declared_size: 2,
                    ..ClassSpec::default()
                },
            ],
            ..Package::default()
        };
        let subclass = package.class_offsets()[1];
        package.constants = vec![
            // An instance field of the first class, token 1.
            [CONSTANT_INSTANCE_FIELDREF, 0x00, 0x00, 1],
            // An instance field of the second class, token 1.
            [
                CONSTANT_INSTANCE_FIELDREF,
                (subclass >> 8) as u8,
                subclass as u8,
                1,
            ],
        ];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        assert_eq!(linked.instance_words(0).unwrap(), 2);
        assert_eq!(linked.instance_words(subclass).unwrap(), 4);
        assert_eq!(linked.instance_field(0).unwrap(), 1);
        // The subclass field sits after everything the superclass declared.
        assert_eq!(linked.instance_field(1).unwrap(), 3);
    }

    #[test]
    fn a_field_in_another_package_needs_an_export_file() {
        let package = Package {
            constants: vec![[CONSTANT_INSTANCE_FIELDREF, 0x80, 0x03, 1]],
            ..Package::default()
        };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        assert_eq!(linked.instance_field(0), Err(Error::Unsupported));
    }

    #[test]
    fn a_constant_of_the_wrong_kind_is_refused() {
        let package = Package {
            constants: vec![[CONSTANT_STATIC_FIELDREF, 0x00, 0x00, 4]],
            ..Package::default()
        };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        // getfield naming a static field would read the wrong image entirely.
        assert_eq!(linked.instance_field(0), Err(Error::Type));
        assert_eq!(linked.static_field(0).unwrap(), 4);
    }

    #[test]
    fn a_virtual_method_resolves_to_the_class_that_defines_the_body() {
        // The superclass defines token 0 at method offset 20. The subclass inherits it,
        // which its table records as 0xffff, and overrides token 1 at offset 30.
        let package = Package {
            classes: vec![
                ClassSpec {
                    public: vec![20, 25],
                    ..ClassSpec::default()
                },
                ClassSpec {
                    super_class: 0,
                    public: vec![0xffff, 30],
                    ..ClassSpec::default()
                },
            ],
            constants: vec![[CONSTANT_VIRTUAL_METHODREF, 0x00, 0x00, 0]],
            ..Package::default()
        };
        let subclass = package.class_offsets()[1];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        // Called on the subclass, the inherited method still finds the superclass body.
        assert_eq!(linked.lookup(subclass, 0).unwrap(), 20);
        // The overridden one finds the subclass body rather than the superclass one.
        assert_eq!(linked.lookup(subclass, 1).unwrap(), 30);
        assert_eq!(linked.lookup(0, 1).unwrap(), 25);
        // A token no class in the chain defines is missing rather than a wrong answer.
        assert_eq!(linked.lookup(subclass, 7), Err(Error::Missing));
    }

    #[test]
    fn the_two_token_namespaces_are_separate_tables() {
        // Public token 0 at offset 20, package-visible token 0 at offset 40.
        let package = Package {
            classes: vec![ClassSpec {
                public: vec![20],
                package: vec![40],
                ..ClassSpec::default()
            }],
            ..Package::default()
        };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        assert_eq!(linked.lookup(0, 0).unwrap(), 20);
        // The high bit picks the other table, so the same token number is another method.
        assert_eq!(linked.lookup(0, PRIVATE_TOKEN).unwrap(), 40);
    }
}
