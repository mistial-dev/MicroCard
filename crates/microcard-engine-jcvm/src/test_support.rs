//! A hand-built Load File Data Block, for tests that need a whole package.
//!
//! Real CAP files are third-party build outputs and stay out of this repository, so a
//! package small enough to reason about is assembled here instead. The integration test
//! covers the opposite case, a package a real converter emitted.
use crate::cap::Tag;
use alloc::vec;
use alloc::vec::Vec;

/// The package AID the builder uses.
pub const PACKAGE_AID: [u8; 5] = [0xf0, 1, 2, 3, 4];
/// The applet AID the builder uses.
pub const APPLET_AID: [u8; 6] = [0xf0, 1, 2, 3, 4, 1];

/// One class in the built package.
pub struct ClassSpec {
    /// A class reference, or `0xffff` for no superclass.
    pub super_class: u16,
    /// Words of field this class declares on its own account.
    pub declared_size: u8,
    /// Method component offsets of the public virtual methods, in token order.
    pub public: Vec<u16>,
    /// The same for the package-visible namespace.
    pub package: Vec<u16>,
    /// Build an interface rather than a class. An interface carries no method table.
    pub interface: bool,
    /// Interfaces this class implements, each a class offset and the virtual method token
    /// its interface tokens map to, in interface token order.
    pub implements: Vec<(u16, Vec<u8>)>,
}

impl Default for ClassSpec {
    fn default() -> Self {
        Self {
            super_class: 0xffff,
            declared_size: 0,
            public: Vec::new(),
            package: Vec::new(),
            interface: false,
            implements: Vec::new(),
        }
    }
}

/// A package that verifies, which tests then take apart one field at a time.
pub struct Package {
    /// Header flags. `0x04` is an applet package.
    pub flags: u8,
    /// The bytecode of the single method, which starts after a two byte header.
    pub code: Vec<u8>,
    /// Operand stack words the method asks for.
    pub max_stack: u8,
    /// Argument words the method takes.
    pub nargs: u8,
    /// Local words the method declares on top of its arguments.
    pub max_locals: u8,
    /// Extra methods, appended after the first, each a header pair and its bytecode.
    pub extra: Vec<(u8, u8, Vec<u8>)>,
    /// Bytes of static field image, all starting at zero.
    pub static_bytes: u16,
    /// Constant pool entries, each already four bytes.
    pub constants: Vec<[u8; 4]>,
    /// Exception handlers, each already eight bytes.
    pub handlers: Vec<[u8; 8]>,
    /// The classes, laid out in the order given.
    pub classes: Vec<ClassSpec>,
}

impl Default for Package {
    fn default() -> Self {
        Self {
            flags: 0x04,
            // return, which is all an install method has to do to be well formed.
            code: vec![0x7a],
            max_stack: 2,
            nargs: 3,
            max_locals: 0,
            extra: Vec::new(),
            static_bytes: 0,
            constants: Vec::new(),
            handlers: Vec::new(),
            classes: vec![ClassSpec::default()],
        }
    }
}

fn component(tag: Tag, info: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag as u8];
    bytes.extend_from_slice(&(info.len() as u16).to_be_bytes());
    bytes.extend_from_slice(info);
    bytes
}

impl Package {
    /// Where the first method's bytecode starts in the Method component.
    pub fn install_offset(&self) -> u16 {
        1 + self.handlers.len() as u16 * 8
    }

    /// Where each method after the first starts.
    pub fn extra_offsets(&self) -> Vec<u16> {
        let mut offsets = Vec::new();
        let mut at = self.install_offset() + 2 + self.code.len() as u16;
        for (_, _, code) in &self.extra {
            offsets.push(at);
            at += 2 + code.len() as u16;
        }
        offsets
    }

    /// Where each class lands in the Class component, which is what a class reference is.
    pub fn class_offsets(&self) -> Vec<u16> {
        let mut offsets = Vec::new();
        let mut at = 0u16;
        for spec in &self.classes {
            offsets.push(at);
            at += if spec.interface {
                1
            } else {
                10 + 2 * (spec.public.len() + spec.package.len()) as u16
                    + spec
                        .implements
                        .iter()
                        .map(|(_, tokens)| 3 + tokens.len() as u16)
                        .sum::<u16>()
            };
        }
        offsets
    }

    /// Assemble the block, filling in every size and count so it agrees with itself.
    pub fn build(&self) -> Vec<u8> {
        let mut header = Vec::from([0xde, 0xca, 0xff, 0xed, 1, 2, self.flags, 0, 1]);
        header.push(PACKAGE_AID.len() as u8);
        header.extend_from_slice(&PACKAGE_AID);

        // One method, whose header says two words of stack and three of argument.
        let mut method = vec![self.handlers.len() as u8];
        for handler in &self.handlers {
            method.extend_from_slice(handler);
        }
        let install = method.len() as u16;
        method.push(self.max_stack & 0x0f);
        method.push((self.nargs << 4) | (self.max_locals & 0x0f));
        method.extend_from_slice(&self.code);
        for (nargs, locals, code) in &self.extra {
            method.push(self.max_stack & 0x0f);
            method.push((nargs << 4) | (locals & 0x0f));
            method.extend_from_slice(code);
        }

        let mut applet = vec![1u8, APPLET_AID.len() as u8];
        applet.extend_from_slice(&APPLET_AID);
        applet.extend_from_slice(&install.to_be_bytes());

        let mut constants = Vec::from((self.constants.len() as u16).to_be_bytes());
        for entry in &self.constants {
            constants.extend_from_slice(entry);
        }

        let mut class = Vec::new();
        for spec in &self.classes {
            if spec.interface {
                // ACC_INTERFACE with no superinterfaces.
                class.push(0x80);
                continue;
            }
            class.push(spec.implements.len() as u8);
            class.extend_from_slice(&spec.super_class.to_be_bytes());
            class.extend_from_slice(&[spec.declared_size, 0, 0, 0]);
            class.push(spec.public.len() as u8);
            class.push(0);
            class.push(spec.package.len() as u8);
            for offset in spec.public.iter().chain(&spec.package) {
                class.extend_from_slice(&offset.to_be_bytes());
            }
            for (interface, tokens) in &spec.implements {
                class.extend_from_slice(&interface.to_be_bytes());
                class.push(tokens.len() as u8);
                class.extend_from_slice(tokens);
            }
        }
        let imports = vec![0u8];
        // An image of only default value fields, which start at zero.
        let mut statics = Vec::from(self.static_bytes.to_be_bytes());
        statics.extend_from_slice(&[0, 0, 0, 0]);
        statics.extend_from_slice(&self.static_bytes.to_be_bytes());
        statics.extend_from_slice(&[0, 0]);
        let ref_location = vec![0, 0, 0, 0];

        let parts = [
            (Tag::Applet, applet),
            (Tag::Import, imports),
            (Tag::ConstantPool, constants),
            (Tag::Class, class),
            (Tag::Method, method),
            (Tag::StaticField, statics),
            (Tag::RefLocation, ref_location),
        ];

        // The Directory records the info size of every component, including its own, so it
        // is built once its own length is known.
        let mut sizes = [0u16; 11];
        sizes[Tag::Header as usize - 1] = header.len() as u16;
        for (tag, info) in &parts {
            sizes[*tag as usize - 1] = info.len() as u16;
        }
        let directory_length = 11 * 2 + 9;
        sizes[Tag::Directory as usize - 1] = directory_length;
        let mut directory = Vec::new();
        for size in sizes {
            directory.extend_from_slice(&size.to_be_bytes());
        }
        // Image size, array initialiser count and bytes, then the import, applet and
        // custom component counts.
        let mut tail = Vec::from(self.static_bytes.to_be_bytes());
        tail.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0]);
        directory.extend_from_slice(&tail);

        let mut block = component(Tag::Header, &header);
        block.extend_from_slice(&component(Tag::Directory, &directory));
        for (tag, info) in &parts {
            block.extend_from_slice(&component(*tag, info));
        }
        block
    }
}
