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

/// A package that verifies, which tests then take apart one field at a time.
pub struct Package {
    /// Header flags. `0x04` is an applet package.
    pub flags: u8,
    /// The bytecode of the single method, which starts after a two byte header.
    pub code: Vec<u8>,
    /// Operand stack words the method asks for.
    pub max_stack: u8,
    /// Constant pool entries, each already four bytes.
    pub constants: Vec<[u8; 4]>,
    /// Exception handlers, each already eight bytes.
    pub handlers: Vec<[u8; 8]>,
}

impl Default for Package {
    fn default() -> Self {
        Self {
            flags: 0x04,
            // return, which is all an install method has to do to be well formed.
            code: vec![0x7a],
            max_stack: 2,
            constants: Vec::new(),
            handlers: Vec::new(),
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
        method.push(0x30);
        method.extend_from_slice(&self.code);

        let mut applet = vec![1u8, APPLET_AID.len() as u8];
        applet.extend_from_slice(&APPLET_AID);
        applet.extend_from_slice(&install.to_be_bytes());

        let mut constants = Vec::from((self.constants.len() as u16).to_be_bytes());
        for entry in &self.constants {
            constants.extend_from_slice(entry);
        }

        // One class with no superclass and no methods of its own.
        let class = vec![0x00, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0];
        let imports = vec![0u8];
        let statics = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
        directory.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0]);

        let mut block = component(Tag::Header, &header);
        block.extend_from_slice(&component(Tag::Directory, &directory));
        for (tag, info) in &parts {
            block.extend_from_slice(&component(*tag, info));
        }
        block
    }
}
