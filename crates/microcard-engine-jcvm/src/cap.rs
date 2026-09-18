//! The CAP container as it arrives on the card, JCVM 3.x §6.
//!
//! The card never sees the `.cap` archive. GlobalPlatform delivers a Load File Data Block,
//! which is the components in §6.3 order with the archive's class files and its Debug and
//! Descriptor components already gone. Everything here reads that block in place, so no
//! component is ever copied and a malformed length costs a refusal instead of an allocation.
use crate::{Error, Result};

mod applet;
mod directory;
mod header;
mod import;

pub use applet::{Applet, AppletRef};
pub use directory::Directory;
pub use header::Header;
pub use import::{Import, PackageRef};

/// Component tags, JCVM §6.2. The tag doubles as the position in the Directory table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Tag {
    Header = 1,
    Directory = 2,
    Applet = 3,
    Import = 4,
    ConstantPool = 5,
    Class = 6,
    Method = 7,
    StaticField = 8,
    RefLocation = 9,
    Export = 10,
    Descriptor = 11,
    Debug = 12,
}

impl Tag {
    pub fn from_byte(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Header,
            2 => Self::Directory,
            3 => Self::Applet,
            4 => Self::Import,
            5 => Self::ConstantPool,
            6 => Self::Class,
            7 => Self::Method,
            8 => Self::StaticField,
            9 => Self::RefLocation,
            10 => Self::Export,
            11 => Self::Descriptor,
            12 => Self::Debug,
            _ => return Err(Error::Format),
        })
    }

    /// Whether a Load File Data Block may carry this component, JCVM §6.3.
    pub fn in_load_file(self) -> bool {
        !matches!(self, Self::Descriptor | Self::Debug)
    }
}

/// One component, borrowed from the block that carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component<'a> {
    pub tag: Tag,
    /// The bytes after the tag and the size, which is what every offset in §6 counts from.
    pub info: &'a [u8],
}

impl<'a> Component<'a> {
    /// Read one component and return it with whatever follows it.
    ///
    /// The declared size is the only bound the rest of the component is read against, so a
    /// component that overruns the block is refused here and never reaches a field parser.
    pub fn split(bytes: &'a [u8]) -> Result<(Self, &'a [u8])> {
        let (head, rest) = bytes.split_at_checked(3).ok_or(Error::Bounds)?;
        let size = u16::from_be_bytes([head[1], head[2]]) as usize;
        let (info, rest) = rest.split_at_checked(size).ok_or(Error::Bounds)?;
        Ok((
            Self {
                tag: Tag::from_byte(head[0])?,
                info,
            },
            rest,
        ))
    }

    /// The size the Directory records for this component, which counts the info alone.
    pub fn declared_size(&self) -> usize {
        self.info.len()
    }
}

/// The components of one Load File Data Block, in the order they arrived.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadFile<'a> {
    header: Option<Component<'a>>,
    directory: Option<Component<'a>>,
    /// Indexed by tag, so a repeated component is caught by finding the slot taken.
    components: [Option<Component<'a>>; 12],
}

impl<'a> LoadFile<'a> {
    /// Parse a whole Load File Data Block and check it against itself.
    ///
    /// Three things are established here, and every later pass may assume them. The block
    /// tiles exactly, with no gap between components and nothing trailing. Each component
    /// appears at most once, in the order of §6.3. The Directory agrees with what the block
    /// actually holds, which is what catches a block assembled from two different builds.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut file = Self::default();
        let mut rest = bytes;
        let mut previous: Option<Tag> = None;
        while !rest.is_empty() {
            let (component, remainder) = Component::split(rest)?;
            rest = remainder;
            if !component.tag.in_load_file() {
                return Err(Error::Format);
            }
            if previous.is_some_and(|last| last >= component.tag) {
                return Err(Error::Format);
            }
            previous = Some(component.tag);
            file.components[component.tag as usize - 1] = Some(component);
        }
        file.header = file.components[Tag::Header as usize - 1];
        file.directory = file.components[Tag::Directory as usize - 1];
        if file.header.is_none() || file.directory.is_none() {
            return Err(Error::Format);
        }
        let directory = file.directory()?;
        // The Directory describes the whole CAP file, so it still records a size for the
        // Descriptor component that the Load File Data Block leaves behind. Only the
        // components a block may carry are compared, and the Descriptor entry is ignored
        // rather than treated as a package that lost a component in transit.
        for tag in 1..=10u8 {
            let present = file.components[tag as usize - 1].map_or(0, |c| c.declared_size());
            if directory.size(Tag::from_byte(tag)?) as usize != present {
                return Err(Error::Inconsistent);
            }
        }
        // A Method component is what an applet is made of, so a block without one is not a
        // package this engine can ever run.
        if file.components[Tag::Method as usize - 1].is_none() {
            return Err(Error::Format);
        }
        Ok(file)
    }

    pub fn component(&self, tag: Tag) -> Option<Component<'a>> {
        self.components[tag as usize - 1]
    }

    pub fn header(&self) -> Result<Header<'a>> {
        Header::parse(self.header.ok_or(Error::Format)?.info)
    }

    pub fn directory(&self) -> Result<Directory<'a>> {
        Directory::parse(self.directory.ok_or(Error::Format)?.info)
    }

    /// The applets this package declares. An applet package always has one.
    pub fn applets(&self) -> Result<Applet<'a>> {
        Applet::parse(self.component(Tag::Applet).ok_or(Error::Format)?.info)
    }

    /// The imports, or an empty table when the package borrows nothing.
    pub fn imports(&self) -> Result<Import<'a>> {
        match self.component(Tag::Import) {
            Some(component) => Import::parse(component.info),
            None => Import::parse(&[0]),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    /// Build one component with a correct tag and size.
    fn component(tag: Tag, info: &[u8]) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![tag as u8];
        bytes.extend_from_slice(&(info.len() as u16).to_be_bytes());
        bytes.extend_from_slice(info);
        bytes
    }

    const PACKAGE_AID: [u8; 9] = [0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0];

    fn header_info() -> alloc::vec::Vec<u8> {
        let mut info = alloc::vec![0xde, 0xca, 0xff, 0xed, 1, 2, 0x04, 10, 1];
        info.push(PACKAGE_AID.len() as u8);
        info.extend_from_slice(&PACKAGE_AID);
        info
    }

    /// A block whose Directory is filled in from the components it actually carries.
    fn block(parts: &[(Tag, alloc::vec::Vec<u8>)]) -> alloc::vec::Vec<u8> {
        let mut sizes = [0u16; 11];
        for (tag, info) in parts {
            sizes[*tag as usize - 1] = info.len() as u16;
        }
        // The Directory records its own size too, and its length is fixed, so one pass is
        // enough once the table and the trailing counts are laid out.
        let mut table = alloc::vec::Vec::new();
        let directory_info_len = 11 * 2 + 9;
        sizes[Tag::Directory as usize - 1] = directory_info_len as u16;
        for size in sizes {
            table.extend_from_slice(&size.to_be_bytes());
        }
        table.extend_from_slice(&[0; 9]);
        let mut all: alloc::vec::Vec<(Tag, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        all.push((Tag::Directory, table));
        all.extend(parts.iter().cloned());
        all.sort_by_key(|(tag, _)| *tag as u8);
        let mut bytes = alloc::vec::Vec::new();
        for (tag, info) in all {
            bytes.extend_from_slice(&component(tag, &info));
        }
        bytes
    }

    fn well_formed() -> alloc::vec::Vec<u8> {
        block(&[
            (Tag::Header, header_info()),
            (Tag::Method, alloc::vec![0; 40]),
        ])
    }

    #[test]
    fn a_well_formed_block_parses_and_keeps_its_components_in_place() {
        let bytes = well_formed();
        let file = LoadFile::parse(&bytes).unwrap();
        let header = file.header().unwrap();
        assert_eq!((header.cap_major, header.cap_minor), (2, 1));
        assert_eq!(header.flags, 0x04);
        assert_eq!((header.package_major, header.package_minor), (1, 10));
        assert_eq!(header.package_aid, &PACKAGE_AID[..]);
        assert_eq!(file.component(Tag::Method).unwrap().declared_size(), 40);
        assert!(file.component(Tag::Import).is_none());
    }

    #[test]
    fn a_component_may_not_overrun_the_block() {
        let mut bytes = well_formed();
        // Claim one byte more than the block holds. Without the check the Method component
        // would borrow whatever followed it in flash.
        let length = bytes.len();
        bytes[length - 40 - 2..length - 40].copy_from_slice(&41u16.to_be_bytes());
        assert_eq!(LoadFile::parse(&bytes), Err(Error::Bounds));
    }

    #[test]
    fn descriptor_and_debug_are_refused_inside_a_load_file() {
        for tag in [Tag::Descriptor, Tag::Debug] {
            let mut bytes = well_formed();
            bytes.extend_from_slice(&component(tag, &[0; 4]));
            assert_eq!(LoadFile::parse(&bytes), Err(Error::Format), "{tag:?}");
        }
    }

    #[test]
    fn components_out_of_order_or_repeated_are_refused() {
        let bytes = well_formed();
        let mut reversed = alloc::vec::Vec::new();
        let (first, rest) = Component::split(&bytes).unwrap();
        let (second, rest) = Component::split(rest).unwrap();
        reversed.extend_from_slice(&component(second.tag, second.info));
        reversed.extend_from_slice(&component(first.tag, first.info));
        reversed.extend_from_slice(rest);
        assert_eq!(LoadFile::parse(&reversed), Err(Error::Format));

        let mut repeated = bytes.clone();
        repeated.extend_from_slice(&component(Tag::Method, &[0; 40]));
        assert_eq!(LoadFile::parse(&repeated), Err(Error::Format));
    }

    #[test]
    fn a_descriptor_size_left_in_the_directory_is_ignored() {
        // Every real block carries this, because the Directory describes the CAP file it
        // came from and the block drops the Descriptor on its way to the card.
        let mut bytes = well_formed();
        let offset = 3 + header_info().len() + 3 + (Tag::Descriptor as usize - 1) * 2;
        bytes[offset..offset + 2].copy_from_slice(&10_622u16.to_be_bytes());
        LoadFile::parse(&bytes).unwrap();
    }

    #[test]
    fn a_directory_that_disagrees_with_the_block_is_refused() {
        let mut bytes = well_formed();
        // The Directory entry for Method sits at its table offset inside the second
        // component. Moving it by one is how two different builds would disagree.
        let offset = 3 + header_info().len() + 3 + (Tag::Method as usize - 1) * 2;
        let claimed = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        bytes[offset..offset + 2].copy_from_slice(&(claimed + 1).to_be_bytes());
        assert_eq!(LoadFile::parse(&bytes), Err(Error::Inconsistent));
    }

    #[test]
    fn a_block_without_a_header_directory_or_method_is_refused() {
        assert_eq!(LoadFile::parse(&[]), Err(Error::Format));
        let no_method = block(&[(Tag::Header, header_info())]);
        assert_eq!(LoadFile::parse(&no_method), Err(Error::Format));
    }
}
