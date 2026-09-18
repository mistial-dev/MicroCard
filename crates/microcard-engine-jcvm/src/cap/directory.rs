//! The Directory component, JCVM 3.x §6.5.
use super::Tag;
use crate::{Error, Result};

/// The Directory carries a size for each of the eleven components that can appear in a CAP
/// file. Debug has no entry, which is one reason it never reaches the card.
const SIZED_COMPONENTS: usize = 11;

/// What the package claims about its own shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Directory<'a> {
    sizes: &'a [u8],
    /// The static field image and the array initialisers, which the loader sizes memory from.
    pub image_size: u16,
    pub array_init_count: u16,
    pub array_init_size: u16,
    pub import_count: u8,
    pub applet_count: u8,
    pub custom_count: u8,
}

impl<'a> Directory<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        // Eleven sizes, then the static field image sizes and the three counts.
        let tail = SIZED_COMPONENTS * 2;
        if info.len() < tail + 9 {
            return Err(Error::Bounds);
        }
        let word = |at: usize| u16::from_be_bytes([info[at], info[at + 1]]);
        let directory = Self {
            sizes: &info[..tail],
            image_size: word(tail),
            array_init_count: word(tail + 2),
            array_init_size: word(tail + 4),
            import_count: info[tail + 6],
            applet_count: info[tail + 7],
            custom_count: info[tail + 8],
        };
        // A custom component would sit after the counts and this build does not read one, so
        // a package carrying any is refused rather than half understood.
        if directory.custom_count != 0 {
            return Err(Error::Unsupported);
        }
        if info.len() != tail + 9 {
            return Err(Error::Format);
        }
        Ok(directory)
    }

    /// The size this Directory records for a component, counting its info bytes alone.
    ///
    /// An absent component records zero, which is how the loader tells an absent Export
    /// component from an empty one.
    pub fn size(&self, tag: Tag) -> u16 {
        let index = tag as usize - 1;
        if index >= SIZED_COMPONENTS {
            return 0;
        }
        u16::from_be_bytes([self.sizes[index * 2], self.sizes[index * 2 + 1]])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn info(sizes: [u16; SIZED_COMPONENTS], custom: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        for size in sizes {
            bytes.extend_from_slice(&size.to_be_bytes());
        }
        bytes.extend_from_slice(&76u16.to_be_bytes());
        bytes.extend_from_slice(&23u16.to_be_bytes());
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes.extend_from_slice(&[6, 1, custom]);
        bytes
    }

    /// The component sizes of the smallest target variant, measured from its CAP file.
    const MEASURED: [u16; SIZED_COMPONENTS] = [19, 31, 15, 60, 3042, 1170, 35856, 462, 4240, 0, 10622];

    #[test]
    fn the_measured_directory_reads_back_component_by_component() {
        let bytes = info(MEASURED, 0);
        let directory = Directory::parse(&bytes).unwrap();
        assert_eq!(directory.size(Tag::Header), 19);
        assert_eq!(directory.size(Tag::Method), 35856);
        assert_eq!(directory.size(Tag::Descriptor), 10622);
        // Export is absent from this package and records zero.
        assert_eq!(directory.size(Tag::Export), 0);
        // Debug has no entry at all, so asking for it answers zero without reading past the
        // table.
        assert_eq!(directory.size(Tag::Debug), 0);
        assert_eq!(directory.image_size, 76);
        assert_eq!(directory.array_init_count, 23);
        assert_eq!(directory.array_init_size, 443);
        assert_eq!((directory.import_count, directory.applet_count), (6, 1));
    }

    #[test]
    fn a_truncated_directory_is_refused() {
        let bytes = info(MEASURED, 0);
        for length in [0, 1, 22, bytes.len() - 1] {
            assert_eq!(Directory::parse(&bytes[..length]), Err(Error::Bounds), "{length}");
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = info(MEASURED, 0);
        bytes.push(0);
        assert_eq!(Directory::parse(&bytes), Err(Error::Format));
    }

    #[test]
    fn a_custom_component_is_refused_while_none_is_understood() {
        let bytes = info(MEASURED, 1);
        assert_eq!(Directory::parse(&bytes), Err(Error::Unsupported));
    }
}
