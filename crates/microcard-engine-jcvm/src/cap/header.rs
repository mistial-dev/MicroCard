//! The Header component, JCVM 3.x §6.4.
use crate::{Error, Result};

/// The magic every CAP file starts with.
pub const MAGIC: [u8; 4] = [0xde, 0xca, 0xff, 0xed];

/// Header flag bits. Only the applet bit is expected, per the profile.
pub const ACC_INT: u8 = 0x01;
pub const ACC_EXPORT: u8 = 0x02;
pub const ACC_APPLET: u8 = 0x04;
pub const ACC_EXTENDED: u8 = 0x08;

/// What the package says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub cap_major: u8,
    pub cap_minor: u8,
    pub flags: u8,
    pub package_major: u8,
    pub package_minor: u8,
    pub package_aid: &'a [u8],
}

impl<'a> Header<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        if info.len() < 10 {
            return Err(Error::Bounds);
        }
        if info[..4] != MAGIC {
            return Err(Error::Format);
        }
        let length = info[9] as usize;
        // An AID is 5 to 16 bytes, JCVM §4.2, and it ends the component. Trailing bytes mean
        // the header was built to a layout this parser does not know.
        if !(5..=16).contains(&length) || info.len() != 10 + length {
            return Err(Error::Format);
        }
        Ok(Self {
            cap_minor: info[4],
            cap_major: info[5],
            flags: info[6],
            package_minor: info[7],
            package_major: info[8],
            package_aid: &info[10..],
        })
    }

    /// Whether this build can run the package, per docs/JCVM_PROFILE.md.
    ///
    /// Every rejection here is a capability this engine does not have. A package needing one
    /// is refused at load, where the failure is legible, instead of at the first opcode that
    /// depends on it.
    pub fn supported(&self) -> Result<()> {
        if (self.cap_major, self.cap_minor) != (2, 1) {
            return Err(Error::Unsupported);
        }
        if self.flags & ACC_APPLET == 0 {
            return Err(Error::Unsupported);
        }
        if self.flags & (ACC_INT | ACC_EXPORT | ACC_EXTENDED) != 0 {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn info(flags: u8, aid: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(MAGIC);
        bytes.extend_from_slice(&[1, 2, flags, 10, 1, aid.len() as u8]);
        bytes.extend_from_slice(aid);
        bytes
    }

    const AID: [u8; 9] = [0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0];

    #[test]
    fn the_target_applet_header_parses_and_is_supported() {
        let bytes = info(ACC_APPLET, &AID);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!((header.cap_major, header.cap_minor), (2, 1));
        assert_eq!((header.package_major, header.package_minor), (1, 10));
        assert_eq!(header.package_aid, &AID[..]);
        header.supported().unwrap();
    }

    #[test]
    fn anything_without_the_magic_is_refused() {
        let mut bytes = info(ACC_APPLET, &AID);
        bytes[0] ^= 1;
        assert_eq!(Header::parse(&bytes), Err(Error::Format));
    }

    #[test]
    fn an_aid_that_does_not_end_the_component_is_refused() {
        // Too long for what follows, too short for it, and outside the legal range.
        let mut bytes = info(ACC_APPLET, &AID);
        bytes[9] += 1;
        assert_eq!(Header::parse(&bytes), Err(Error::Format));
        let mut bytes = info(ACC_APPLET, &AID);
        bytes.push(0);
        assert_eq!(Header::parse(&bytes), Err(Error::Format));
        assert_eq!(Header::parse(&info(ACC_APPLET, &[1, 2, 3, 4])), Err(Error::Format));
        assert_eq!(Header::parse(&info(ACC_APPLET, &[7; 17])), Err(Error::Format));
    }

    #[test]
    fn a_truncated_header_is_refused_before_any_field_is_read() {
        let bytes = info(ACC_APPLET, &AID);
        for length in 0..10 {
            assert_eq!(Header::parse(&bytes[..length]), Err(Error::Bounds), "{length}");
        }
    }

    #[test]
    fn capabilities_this_engine_lacks_are_refused_at_load() {
        // Each of these parses cleanly and still cannot run here, which is the distinction
        // the profile draws between a malformed package and an unsupported one.
        for flag in [ACC_INT, ACC_EXPORT, ACC_EXTENDED] {
            let bytes = info(ACC_APPLET | flag, &AID);
            let header = Header::parse(&bytes).unwrap();
            assert_eq!(header.supported(), Err(Error::Unsupported), "{flag:#04x}");
        }
        // A library package carries no applet and has nothing to select.
        let library = info(0, &AID);
        assert_eq!(Header::parse(&library).unwrap().supported(), Err(Error::Unsupported));
        // A later CAP format may move any field this parser reads by offset.
        let mut future = info(ACC_APPLET, &AID);
        future[5] = 3;
        assert_eq!(Header::parse(&future).unwrap().supported(), Err(Error::Unsupported));
    }
}
