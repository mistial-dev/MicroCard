//! The Applet component, JCVM 3.x §6.6.
//!
//! One entry per applet the package declares. The install method offset points into the
//! Method component, and following it is how a card runs `install` at instantiation.
use crate::{Error, Result};

/// One declared applet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppletRef<'a> {
    pub aid: &'a [u8],
    /// A byte offset into the Method component, checked against it at link time.
    pub install_method_offset: u16,
}

/// The applets of one package, borrowed from the component that carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applet<'a> {
    count: u8,
    entries: &'a [u8],
}

impl<'a> Applet<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let (&count, mut rest) = info.split_first().ok_or(Error::Bounds)?;
        // An applet package declares at least one applet, JCVM §6.6.
        if count == 0 {
            return Err(Error::Format);
        }
        for _ in 0..count {
            let (_, remainder) = read_applet(rest)?;
            rest = remainder;
        }
        if !rest.is_empty() {
            return Err(Error::Format);
        }
        Ok(Self {
            count,
            entries: &info[1..],
        })
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn iter(&self) -> impl Iterator<Item = AppletRef<'a>> {
        let mut rest = self.entries;
        (0..self.count).map(move |_| {
            let (applet, remainder) = read_applet(rest).expect("checked during parse");
            rest = remainder;
            applet
        })
    }

    /// The applet with this AID, which is how SELECT finds one.
    pub fn find(&self, aid: &[u8]) -> Option<AppletRef<'a>> {
        self.iter().find(|applet| applet.aid == aid)
    }
}

fn read_applet(bytes: &[u8]) -> Result<(AppletRef<'_>, &[u8])> {
    let (&length, rest) = bytes.split_first().ok_or(Error::Bounds)?;
    if !(5..=16).contains(&length) {
        return Err(Error::Format);
    }
    let (aid, rest) = rest.split_at_checked(length as usize).ok_or(Error::Bounds)?;
    let (offset, rest) = rest.split_at_checked(2).ok_or(Error::Bounds)?;
    Ok((
        AppletRef {
            aid,
            install_method_offset: u16::from_be_bytes([offset[0], offset[1]]),
        },
        rest,
    ))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    const PIV: [u8; 11] = [0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0];
    const OTHER: [u8; 5] = [0xf0, 1, 2, 3, 4];

    fn info(applets: &[(&[u8], u16)]) -> Vec<u8> {
        let mut bytes = alloc::vec![applets.len() as u8];
        for (aid, offset) in applets {
            bytes.push(aid.len() as u8);
            bytes.extend_from_slice(aid);
            bytes.extend_from_slice(&offset.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn the_target_applet_reads_back_with_its_install_entry_point() {
        let bytes = info(&[(&PIV, 0x0177)]);
        let applet = Applet::parse(&bytes).unwrap();
        assert_eq!(applet.count(), 1);
        let entry = applet.find(&PIV).unwrap();
        assert_eq!(entry.aid, &PIV[..]);
        assert_eq!(entry.install_method_offset, 0x0177);
        // A SELECT for something this package does not declare finds nothing, without the
        // caller having to know how many applets there are.
        assert!(applet.find(&OTHER).is_none());
        // A prefix of a declared AID is a different applet, JCVM §4.2.
        assert!(applet.find(&PIV[..10]).is_none());
    }

    #[test]
    fn several_applets_keep_their_own_entry_points() {
        let bytes = info(&[(&PIV, 1), (&OTHER, 0xfffe)]);
        let applet = Applet::parse(&bytes).unwrap();
        assert_eq!(applet.count(), 2);
        assert_eq!(applet.find(&OTHER).unwrap().install_method_offset, 0xfffe);
        assert_eq!(applet.find(&PIV).unwrap().install_method_offset, 1);
    }

    #[test]
    fn a_package_declaring_no_applet_is_refused_here() {
        // The Header flags say whether a package is an applet package. A component claiming
        // zero applets contradicts that, and a card would have nothing to install.
        assert_eq!(Applet::parse(&[0]), Err(Error::Format));
        assert_eq!(Applet::parse(&[]), Err(Error::Bounds));
    }

    #[test]
    fn a_count_that_disagrees_with_the_table_is_refused() {
        let mut bytes = info(&[(&PIV, 1)]);
        bytes[0] = 2;
        assert_eq!(Applet::parse(&bytes), Err(Error::Bounds));
        let mut bytes = info(&[(&PIV, 1), (&OTHER, 2)]);
        bytes[0] = 1;
        assert_eq!(Applet::parse(&bytes), Err(Error::Format));
    }

    #[test]
    fn an_aid_outside_the_legal_length_is_refused() {
        for length in [0u8, 4, 17] {
            let mut bytes = info(&[(&PIV, 1)]);
            bytes[1] = length;
            assert_eq!(Applet::parse(&bytes), Err(Error::Format), "{length}");
        }
    }

    #[test]
    fn an_entry_without_room_for_its_offset_is_refused() {
        let mut bytes = info(&[(&PIV, 1)]);
        bytes.truncate(bytes.len() - 1);
        assert_eq!(Applet::parse(&bytes), Err(Error::Bounds));
    }
}
