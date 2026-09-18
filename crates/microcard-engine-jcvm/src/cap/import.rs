//! The Import component, JCVM 3.x §6.7.
//!
//! This is where a card decides whether it can run a package at all. Every class, method
//! and field the package borrows is addressed by a token whose meaning comes from the
//! export file of the package named here, so an import resolved against the wrong version
//! silently changes what a token means.
use crate::{Error, Result};

/// One package the CAP file borrows from, with the minimum version it was linked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageRef<'a> {
    pub major: u8,
    pub minor: u8,
    pub aid: &'a [u8],
}

impl PackageRef<'_> {
    /// Whether a package the card provides can stand in for this import, JCVM §4.5.2.
    ///
    /// The major version has to be the same, because a new major version is free to
    /// renumber tokens. A newer minor version only adds to the end, so it still answers
    /// every token this package knows.
    pub fn satisfied_by(&self, major: u8, minor: u8) -> bool {
        major == self.major && minor >= self.minor
    }
}

/// The imports of one package, borrowed from the component that carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import<'a> {
    count: u8,
    entries: &'a [u8],
}

impl<'a> Import<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let (&count, mut rest) = info.split_first().ok_or(Error::Bounds)?;
        // Walk the whole table now so every later read is a walk over checked bytes.
        for _ in 0..count {
            let (_, remainder) = read_package(rest)?;
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

    /// The imports in the order the package numbers them, which is how a token names one.
    pub fn iter(&self) -> impl Iterator<Item = PackageRef<'a>> {
        let mut rest = self.entries;
        (0..self.count).map(move |_| {
            let (package, remainder) = read_package(rest).expect("checked during parse");
            rest = remainder;
            package
        })
    }

    /// The import a package token refers to, by its index in this table.
    pub fn get(&self, index: u8) -> Result<PackageRef<'a>> {
        self.iter().nth(index as usize).ok_or(Error::Bounds)
    }
}

fn read_package(bytes: &[u8]) -> Result<(PackageRef<'_>, &[u8])> {
    let (head, rest) = bytes.split_at_checked(3).ok_or(Error::Bounds)?;
    let length = head[2] as usize;
    if !(5..=16).contains(&length) {
        return Err(Error::Format);
    }
    let (aid, rest) = rest.split_at_checked(length).ok_or(Error::Bounds)?;
    Ok((
        PackageRef {
            minor: head[0],
            major: head[1],
            aid,
        },
        rest,
    ))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    const JAVA_LANG: [u8; 7] = [0xa0, 0, 0, 0, 0x62, 0, 1];
    const FRAMEWORK: [u8; 7] = [0xa0, 0, 0, 0, 0x62, 1, 1];

    fn info(packages: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut bytes = alloc::vec![packages.len() as u8];
        for (major, minor, aid) in packages {
            bytes.extend_from_slice(&[*minor, *major, aid.len() as u8]);
            bytes.extend_from_slice(aid);
        }
        bytes
    }

    #[test]
    fn imports_read_back_in_the_order_a_token_names_them() {
        let bytes = info(&[(1, 0, &JAVA_LANG), (1, 6, &FRAMEWORK)]);
        let imports = Import::parse(&bytes).unwrap();
        assert_eq!(imports.count(), 2);
        let all: Vec<PackageRef> = imports.iter().collect();
        assert_eq!(all[0], PackageRef { major: 1, minor: 0, aid: &JAVA_LANG });
        assert_eq!(all[1], PackageRef { major: 1, minor: 6, aid: &FRAMEWORK });
        assert_eq!(imports.get(1).unwrap().aid, &FRAMEWORK[..]);
        assert_eq!(imports.get(2), Err(Error::Bounds));
    }

    #[test]
    fn a_card_may_be_newer_in_the_minor_version_and_no_other_way() {
        // Java Card 3.0.5 exports javacard.framework 1.6. A 3.0.4 card exports 1.5 and
        // cannot run this package, which is the whole reason the target version is 3.0.5.
        let needs = PackageRef { major: 1, minor: 6, aid: &FRAMEWORK };
        assert!(needs.satisfied_by(1, 6));
        assert!(needs.satisfied_by(1, 7));
        assert!(!needs.satisfied_by(1, 5));
        // A new major version is free to renumber every token, so it is not a substitute in
        // either direction.
        assert!(!needs.satisfied_by(2, 6));
        assert!(!needs.satisfied_by(0, 9));
    }

    #[test]
    fn a_count_that_disagrees_with_the_table_is_refused() {
        let mut bytes = info(&[(1, 0, &JAVA_LANG)]);
        bytes[0] = 2;
        assert_eq!(Import::parse(&bytes), Err(Error::Bounds));
        let mut bytes = info(&[(1, 0, &JAVA_LANG), (1, 6, &FRAMEWORK)]);
        bytes[0] = 1;
        assert_eq!(Import::parse(&bytes), Err(Error::Format));
    }

    #[test]
    fn an_aid_outside_the_legal_length_is_refused() {
        for length in [0u8, 4, 17] {
            let mut bytes = info(&[(1, 0, &JAVA_LANG)]);
            bytes[3] = length;
            assert_eq!(Import::parse(&bytes), Err(Error::Format), "{length}");
        }
    }

    #[test]
    fn an_aid_running_past_the_component_is_refused() {
        let mut bytes = info(&[(1, 0, &JAVA_LANG)]);
        bytes[3] = 16;
        assert_eq!(Import::parse(&bytes), Err(Error::Bounds));
    }

    #[test]
    fn an_empty_component_is_refused() {
        assert_eq!(Import::parse(&[]), Err(Error::Bounds));
        // A package importing nothing is legal and still has to say so.
        assert_eq!(Import::parse(&[0]).unwrap().count(), 0);
    }
}
