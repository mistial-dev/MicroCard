//! Stable native capability identifiers shared by package and domain validation.
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub arguments: u8,
    pub returns: bool,
}

pub fn signature(id: u8) -> Result<Signature> {
    let (arguments, returns) = match id {
        2 => (1, false),
        3 => (1, true),
        4 | 6 => (2, false),
        5 | 9 | 10 => (0, true),
        11 => (0, true),
        12 => (4, false),
        13 => (3, false),
        7 => (2, true),
        8 => (3, false),
        20 => (1, true),
        22 => (3, true),
        23 => (2, true),
        24 => (2, false),
        25 | 26 => (2, true),
        27 | 28 => (3, true),
        29 | 30 => (4, true),
        31 => (2, true),
        32 => (3, false),
        33 => (2, false),
        34 => (2, true),
        35 => (1, true),
        36 => (4, true),
        37 => (3, true),
        38 => (2, true),
        39 => (3, false),
        40 => (9, false),
        41 => (4, true),
        42 => (1, true),
        43 => (4, false),
        44 => (7, true),
        45 => (2, true),
        46..=48 => (1, false),
        49 | 53 => (5, true),
        50 => (1, true),
        51 | 54 => (6, true),
        52 => (5, false),
        _ => return Err(Error::Native),
    };
    Ok(Signature { arguments, returns })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_table_is_exact() {
        let valid = [
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20, 22, 23, 24, 25, 26, 27, 28,
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54,
        ];
        for id in 0..=u8::MAX {
            assert_eq!(
                signature(id).is_ok(),
                valid.contains(&id),
                "capability {id}"
            );
        }
    }
}
