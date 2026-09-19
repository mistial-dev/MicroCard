//! The Static Field component, JCVM 3.x §6.11.
//!
//! The static field image is a flat array of words that every `getstatic` and `putstatic`
//! indexes into. This component says how large it is, which part of it holds references,
//! and what the fields that are not zero start out as.
use crate::{Error, Result};

/// Array element types, JCVM Table 6-15.
pub const TYPE_BOOLEAN: u8 = 2;
pub const TYPE_BYTE: u8 = 3;
pub const TYPE_SHORT: u8 = 4;
pub const TYPE_INT: u8 = 5;

/// One primitive array a static field starts out holding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArrayInit<'a> {
    pub element_type: u8,
    /// The initial bytes, big endian for the wider types.
    pub values: &'a [u8],
}

impl ArrayInit<'_> {
    /// Bytes one element occupies, JCVM Table 6-14.
    pub fn element_size(&self) -> usize {
        match self.element_type {
            TYPE_BOOLEAN | TYPE_BYTE => 1,
            TYPE_SHORT => 2,
            _ => 4,
        }
    }

    /// Elements the array has, which is the length Java sees.
    pub fn length(&self) -> usize {
        self.values.len() / self.element_size()
    }
}

/// The static field image of one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticField<'a> {
    /// Bytes the whole image occupies.
    pub image_size: u16,
    /// Words at the start of the image that hold references, JCVM §6.11. They are
    /// initialised to null and are the only part the firewall has to trace.
    pub reference_count: u16,
    array_init_count: u16,
    array_inits: &'a [u8],
    /// Fields that start at zero, counted in bytes.
    pub default_value_count: u16,
    /// Initial bytes of the fields that do not start at zero.
    pub non_default_values: &'a [u8],
}

impl<'a> StaticField<'a> {
    pub fn parse(info: &'a [u8]) -> Result<Self> {
        let head = info.get(..6).ok_or(Error::Bounds)?;
        let word = |at: usize| u16::from_be_bytes([head[at], head[at + 1]]);
        let array_init_count = word(4);
        // Walk the array initialisers to find where they end, since each one carries its
        // own length and there is no table of offsets.
        let mut at = 6;
        for _ in 0..array_init_count {
            let entry = info.get(at..at + 3).ok_or(Error::Bounds)?;
            if !(TYPE_BOOLEAN..=TYPE_INT).contains(&entry[0]) {
                return Err(Error::Format);
            }
            let count = u16::from_be_bytes([entry[1], entry[2]]) as usize;
            at = at.checked_add(3 + count).ok_or(Error::Bounds)?;
            if at > info.len() {
                return Err(Error::Bounds);
            }
        }
        let array_inits = &info[6..at];
        let tail = info.get(at..at + 4).ok_or(Error::Bounds)?;
        let default_value_count = u16::from_be_bytes([tail[0], tail[1]]);
        let non_default_value_count = u16::from_be_bytes([tail[2], tail[3]]) as usize;
        let non_default_values = info
            .get(at + 4..at + 4 + non_default_value_count)
            .ok_or(Error::Bounds)?;
        if at + 4 + non_default_value_count != info.len() {
            return Err(Error::Format);
        }
        let image_size = word(0);
        let field = Self {
            image_size,
            reference_count: word(2),
            array_init_count,
            array_inits,
            default_value_count,
            non_default_values,
        };
        // The image has to account for exactly what the component describes, or a static
        // field would read initial bytes that belong to another field.
        let described = field.reference_count as u32 * 2
            + default_value_count as u32
            + non_default_value_count as u32;
        if described != image_size as u32 || array_init_count > field.reference_count {
            return Err(Error::Inconsistent);
        }
        for array in field.array_inits() {
            if !array.values.len().is_multiple_of(array.element_size())
                || array.length() > i16::MAX as usize
                || (array.element_type == TYPE_BOOLEAN && array.values.iter().any(|byte| *byte > 1))
            {
                return Err(Error::Format);
            }
        }
        Ok(field)
    }

    pub fn array_init_count(&self) -> usize {
        self.array_init_count as usize
    }

    pub fn array_inits(&self) -> impl Iterator<Item = ArrayInit<'a>> + use<'a> {
        let mut rest = self.array_inits;
        core::iter::from_fn(move || {
            let entry = rest.get(..3)?;
            let count = u16::from_be_bytes([entry[1], entry[2]]) as usize;
            let values = rest.get(3..3 + count)?;
            rest = &rest[3 + count..];
            Some(ArrayInit {
                element_type: entry[0],
                values,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn component(references: u16, arrays: &[(u8, &[u8])], defaults: u16, values: &[u8]) -> Vec<u8> {
        let image = references * 2 + defaults + values.len() as u16;
        let mut bytes = Vec::from(image.to_be_bytes());
        bytes.extend_from_slice(&references.to_be_bytes());
        bytes.extend_from_slice(&(arrays.len() as u16).to_be_bytes());
        for (element_type, data) in arrays {
            bytes.push(*element_type);
            bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            bytes.extend_from_slice(data);
        }
        bytes.extend_from_slice(&defaults.to_be_bytes());
        bytes.extend_from_slice(&(values.len() as u16).to_be_bytes());
        bytes.extend_from_slice(values);
        bytes
    }

    #[test]
    fn the_image_is_described_by_its_three_parts() {
        let info = component(3, &[], 10, &[1, 2, 3, 4]);
        let fields = StaticField::parse(&info).unwrap();
        // References come first and start as null, then the fields that start at zero, then
        // the ones with an initial value.
        assert_eq!(fields.reference_count, 3);
        assert_eq!(fields.default_value_count, 10);
        assert_eq!(fields.non_default_values, &[1, 2, 3, 4]);
        assert_eq!(fields.image_size, 20);
    }

    #[test]
    fn an_image_size_that_does_not_add_up_is_refused() {
        // A field whose initial bytes are not accounted for would read whatever the image
        // held next.
        let mut info = component(1, &[], 4, &[9, 9]);
        info[0..2].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(StaticField::parse(&info), Err(Error::Inconsistent));
    }

    #[test]
    fn array_initialisers_carry_their_own_lengths() {
        let info = component(
            2,
            &[(TYPE_BYTE, &[1, 2, 3]), (TYPE_SHORT, &[0, 4, 0, 5])],
            0,
            &[],
        );
        let fields = StaticField::parse(&info).unwrap();
        assert_eq!(fields.array_init_count(), 2);
        let all: Vec<ArrayInit> = fields.array_inits().collect();
        assert_eq!(all[0].length(), 3);
        // The count is bytes, so a short array is half as long as its byte count, which is
        // the distinction the specification calls out.
        assert_eq!(all[1].element_size(), 2);
        assert_eq!(all[1].length(), 2);
        assert_eq!(all[1].values, &[0, 4, 0, 5]);
        for (references, arrays) in [
            (0, &[(TYPE_BYTE, &[1][..])][..]),
            (1, &[(TYPE_SHORT, &[1][..])][..]),
            (1, &[(TYPE_BOOLEAN, &[2][..])][..]),
        ] {
            assert!(StaticField::parse(&component(references, arrays, 0, &[])).is_err());
        }
    }

    #[test]
    fn a_truncated_or_overrunning_component_is_refused() {
        let info = component(1, &[(TYPE_BYTE, &[1, 2, 3])], 0, &[]);
        for length in 0..info.len() {
            assert!(StaticField::parse(&info[..length]).is_err(), "{length}");
        }
        // Trailing bytes mean the component was built to a layout this parser cannot read.
        let mut longer = info.clone();
        longer.push(0);
        assert_eq!(StaticField::parse(&longer), Err(Error::Format));
    }

    #[test]
    fn an_unknown_array_type_is_refused() {
        for element_type in [0u8, 1, 6, 0xff] {
            let info = component(0, &[(element_type, &[1])], 0, &[]);
            assert_eq!(StaticField::parse(&info), Err(Error::Format), "{element_type}");
        }
    }
}
