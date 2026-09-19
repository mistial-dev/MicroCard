//! Restricted deterministic CBOR primitives for versioned device contracts.
//! Callers supply field order, collection limits, and semantic validation.
use crate::{Error, Result};
use alloc::{string::String, vec::Vec};
use zeroize::Zeroize;

pub struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let value = self.remaining.get(..length).ok_or(Error::Format)?;
        self.remaining = &self.remaining[length..];
        Ok(value)
    }

    fn argument(&mut self, major: u8) -> Result<u64> {
        let initial = self.take(1)?[0];
        if initial >> 5 != major {
            return Err(Error::Format);
        }
        let extra = initial & 31;
        let (length, minimum) = match extra {
            0..=23 => return Ok(u64::from(extra)),
            24 => (1, 24),
            25 => (2, 256),
            26 => (4, 65536),
            27 => (8, 4294967296),
            _ => return Err(Error::Format),
        };
        let mut value = 0u64;
        for byte in self.take(length)? {
            value = (value << 8) | u64::from(*byte);
        }
        if value < minimum {
            return Err(Error::Format);
        }
        Ok(value)
    }

    pub(crate) fn number<T: TryFrom<u64>>(&mut self) -> Result<T> {
        T::try_from(self.unsigned()?).map_err(|_| Error::Format)
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?.try_into().map_err(|_| Error::Format)
    }

    pub(crate) fn owned_text(&mut self, maximum: usize) -> Result<String> {
        let text = self.text(maximum)?;
        let mut output = String::new();
        output
            .try_reserve_exact(text.len())
            .map_err(|_| Error::Quota)?;
        output.push_str(text);
        Ok(output)
    }

    pub fn unsigned(&mut self) -> Result<u64> {
        self.argument(0)
    }

    pub fn integer(&mut self) -> Result<i64> {
        let major = self.remaining.first().ok_or(Error::Format)? >> 5;
        if major > 1 {
            return Err(Error::Format);
        }
        let value = i64::try_from(self.argument(major)?).map_err(|_| Error::Format)?;
        Ok(if major == 0 { value } else { -1 - value })
    }

    fn length(&mut self, major: u8, maximum: usize) -> Result<usize> {
        let length = usize::try_from(self.argument(major)?).map_err(|_| Error::Format)?;
        if length > maximum {
            return Err(Error::Format);
        }
        Ok(length)
    }

    pub fn array(&mut self, maximum: usize) -> Result<usize> {
        self.length(4, maximum)
    }

    pub fn record(&mut self, fields: usize) -> Result<()> {
        if self.array(fields)? != fields {
            return Err(Error::Format);
        }
        Ok(())
    }

    pub fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = self.length(2, maximum)?;
        self.take(length)
    }

    pub fn text(&mut self, maximum: usize) -> Result<&'a str> {
        let length = self.length(3, maximum)?;
        core::str::from_utf8(self.take(length)?).map_err(|_| Error::Format)
    }

    pub fn boolean(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(Error::Format),
        }
    }

    /// Consume null when present; the caller decodes the other permitted type otherwise.
    pub fn null(&mut self) -> bool {
        if self.remaining.first() == Some(&0xf6) {
            self.remaining = &self.remaining[1..];
            true
        } else {
            false
        }
    }

    pub fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Format)
        }
    }
}

pub struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Encoder {
    pub fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(Error::Quota);
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            // Snapshot buffers can contain keys. Wipe the old allocation before releasing it.
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.maximum);
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(capacity)
                .map_err(|_| Error::Quota)?;
            replacement.extend_from_slice(&self.bytes);
            self.bytes.zeroize();
            self.bytes = replacement;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn argument(&mut self, major: u8, value: u64) -> Result<()> {
        let mut header = [0; 9];
        let (additional, length) = match value {
            0..=23 => (value as u8, 0),
            24..=255 => (24, 1),
            256..=65535 => (25, 2),
            65536..=4294967295 => (26, 4),
            _ => (27, 8),
        };
        header[0] = major << 5 | additional;
        header[1..1 + length].copy_from_slice(&value.to_be_bytes()[8 - length..]);
        self.append(&header[..1 + length])
    }

    pub fn unsigned(&mut self, value: u64) -> Result<()> {
        self.argument(0, value)
    }
    pub fn integer(&mut self, value: i64) -> Result<()> {
        if value >= 0 {
            self.argument(0, value as u64)
        } else {
            self.argument(1, (-1 - value) as u64)
        }
    }
    pub fn array(&mut self, length: usize) -> Result<()> {
        self.argument(4, length as u64)
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.argument(2, bytes.len() as u64)?;
        self.append(bytes)
    }
    pub fn text(&mut self, text: &str) -> Result<()> {
        self.argument(3, text.len() as u64)?;
        self.append(text.as_bytes())
    }
    pub fn boolean(&mut self, value: bool) -> Result<()> {
        self.append(&[if value { 0xf5 } else { 0xf4 }])
    }
    pub fn null(&mut self) -> Result<()> {
        self.append(&[0xf6])
    }
    pub fn finish(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8949_integer_examples_and_boundaries() {
        for (value, bytes) in [
            (0, &b"\x00"[..]),
            (23, &b"\x17"[..]),
            (24, &b"\x18\x18"[..]),
            (255, &b"\x18\xff"[..]),
            (256, &b"\x19\x01\x00"[..]),
            (65535, &b"\x19\xff\xff"[..]),
            (65536, &b"\x1a\x00\x01\x00\x00"[..]),
            (u32::MAX as u64, &b"\x1a\xff\xff\xff\xff"[..]),
            (1u64 << 32, &b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00"[..]),
            (u64::MAX, &b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff"[..]),
        ] {
            let mut writer = Encoder::new(9);
            writer.unsigned(value).unwrap();
            assert_eq!(writer.finish(), bytes);
            let mut reader = Decoder::new(bytes);
            assert_eq!(reader.unsigned(), Ok(value));
            reader.finish().unwrap();
            for end in 0..bytes.len() {
                assert_eq!(Decoder::new(&bytes[..end]).unsigned(), Err(Error::Format));
            }
        }
        for value in [i64::MIN, -65537, -25, -24, -1, 0, i64::MAX] {
            let mut writer = Encoder::new(9);
            writer.integer(value).unwrap();
            assert_eq!(Decoder::new(&writer.finish()).integer(), Ok(value));
        }
        assert_eq!(Decoder::new(b"\x20").integer(), Ok(-1));
        assert_eq!(Decoder::new(b"\x38\x63").integer(), Ok(-100));
    }

    #[test]
    fn restricted_types_lengths_and_preferred_encodings() {
        for bytes in [
            &b"\x18\x00"[..],
            &b"\x19\x00\xff"[..],
            &b"\x1a\x00\x00\xff\xff"[..],
            &b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff"[..],
            &b"\x1c"[..],
            &b"\x1f"[..],
            &b"\xf9\x00\x00"[..],
            &b"\xc0\x00"[..],
        ] {
            assert_eq!(Decoder::new(bytes).unsigned(), Err(Error::Format));
        }
        assert_eq!(Decoder::new(b"\x9f\xff").array(10), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x98\x01\x00").array(10), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x82").array(1), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x81").record(2), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x61\xff").text(64), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x42\x00").bytes(2), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x42\x00\x00").bytes(1), Err(Error::Format));
        assert_eq!(Decoder::new(b"\x00").finish(), Err(Error::Format));
        assert_eq!(Encoder::new(1).unsigned(24), Err(Error::Quota));
        assert_eq!(
            Decoder::new(b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff").integer(),
            Err(Error::Format)
        );
    }

    #[test]
    fn records_borrow_strings_and_preserve_binary_values() {
        let expected = b"\x85\x01\x63ISD\x43\x00\xff\x80\xf5\xf6";
        let mut writer = Encoder::new(expected.len());
        writer.array(5).unwrap();
        writer.unsigned(1).unwrap();
        writer.text("ISD").unwrap();
        writer.bytes(&[0, 255, 128]).unwrap();
        writer.boolean(true).unwrap();
        writer.null().unwrap();
        assert_eq!(writer.finish(), expected);
        let mut reader = Decoder::new(expected);
        reader.record(5).unwrap();
        assert_eq!(reader.unsigned(), Ok(1));
        let text = reader.text(64).unwrap();
        assert_eq!(text, "ISD");
        assert_eq!(text.as_ptr(), expected[3..].as_ptr());
        assert_eq!(reader.bytes(3), Ok(&[0, 255, 128][..]));
        assert_eq!(reader.boolean(), Ok(true));
        assert!(reader.null());
        reader.finish().unwrap();
    }
}
