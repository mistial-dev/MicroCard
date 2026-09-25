//! Short command APDU cases, ISO/IEC 7816-4:2020 §5.2.
use crate::{Error, Result};
use alloc::borrow::Cow;
use alloc::vec::Vec;
use zeroize::Zeroize;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Borrows transport input until encrypted secure messaging supplies owned plaintext.
    pub data: Cow<'a, [u8]>,
    pub le: Option<u16>,
}
impl<'a> Command<'a> {
    fn zeroize_owned_data(&mut self) {
        if let Cow::Owned(data) = &mut self.data {
            data.zeroize();
        }
    }

    pub fn parse(b: &'a [u8]) -> Result<Self> {
        if b.len() < 4 || b.len() > 261 {
            return Err(Error::Format);
        }
        let mut c = Self {
            cla: b[0],
            ins: b[1],
            p1: b[2],
            p2: b[3],
            data: Cow::Borrowed(&[]),
            le: None,
        };
        let le = |x: u8| if x == 0 { 256 } else { x as u16 };
        match b.len() {
            4 => {}
            5 => c.le = Some(le(b[4])),
            _ => {
                let n = b[4] as usize;
                if n == 0 || !(b.len() == 5 + n || b.len() == 6 + n) {
                    return Err(Error::Format);
                }
                c.data = Cow::Borrowed(&b[5..5 + n]);
                if b.len() == 6 + n {
                    c.le = Some(le(b[5 + n]));
                }
            }
        }
        Ok(c)
    }
    fn encoded_len(&self) -> Result<usize> {
        if self.data.len() > 255 || self.le.is_some_and(|x| x == 0 || x > 256) {
            return Err(Error::Bounds);
        }
        4usize
            .checked_add(usize::from(!self.data.is_empty()))
            .and_then(|length| length.checked_add(self.data.len()))
            .and_then(|length| length.checked_add(usize::from(self.le.is_some())))
            .ok_or(Error::Bounds)
    }

    /// Encode into caller-owned storage, so a card command needs no temporary allocation.
    pub fn encode_into<'b>(&self, output: &'b mut [u8]) -> Result<&'b [u8]> {
        let length = self.encoded_len()?;
        let output = output.get_mut(..length).ok_or(Error::Bounds)?;
        output[..4].copy_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        let mut at = 4;
        if !self.data.is_empty() {
            output[at] = self.data.len() as u8;
            at += 1;
            output[at..at + self.data.len()].copy_from_slice(&self.data);
            at += self.data.len();
        }
        if let Some(le) = self.le {
            output[at] = le as u8;
        }
        Ok(output)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let capacity = self.encoded_len()?;
        let mut b = Vec::new();
        b.try_reserve_exact(capacity).map_err(|_| Error::Quota)?;
        b.resize(capacity, 0);
        self.encode_into(&mut b)?;
        Ok(b)
    }
}

impl Drop for Command<'_> {
    fn drop(&mut self) {
        self.zeroize_owned_data();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;

    #[test]
    fn parsed_command_data_borrows_the_transport_buffer() {
        let raw = [0x80, 0xca, 0, 0, 3, 1, 2, 3];
        let command = Command::parse(&raw).unwrap();
        assert!(matches!(command.data, Cow::Borrowed(_)));
        assert_eq!(command.data.as_ptr(), raw[5..].as_ptr());
    }

    #[test]
    fn owned_command_data_is_cleared_before_release() {
        let mut command = Command {
            cla: 0x80,
            ins: 0xca,
            p1: 0,
            p2: 0,
            data: alloc::vec![0x5a; 32].into(),
            le: None,
        };
        command.zeroize_owned_data();
        assert!(command.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bounded_encoding_matches_short_apdu_cases() {
        for raw in [
            &b"\x00\x84\x00\x00"[..],
            &b"\x00\x84\x00\x00\x00"[..],
            &b"\x80\xda\x00\x00\x02\x12\x34"[..],
            &b"\x80\xda\x00\x00\x02\x12\x34\x00"[..],
        ] {
            let command = Command::parse(raw).unwrap();
            let mut buffer = [0xa5; 261];
            let encoded = command.encode_into(&mut buffer).unwrap();
            assert_eq!(encoded, raw);
            assert_eq!(command.encode().unwrap(), raw);
            assert_eq!(buffer[raw.len()], 0xa5);
            assert_eq!(command.encode_into(&mut buffer[..raw.len() - 1]), Err(Error::Bounds));
        }
    }
}
