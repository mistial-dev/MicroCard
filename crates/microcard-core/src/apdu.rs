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
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data.len() > 255 || self.le.is_some_and(|x| x == 0 || x > 256) {
            return Err(Error::Bounds);
        }
        let capacity = 4usize
            .checked_add(usize::from(!self.data.is_empty()))
            .and_then(|length| length.checked_add(self.data.len()))
            .and_then(|length| length.checked_add(usize::from(self.le.is_some())))
            .ok_or(Error::Bounds)?;
        let mut b = Vec::new();
        b.try_reserve_exact(capacity).map_err(|_| Error::Quota)?;
        b.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() {
            b.push(self.data.len() as u8);
            b.extend_from_slice(&self.data)
        }
        if let Some(le) = self.le {
            b.push(le as u8)
        }
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
}
