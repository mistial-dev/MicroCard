//! UART short-APDU framing shared with the host binary transport.
pub struct Decoder {
    header: [u8; 2],
    data: [u8; 261],
    position: usize,
    length: usize,
    started: u32,
}
impl Default for Decoder {
    fn default() -> Self {
        Self {
            header: [0; 2],
            data: [0; 261],
            position: 0,
            length: 0,
            started: 0,
        }
    }
}
impl Decoder {
    pub fn expire(&mut self, now: u32) {
        if self.position != 0 && now.wrapping_sub(self.started) > 1_000_000 {
            self.position = 0;
            self.length = 0;
        }
    }
    pub fn push(&mut self, byte: u8, now: u32) -> Option<&[u8]> {
        self.expire(now);
        if self.position == 0 {
            self.started = now;
        }
        if self.position < 2 {
            self.header[self.position] = byte;
            self.position += 1;
            if self.position == 2 {
                self.length = u16::from_le_bytes(self.header) as usize;
                if !(4..=261).contains(&self.length) {
                    self.position = 0;
                }
            }
            return None;
        }
        self.data[self.position - 2] = byte;
        self.position += 1;
        if self.position == self.length + 2 {
            self.position = 0;
            return Some(&self.data[..self.length]);
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_back_to_back_and_timeout() {
        let mut d = Decoder::default();
        for b in [4, 0, 0, 1, 2] {
            assert!(d.push(b, 0).is_none())
        }
        assert_eq!(d.push(3, 0), Some(&[0, 1, 2, 3][..]));
        for b in [4, 0, 1] {
            assert!(d.push(b, u32::MAX - 10).is_none())
        }
        d.expire(1_000_000);
        for b in [4, 0, 0, 1, 2] {
            assert!(d.push(b, 1_000_001).is_none())
        }
        assert_eq!(d.push(3, 1_000_001), Some(&[0, 1, 2, 3][..]));
    }
    #[test]
    fn rejects_lengths() {
        let mut d = Decoder::default();
        for n in [0u16, 1, 2, 3, 262, 65535] {
            for b in n.to_le_bytes() {
                assert!(d.push(b, 0).is_none());
            }
        }
        assert_eq!(d.position, 0);
    }
}
