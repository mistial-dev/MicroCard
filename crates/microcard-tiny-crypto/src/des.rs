//! Optional DES/3DES compatibility primitives. Java Card padding belongs to the caller.

use crate::Error;

const ISO9797_CONTEXT_BYTES: usize = 384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MacAlgorithm {
    Cbc = 1,
    Retail = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MacPadding {
    None = 0,
    Iso9797M1 = 1,
    Iso9797M2 = 2,
}

extern "C" {
    fn mc_tc_des_crypt(
        key: *const u8,
        key_len: usize,
        iv: *const u8,
        data: *mut u8,
        data_len: usize,
        encrypt: i32,
    ) -> i32;
    fn mc_tc_des_iso9797_mac(
        algorithm: u32,
        padding: u32,
        key: *const u8,
        key_len: usize,
        message: *const u8,
        message_len: usize,
        tag: *mut u8,
        tag_len: usize,
    ) -> i32;
    fn mc_tc_des_iso9797_verify(
        algorithm: u32,
        padding: u32,
        key: *const u8,
        key_len: usize,
        message: *const u8,
        message_len: usize,
        tag: *const u8,
        tag_len: usize,
    ) -> i32;
    fn mc_tc_des_iso9797_init(
        context: *mut u8,
        algorithm: u32,
        padding: u32,
        key: *const u8,
        key_len: usize,
    ) -> i32;
    fn mc_tc_des_iso9797_update(context: *mut u8, message: *const u8, len: usize) -> i32;
    fn mc_tc_des_iso9797_final(context: *mut u8, tag: *mut u8) -> i32;
    fn mc_tc_des_iso9797_clear(context: *mut u8);
}

fn valid_key(key: &[u8]) -> bool {
    matches!(key.len(), 8 | 16 | 24)
}

/// Transform complete DES blocks in place. `iv=None` selects ECB; CBC requires
/// an eight-byte IV. Failure clears the entire caller buffer.
pub fn crypt_in_place(
    key: &[u8],
    iv: Option<&[u8; 8]>,
    data: &mut [u8],
    encrypt: bool,
) -> Result<(), Error> {
    if !valid_key(key) || data.is_empty() || !data.len().is_multiple_of(8) {
        data.fill(0);
        return Err(Error::InvalidLength);
    }
    let iv_ptr = iv.map_or(core::ptr::null(), |value| value.as_ptr());
    let status = unsafe {
        mc_tc_des_crypt(
            key.as_ptr(),
            key.len(),
            iv_ptr,
            data.as_mut_ptr(),
            data.len(),
            i32::from(encrypt),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        data.fill(0);
        Err(Error::OperationFailed)
    }
}

/// ISO 9797-1 algorithm 1 or 3 with no padding, method 1, or method 2.
/// Returns the full eight-byte tag; callers may use its leading four bytes.
pub fn iso9797_mac(
    algorithm: MacAlgorithm,
    padding: MacPadding,
    key: &[u8],
    message: &[u8],
    tag: &mut [u8; 8],
) -> Result<(), Error> {
    tag.fill(0);
    if !valid_key(key) || (algorithm == MacAlgorithm::Retail && key.len() == 8) {
        return Err(Error::InvalidLength);
    }
    let status = unsafe {
        mc_tc_des_iso9797_mac(
            algorithm as u32,
            padding as u32,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            tag.as_mut_ptr(),
            tag.len(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        tag.fill(0);
        Err(Error::OperationFailed)
    }
}

/// Verify a full or leading four-byte tag without early-exit comparison.
pub fn iso9797_verify(
    algorithm: MacAlgorithm,
    padding: MacPadding,
    key: &[u8],
    message: &[u8],
    tag: &[u8],
) -> Result<bool, Error> {
    if !valid_key(key)
        || (algorithm == MacAlgorithm::Retail && key.len() == 8)
        || !matches!(tag.len(), 4 | 8)
    {
        return Err(Error::InvalidLength);
    }
    let status = unsafe {
        mc_tc_des_iso9797_verify(
            algorithm as u32,
            padding as u32,
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            tag.as_ptr(),
            tag.len(),
        )
    };
    match status {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(Error::OperationFailed),
    }
}

/// Caller-owned streaming ISO 9797-1 MAC context. It is wiped on finalization,
/// failure, or drop.
#[repr(C, align(8))]
pub struct Iso9797Mac {
    context: [u8; ISO9797_CONTEXT_BYTES],
    active: bool,
}

impl Iso9797Mac {
    pub fn new(algorithm: MacAlgorithm, padding: MacPadding, key: &[u8]) -> Result<Self, Error> {
        if !valid_key(key) || (algorithm == MacAlgorithm::Retail && key.len() == 8) {
            return Err(Error::InvalidLength);
        }
        let mut mac = Self {
            context: [0; ISO9797_CONTEXT_BYTES],
            active: false,
        };
        let status = unsafe {
            mc_tc_des_iso9797_init(
                mac.context.as_mut_ptr(),
                algorithm as u32,
                padding as u32,
                key.as_ptr(),
                key.len(),
            )
        };
        if status != 0 {
            return Err(Error::OperationFailed);
        }
        mac.active = true;
        Ok(mac)
    }

    pub fn update(&mut self, message: &[u8]) -> Result<(), Error> {
        if !self.active {
            return Err(Error::OperationFailed);
        }
        let status = unsafe {
            mc_tc_des_iso9797_update(self.context.as_mut_ptr(), message.as_ptr(), message.len())
        };
        if status == 0 {
            Ok(())
        } else {
            self.clear();
            Err(Error::OperationFailed)
        }
    }

    pub fn finalize(&mut self, tag: &mut [u8; 8]) -> Result<(), Error> {
        tag.fill(0);
        if !self.active {
            return Err(Error::OperationFailed);
        }
        let status =
            unsafe { mc_tc_des_iso9797_final(self.context.as_mut_ptr(), tag.as_mut_ptr()) };
        self.clear();
        if status == 0 {
            Ok(())
        } else {
            tag.fill(0);
            Err(Error::OperationFailed)
        }
    }

    fn clear(&mut self) {
        unsafe { mc_tc_des_iso9797_clear(self.context.as_mut_ptr()) };
        self.context.fill(0);
        self.active = false;
    }
}

impl Drop for Iso9797Mac {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_fips_block_and_failure_clearing() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        let mut block = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        crypt_in_place(&key, None, &mut block, true).unwrap();
        assert_eq!(block, [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]);
        crypt_in_place(&key, None, &mut block, false).unwrap();
        assert_eq!(block, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let mut partial = [0xa5; 7];
        assert_eq!(
            crypt_in_place(&key, None, &mut partial, true),
            Err(Error::InvalidLength)
        );
        assert_eq!(partial, [0; 7]);
    }

    #[test]
    fn two_and_three_key_tdea_match_openssl_cbc() {
        let key2 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let key3 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
        ];
        let iv2 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let iv3 = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let plain2 = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let plain3 = *b"Now is the time ";
        let mut data2 = plain2;
        let mut data3 = plain3;
        crypt_in_place(&key2, Some(&iv2), &mut data2, true).unwrap();
        crypt_in_place(&key3, Some(&iv3), &mut data3, true).unwrap();
        assert_eq!(
            data2,
            [
                0x1a, 0xab, 0x6a, 0xcb, 0xa5, 0xab, 0xd5, 0x44, 0x2b, 0x1e, 0xf4, 0x86, 0x03, 0xe1,
                0xb7, 0x24
            ]
        );
        assert_eq!(
            data3,
            [
                0xf3, 0xc0, 0xff, 0x02, 0x6c, 0x02, 0x30, 0x89, 0x65, 0x6f, 0xbb, 0x16, 0x9d, 0xef,
                0x7e, 0xdb
            ]
        );
        crypt_in_place(&key2, Some(&iv2), &mut data2, false).unwrap();
        crypt_in_place(&key3, Some(&iv3), &mut data3, false).unwrap();
        assert_eq!(data2, plain2);
        assert_eq!(data3, plain3);
    }

    #[test]
    fn published_retail_mac_and_negative_cases() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let message = b"Now is the time for all ";
        let mut tag = [0xa5; 8];
        iso9797_mac(
            MacAlgorithm::Retail,
            MacPadding::None,
            &key,
            message,
            &mut tag,
        )
        .unwrap();
        assert_eq!(tag, [0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6]);
        assert_eq!(
            iso9797_verify(
                MacAlgorithm::Retail,
                MacPadding::None,
                &key,
                message,
                &tag[..4]
            ),
            Ok(true)
        );
        tag[0] ^= 1;
        assert_eq!(
            iso9797_verify(MacAlgorithm::Retail, MacPadding::None, &key, message, &tag),
            Ok(false)
        );
        tag.fill(0xa5);
        assert_eq!(
            iso9797_mac(
                MacAlgorithm::Retail,
                MacPadding::None,
                &key,
                &message[..3],
                &mut tag
            ),
            Err(Error::OperationFailed)
        );
        assert_eq!(tag, [0; 8]);

        let mut streaming = Iso9797Mac::new(MacAlgorithm::Retail, MacPadding::None, &key).unwrap();
        for chunk in message.chunks(3) {
            streaming.update(chunk).unwrap();
        }
        streaming.finalize(&mut tag).unwrap();
        assert_eq!(tag, [0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6]);
        tag.fill(0xa5);
        assert_eq!(streaming.finalize(&mut tag), Err(Error::OperationFailed));
        assert_eq!(tag, [0; 8]);
        assert_eq!(
            iso9797_mac(
                MacAlgorithm::Retail,
                MacPadding::Iso9797M2,
                &key[..8],
                message,
                &mut tag
            ),
            Err(Error::InvalidLength)
        );
        assert_eq!(tag, [0; 8]);
    }
}
