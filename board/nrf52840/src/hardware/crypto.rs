use super::Hardware;
#[cfg(feature = "cc310-sha256")]
use crate::cc310;
#[cfg(any(feature = "cc310-sha256", feature = "engine-jcvm"))]
use microcard_core::Error;
use microcard_core::Result;

#[cfg(feature = "crypto-profile-self-test")]
#[no_mangle]
#[used]
static mut MICROCARD_PROFILE_TIMINGS_US: [u32; 8] = [0; 8];

#[cfg(feature = "crypto-profile-self-test")]
fn record_profile_time(index: usize, start: u32) {
    let elapsed = crate::platform::now().wrapping_sub(start);
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(MICROCARD_PROFILE_TIMINGS_US).cast::<u32>().add(index),
            elapsed,
        );
    }
}

impl Hardware {
    #[cfg(feature = "cc310-sha256")]
    pub(super) fn ensure_cc310(&mut self) -> Result<()> {
        if !self.cc310_initialized {
            if !cc310::initialize() {
                return Err(Error::Native);
            }
            self.cc310_initialized = true;
        }
        Ok(())
    }

    pub(crate) fn self_test(&mut self) -> Result<()> {
        #[cfg(feature = "cc310-sha256")]
        {
            use microcard_core::crypto::CryptoProvider;

            const EMPTY_DIGEST: [u8; 32] = [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ];
            const ABC_DIGEST: [u8; 32] = [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ];
            static FLASH_INPUT: [u8; 3] = *b"abc";

            self.self_test_stage = 1;
            let mut digest = [0; 32];
            self.sha256_into(&[], &mut digest)?;
            if digest != EMPTY_DIGEST {
                return Err(Error::Native);
            }
            self.self_test_stage = 2;
            self.sha256_into(&FLASH_INPUT, &mut digest)?;
            if digest != ABC_DIGEST {
                return Err(Error::Native);
            }
            self.self_test_stage = 3;
            let ram_input = *b"abc";
            self.sha256_into(&ram_input, &mut digest)?;
            if digest != ABC_DIGEST {
                return Err(Error::Native);
            }
            #[cfg(feature = "cc310-p256")]
            {
                self.self_test_stage = 4;
                let mut state = [0; microcard_core::crypto::SHA256_STATE_BYTES];
                self.sha256_stream(&mut state, &FLASH_INPUT[..1], None)?;
                self.sha256_stream(&mut state, &ram_input[1..], Some(&mut digest))?;
                if digest != ABC_DIGEST || state.iter().any(|byte| *byte != 0) {
                    return Err(Error::Native);
                }
                const SHA1_ABC: [u8; 20] = [
                    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
                    0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
                ];
                const SHA224_ABC: [u8; 28] = [
                    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd,
                    0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c,
                    0x9d, 0xa7,
                ];
                let mut sha1 = [0; 20];
                self.sha1_stream(&mut state, &FLASH_INPUT[..1], None)?;
                self.sha1_stream(&mut state, &ram_input[1..], Some(&mut sha1))?;
                if sha1 != SHA1_ABC || state.iter().any(|byte| *byte != 0) {
                    sha1.fill(0);
                    return Err(Error::Native);
                }
                sha1.fill(0);
                let mut sha224 = [0; 28];
                self.sha224_stream(&mut state, &FLASH_INPUT[..1], None)?;
                self.sha224_stream(&mut state, &ram_input[1..], Some(&mut sha224))?;
                if sha224 != SHA224_ABC || state.iter().any(|byte| *byte != 0) {
                    sha224.fill(0);
                    return Err(Error::Native);
                }
                sha224.fill(0);
            }
            #[cfg(feature = "cc310-entropy")]
            {
                self.self_test_stage = 5;
                let mut first = [0; 32];
                let mut second = [0; 32];
                if !cc310::fill_entropy(&mut first)
                    || !cc310::fill_entropy(&mut second)
                    || first == second
                    || first.iter().all(|byte| *byte == 0)
                    || first.iter().all(|byte| *byte == 0xff)
                    || second.iter().all(|byte| *byte == 0)
                    || second.iter().all(|byte| *byte == 0xff)
                {
                    first.fill(0);
                    second.fill(0);
                    return Err(Error::Native);
                }
                first.fill(0);
                second.fill(0);
            }
            #[cfg(feature = "cc310-cmac")]
            {
                self.self_test_stage = 6;
                const KEY: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ];
                static MESSAGE: [u8; 64] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
                    0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
                    0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
                    0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
                ];
                const EXPECTED_EMPTY: [u8; 16] = [
                    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b,
                    0x75, 0x67, 0x46,
                ];
                const EXPECTED_16: [u8; 16] = [
                    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0,
                    0x4a, 0x28, 0x7c,
                ];
                const EXPECTED_42: [u8; 16] = [
                    0x17, 0xb0, 0x9c, 0xab, 0xe5, 0x09, 0x25, 0xeb, 0xd0, 0x5a, 0xc5, 0x60, 0x66,
                    0x83, 0xdb, 0xf3,
                ];
                const EXPECTED_64: [u8; 16] = [
                    0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79,
                    0x36, 0x3c, 0xfe,
                ];
                let mut mac = [0; 16];
                self.aes_cmac_parts_into(&KEY, &[&[]], &mut mac)?;
                if mac != EXPECTED_EMPTY {
                    return Err(Error::Native);
                }
                self.aes_cmac_parts_into(&KEY, &[&MESSAGE[..16]], &mut mac)?;
                if mac != EXPECTED_16 {
                    return Err(Error::Native);
                }
                self.aes_cmac_parts_into(&KEY, &[&MESSAGE[..26], &MESSAGE[26..42]], &mut mac)?;
                if mac != EXPECTED_42 {
                    return Err(Error::Native);
                }
                let mut ram_message = MESSAGE;
                core::hint::black_box(&mut ram_message);
                self.aes_cmac_parts_into(&KEY, &[&ram_message], &mut mac)?;
                ram_message.fill(0);
                if mac != EXPECTED_64 {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                mac.fill(0);
            }
            #[cfg(feature = "cc310-hmac")]
            {
                self.self_test_stage = 7;
                const KEY: [u8; 20] = [0x0b; 20];
                const EXPECTED: [u8; 32] = [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ];
                let mut message = *b"Hi There";
                core::hint::black_box(&mut message);
                let mut mac = [0; 32];
                self.hmac_sha256_into(&KEY, &message, &mut mac)?;
                message.fill(0);
                if mac != EXPECTED {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                const EXPECTED_EMPTY: [u8; 32] = [
                    0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec, 0x77, 0x2f, 0x95, 0xd7, 0x78,
                    0xc3, 0x5f, 0xc5, 0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53, 0xc6, 0xc7,
                    0x12, 0x14, 0x42, 0x92, 0xc5, 0xad,
                ];
                self.hmac_sha256_into(&[], &[], &mut mac)?;
                if mac != EXPECTED_EMPTY {
                    mac.fill(0);
                    return Err(Error::Native);
                }
                mac.fill(0);
            }
            #[cfg(feature = "cc310-aes")]
            {
                self.self_test_stage = 8;
                const KEY: [u8; 16] = [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ];
                const EXPECTED: [u8; 16] = [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ];
                const PLAINTEXT: [u8; 16] = [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ];
                let mut block = PLAINTEXT;
                core::hint::black_box(&mut block);
                self.aes128_encrypt_block_in_place(&KEY, &mut block)?;
                if block != EXPECTED {
                    block.fill(0);
                    return Err(Error::Native);
                }
                self.aes128_decrypt_block_in_place(&KEY, &mut block)?;
                if block != PLAINTEXT {
                    block.fill(0);
                    return Err(Error::Native);
                }
                block.fill(0);
            }
            #[cfg(feature = "cc310-cbc")]
            {
                self.self_test_stage = 9;
                const KEY: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ];
                const IV: [u8; 16] = [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ];
                const PLAINTEXT: [u8; 16] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ];
                const CIPHERTEXT: [u8; 16] = [
                    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
                    0xe9, 0x19, 0x7d,
                ];
                let mut ciphertext = [0; 32];
                let ciphertext_length =
                    self.aes_cbc_encrypt(&KEY, IV, &PLAINTEXT, &mut ciphertext)?;
                if ciphertext_length != ciphertext.len() || ciphertext[..16] != CIPHERTEXT {
                    ciphertext.fill(0);
                    return Err(Error::Native);
                }
                let mut plaintext = [0; 32];
                let plaintext_length = self.aes_cbc_decrypt(
                    &KEY,
                    IV,
                    &ciphertext[..ciphertext_length],
                    &mut plaintext,
                )?;
                ciphertext.fill(0);
                if plaintext_length != PLAINTEXT.len() || plaintext[..plaintext_length] != PLAINTEXT
                {
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                plaintext.fill(0);
            }
            #[cfg(feature = "cc310-ctr")]
            {
                self.self_test_stage = 14;
                const KEY: [u8; 16] = [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ];
                const COUNTER: [u8; 16] = [
                    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
                    0xfd, 0xfe, 0xff,
                ];
                const PLAINTEXT: [u8; 33] = [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
                    0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
                ];
                const CIPHERTEXT: [u8; 33] = [
                    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99,
                    0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17,
                    0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a,
                ];
                let mut buffer = PLAINTEXT;
                core::hint::black_box(&mut buffer);
                self.aes_ctr_in_place(&KEY, &COUNTER, &mut buffer)?;
                if buffer != CIPHERTEXT {
                    buffer.fill(0);
                    return Err(Error::Native);
                }
                self.aes_ctr_in_place(&KEY, &COUNTER, &mut buffer)?;
                if buffer != PLAINTEXT {
                    buffer.fill(0);
                    return Err(Error::Native);
                }
                buffer.fill(0);
            }
            #[cfg(feature = "cc310-ccm")]
            {
                self.self_test_stage = 10;
                const KEY: [u8; 16] = [
                    0xd2, 0x4a, 0x3d, 0x3d, 0xde, 0x8c, 0x84, 0x83, 0x02, 0x80, 0xcb, 0x87, 0xab,
                    0xad, 0x0b, 0xb3,
                ];
                const NONCE: [u8; 13] = [
                    0xf1, 0x10, 0x00, 0x35, 0xbb, 0x24, 0xa8, 0xd2, 0x60, 0x04, 0xe0, 0xe2, 0x4b,
                ];
                const PLAINTEXT: [u8; 24] = [
                    0x7c, 0x86, 0x13, 0x5e, 0xd9, 0xc2, 0xa5, 0x15, 0xaa, 0xae, 0x0e, 0x9a, 0x20,
                    0x81, 0x33, 0x89, 0x72, 0x69, 0x22, 0x0f, 0x30, 0x87, 0x00, 0x06,
                ];
                const CIPHERTEXT: [u8; 40] = [
                    0x1f, 0xae, 0xb0, 0xee, 0x2c, 0xa2, 0xcd, 0x52, 0xf0, 0xaa, 0x39, 0x66, 0x57,
                    0x83, 0x44, 0xf2, 0x4e, 0x69, 0xb7, 0x42, 0xc4, 0xab, 0x37, 0xab, 0x11, 0x23,
                    0x30, 0x12, 0x19, 0xc7, 0x05, 0x99, 0xb7, 0xc3, 0x73, 0xad, 0x4b, 0x3a, 0xd6,
                    0x7b,
                ];
                // CC310's AEAD path consumes the payload through DMA. Real APDUs are in RAM,
                // so keep this vector in RAM instead of relying on a promoted flash constant.
                let plaintext = PLAINTEXT;
                core::hint::black_box(&plaintext);
                let mut ciphertext = [0; 40];
                let ciphertext_length =
                    self.aes_ccm_encrypt(&KEY, &NONCE, &[], &plaintext, &mut ciphertext)?;
                if ciphertext_length != ciphertext.len() || ciphertext != CIPHERTEXT {
                    ciphertext.fill(0);
                    return Err(Error::Native);
                }
                let mut plaintext = [0; 24];
                let plaintext_length =
                    self.aes_ccm_decrypt(&KEY, &NONCE, &[], &ciphertext, &mut plaintext)?;
                if plaintext_length != plaintext.len() || plaintext != PLAINTEXT {
                    ciphertext.fill(0);
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                ciphertext[39] ^= 1;
                plaintext.fill(0xa5);
                if self.aes_ccm_decrypt(&KEY, &NONCE, &[], &ciphertext, &mut plaintext)
                    != Err(Error::Authentication)
                    || plaintext.iter().any(|byte| *byte != 0)
                {
                    ciphertext.fill(0);
                    plaintext.fill(0);
                    return Err(Error::Native);
                }
                ciphertext.fill(0);
                plaintext.fill(0);
            }
            #[cfg(feature = "cc310-p256")]
            {
                self.self_test_stage = 11;
                const PRIVATE_KEY: [u8; 32] = [
                    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67,
                    0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a,
                    0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
                ];
                const PUBLIC_KEY: [u8; 65] = [
                    0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
                    0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6,
                    0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8,
                    0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2,
                    0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
                ];
                const SIGNATURE: [u8; 64] = [
                    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4,
                    0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d,
                    0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c,
                    0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb,
                    0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
                ];
                const PEER_PUBLIC_KEY: [u8; 65] = [
                    0x04, 0x55, 0x0f, 0x47, 0x10, 0x03, 0xf3, 0xdf, 0x97, 0xc3, 0xdf, 0x50, 0x6a,
                    0xc7, 0x97, 0xf6, 0x72, 0x1f, 0xb1, 0xa1, 0xfb, 0x7b, 0x8f, 0x6f, 0x83, 0xd2,
                    0x24, 0x49, 0x8a, 0x65, 0xc8, 0x8e, 0x24, 0x13, 0x60, 0x93, 0xd7, 0x01, 0x2e,
                    0x50, 0x9a, 0x73, 0x71, 0x5c, 0xbd, 0x0b, 0x00, 0xa3, 0xcc, 0x0f, 0xf4, 0xb5,
                    0xc0, 0x1b, 0x3f, 0xfa, 0x19, 0x6a, 0xb1, 0xfb, 0x32, 0x70, 0x36, 0xb8, 0xe6,
                ];
                const SHARED_SECRET: [u8; 32] = [
                    0x1a, 0x6f, 0xfb, 0x29, 0x06, 0x9a, 0xce, 0x9c, 0x04, 0xba, 0x94, 0x28, 0x91,
                    0x1b, 0xd0, 0x09, 0x0f, 0x87, 0x26, 0xae, 0xb3, 0x2e, 0x81, 0xd4, 0x7b, 0x24,
                    0x1a, 0x1f, 0x88, 0x04, 0xe4, 0x7d,
                ];
                let mut public_key = [0; 65];
                self.p256_public_key_into(&PRIVATE_KEY, &mut public_key)?;
                if public_key != PUBLIC_KEY {
                    public_key.fill(0);
                    return Err(Error::Native);
                }
                let mut signature = [0; 64];
                self.self_test_stage = 12;
                self.p256_ecdsa_sign_into(&PRIVATE_KEY, b"sample", &mut signature)?;
                if signature != SIGNATURE
                    || !self.p256_ecdsa_verify(&public_key, b"sample", &signature)?
                    || self.p256_ecdsa_verify(&public_key, b"changed", &signature)?
                {
                    public_key.fill(0);
                    signature.fill(0);
                    return Err(Error::Native);
                }
                let mut shared_secret = [0; 32];
                self.self_test_stage = 13;
                self.p256_ecdh_into(&PRIVATE_KEY, &PEER_PUBLIC_KEY, &mut shared_secret)?;
                if shared_secret != SHARED_SECRET {
                    public_key.fill(0);
                    signature.fill(0);
                    shared_secret.fill(0);
                    return Err(Error::Native);
                }
                public_key.fill(0);
                signature.fill(0);
                shared_secret.fill(0);
            }
            #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
            {
                self.self_test_stage = 15;
                let mut private = *include_bytes!("../../testdata/rsa1024-private.der");
                let mut public = *include_bytes!("../../testdata/rsa1024-public.der");
                core::hint::black_box(&mut private);
                core::hint::black_box(&mut public);
                let mut signature = [0u8; 128];
                let signed =
                    cc310::rsa_pkcs1v15_sha256_sign(&private, 1024, &ABC_DIGEST, &mut signature);
                let valid = signed
                    && signature == *include_bytes!("../../testdata/rsa1024-abc.sig")
                    && cc310::rsa_pkcs1v15_sha256_verify(&public, 1024, &ABC_DIGEST, &signature)
                        == 0;
                signature[0] ^= 1;
                let rejects_tamper =
                    cc310::rsa_pkcs1v15_sha256_verify(&public, 1024, &ABC_DIGEST, &signature) == 1;
                private[0] ^= 1;
                let mut failed_signature = [0xa5u8; 128];
                let rejects_bad_key = !cc310::rsa_pkcs1v15_sha256_sign(
                    &private,
                    1024,
                    &ABC_DIGEST,
                    &mut failed_signature,
                ) && failed_signature.iter().all(|byte| *byte == 0);
                failed_signature.fill(0);
                private.fill(0);
                public.fill(0);
                signature.fill(0);
                if !valid || !rejects_tamper || !rejects_bad_key {
                    return Err(Error::Native);
                }

                let mut private = *include_bytes!("../../testdata/rsa2048-private.der");
                let mut public = *include_bytes!("../../testdata/rsa2048-public.der");
                core::hint::black_box(&mut private);
                core::hint::black_box(&mut public);
                let mut signature = [0u8; 256];
                let signed =
                    cc310::rsa_pkcs1v15_sha256_sign(&private, 2048, &ABC_DIGEST, &mut signature);
                let valid = signed
                    && signature == *include_bytes!("../../testdata/rsa2048-abc.sig")
                    && cc310::rsa_pkcs1v15_sha256_verify(&public, 2048, &ABC_DIGEST, &signature)
                        == 0;
                signature[0] ^= 1;
                let rejects_tamper =
                    cc310::rsa_pkcs1v15_sha256_verify(&public, 2048, &ABC_DIGEST, &signature) == 1;
                private.fill(0);
                public.fill(0);
                signature.fill(0);
                if !valid || !rejects_tamper {
                    return Err(Error::Native);
                }
            }
            #[cfg(feature = "crypto-profile-self-test")]
            {
                self.self_test_stage = 16;
                let p384_start = crate::platform::now();
                let mut private = [0u8; 48];
                let mut public = [0u8; 97];
                let mut derived = [0u8; 97];
                let mut shared = [0u8; 48];
                let mut signature = [0u8; 96];
                let hash = [0x42u8; 48];
                let result = (|| -> Result<()> {
                    let started = crate::platform::now();
                    self.p384_generate_key_pair_with_entropy(&mut private, &mut public)?;
                    record_profile_time(0, started);
                    let started = crate::platform::now();
                    self.p384_public_key_into(&private, &mut derived)?;
                    if public != derived || !self.p384_public_key_valid(&public)? {
                        return Err(Error::Native);
                    }
                    record_profile_time(1, started);
                    self.self_test_stage = 17;
                    let started = crate::platform::now();
                    self.p384_ecdh_into(&private, &public, &mut shared)?;
                    if shared.iter().all(|byte| *byte == 0) { return Err(Error::Native); }
                    record_profile_time(2, started);
                    let started = crate::platform::now();
                    self.p384_sign_hash_with_entropy(&private, &hash, &mut signature)?;
                    record_profile_time(3, started);
                    let started = crate::platform::now();
                    if !self.p384_verify_hash(&public, &hash, &signature)? { return Err(Error::Native); }
                    signature[0] ^= 1;
                    if self.p384_verify_hash(&public, &hash, &signature)? { return Err(Error::Native); }
                    public[0] = 0;
                    if self.p384_public_key_valid(&public)? { return Err(Error::Native); }
                    shared.fill(0xa5);
                    if self.p384_ecdh_into(&private, &public, &mut shared).is_ok()
                        || shared.iter().any(|byte| *byte != 0) { return Err(Error::Native); }
                    record_profile_time(4, started);
                    Ok(())
                })();
                private.fill(0);
                public.fill(0);
                derived.fill(0);
                shared.fill(0);
                signature.fill(0);
                record_profile_time(7, p384_start);
                result?;

                self.self_test_stage = 18;
                let mut private = [0u8; 1400];
                let mut public = [0u8; 300];
                let mut signature = [0u8; 256];
                let result = (|| -> Result<()> {
                    for bits in [1024, 2048] {
                        self.self_test_stage = if bits == 1024 { 18 } else { 19 };
                        let started = crate::platform::now();
                        let (private_len, public_len) =
                            cc310::rsa_generate_key_pair(bits, &mut private, &mut public)
                                .ok_or(Error::Native)?;
                        record_profile_time(if bits == 1024 { 5 } else { 6 }, started);
                        if private_len == 0 || public_len == 0 { return Err(Error::Native); }
                        let signed = &mut signature[..bits / 8];
                        if !cc310::rsa_pkcs1v15_sha256_sign(
                            &private[..private_len], bits, &ABC_DIGEST, signed)
                            || cc310::rsa_pkcs1v15_sha256_verify(
                                &public[..public_len], bits, &ABC_DIGEST, signed) != 0 {
                            return Err(Error::Native);
                        }
                        signed[0] ^= 1;
                        if cc310::rsa_pkcs1v15_sha256_verify(
                            &public[..public_len], bits, &ABC_DIGEST, signed) != 1 {
                            return Err(Error::Native);
                        }
                    }
                    Ok(())
                })();
                private.fill(0);
                public.fill(0);
                signature.fill(0);
                result?;
            }
        }
        self.self_test_stage = 0;
        Ok(())
    }
}

impl microcard_core::crypto::CryptoProvider for Hardware {
    fn supports_sha256(&self) -> bool {
        cfg!(feature = "cc310-sha256")
            || cfg!(feature = "software-crypto")
            || cfg!(feature = "software-sha256")
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn supports_rsa_keygen(&self) -> bool {
        true
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn rsa_generate_key_pair_with_entropy(
        &mut self,
        key_bits: usize,
        private_der: &mut [u8],
        public_der: &mut [u8],
    ) -> Result<(usize, usize)> {
        private_der.fill(0);
        public_der.fill(0);
        self.ensure_cc310()?;
        #[cfg(feature = "diagnostic-apdu")]
        let started = crate::platform::now();
        let generated = cc310::rsa_generate_key_pair(key_bits, private_der, public_der);
        #[cfg(feature = "diagnostic-apdu")]
        crate::diagnostic_apdu::rsa_generate_us(crate::platform::now().wrapping_sub(started));
        generated.ok_or(Error::Native)
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn supports_rsa_pkcs1v15_sha256(&self) -> bool {
        true
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn rsa_pkcs1v15_sha256_sign_der(
        &mut self,
        private_der: &[u8],
        key_bits: usize,
        hash: &[u8; 32],
        signature: &mut [u8],
        _random: &mut dyn FnMut(&mut [u8]) -> bool,
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(signature, ready)?;
        let result = if cc310::rsa_pkcs1v15_sha256_sign(private_der, key_bits, hash, signature) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(signature, result)
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn rsa_pkcs1v15_sha256_sign_with_entropy(
        &mut self,
        private_der: &[u8],
        key_bits: usize,
        hash: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<()> {
        // The pinned CC310 API has no caller RNG parameter.
        let mut unused = |_bytes: &mut [u8]| false;
        self.rsa_pkcs1v15_sha256_sign_der(private_der, key_bits, hash, signature, &mut unused)
    }

    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn rsa_pkcs1v15_sha256_verify_der(
        &mut self,
        public_der: &[u8],
        key_bits: usize,
        hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool> {
        self.ensure_cc310()?;
        match cc310::rsa_pkcs1v15_sha256_verify(public_der, key_bits, hash, signature) {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(Error::Native),
        }
    }

    fn supports_sha1(&self) -> bool {
        cfg!(feature = "cc310-p256") || cfg!(feature = "software-sha1")
    }

    #[cfg(feature = "cc310-p256")]
    fn sha1_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        mut output: Option<&mut [u8; 20]>,
    ) -> Result<()> {
        if let Some(output) = output.as_mut() {
            output.fill(0);
        }
        let result = (|| {
            self.ensure_cc310()?;
            let pointer = output
                .as_mut()
                .map_or(core::ptr::null_mut(), |value| value.as_mut_ptr());
            let status = unsafe {
                cc310::microcard_cc310_sha1_stream(
                    state.as_mut_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    pointer,
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(Error::Native)
            }
        })();
        if result.is_err() {
            state.fill(0);
            if let Some(output) = output {
                output.fill(0);
            }
        }
        result
    }

    fn supports_sha224(&self) -> bool {
        cfg!(feature = "cc310-p256") || cfg!(feature = "software-sha256")
    }

    #[cfg(feature = "engine-jcvm")]
    fn supports_sha384(&self) -> bool {
        true
    }

    #[cfg(feature = "engine-jcvm")]
    fn sha384_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        output: Option<&mut [u8; 48]>,
    ) -> Result<()> {
        microcard_tiny_crypto::hash::stream(
            microcard_tiny_crypto::hash::Algorithm::Sha384,
            state,
            input,
            output.map(|bytes| &mut bytes[..]),
        )
        .map_err(|_| Error::Native)
    }

    #[cfg(feature = "engine-jcvm")]
    fn supports_sha512(&self) -> bool {
        true
    }

    #[cfg(feature = "engine-jcvm")]
    fn sha512_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        output: Option<&mut [u8; 64]>,
    ) -> Result<()> {
        microcard_tiny_crypto::hash::stream(
            microcard_tiny_crypto::hash::Algorithm::Sha512,
            state,
            input,
            output.map(|bytes| &mut bytes[..]),
        )
        .map_err(|_| Error::Native)
    }

    #[cfg(feature = "cc310-p256")]
    fn sha224_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        mut output: Option<&mut [u8; 28]>,
    ) -> Result<()> {
        if let Some(output) = output.as_mut() {
            output.fill(0);
        }
        let result = (|| {
            self.ensure_cc310()?;
            let pointer = output
                .as_mut()
                .map_or(core::ptr::null_mut(), |value| value.as_mut_ptr());
            let status = unsafe {
                cc310::microcard_cc310_sha224_stream(
                    state.as_mut_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    pointer,
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(Error::Native)
            }
        })();
        if result.is_err() {
            state.fill(0);
            if let Some(output) = output {
                output.fill(0);
            }
        }
        result
    }

    #[cfg(feature = "cc310-p256")]
    fn sha256_stream(
        &mut self,
        state: &mut [u8; microcard_core::crypto::SHA256_STATE_BYTES],
        input: &[u8],
        mut output: Option<&mut [u8; 32]>,
    ) -> Result<()> {
        if let Some(output) = output.as_mut() {
            output.fill(0);
        }
        let result = (|| {
            self.ensure_cc310()?;
            let pointer = output
                .as_mut()
                .map_or(core::ptr::null_mut(), |value| value.as_mut_ptr());
            let status = unsafe {
                cc310::microcard_cc310_sha256_stream(
                    state.as_mut_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    pointer,
                )
            };
            if status == 0 {
                Ok(())
            } else {
                Err(Error::Native)
            }
        })();
        if result.is_err() {
            state.fill(0);
            if let Some(output) = output {
                output.fill(0);
            }
        }
        result
    }

    #[cfg(feature = "cc310-sha256")]
    fn sha256_into(&mut self, data: &[u8], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::sha256(data, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-hmac")]
    fn hmac_sha256_into(&mut self, key: &[u8], data: &[u8], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::hmac_sha256(key, data, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes128_encrypt_block_in_place(
        &mut self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(block, ready)?;
        let result = if cc310::aes128_encrypt_block(key, block) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(block, result)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes128_decrypt_block_in_place(
        &mut self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<()> {
        // One CBC block with a zero IV is raw AES decryption.
        self.aes_cbc_in_place(key, &[0; 16], block, false)
    }

    #[cfg(feature = "cc310-aes")]
    fn aes_cbc_in_place(
        &mut self,
        key: &[u8; 16],
        iv: &[u8; 16],
        buffer: &mut [u8],
        encrypt: bool,
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(buffer, ready)?;
        if buffer.is_empty() || !buffer.len().is_multiple_of(16) {
            buffer.fill(0);
            return Err(Error::Bounds);
        }
        let result = if cc310::aes128_cbc_in_place(key, iv, buffer, encrypt) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(buffer, result)
    }

    #[cfg(feature = "cc310-ctr")]
    fn aes_ctr_in_place(
        &mut self,
        key: &[u8; 16],
        counter: &[u8; 16],
        buffer: &mut [u8],
    ) -> Result<()> {
        let ready = self.ensure_cc310();
        microcard_core::crypto::clear_output_on_error(buffer, ready)?;
        let result = if cc310::aes128_ctr_in_place(key, counter, buffer) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(buffer, result)
    }

    #[cfg(feature = "cc310-cbc")]
    #[inline(never)]
    fn aes_cbc_encrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        let padded = microcard_core::crypto::cbc_pad_into(data, output);
        let length = microcard_core::crypto::clear_output_on_error(output, padded)?;
        let result = self
            .aes_cbc_in_place(key, &iv, &mut output[..length], true)
            .map(|()| length);
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-cbc")]
    #[inline(never)]
    fn aes_cbc_decrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(Error::Authentication);
        }
        if output.len() < data.len() {
            return Err(Error::Bounds);
        }
        let plaintext = &mut output[..data.len()];
        plaintext.copy_from_slice(data);
        if let Err(error) = self.aes_cbc_in_place(key, &iv, plaintext, false) {
            output.fill(0);
            return Err(error);
        }
        let result = microcard_core::crypto::cbc_unpad_in_place(plaintext);
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    #[inline(never)]
    fn aes_ccm_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        self.ensure_cc310()?;
        let length = plaintext.len().checked_add(16).ok_or(Error::Bounds)?;
        if output.len() < length {
            return Err(Error::Bounds);
        }
        let result =
            if cc310::aes128_ccm_encrypt(key, nonce, aad, plaintext, &mut output[..length]) == 0 {
                Ok(length)
            } else {
                Err(Error::Native)
            };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    fn aes_ccm_encrypt_in_place(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize> {
        let result = (|| {
            self.ensure_cc310()?;
            if buffer.len() < 16 {
                return Err(Error::Bounds);
            }
            if cc310::aes128_ccm_encrypt_in_place(key, nonce, aad, buffer) == 0 {
                Ok(buffer.len())
            } else {
                Err(Error::Native)
            }
        })();
        microcard_core::crypto::clear_output_on_error(buffer, result)
    }

    #[cfg(feature = "cc310-ccm")]
    #[inline(never)]
    fn aes_ccm_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        output.fill(0);
        self.ensure_cc310()?;
        let length = ciphertext
            .len()
            .checked_sub(16)
            .ok_or(Error::Authentication)?;
        if output.len() < length {
            return Err(Error::Bounds);
        }
        let result =
            match cc310::aes128_ccm_decrypt(key, nonce, aad, ciphertext, &mut output[..length]) {
                0 => Ok(length),
                1 => Err(Error::Authentication),
                _ => Err(Error::Native),
            };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-ccm")]
    fn aes_ccm_decrypt_in_place(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        let result = (|| {
            self.ensure_cc310()?;
            let length = ciphertext
                .len()
                .checked_sub(16)
                .ok_or(Error::Authentication)?;
            match cc310::aes128_ccm_decrypt_in_place(key, nonce, aad, ciphertext) {
                0 => {
                    ciphertext[length..].fill(0);
                    Ok(length)
                }
                1 => Err(Error::Authentication),
                _ => Err(Error::Native),
            }
        })();
        microcard_core::crypto::clear_output_on_error(ciphertext, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_public_key_into(
        &mut self,
        private_key: &[u8; 32],
        output: &mut [u8; 65],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = if cc310::p256_public_key(private_key, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdsa_sign_into(
        &mut self,
        private_key: &[u8; 32],
        message: &[u8],
        output: &mut [u8; 64],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let mut hash = [0; 32];
        self.sha256_into(message, &mut hash)?;
        let result = self.p256_sign_hash_into(private_key, &hash, output);
        hash.fill(0);
        result
    }

    #[cfg(feature = "cc310-p256")]
    fn p256_sign_hash_into(
        &mut self,
        private_key: &[u8; 32],
        hash: &[u8; 32],
        output: &mut [u8; 64],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = if cc310::p256_sign_hash(private_key, hash, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdsa_verify(
        &mut self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.ensure_cc310()?;
        let mut hash = [0; 32];
        self.sha256_into(message, &mut hash)?;
        let result = self.p256_verify_hash(public_key, &hash, signature);
        hash.fill(0);
        result
    }

    #[cfg(feature = "cc310-p256")]
    fn p256_verify_hash(
        &mut self,
        public_key: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool> {
        self.ensure_cc310()?;
        match cc310::p256_verify_hash(public_key, hash, signature) {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(Error::Native),
        }
    }

    #[cfg(feature = "cc310-p256")]
    #[inline(never)]
    fn p256_ecdh_into(
        &mut self,
        private_key: &[u8; 32],
        peer_public_key: &[u8],
        output: &mut [u8; 32],
    ) -> Result<()> {
        output.fill(0);
        if !microcard_core::crypto::p256_private_key_valid(private_key) {
            return Err(Error::Storage);
        }
        self.ensure_cc310()?;
        let result = match cc310::p256_ecdh(private_key, peer_public_key, output) {
            0 => Ok(()),
            1 => Err(Error::Authentication),
            _ => Err(Error::Native),
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }

    #[cfg(feature = "cc310-cmac")]
    fn aes_cmac_parts_into(
        &mut self,
        key: &[u8; 16],
        parts: &[&[u8]],
        output: &mut [u8; 16],
    ) -> Result<()> {
        output.fill(0);
        self.ensure_cc310()?;
        let result = if cc310::aes_cmac_parts(key, parts, output) {
            Ok(())
        } else {
            Err(Error::Native)
        };
        microcard_core::crypto::clear_output_on_error(output, result)
    }
}
