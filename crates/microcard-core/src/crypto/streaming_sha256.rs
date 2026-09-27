//! SHA-224/256 reference compression with shared serializable transient state.
use super::{Result, SHA256_STATE_BYTES};
use sha2::compress256;

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const INITIAL_224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

pub(super) fn run(state: &mut [u8; SHA256_STATE_BYTES], input: &[u8],
    output: Option<&mut [u8; 32]>) -> Result<()> {
    super::streaming_hash::run(state, input, output.map(|value| &mut value[..]), INITIAL,
        |words, block| compress256(words, &[(*block).into()]))
}

pub(super) fn run224(state: &mut [u8; SHA256_STATE_BYTES], input: &[u8],
    output: Option<&mut [u8; 28]>) -> Result<()> {
    super::streaming_hash::run(state, input, output.map(|value| &mut value[..]), INITIAL_224,
        |words, block| compress256(words, &[(*block).into()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use sha2::{Digest, Sha224, Sha256};

    #[test]
    fn split_and_final_padding_match_independent_digest_api() {
        let message = [0x37; 129];
        for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 129] {
            for split in [0, length / 2, length] {
                let mut state = [0; SHA256_STATE_BYTES];
                run(&mut state, &message[..split], None).unwrap();
                let mut output = [0; 32];
                run(&mut state, &message[split..length], Some(&mut output)).unwrap();
                assert_eq!(output.as_slice(), Sha256::digest(&message[..length]).as_slice());
                assert_eq!(state, [0; SHA256_STATE_BYTES]);
            }
        }
    }

    #[test]
    fn sha224_split_padding_and_known_vectors() {
        let message = [0x37; 129];
        for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 129] {
            for split in [0, length / 2, length] {
                let mut state = [0; SHA256_STATE_BYTES];
                run224(&mut state, &message[..split], None).unwrap();
                let mut output = [0; 28];
                run224(&mut state, &message[split..length], Some(&mut output)).unwrap();
                assert_eq!(output.as_slice(), Sha224::digest(&message[..length]).as_slice());
                assert_eq!(state, [0; SHA256_STATE_BYTES]);
            }
        }
        let mut state = [0; SHA256_STATE_BYTES];
        let mut output = [0; 28];
        run224(&mut state, b"abc", Some(&mut output)).unwrap();
        assert_eq!(output, [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
            0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
            0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
            0xe3, 0x6c, 0x9d, 0xa7,
        ]);
        run224(&mut state, b"", Some(&mut output)).unwrap();
        assert_eq!(output, [
            0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
            0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
            0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
            0xc5, 0xb3, 0xe4, 0x2f,
        ]);
        state[0] = 2;
        assert_eq!(run224(&mut state, b"x", None), Err(Error::Format));
        assert_eq!(state, [0; SHA256_STATE_BYTES]);
    }
}
