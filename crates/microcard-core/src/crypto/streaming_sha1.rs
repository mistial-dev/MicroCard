//! SHA-1 reference compression with shared serializable transient state.
use super::{Result, SHA256_STATE_BYTES};
use sha1::compress;

const INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

pub(super) fn run(
    state: &mut [u8; SHA256_STATE_BYTES],
    input: &[u8],
    output: Option<&mut [u8; 20]>,
) -> Result<()> {
    super::streaming_hash::run(
        state,
        input,
        output.map(|value| &mut value[..]),
        INITIAL,
        |words, block| compress(words, &[(*block).into()]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest, Sha1};

    #[test]
    fn split_and_final_padding_match_independent_digest_api() {
        let message = [0x37; 129];
        for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 129] {
            for split in [0, length / 2, length] {
                let mut state = [0; SHA256_STATE_BYTES];
                run(&mut state, &message[..split], None).unwrap();
                let mut output = [0; 20];
                run(&mut state, &message[split..length], Some(&mut output)).unwrap();
                assert_eq!(
                    output.as_slice(),
                    Sha1::digest(&message[..length]).as_slice()
                );
                assert_eq!(state, [0; SHA256_STATE_BYTES]);
            }
        }
    }
}
