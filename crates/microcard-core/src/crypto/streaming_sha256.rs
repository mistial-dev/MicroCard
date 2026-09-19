//! Serializable reference state; compression remains in the optional RustCrypto backend.
use super::{Error, Result, SHA256_STATE_BYTES};
use sha2::compress256;
use zeroize::Zeroizing;

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(super) fn run(state: &mut [u8; SHA256_STATE_BYTES], mut input: &[u8],
    output: Option<&mut [u8; 32]>) -> Result<()> {
    let result = (|| {
        let mut words = Zeroizing::new(INITIAL);
        let mut count = 0u64;
        let mut block = Zeroizing::new([0u8; 64]);
        match state[0] {
            0 if state.iter().all(|byte| *byte == 0) => {}
            1 => {
                for (word, bytes) in words.iter_mut().zip(state[8..40].chunks_exact(4)) {
                    *word = u32::from_be_bytes(bytes.try_into().unwrap());
                }
                count = u64::from_be_bytes(state[40..48].try_into().unwrap());
                block.copy_from_slice(&state[48..112]);
            }
            _ => return Err(Error::Format),
        }
        let total = count.checked_add(input.len() as u64).filter(|value| *value <= u64::MAX / 8)
            .ok_or(Error::Quota)?;
        let mut used = (count % 64) as usize;
        while !input.is_empty() {
            let take = (64 - used).min(input.len());
            block[used..used + take].copy_from_slice(&input[..take]);
            used += take;
            input = &input[take..];
            if used == 64 {
                compress256(&mut words, &[(*block).into()]);
                block.fill(0);
                used = 0;
            }
        }
        if let Some(output) = output {
            block[used] = 0x80;
            block[used + 1..].fill(0);
            if used >= 56 {
                compress256(&mut words, &[(*block).into()]);
                block.fill(0);
            }
            block[56..].copy_from_slice(&(total * 8).to_be_bytes());
            compress256(&mut words, &[(*block).into()]);
            for (bytes, word) in output.chunks_exact_mut(4).zip(words.iter()) {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
            state.fill(0);
        } else {
            state.fill(0);
            state[0] = 1;
            for (bytes, word) in state[8..40].chunks_exact_mut(4).zip(words.iter()) {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
            state[40..48].copy_from_slice(&total.to_be_bytes());
            state[48..112].copy_from_slice(&block[..]);
        }
        Ok(())
    })();
    if result.is_err() { state.fill(0); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

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
}
