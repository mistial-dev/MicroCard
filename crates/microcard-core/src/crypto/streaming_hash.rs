//! Serializable transient hash state; the compression function comes from RustCrypto.
use super::{Error, Result, SHA256_STATE_BYTES};
use zeroize::Zeroizing;

pub(super) fn run<const WORDS: usize>(
    state: &mut [u8; SHA256_STATE_BYTES],
    mut input: &[u8],
    output: Option<&mut [u8]>,
    initial: [u32; WORDS],
    mut compress: impl FnMut(&mut [u32; WORDS], &[u8; 64]),
) -> Result<()> {
    let result = (|| {
        let mut words = Zeroizing::new(initial);
        let word_end = 8 + WORDS * 4;
        let count_end = word_end + 8;
        let block_end = count_end + 64;
        let mut count = 0u64;
        let mut block = Zeroizing::new([0u8; 64]);
        match state[0] {
            0 if state.iter().all(|byte| *byte == 0) => {}
            1 => {
                for (word, bytes) in words.iter_mut().zip(state[8..word_end].chunks_exact(4)) {
                    *word = u32::from_be_bytes(bytes.try_into().unwrap());
                }
                count = u64::from_be_bytes(state[word_end..count_end].try_into().unwrap());
                block.copy_from_slice(&state[count_end..block_end]);
            }
            _ => return Err(Error::Format),
        }
        let total = count
            .checked_add(input.len() as u64)
            .filter(|value| *value <= u64::MAX / 8)
            .ok_or(Error::Quota)?;
        let mut used = (count % 64) as usize;
        while !input.is_empty() {
            let take = (64 - used).min(input.len());
            block[used..used + take].copy_from_slice(&input[..take]);
            used += take;
            input = &input[take..];
            if used == 64 {
                compress(&mut words, &block);
                block.fill(0);
                used = 0;
            }
        }
        if let Some(output) = output {
            if output.len() > WORDS * 4 {
                return Err(Error::Bounds);
            }
            block[used] = 0x80;
            block[used + 1..].fill(0);
            if used >= 56 {
                compress(&mut words, &block);
                block.fill(0);
            }
            block[56..].copy_from_slice(&(total * 8).to_be_bytes());
            compress(&mut words, &block);
            for (bytes, word) in output.chunks_exact_mut(4).zip(words.iter()) {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
            state.fill(0);
        } else {
            state.fill(0);
            state[0] = 1;
            for (bytes, word) in state[8..word_end].chunks_exact_mut(4).zip(words.iter()) {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
            state[word_end..count_end].copy_from_slice(&total.to_be_bytes());
            state[count_end..block_end].copy_from_slice(&block[..]);
        }
        Ok(())
    })();
    if result.is_err() {
        state.fill(0);
    }
    result
}
