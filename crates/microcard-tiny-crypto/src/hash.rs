//! Caller-owned SHA-384 and SHA-512 state for the Java Card digest service.
use crate::Error;

pub const STATE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha384,
    Sha512,
}

impl Algorithm {
    pub const fn output_bytes(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    const fn bits(self) -> u32 {
        match self {
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }
}

extern "C" {
    fn mc_tc_sha512_stream(
        algorithm: u32,
        state: *mut u8,
        state_len: usize,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
    ) -> i32;
}

/// Zero state starts a message; finalization or failure clears it. A caller may
/// keep state between APDUs only while Java Card object lifetime permits it.
pub fn stream(
    algorithm: Algorithm,
    state: &mut [u8; STATE_BYTES],
    input: &[u8],
    mut output: Option<&mut [u8]>,
) -> Result<(), Error> {
    if let Some(buffer) = output.as_mut() {
        buffer.fill(0);
        if buffer.len() != algorithm.output_bytes() {
            state.fill(0);
            return Err(Error::InvalidLength);
        }
    }
    let pointer = output.as_mut().map_or(core::ptr::null_mut(), |value| value.as_mut_ptr());
    let status = unsafe {
        mc_tc_sha512_stream(
            algorithm.bits(),
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
        state.fill(0);
        if let Some(buffer) = output { buffer.fill(0); }
        Err(Error::OperationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::{format, string::String};

    #[test]
    fn fips_180_4_streams_and_clears_state() {
        let cases = [
            (Algorithm::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7"),
            (Algorithm::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ];
        for (algorithm, expected) in cases {
            let mut state = [0; STATE_BYTES];
            let mut result = [0; 64];
            stream(algorithm, &mut state, b"a", None).unwrap();
            stream(algorithm, &mut state, b"bc", Some(&mut result[..algorithm.output_bytes()])).unwrap();
            assert!(state.iter().all(|byte| *byte == 0));
            let actual: String = result[..algorithm.output_bytes()]
                .iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected);

            state[0] = 3;
            result.fill(0xaa);
            assert_eq!(stream(algorithm, &mut state, b"x",
                Some(&mut result[..algorithm.output_bytes()])), Err(Error::OperationFailed));
            assert_eq!(state, [0; STATE_BYTES]);
            assert!(result[..algorithm.output_bytes()].iter().all(|byte| *byte == 0));
        }
    }
}
