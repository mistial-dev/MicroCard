//! Java Card's supported algorithms use the same providers as transport and persistence.
use crate::{crypto::CryptoProvider, hal::Entropy};
use microcard_engine_jcvm::{Error, Result, host::Host};

pub struct Services<'a, P>(pub &'a mut P);

impl<P: CryptoProvider + Entropy> Host for Services<'_, P> {
    fn supports_digest(&self, algorithm: u8) -> bool {
        algorithm == 4
    }
    fn supports_random(&self, algorithm: u8) -> bool {
        matches!(algorithm, 1 | 2)
    }

    fn supports_cipher(&self, algorithm: u8) -> bool {
        algorithm == 14 // ALG_AES_BLOCK_128_ECB_NOPAD
    }

    fn aes128_block(&mut self, key: &[u8; 16], block: &mut [u8; 16], encrypt: bool) -> Result<()> {
        let result = if encrypt {
            self.0.aes128_encrypt_block_in_place(key, block)
        } else {
            self.0.aes128_decrypt_block_in_place(key, block)
        };
        if result.is_err() {
            block.fill(0);
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        output.fill(0);
        if self.0.fill_entropy(output).is_err() {
            output.fill(0);
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
        output.fill(0);
        if !self.supports_digest(algorithm) {
            return Err(Error::Unsupported);
        }
        let destination = output.get_mut(..32).ok_or(Error::Bounds)?;
        if self
            .0
            .sha256_into(message, destination.try_into().unwrap())
            .is_err()
        {
            output.fill(0);
            return Err(Error::Unauthorized);
        }
        Ok(32)
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Provider {
        calls: usize,
        fail: bool,
    }
    impl CryptoProvider for Provider {
        fn aes128_encrypt_block_in_place(&mut self, key: &[u8; 16], block: &mut [u8; 16]) -> crate::Result<()> {
            self.calls += 1;
            if self.fail { block.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.aes128_encrypt_block_in_place(key, block)
        }
        fn aes128_decrypt_block_in_place(&mut self, key: &[u8; 16], block: &mut [u8; 16]) -> crate::Result<()> {
            self.calls += 1;
            if self.fail { block.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.aes128_decrypt_block_in_place(key, block)
        }
        fn sha256_into(&mut self, _: &[u8], output: &mut [u8; 32]) -> crate::Result<()> {
            self.calls += 1;
            output.fill(0x42);
            if self.fail {
                Err(crate::Error::Native)
            } else {
                Ok(())
            }
        }
    }
    impl Entropy for Provider {
        fn fill_entropy(&mut self, output: &mut [u8]) -> crate::Result<()> {
            self.calls += 1;
            output.fill(0x17);
            if self.fail {
                Err(crate::Error::Native)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn provider_routing_bounds_and_failures_never_leave_partial_output_or_retry() {
        let mut provider = Provider::default();
        let mut host = Services(&mut provider);
        let mut output = [0xaa; 64];
        assert_eq!(host.digest(4, b"message", &mut output), Ok(32));
        assert_eq!(output[..32], [0x42; 32]);
        assert_eq!(output[32..], [0; 32]);
        assert_eq!(host.0.calls, 1);
        for (algorithm, length, error) in [(5, 64, Error::Unsupported), (4, 31, Error::Bounds)] {
            output.fill(0xaa);
            assert_eq!(
                host.digest(algorithm, b"message", &mut output[..length]),
                Err(error)
            );
            assert!(output[..length].iter().all(|byte| *byte == 0));
            assert_eq!(host.0.calls, 1);
        }
        host.random(&mut output).unwrap();
        assert_eq!(output, [0x17; 64]);
        host.0.fail = true;
        assert_eq!(
            host.digest(4, b"message", &mut output),
            Err(Error::Unauthorized)
        );
        assert_eq!(output, [0; 64]);
        assert_eq!(host.random(&mut output), Err(Error::Unauthorized));
        assert_eq!(output, [0; 64]);
        assert_eq!(host.0.calls, 4);
        host.0.fail = false;
        let mut block = [0; 16];
        host.aes128_block(&[0; 16], &mut block, true).unwrap();
        assert_eq!(block, [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e]);
        host.aes128_block(&[0; 16], &mut block, false).unwrap();
        assert_eq!(block, [0; 16]);
        host.0.fail = true;
        for encrypt in [true, false] {
            assert_eq!(host.aes128_block(&[0; 16], &mut block, encrypt), Err(Error::Unauthorized));
            assert_eq!(block, [0; 16]);
        }
        assert_eq!(host.0.calls, 8);
    }
}
