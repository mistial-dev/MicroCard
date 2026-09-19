//! Java Card's supported algorithms use the same providers as transport and persistence.
use crate::{crypto::CryptoProvider, hal::Entropy};
use microcard_engine_jcvm::{Error, Result, host::Host};

mod ecdsa;
mod ec_parameters;

pub struct Services<'a, P>(pub &'a mut P);

// Kept outside the host vtable until the P-256 applet bindings are enabled.
impl<P: CryptoProvider> Services<'_, P> {
    /// Derive an uncompressed SEC1 key without retaining private material.
    pub fn p256_public(&mut self, key: &[u8; 32], output: &mut [u8; 65]) -> Result<()> {
        output.fill(0);
        if !crate::crypto::p256_private_key_valid(key) { return Err(Error::Bounds); }
        if self.0.p256_public_key_into(key, output).is_err() {
            output.fill(0);
            return Err(Error::Unauthorized);
        }
        if output[0] != 4 {
            output.fill(0);
            return Err(Error::Format);
        }
        Ok(())
    }

    /// Validate curve membership through the provider; malformed keys are not driver failures.
    pub fn p256_public_valid(&mut self, key: &[u8; 65]) -> Result<bool> {
        if key[0] != 4 { return Ok(false); }
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut scratch = zeroize::Zeroizing::new([0u8; 32]);
        match self.0.p256_ecdh_into(&one, key, &mut scratch) {
            Ok(()) => Ok(true),
            Err(crate::Error::Authentication) => Ok(false),
            Err(_) => Err(Error::Unauthorized),
        }
    }

    /// Derive a raw P-256 shared secret, preserving the 65-byte public-key contract.
    pub fn p256_agree(&mut self, key: &[u8; 32], peer: &[u8; 65], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        if !crate::crypto::p256_private_key_valid(key) || peer[0] != 4 { return Err(Error::Bounds); }
        if let Err(error) = self.0.p256_ecdh_into(key, peer, output) {
            output.fill(0);
            return Err(if error == crate::Error::Authentication { Error::Bounds } else { Error::Unauthorized });
        }
        Ok(())
    }

    /// Publish a complete key pair only after entropy and public-key derivation succeed.
    pub fn p256_generate(&mut self, private: &mut [u8; 32], public: &mut [u8; 65]) -> Result<()>
    where P: Entropy {
        private.fill(0);
        public.fill(0);
        let mut candidate = zeroize::Zeroizing::new([0u8; 32]);
        crate::crypto::p256_generate_private_into(&mut candidate, |output| self.0.fill_entropy(output))
            .map_err(|_| Error::Unauthorized)?;
        self.p256_public(&candidate, public)?;
        *private = *candidate;
        Ok(())
    }

    /// Sign through the provider and emit minimal DER; failure leaves output zeroed.
    pub fn p256_sign_hash(&mut self, key: &[u8; 32], message: &[u8; 32], output: &mut [u8; 72]) -> Result<usize> {
        output.fill(0);
        if !crate::crypto::p256_private_key_valid(key) { return Err(Error::Bounds); }
        let mut raw = zeroize::Zeroizing::new([0u8; 64]);
        self.0.p256_sign_hash_into(key, message, &mut raw).map_err(|_| Error::Unauthorized)?;
        if !crate::crypto::p256_private_key_valid(raw[..32].try_into().unwrap())
            || !crate::crypto::p256_private_key_valid(raw[32..].try_into().unwrap()) {
            return Err(Error::Format);
        }
        Ok(ecdsa::encode(&raw, output))
    }

    /// Reject malformed DER locally and preserve provider failures as errors.
    pub fn p256_verify_hash(&mut self, key: &[u8; 65], message: &[u8; 32], signature: &[u8]) -> Result<bool> {
        if key[0] != 4 { return Ok(false); }
        let Some(raw) = ecdsa::decode(signature) else { return Ok(false); };
        // Java Card accepts either S form; package canonicalization remains separate.
        if !crate::crypto::p256_private_key_valid(raw[..32].try_into().unwrap())
            || !crate::crypto::p256_private_key_valid(raw[32..].try_into().unwrap()) { return Ok(false); }
        self.0.p256_verify_hash(key, message, &raw).map_err(|_| Error::Unauthorized)
    }

}

impl<P: CryptoProvider + Entropy> Host for Services<'_, P> {
    fn sha256_stream(&mut self, state: &mut [u8; microcard_engine_jcvm::host::SHA256_STATE_BYTES],
        input: &[u8], mut output: Option<&mut [u8; 32]>) -> Result<()> {
        let result = self.0.sha256_stream(state, input, output.as_deref_mut());
        if result.is_err() {
            state.fill(0);
            if let Some(output) = output { output.fill(0); }
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn p256_sign_hash(&mut self, key: &[u8; 32], message: &[u8; 32], output: &mut [u8; 72]) -> Result<usize> {
        Services::p256_sign_hash(self, key, message, output)
    }

    fn p256_verify_hash(&mut self, key: &[u8; 65], message: &[u8; 32], signature: &[u8]) -> Result<bool> {
        Services::p256_verify_hash(self, key, message, signature)
    }

    fn supports_agreement(&self, algorithm: u8) -> bool { algorithm == 3 }
    fn supports_signature(&self, algorithm: u8) -> bool { algorithm == 33 }
    fn p256_generate(&mut self, private: &mut [u8; 32], public: &mut [u8; 65]) -> Result<()> {
        Services::p256_generate(self, private, public)
    }
    fn p256_agree(&mut self, key: &[u8; 32], peer: &[u8; 65], output: &mut [u8; 32]) -> Result<()> {
        Services::p256_agree(self, key, peer, output)
    }

    fn p256_parameter(&self, id: u8) -> Option<&'static [u8]> { ec_parameters::parameter(id) }

    fn p256_key_valid(&mut self, private: bool, key: &[u8]) -> Result<bool> {
        if private {
            Ok(key.try_into().is_ok_and(crate::crypto::p256_private_key_valid))
        } else {
            match key.try_into() {
                Ok(key) => self.p256_public_valid(key),
                Err(_) => Ok(false),
            }
        }
    }

    fn supports_digest(&self, algorithm: u8) -> bool {
        algorithm == 4
    }
    fn supports_random(&self, algorithm: u8) -> bool {
        matches!(algorithm, 1 | 2)
    }

    fn supports_cipher(&self, algorithm: u8) -> bool {
        matches!(algorithm, 13 | 14) // AES-128 CBC/ECB, no padding
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

    fn aes128_cbc(&mut self, key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8], encrypt: bool) -> Result<()> {
        if self.0.aes_cbc_in_place(key, iv, buffer, encrypt).is_err() {
            buffer.fill(0);
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
        fail_public: bool,
        bad_entropy: bool,
    }
    impl CryptoProvider for Provider {
        fn sha256_stream(&mut self, state: &mut [u8; crate::crypto::SHA256_STATE_BYTES],
            input: &[u8], output: Option<&mut [u8; 32]>) -> crate::Result<()> {
            if self.fail {
                state.fill(0x42);
                if let Some(output) = output { output.fill(0x42); }
                return Err(crate::Error::Native);
            }
            crate::crypto::SoftwareCrypto.sha256_stream(state, input, output)
        }

        fn p256_public_key_into(&mut self, key: &[u8; 32], output: &mut [u8; 65]) -> crate::Result<()> {
            self.calls += 1;
            if self.fail || self.fail_public { output.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.p256_public_key_into(key, output)
        }
        fn p256_ecdh_into(&mut self, key: &[u8; 32], peer: &[u8], output: &mut [u8; 32]) -> crate::Result<()> {
            self.calls += 1;
            if self.fail { output.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.p256_ecdh_into(key, peer, output)
        }
        fn p256_sign_hash_into(&mut self, key: &[u8; 32], message: &[u8; 32], output: &mut [u8; 64]) -> crate::Result<()> {
            self.calls += 1;
            if self.fail { output.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.p256_sign_hash_into(key, message, output)
        }
        fn p256_verify_hash(&mut self, key: &[u8], message: &[u8; 32], signature: &[u8]) -> crate::Result<bool> {
            self.calls += 1;
            if self.fail { return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.p256_verify_hash(key, message, signature)
        }
        fn aes_cbc_in_place(&mut self, key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8], encrypt: bool) -> crate::Result<()> {
            self.calls += 1;
            if self.fail { buffer.fill(0x42); return Err(crate::Error::Native); }
            crate::crypto::SoftwareCrypto.aes_cbc_in_place(key, iv, buffer, encrypt)
        }
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
            output.fill(if self.bad_entropy { 0 } else { 0x17 });
            if self.fail {
                Err(crate::Error::Native)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn p256_keys_validate_through_provider_and_generation_fails_without_partial_keys() {
        let mut provider = Provider::default();
        let mut host = Services(&mut provider);
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(host.p256_parameter(3).unwrap(), crate::crypto::p256_public_key(&one).unwrap());
        assert_eq!(host.p256_key_valid(true, &one), Ok(true));
        assert_eq!(host.p256_key_valid(true, host.p256_parameter(4).unwrap()), Ok(false));
        assert_eq!(host.p256_parameter(5), None);
        let mut private = [0xaa;32];
        let mut public = [0xaa;65];
        Host::p256_generate(&mut host, &mut private, &mut public).unwrap();
        assert_eq!(private, [0x17;32]);
        assert_eq!(public, crate::crypto::p256_public_key(&private).unwrap());
        assert_eq!(host.p256_public_valid(&public), Ok(true));
        let peer_private = [1;32];
        let peer = crate::crypto::p256_public_key(&peer_private).unwrap();
        let mut shared = [0xaa;32];
        Host::p256_agree(&mut host, &private, &peer, &mut shared).unwrap();
        assert_eq!(shared, crate::crypto::p256_ecdh(&peer_private, &public).unwrap());
        let mut off_curve = [0;65];
        off_curve[0] = 4;
        assert_eq!(host.p256_public_valid(&off_curve), Ok(false));
        assert_eq!(Host::p256_agree(&mut host, &private, &off_curve, &mut shared), Err(Error::Bounds));
        assert_eq!(shared, [0;32]);
        host.0.fail = true;
        assert_eq!(host.p256_public_valid(&public), Err(Error::Unauthorized));
        assert_eq!(Host::p256_agree(&mut host, &private, &peer, &mut shared), Err(Error::Unauthorized));
        assert_eq!(shared, [0;32]);
        for (fail, fail_public, bad_entropy, expected_calls) in [(true,false,false,1), (false,true,false,2), (false,false,true,8)] {
            host.0.fail = fail;
            host.0.fail_public = fail_public;
            host.0.bad_entropy = bad_entropy;
            let before = host.0.calls;
            private.fill(0xaa);
            public.fill(0xaa);
            assert_eq!(Host::p256_generate(&mut host, &mut private, &mut public), Err(Error::Unauthorized));
            assert_eq!(private, [0;32]);
            assert_eq!(public, [0;65]);
            assert_eq!(host.0.calls - before, expected_calls);
        }
    }

    #[test]
    fn p256_der_bridge_uses_provider_and_distinguishes_bad_signatures_from_failures() {
        let key = [1u8; 32];
        let public = crate::crypto::p256_public_key(&key).unwrap();
        let mut provider = Provider::default();
        let mut host = Services(&mut provider);
        let mut signature = [0xaa; 72];
        let mut state = [0; microcard_engine_jcvm::host::SHA256_STATE_BYTES];
        let mut digest = [0; 32];
        Host::sha256_stream(&mut host, &mut state, b"mes", None).unwrap();
        Host::sha256_stream(&mut host, &mut state, b"sage", Some(&mut digest)).unwrap();
        assert_eq!(state, [0; microcard_engine_jcvm::host::SHA256_STATE_BYTES]);
        let written = Host::p256_sign_hash(&mut host, &key, &digest, &mut signature).unwrap();
        let expected = crate::crypto::p256_ecdsa_sign(&key, b"message").unwrap();
        assert_eq!(&signature[..written], p256::ecdsa::Signature::from_slice(&expected).unwrap().to_der().as_bytes());
        assert_eq!(Host::p256_verify_hash(&mut host, &public, &crate::crypto::sha256(b"message"), &signature[..written]), Ok(true));
        assert_eq!(Host::p256_verify_hash(&mut host, &public, &crate::crypto::sha256(b"changed"), &signature[..written]), Ok(false));
        let calls = host.0.calls;
        assert_eq!(Host::p256_verify_hash(&mut host, &public, &crate::crypto::sha256(b"message"), &signature[..written - 1]), Ok(false));
        let mut compressed = public;
        compressed[0] = 2;
        assert_eq!(Host::p256_verify_hash(&mut host, &compressed, &crate::crypto::sha256(b"message"), &signature[..written]), Ok(false));
        let valid_signature = signature;
        assert_eq!(Host::p256_sign_hash(&mut host, &[0;32], &crate::crypto::sha256(b"message"), &mut signature), Err(Error::Bounds));
        assert_eq!(signature, [0;72]);
        assert_eq!(host.0.calls, calls);
        host.0.fail = true;
        assert_eq!(Host::p256_sign_hash(&mut host, &key, &crate::crypto::sha256(b"message"), &mut signature), Err(Error::Unauthorized));
        assert_eq!(signature, [0;72]);
        assert_eq!(Host::p256_verify_hash(&mut host, &public, &crate::crypto::sha256(b"message"), &valid_signature[..written]), Err(Error::Unauthorized));
        assert_eq!(host.0.calls, calls + 2);
        assert_eq!(Host::sha256_stream(&mut host, &mut state, b"x", Some(&mut digest)), Err(Error::Unauthorized));
        assert_eq!(state, [0; microcard_engine_jcvm::host::SHA256_STATE_BYTES]);
        assert_eq!(digest, [0; 32]);
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
        host.0.fail = false;
        host.aes128_cbc(&[0;16], &[0;16], &mut block, true).unwrap();
        assert_eq!(block, [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e]);
        host.aes128_cbc(&[0;16], &[0;16], &mut block, false).unwrap();
        assert_eq!(block, [0;16]);
        host.0.fail = true;
        for encrypt in [true, false] {
            assert_eq!(host.aes128_cbc(&[0;16], &[0;16], &mut block, encrypt), Err(Error::Unauthorized));
            assert_eq!(block, [0;16]);
        }
        assert_eq!(host.0.calls, 12);
    }
}
