//! What the engine asks the card for, JCRE §5.
//!
//! Algorithms are not the virtual machine's business. A card has accelerators, key storage
//! and an entropy source, and which of those exist differs between one card and the next.
//! The engine asks through this trait so a platform can supply hardware implementations.
//! This boundary covers digest, entropy, AES, and P-256 key validation.
use crate::{Error, Result};

pub const SHA256_STATE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointReason {
    Installation,
    ApduEnd,
    OwnerPin,
    TransactionCommit,
}

/// The services an applet's cryptography needs.
pub trait Host {
    /// Check capacity before an immediate security-state mutation. This does not
    /// reserve flash or replace the checkpoint's write-error handling.
    fn ensure_checkpoint_capacity(&mut self, _count: u32) -> Result<()> {
        Err(Error::Storage)
    }
    /// Return only after this state is durable. Failure stops execution and requires
    /// recovery; cryptographic availability alone does not imply storage support.
    fn checkpoint(&mut self, _state: crate::applet::PersistentView<'_>, _reason: CheckpointReason) -> Result<()> {
        Err(Error::Storage)
    }
    /// Current command protection, in GlobalPlatform SecureChannel bit assignments.
    /// A saved applet handle never supplies authority for a later command.
    fn secure_channel_available(&self) -> bool { false }
    fn secure_channel_level(&self) -> u8 { 0 }
    fn reset_secure_channel(&mut self) -> Result<()> { Err(Error::Unsupported) }

    /// Consume the exact command already verified by the platform transport.
    /// Implementations reject changed bytes and repeated unwrapping.
    fn unwrap_secure_command(&mut self, _command: &mut [u8]) -> Result<()> {
        Err(Error::Unauthorized)
    }

    /// Report support only when both one-shot and streaming digest calls work.
    fn supports_digest(&self, _algorithm: u8) -> bool { false }
    fn supports_random(&self, _algorithm: u8) -> bool { false }
    fn supports_cipher(&self, _algorithm: u8) -> bool { false }
    fn supports_agreement(&self, _algorithm: u8) -> bool { false }
    fn supports_signature(&self, _algorithm: u8) -> bool { false }
    fn supports_rsa_keygen(&self) -> bool { false }

    /// Transform one AES-128 block; failed operations clear the entire block.
    fn aes128_block(&mut self, _key: &[u8; 16], block: &mut [u8; 16], _encrypt: bool) -> Result<()> {
        block.fill(0);
        Err(Error::Unsupported)
    }

    /// Transform nonempty, complete AES-128 CBC blocks without padding.
    fn aes128_cbc(&mut self, _key: &[u8; 16], _iv: &[u8; 16], buffer: &mut [u8], _encrypt: bool) -> Result<()> {
        buffer.fill(0);
        Err(Error::Unsupported)
    }

    /// AES-128 CTR with a big-endian 128-bit counter; failure clears the output.
    fn aes128_ctr(&mut self, _key: &[u8; 16], _counter: &[u8; 16], buffer: &mut [u8]) -> Result<()> {
        buffer.fill(0);
        Err(Error::Unsupported)
    }

    /// DES or two/three-key 3DES, complete blocks, with an optional CBC IV.
    fn des_crypt(&mut self, _key: &[u8], _iv: Option<&[u8; 8]>, buffer: &mut [u8], _encrypt: bool) -> Result<()> {
        buffer.fill(0);
        Err(Error::Unsupported)
    }

    /// P-256 domain fields: prime, A, B, uncompressed generator, and order.
    fn p256_parameter(&self, _id: u8) -> Option<&'static [u8]> { None }

    fn p256_key_valid(&mut self, _private: bool, _key: &[u8]) -> Result<bool> {
        Err(Error::Unsupported)
    }

    fn p384_parameter(&self, _id: u8) -> Option<&'static [u8]> { None }

    fn p384_key_valid(&mut self, _private: bool, _key: &[u8]) -> Result<bool> {
        Err(Error::Unsupported)
    }

    /// Opaque transient state; zero begins a message, finalization clears state.
    fn sha256_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], _input: &[u8],
        output: Option<&mut [u8; 32]>) -> Result<()> {
        state.fill(0);
        if let Some(output) = output { output.fill(0); }
        Err(Error::Unsupported)
    }

    /// SHA-224 uses the same sized opaque transient state, with a 28-byte result.
    fn sha224_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], _input: &[u8],
        output: Option<&mut [u8; 28]>) -> Result<()> {
        state.fill(0);
        if let Some(output) = output { output.fill(0); }
        Err(Error::Unsupported)
    }

    /// SHA-1 remains necessary for the declared Java Card compatibility profile.
    fn sha1_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], _input: &[u8],
        output: Option<&mut [u8; 20]>) -> Result<()> {
        state.fill(0);
        if let Some(output) = output { output.fill(0); }
        Err(Error::Unsupported)
    }

    fn sha384_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], _input: &[u8],
        output: Option<&mut [u8; 48]>) -> Result<()> {
        state.fill(0);
        if let Some(output) = output { output.fill(0); }
        Err(Error::Unsupported)
    }

    fn sha512_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES], _input: &[u8],
        output: Option<&mut [u8; 64]>) -> Result<()> {
        state.fill(0);
        if let Some(output) = output { output.fill(0); }
        Err(Error::Unsupported)
    }

    /// ECDSA over a SHA-256 digest with minimal DER output; failed signing clears output.
    fn p256_sign_hash(&mut self, _key: &[u8; 32], _hash: &[u8; 32], output: &mut [u8; 72]) -> Result<usize> {
        output.fill(0);
        Err(Error::Unsupported)
    }

    fn p256_verify_hash(&mut self, _key: &[u8; 65], _hash: &[u8; 32], _signature: &[u8]) -> Result<bool> {
        Err(Error::Unsupported)
    }

    /// Generate a complete pair; failure clears both outputs.
    fn p256_generate(&mut self, private: &mut [u8; 32], public: &mut [u8; 65]) -> Result<()> {
        private.fill(0);
        public.fill(0);
        Err(Error::Unsupported)
    }

    /// Raw P-256 ECDH x-coordinate; failure clears all output.
    fn p256_agree(&mut self, _key: &[u8; 32], _peer: &[u8; 65], output: &mut [u8; 32]) -> Result<()> {
        output.fill(0);
        Err(Error::Unsupported)
    }

    fn p384_generate(&mut self, private: &mut [u8; 48], public: &mut [u8; 97]) -> Result<()> {
        private.fill(0);
        public.fill(0);
        Err(Error::Unsupported)
    }

    fn p384_agree(&mut self, _key: &[u8; 48], _peer: &[u8; 97], output: &mut [u8; 48]) -> Result<()> {
        output.fill(0);
        Err(Error::Unsupported)
    }

    fn p384_sign_hash(&mut self, _key: &[u8; 48], _hash: &[u8; 48], output: &mut [u8; 104]) -> Result<usize> {
        output.fill(0);
        Err(Error::Unsupported)
    }

    fn p384_verify_hash(&mut self, _key: &[u8; 97], _hash: &[u8; 48], _signature: &[u8]) -> Result<bool> {
        Err(Error::Unsupported)
    }

    /// PKCS#1 DER keys, SHA-256 digest, and an exact modulus-sized signature.
    fn rsa_pkcs1v15_sha256_sign(&mut self, _private_der: &[u8], _key_bits: usize,
        _hash: &[u8; 32], signature: &mut [u8]) -> Result<()> {
        signature.fill(0);
        Err(Error::Unsupported)
    }

    fn rsa_pkcs1v15_sha256_verify(&mut self, _public_der: &[u8], _key_bits: usize,
        _hash: &[u8; 32], _signature: &[u8]) -> Result<bool> {
        Err(Error::Unsupported)
    }

    /// Generate complete PKCS#1 DER keys and publish lengths only on success.
    fn rsa_generate(&mut self, _key_bits: usize, private_der: &mut [u8],
        public_der: &mut [u8]) -> Result<(usize, usize)> {
        private_der.fill(0);
        public_der.fill(0);
        Err(Error::Unsupported)
    }

    /// Fill a buffer with random bytes.
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        let _ = output;
        Err(Error::Unsupported)
    }

    /// Hash a message, answering how many bytes the digest occupies.
    ///
    /// The algorithm is the code `javacard.security.MessageDigest` uses.
    fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
        let _ = (algorithm, message, output);
        Err(Error::Unsupported)
    }
}

/// A card that provides no algorithms, which is what a build with nothing wired up has.
///
/// Every operation refuses rather than answering with something predictable, because a
/// predictable answer from a random source is worse than no answer at all.
pub struct NoHost;

impl Host for NoHost {
    // This explicitly volatile engine host is used without a persistent session.
    fn ensure_checkpoint_capacity(&mut self, _count: u32) -> Result<()> { Ok(()) }
    fn checkpoint(&mut self, _state: crate::applet::PersistentView<'_>, _reason: CheckpointReason) -> Result<()> { Ok(()) }
}
