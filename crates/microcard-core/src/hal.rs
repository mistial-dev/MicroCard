//! Portable, allocation-free hardware contracts used below the managed runtime.
//!
//! Implementations validate lengths before touching peripherals, borrow inputs,
//! write into caller-owned outputs, and return `Error::Bounds` for oversized data.

use crate::{crypto::CryptoProvider, Error, Result};

pub use crate::journal::Flash as JournalFlash;

pub const MAX_SHORT_COMMAND_BYTES: usize = 261;
pub const MAX_SHORT_RESPONSE_BYTES: usize = 258;
pub const MAX_DEVICE_IDENTITY_BYTES: usize = 32;
pub const MAX_PROTECTED_KEY_INPUTS: usize = 4;

pub trait Entropy {
    /// Fill the complete output or clear it completely before returning an error.
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()>;
}

pub trait LogicalGpio {
    /// Access only a provisioned logical resource. Raw pins never cross this boundary.
    fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()>;
}

pub trait MonotonicClock {
    fn ticks(&mut self) -> u64;
    fn ticks_per_second(&self) -> u32;
}

#[derive(Default)]
pub struct TickExtender {
    previous: u32,
    epoch: u64,
}

impl TickExtender {
    /// Extend a frequently sampled wrapping 32-bit hardware counter.
    pub fn update(&mut self, current: u32) -> u64 {
        if current < self.previous {
            self.epoch = self.epoch.saturating_add(1_u64 << 32);
        }
        self.previous = current;
        self.epoch | u64::from(current)
    }
}

pub trait Watchdog {
    /// Arm using monotonic ticks. A zero timeout is invalid.
    fn arm(&mut self, timeout_ticks: u64) -> Result<()>;
    fn feed(&mut self) -> Result<()>;
}

pub trait ApduTransport {
    /// Receive one complete frame into `output`, bounded by `deadline_ticks`.
    fn receive(&mut self, output: &mut [u8], deadline_ticks: u64) -> Result<usize>;
    fn send(&mut self, input: &[u8], deadline_ticks: u64) -> Result<()>;
}

pub fn receive_command<T: ApduTransport>(
    transport: &mut T,
    output: &mut [u8],
    deadline_ticks: u64,
) -> Result<usize> {
    let capacity = output.len().min(MAX_SHORT_COMMAND_BYTES);
    let written = transport.receive(&mut output[..capacity], deadline_ticks)?;
    if written > capacity {
        return Err(Error::Bounds);
    }
    Ok(written)
}

pub fn send_response<T: ApduTransport>(
    transport: &mut T,
    input: &[u8],
    deadline_ticks: u64,
) -> Result<()> {
    if input.len() > MAX_SHORT_RESPONSE_BYTES {
        return Err(Error::Bounds);
    }
    transport.send(input, deadline_ticks)
}

pub trait StagingFlash {
    fn capacity(&self) -> usize;
    fn read(&self, offset: usize, output: &mut [u8]) -> Result<()>;
    fn erase(&mut self) -> Result<()>;
    /// Programming may only clear bits. Partial failure must be reported.
    fn program(&mut self, offset: usize, input: &[u8]) -> Result<()>;
}

pub trait DeviceIdentity {
    /// Return an immutable, non-secret device identity in caller-owned storage.
    fn read_identity(&self, output: &mut [u8]) -> Result<usize>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetReason {
    PowerOn,
    Pin,
    Watchdog,
    Software,
    Brownout,
    Unknown,
}

pub trait ResetReport {
    fn reset_reason(&self) -> ResetReason;
}

/// Backend-only key handle. It is never exposed directly to managed code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectedKeyHandle(pub u32);

pub trait ProtectedKeys {
    fn generate_key(&mut self, slot: u8, algorithm: u8, usage: u8) -> Result<ProtectedKeyHandle>;
    fn destroy_key(&mut self, handle: ProtectedKeyHandle) -> Result<()>;
    fn key_operation(
        &mut self,
        handle: ProtectedKeyHandle,
        operation: u8,
        inputs: &[&[u8]],
        output: &mut [u8],
        deadline_ticks: u64,
    ) -> Result<usize>;
}

pub fn protected_key_operation<K: ProtectedKeys>(
    keys: &mut K,
    handle: ProtectedKeyHandle,
    operation: u8,
    inputs: &[&[u8]],
    output: &mut [u8],
    deadline_ticks: u64,
) -> Result<usize> {
    if inputs.len() > MAX_PROTECTED_KEY_INPUTS {
        output.fill(0);
        return Err(Error::Bounds);
    }
    let written = match keys.key_operation(handle, operation, inputs, output, deadline_ticks) {
        Ok(written) => written,
        Err(error) => {
            output.fill(0);
            return Err(error);
        }
    };
    if written > output.len() {
        output.fill(0);
        return Err(Error::Bounds);
    }
    Ok(written)
}

/// Services used by the portable interpreter and domain manager today.
pub trait RuntimePlatform: CryptoProvider + Entropy + LogicalGpio {
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        output.fill(0);
        let result = self.fill_entropy(output);
        crate::crypto::clear_output_on_error(output, result)
    }

    fn gpio(&mut self, resource: i32, value: i32) -> Result<()> {
        self.write_gpio(resource, value)
    }
}

impl<T> RuntimePlatform for T where T: CryptoProvider + Entropy + LogicalGpio {}

#[cfg(feature = "hal-conformance")]
pub mod conformance {
    use super::*;

    pub trait Control {
        fn reset_entropy(&mut self, seed: u64);
        fn fail_entropy(&mut self);
        fn deny_gpio(&mut self);
        fn set_reset_reason(&mut self, reason: ResetReason);
        fn advance_clock(&mut self, ticks: u64);
        fn advance_watchdog(&mut self, ticks: u64);
        fn queue_transport(&mut self, fragment: &[u8]);
        fn sent_response(&self) -> &[u8];
        fn fail_staging_after(&mut self, bytes: usize);
        fn power_cycle_staging(&mut self);
    }

    fn require(condition: bool) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(Error::Native)
        }
    }

    /// Exercise provider-independent primitive semantics with fixed buffers.
    pub fn run_crypto<P: CryptoProvider>(provider: &mut P) -> Result<()> {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
            0xcf, 0x4f, 0x3c,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
            0x93, 0x17, 0x2a,
        ];

        // FIPS 180-4 SHA-256 example and RFC 4231 section 4.2.
        let mut digest = [0; 32];
        provider.sha256_into(b"abc", &mut digest)?;
        require(
            digest
                == [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
                    0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
        )?;
        let mut hmac = [0; 32];
        provider.hmac_sha256_into(&[0x0b; 20], b"Hi There", &mut hmac)?;
        require(
            hmac
                == [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce,
                    0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ],
        )?;

        // RFC 4493 section 4.2 and segmented-input equivalence.
        let expected_cmac = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0,
            0x4a, 0x28, 0x7c,
        ];
        let mut cmac = [0; 16];
        provider.aes_cmac_into(&key, &plaintext, &mut cmac)?;
        require(cmac == expected_cmac)?;
        cmac.fill(0);
        provider.aes_cmac_parts_into(&key, &[&plaintext[..5], &plaintext[5..]], &mut cmac)?;
        require(cmac == expected_cmac)?;

        // NIST SP 800-38A appendices F.1 and F.2, first AES-128 block.
        let mut block = plaintext;
        provider.aes128_encrypt_block_in_place(&key, &mut block)?;
        require(
            block
                == [
                    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3,
                    0x24, 0x66, 0xef, 0x97,
                ],
        )?;
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];
        let mut ciphertext = [0; 32];
        let ciphertext_length = provider.aes_cbc_encrypt(&key, iv, &plaintext, &mut ciphertext)?;
        require(ciphertext_length == 32)?;
        require(
            ciphertext[..16]
                == [
                    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
                    0x12, 0xe9, 0x19, 0x7d,
                ],
        )?;
        let mut recovered = [0; 32];
        let recovered_length = provider.aes_cbc_decrypt(
            &key,
            iv,
            &ciphertext[..ciphertext_length],
            &mut recovered,
        )?;
        require(recovered_length == plaintext.len() && recovered[..recovered_length] == plaintext)?;
        ciphertext[ciphertext_length - 1] ^= 1;
        recovered.fill(0xa5);
        require(
            provider.aes_cbc_decrypt(
                &key,
                iv,
                &ciphertext[..ciphertext_length],
                &mut recovered,
            ) == Err(Error::Authentication),
        )?;
        require(recovered == [0; 32])?;
        let mut short_cbc = [0xa5; 31];
        require(
            provider.aes_cbc_encrypt(&key, iv, &plaintext, &mut short_cbc)
                == Err(Error::Bounds),
        )?;
        require(short_cbc == [0; 31])?;
        recovered.fill(0xa5);
        require(
            provider.aes_cbc_decrypt(&key, iv, &[], &mut recovered)
                == Err(Error::Authentication),
        )?;
        require(recovered == [0; 32])?;

        // NIST CAVP CCM-VADT AES-128, Alen=0, Count=0.
        let ccm_key = [
            0xd2, 0x4a, 0x3d, 0x3d, 0xde, 0x8c, 0x84, 0x83, 0x02, 0x80, 0xcb, 0x87, 0xab,
            0xad, 0x0b, 0xb3,
        ];
        let nonce = [
            0xf1, 0x10, 0x00, 0x35, 0xbb, 0x24, 0xa8, 0xd2, 0x60, 0x04, 0xe0, 0xe2, 0x4b,
        ];
        let payload = [
            0x7c, 0x86, 0x13, 0x5e, 0xd9, 0xc2, 0xa5, 0x15, 0xaa, 0xae, 0x0e, 0x9a, 0x20,
            0x81, 0x33, 0x89, 0x72, 0x69, 0x22, 0x0f, 0x30, 0x87, 0x00, 0x06,
        ];
        let expected_ccm = [
            0x1f, 0xae, 0xb0, 0xee, 0x2c, 0xa2, 0xcd, 0x52, 0xf0, 0xaa, 0x39, 0x66, 0x57,
            0x83, 0x44, 0xf2, 0x4e, 0x69, 0xb7, 0x42, 0xc4, 0xab, 0x37, 0xab, 0x11, 0x23,
            0x30, 0x12, 0x19, 0xc7, 0x05, 0x99, 0xb7, 0xc3, 0x73, 0xad, 0x4b, 0x3a, 0xd6,
            0x7b,
        ];
        let mut ccm = [0; 40];
        require(provider.aes_ccm_encrypt(&ccm_key, &nonce, &[], &payload, &mut ccm)? == 40)?;
        require(ccm == expected_ccm)?;
        let mut opened = [0; 24];
        require(provider.aes_ccm_decrypt(&ccm_key, &nonce, &[], &ccm, &mut opened)? == 24)?;
        require(opened == payload)?;
        ccm[39] ^= 1;
        opened.fill(0xa5);
        require(
            provider.aes_ccm_decrypt(&ccm_key, &nonce, &[], &ccm, &mut opened)
                == Err(Error::Authentication),
        )?;
        require(opened == [0; 24])?;
        let mut short_ccm = [0xa5; 39];
        require(
            provider.aes_ccm_encrypt(&ccm_key, &nonce, &[], &payload, &mut short_ccm)
                == Err(Error::Bounds),
        )?;
        require(short_ccm == [0; 39])?;
        opened.fill(0xa5);
        require(
            provider.aes_ccm_decrypt(&ccm_key, &nonce, &[], &[0; 15], &mut opened)
                == Err(Error::Authentication),
        )?;
        require(opened == [0; 24])?;

        // RFC 8032 section 7.1, Ed25519 test vector 1.
        let public_key = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9,
            0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02,
            0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80,
            0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73,
            0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b,
            0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0,
            0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        require(provider.ed25519_public_key_valid(&public_key)?)?;
        require(provider.ed25519_verify(&public_key, &signature, &[])?)?;
        require(!provider.ed25519_verify(&public_key, &signature, &[0])?)?;
        require(!provider.ed25519_verify(&public_key[..31], &signature, &[])?)?;
        require(!provider.ed25519_verify(&public_key, &signature[..63], &[])?)?;

        // RFC 6979 appendix A.2.5 plus a fixed P-256 ECDH known answer.
        let private_key = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67,
            0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a,
            0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
        ];
        let expected_public_key = [
            0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
            0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6,
            0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8,
            0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2,
            0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
        ];
        let expected_signature = [
            0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4,
            0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d,
            0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c,
            0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb,
            0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
        ];
        let peer_public_key = [
            0x04, 0x55, 0x0f, 0x47, 0x10, 0x03, 0xf3, 0xdf, 0x97, 0xc3, 0xdf, 0x50, 0x6a,
            0xc7, 0x97, 0xf6, 0x72, 0x1f, 0xb1, 0xa1, 0xfb, 0x7b, 0x8f, 0x6f, 0x83, 0xd2,
            0x24, 0x49, 0x8a, 0x65, 0xc8, 0x8e, 0x24, 0x13, 0x60, 0x93, 0xd7, 0x01, 0x2e,
            0x50, 0x9a, 0x73, 0x71, 0x5c, 0xbd, 0x0b, 0x00, 0xa3, 0xcc, 0x0f, 0xf4, 0xb5,
            0xc0, 0x1b, 0x3f, 0xfa, 0x19, 0x6a, 0xb1, 0xfb, 0x32, 0x70, 0x36, 0xb8, 0xe6,
        ];
        let expected_shared_secret = [
            0x1a, 0x6f, 0xfb, 0x29, 0x06, 0x9a, 0xce, 0x9c, 0x04, 0xba, 0x94, 0x28, 0x91,
            0x1b, 0xd0, 0x09, 0x0f, 0x87, 0x26, 0xae, 0xb3, 0x2e, 0x81, 0xd4, 0x7b, 0x24,
            0x1a, 0x1f, 0x88, 0x04, 0xe4, 0x7d,
        ];
        let mut derived_public_key = [0; 65];
        provider.p256_public_key_into(&private_key, &mut derived_public_key)?;
        require(derived_public_key == expected_public_key)?;
        let mut p256_signature = [0; 64];
        provider.p256_ecdsa_sign_into(&private_key, b"sample", &mut p256_signature)?;
        require(p256_signature == expected_signature)?;
        require(provider.p256_ecdsa_verify(
            &derived_public_key,
            b"sample",
            &p256_signature,
        )?)?;
        require(!provider.p256_ecdsa_verify(
            &derived_public_key,
            b"changed",
            &p256_signature,
        )?)?;
        require(!provider.p256_ecdsa_verify(
            &[0; 65],
            b"sample",
            &p256_signature,
        )?)?;
        let mut shared_secret = [0; 32];
        provider.p256_ecdh_into(&private_key, &peer_public_key, &mut shared_secret)?;
        require(shared_secret == expected_shared_secret)?;
        shared_secret.fill(0);
        require(
            provider.p256_ecdh_into(&private_key, &[0; 65], &mut shared_secret)
                == Err(Error::Authentication),
        )?;
        require(shared_secret == [0; 32])?;
        derived_public_key.fill(0);
        require(
            provider.p256_public_key_into(&[0; 32], &mut derived_public_key)
                == Err(Error::Storage),
        )?;
        require(derived_public_key == [0; 65])?;
        p256_signature.fill(0);
        require(
            provider.p256_ecdsa_sign_into(&[0; 32], b"sample", &mut p256_signature)
                == Err(Error::Storage),
        )?;
        require(p256_signature == [0; 64])
    }

    /// Run deterministic behavioral checks against a port's test adapter.
    pub fn run<H>(hal: &mut H) -> Result<()>
    where
        H: Control
            + CryptoProvider
            + Entropy
            + LogicalGpio
            + MonotonicClock
            + Watchdog
            + ApduTransport
            + StagingFlash
            + DeviceIdentity
            + ResetReport,
    {
        let mut first = [0; 32];
        let mut second = [0; 32];
        hal.reset_entropy(7);
        hal.fill_entropy(&mut first)?;
        hal.reset_entropy(7);
        hal.fill_entropy(&mut second)?;
        require(first == second)?;
        hal.fail_entropy();
        first.fill(0xa5);
        require(hal.fill_entropy(&mut first) == Err(Error::Native) && first == [0; 32])?;
        hal.deny_gpio();
        require(hal.write_gpio(0, 1) == Err(Error::Unauthorized))?;

        let mut identity = [0xa5; MAX_DEVICE_IDENTITY_BYTES];
        let identity_length = hal.read_identity(&mut identity)?;
        require((1..=MAX_DEVICE_IDENTITY_BYTES).contains(&identity_length))?;
        let mut repeated_identity = [0x5a; MAX_DEVICE_IDENTITY_BYTES];
        require(hal.read_identity(&mut repeated_identity) == Ok(identity_length))?;
        require(identity[..identity_length] == repeated_identity[..identity_length])?;
        require(identity[identity_length..] == [0xa5; MAX_DEVICE_IDENTITY_BYTES][identity_length..])?;
        require(
            repeated_identity[identity_length..]
                == [0x5a; MAX_DEVICE_IDENTITY_BYTES][identity_length..],
        )?;
        hal.set_reset_reason(ResetReason::Watchdog);
        require(hal.reset_reason() == ResetReason::Watchdog)?;

        hal.advance_clock(17);
        require(hal.ticks() == 17)?;
        hal.arm(10)?;
        hal.advance_watchdog(9);
        hal.feed()?;
        hal.advance_watchdog(10);
        require(hal.feed() == Err(Error::Native))?;

        let command = [0x00, 0xa4, 0x04, 0x00];
        let mut frame = [0; 6];
        frame[..2].copy_from_slice(&(command.len() as u16).to_le_bytes());
        frame[2..].copy_from_slice(&command);
        let mut output = [0; MAX_SHORT_COMMAND_BYTES];
        hal.queue_transport(&frame[..3]);
        require(hal.receive(&mut output, 100) == Err(Error::Native))?;
        hal.queue_transport(&frame[3..]);
        require(hal.receive(&mut output, 200) == Ok(command.len()))?;
        require(output[..command.len()] == command)?;
        send_response(hal, &[0x90, 0x00], 300)?;
        require(hal.sent_response() == [0x90, 0x00])?;

        hal.fail_staging_after(2);
        require(hal.program(0, &[0xf0, 0x0f, 0xaa]) == Err(Error::Native))?;
        hal.power_cycle_staging();
        let mut recovered = [0; 3];
        hal.read(0, &mut recovered)?;
        require(recovered == [0xf0, 0x0f, 0xff])?;
        require(hal.program(0, &[0xff]) == Err(Error::Storage))?;
        hal.read(0, &mut recovered)?;
        require(recovered == [0xf0, 0x0f, 0xff])?;

        run_crypto(hal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BadTransport;
    impl ApduTransport for BadTransport {
        fn receive(&mut self, output: &mut [u8], _: u64) -> Result<usize> {
            Ok(output.len() + 1)
        }

        fn send(&mut self, _: &[u8], _: u64) -> Result<()> {
            Ok(())
        }
    }

    struct BadKeys;
    impl ProtectedKeys for BadKeys {
        fn generate_key(&mut self, _: u8, _: u8, _: u8) -> Result<ProtectedKeyHandle> {
            Err(Error::Native)
        }

        fn destroy_key(&mut self, _: ProtectedKeyHandle) -> Result<()> {
            Err(Error::Native)
        }

        fn key_operation(
            &mut self,
            _: ProtectedKeyHandle,
            _: u8,
            _: &[&[u8]],
            output: &mut [u8],
            _: u64,
        ) -> Result<usize> {
            output.fill(0xa5);
            Ok(output.len() + 1)
        }
    }

    #[test]
    fn transport_helpers_enforce_short_apdu_bounds() {
        let mut transport = BadTransport;
        let mut oversized = [0; MAX_SHORT_COMMAND_BYTES + 1];
        assert_eq!(
            receive_command(&mut transport, &mut oversized, 1),
            Err(Error::Bounds)
        );
        let mut bounded = [0; MAX_SHORT_COMMAND_BYTES];
        assert_eq!(
            receive_command(&mut transport, &mut bounded, 1),
            Err(Error::Bounds)
        );
        assert_eq!(
            send_response(&mut transport, &[0; MAX_SHORT_RESPONSE_BYTES + 1], 1),
            Err(Error::Bounds)
        );
    }

    #[test]
    fn protected_key_helper_bounds_inputs_and_clears_invalid_output() {
        let mut output = [0xff; 16];
        assert_eq!(
            protected_key_operation(&mut BadKeys, ProtectedKeyHandle(7), 1, &[], &mut output, 1,),
            Err(Error::Bounds)
        );
        assert_eq!(output, [0; 16]);

        output.fill(0xff);
        let inputs = [&[][..]; MAX_PROTECTED_KEY_INPUTS + 1];
        assert_eq!(
            protected_key_operation(
                &mut BadKeys,
                ProtectedKeyHandle(7),
                1,
                &inputs,
                &mut output,
                1,
            ),
            Err(Error::Bounds)
        );
        assert_eq!(output, [0; 16]);
    }

    #[test]
    fn tick_extender_preserves_order_across_counter_wrap() {
        let mut ticks = TickExtender::default();
        assert_eq!(ticks.update(u32::MAX - 1), u64::from(u32::MAX) - 1);
        assert_eq!(ticks.update(u32::MAX), u64::from(u32::MAX));
        assert_eq!(ticks.update(0), 1_u64 << 32);
        assert_eq!(ticks.update(7), (1_u64 << 32) + 7);
    }
}
