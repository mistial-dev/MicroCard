#![no_std]

use core::ffi::c_void;

const SCRATCH_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    P192,
    P384,
}

impl Curve {
    const fn bits(self) -> u32 {
        match self {
            Self::P192 => 192,
            Self::P384 => 384,
        }
    }

    pub const fn key_bytes(self) -> usize {
        (self.bits() / 8) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLength,
    OperationFailed,
}

#[repr(C, align(8))]
struct Scratch([u8; SCRATCH_BYTES]);

impl Scratch {
    fn new() -> Self {
        Self([0; SCRATCH_BYTES])
    }

    fn as_void(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // C already wipes used workspace; cover preflight errors and the unused tail too.
        unsafe { tc_secure_zero(self.0.as_mut_ptr().cast(), SCRATCH_BYTES) }
    }
}

type Fill = extern "C" fn(*mut c_void, *mut u8, usize) -> i32;

extern "C" {
    #[link_name = "TC_secure_zero"]
    fn tc_secure_zero(memory: *mut c_void, len: usize);
    fn mc_tc_ec_generate(
        bits: u32,
        private_key: *mut u8,
        private_len: usize,
        public_key: *mut u8,
        public_len: usize,
        fill: Fill,
        context: *mut c_void,
        scratch: *mut c_void,
    ) -> i32;
    fn mc_tc_ec_public_key(
        bits: u32,
        private_key: *const u8,
        private_len: usize,
        public_key: *mut u8,
        public_len: usize,
        scratch: *mut c_void,
    ) -> i32;
    fn mc_tc_ec_valid_public(
        bits: u32,
        public_key: *const u8,
        public_len: usize,
        scratch: *mut c_void,
    ) -> i32;
    fn mc_tc_ec_agree(
        bits: u32,
        private_key: *const u8,
        private_len: usize,
        peer_key: *const u8,
        peer_len: usize,
        secret: *mut u8,
        secret_len: usize,
        scratch: *mut c_void,
    ) -> i32;
    fn mc_tc_ecdsa_sign(
        bits: u32,
        private_key: *const u8,
        private_len: usize,
        digest: *const u8,
        digest_len: usize,
        signature: *mut u8,
        signature_len: usize,
        fill: Fill,
        context: *mut c_void,
        scratch: *mut c_void,
    ) -> i32;
    fn mc_tc_ecdsa_verify(
        bits: u32,
        public_key: *const u8,
        public_len: usize,
        digest: *const u8,
        digest_len: usize,
        signature: *const u8,
        signature_len: usize,
        scratch: *mut c_void,
    ) -> i32;
}

extern "C" fn fill_from<F: FnMut(&mut [u8]) -> bool>(
    context: *mut c_void,
    output: *mut u8,
    len: usize,
) -> i32 {
    // C supplies its own bounded nonce buffer and calls only during this Rust frame.
    let random = unsafe { &mut *context.cast::<F>() };
    let bytes = unsafe { core::slice::from_raw_parts_mut(output, len) };
    if random(bytes) {
        0
    } else {
        -1
    }
}

/// Generate a key pair with a secure entropy callback. The callback must fill
/// every byte before returning true and must not panic across the C boundary.
pub fn generate_key_pair<F: FnMut(&mut [u8]) -> bool>(
    curve: Curve,
    private_key: &mut [u8],
    public_key: &mut [u8],
    random: &mut F,
) -> Result<(), Error> {
    private_key.fill(0);
    public_key.fill(0);
    let n = curve.key_bytes();
    if private_key.len() != n || public_key.len() != 1 + 2 * n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ec_generate(
            curve.bits(),
            private_key.as_mut_ptr(),
            n,
            public_key.as_mut_ptr(),
            public_key.len(),
            fill_from::<F>,
            (random as *mut F).cast(),
            scratch.as_void(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        private_key.fill(0);
        public_key.fill(0);
        Err(Error::OperationFailed)
    }
}

/// Derive the SEC 1 uncompressed public key. Invalid private scalars fail.
pub fn public_key(curve: Curve, private_key: &[u8], output: &mut [u8]) -> Result<(), Error> {
    output.fill(0);
    let n = curve.key_bytes();
    if private_key.len() != n || output.len() != 1 + 2 * n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ec_public_key(
            curve.bits(),
            private_key.as_ptr(),
            n,
            output.as_mut_ptr(),
            output.len(),
            scratch.as_void(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        output.fill(0);
        Err(Error::OperationFailed)
    }
}

/// Check a SEC 1 uncompressed public key against the selected curve.
pub fn public_key_valid(curve: Curve, public_key: &[u8]) -> Result<bool, Error> {
    let n = curve.key_bytes();
    if public_key.len() != 1 + 2 * n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ec_valid_public(
            curve.bits(),
            public_key.as_ptr(),
            public_key.len(),
            scratch.as_void(),
        )
    };
    Ok(status == 0)
}

/// Compute the raw ECDH X coordinate. Derive a protocol key before use.
pub fn agree(
    curve: Curve,
    private_key: &[u8],
    peer_key: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    output.fill(0);
    let n = curve.key_bytes();
    if private_key.len() != n || peer_key.len() != 1 + 2 * n || output.len() != n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ec_agree(
            curve.bits(),
            private_key.as_ptr(),
            n,
            peer_key.as_ptr(),
            peer_key.len(),
            output.as_mut_ptr(),
            n,
            scratch.as_void(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        output.fill(0);
        Err(Error::OperationFailed)
    }
}

/// Sign a precomputed digest with secure per-signature entropy. The output is
/// fixed-width `r || s` and is cleared on failure.
pub fn sign_digest<F: FnMut(&mut [u8]) -> bool>(
    curve: Curve,
    private_key: &[u8],
    digest: &[u8],
    signature: &mut [u8],
    random: &mut F,
) -> Result<(), Error> {
    signature.fill(0);
    let n = curve.key_bytes();
    if private_key.len() != n || digest.is_empty() || signature.len() != 2 * n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ecdsa_sign(
            curve.bits(),
            private_key.as_ptr(),
            n,
            digest.as_ptr(),
            digest.len(),
            signature.as_mut_ptr(),
            signature.len(),
            fill_from::<F>,
            (random as *mut F).cast(),
            scratch.as_void(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        signature.fill(0);
        Err(Error::OperationFailed)
    }
}

pub fn verify_digest(
    curve: Curve,
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let n = curve.key_bytes();
    if public_key.len() != 1 + 2 * n || digest.is_empty() || signature.len() != 2 * n {
        return Err(Error::InvalidLength);
    }
    let mut scratch = Scratch::new();
    let status = unsafe {
        mc_tc_ecdsa_verify(
            curve.bits(),
            public_key.as_ptr(),
            public_key.len(),
            digest.as_ptr(),
            digest.len(),
            signature.as_ptr(),
            signature.len(),
            scratch.as_void(),
        )
    };
    match status {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(Error::OperationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_boundary_preserves_results_and_clears_failed_outputs() {
        for curve in [Curve::P192, Curve::P384] {
            let n = curve.key_bytes();
            let mut private = [0u8; 48];
            let mut public = [0u8; 97];
            let mut signature = [0u8; 96];
            let mut draw = |bytes: &mut [u8]| {
                bytes.fill(0);
                bytes[bytes.len() - 1] = 1;
                true
            };
            generate_key_pair(
                curve,
                &mut private[..n],
                &mut public[..1 + 2 * n],
                &mut draw,
            )
            .unwrap();
            assert_eq!(private[n - 1], 1);
            assert_eq!(public[0], 4);
            assert_eq!(public_key_valid(curve, &public[..1 + 2 * n]), Ok(true));
            let mut derived = [0u8; 97];
            public_key(curve, &private[..n], &mut derived[..1 + 2 * n]).unwrap();
            assert_eq!(derived[..1 + 2 * n], public[..1 + 2 * n]);
            let mut secret = [0u8; 48];
            agree(curve, &private[..n], &public[..1 + 2 * n], &mut secret[..n]).unwrap();
            assert_eq!(secret[..n], public[1..1 + n]);
            derived[0] = 0;
            assert_eq!(public_key_valid(curve, &derived[..1 + 2 * n]), Ok(false));
            secret[..n].fill(0xa5);
            assert_eq!(
                agree(
                    curve,
                    &private[..n],
                    &derived[..1 + 2 * n],
                    &mut secret[..n]
                ),
                Err(Error::OperationFailed)
            );
            assert_eq!(secret[..n], [0; 48][..n]);
            derived[..1 + 2 * n].fill(0xa5);
            assert_eq!(
                public_key(curve, &[0; 48][..n], &mut derived[..1 + 2 * n]),
                Err(Error::OperationFailed)
            );
            assert_eq!(derived[..1 + 2 * n], [0; 97][..1 + 2 * n]);
            let mut digest = [0x42u8; 32];
            sign_digest(
                curve,
                &private[..n],
                &digest,
                &mut signature[..2 * n],
                &mut draw,
            )
            .unwrap();
            assert_eq!(
                verify_digest(curve, &public[..1 + 2 * n], &digest, &signature[..2 * n]),
                Ok(true)
            );
            digest[0] ^= 1;
            assert_eq!(
                verify_digest(curve, &public[..1 + 2 * n], &digest, &signature[..2 * n]),
                Ok(false)
            );

            signature.fill(0xa5);
            assert_eq!(
                sign_digest(
                    curve,
                    &private[..n],
                    &digest,
                    &mut signature[..2 * n],
                    &mut |_| false
                ),
                Err(Error::OperationFailed)
            );
            assert!(signature[..2 * n].iter().all(|&byte| byte == 0));

            private.fill(0xa5);
            public.fill(0xa5);
            assert_eq!(
                generate_key_pair(
                    curve,
                    &mut private[..n],
                    &mut public[..1 + 2 * n],
                    &mut |_| false,
                ),
                Err(Error::OperationFailed)
            );
            assert!(private[..n].iter().all(|&byte| byte == 0));
            assert!(public[..1 + 2 * n].iter().all(|&byte| byte == 0));
        }
    }
}
