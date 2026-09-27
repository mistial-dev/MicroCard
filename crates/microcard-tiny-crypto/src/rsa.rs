//! Bounded PKCS#1 DER bridge to tiny-crypto-c's prehashed RSA operations.

use core::ffi::c_void;

use crate::{Error, Fill};

const WORKSPACE_WORDS: usize = 14 * (2048 / 32);
const KEYGEN_WORKSPACE_WORDS: usize = 8 * (2048 / 32);

#[repr(C, align(4))]
struct Scratch([u32; WORKSPACE_WORDS]);

impl Scratch {
    fn new() -> Self { Self([0; WORKSPACE_WORDS]) }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        unsafe { super::tc_secure_zero(self.0.as_mut_ptr().cast(), core::mem::size_of_val(&self.0)) }
    }
}

extern "C" {
    fn mc_tc_rsa_keygen(
        bits: usize, n: *mut u8, e: *mut u8, d: *mut u8, p: *mut u8, q: *mut u8,
        fill: Fill, random_context: *mut c_void, scratch: *mut u32,
        scratch_words: usize,
    ) -> i32;
    fn mc_tc_rsa_derive_crt(
        bits: usize, n: *const u8, e: *const u8, d: *const u8,
        p: *const u8, q: *const u8, dp: *mut u8, dq: *mut u8, qi: *mut u8,
        scratch: *mut u32, scratch_words: usize,
    ) -> i32;
    fn mc_tc_rsa_sign_sha256(
        n: *const u8, n_len: usize, e: *const u8, e_len: usize,
        d: *const u8, d_len: usize, p: *const u8, p_len: usize,
        q: *const u8, q_len: usize, hash: *const u8,
        signature: *mut u8, signature_len: usize, fill: Fill,
        random_context: *mut c_void, scratch: *mut u32, scratch_words: usize,
    ) -> i32;
    fn mc_tc_rsa_verify_sha256(
        n: *const u8, n_len: usize, e: *const u8, e_len: usize,
        hash: *const u8, signature: *const u8, signature_len: usize,
        scratch: *mut u32, scratch_words: usize,
    ) -> i32;
}

/// Fixed-capacity RSA components. Only the first `bits / 8` bytes of `n` and
/// `d`, and the first `bits / 16` bytes of `p` and `q`, are populated.
pub struct KeyPairComponents {
    pub modulus: [u8; 256],
    pub public_exponent: [u8; 3],
    pub private_exponent: [u8; 256],
    pub p: [u8; 128],
    pub q: [u8; 128],
    pub dp: [u8; 128],
    pub dq: [u8; 128],
    pub q_inverse: [u8; 128],
}

impl KeyPairComponents {
    pub const fn new() -> Self {
        Self { modulus: [0; 256], public_exponent: [0; 3],
            private_exponent: [0; 256], p: [0; 128], q: [0; 128],
            dp: [0; 128], dq: [0; 128], q_inverse: [0; 128] }
    }
}

impl Default for KeyPairComponents {
    fn default() -> Self { Self::new() }
}

impl Drop for KeyPairComponents {
    fn drop(&mut self) {
        unsafe { super::tc_secure_zero((self as *mut Self).cast(), core::mem::size_of::<Self>()) }
    }
}

/// Generate a complete RSA-1024/2048 pair with bounded work and injected RNG.
/// Outputs are published together; failure clears every component.
pub fn generate_key_pair(bits: usize, output: &mut KeyPairComponents,
    random: &mut dyn FnMut(&mut [u8]) -> bool) -> Result<(), Error> {
    *output = KeyPairComponents::new();
    if !matches!(bits, 1024 | 2048) { return Err(Error::InvalidLength); }
    let mut scratch = [0u32; KEYGEN_WORKSPACE_WORDS];
    let mut source = Random(random);
    let status = unsafe { mc_tc_rsa_keygen(bits, output.modulus.as_mut_ptr(),
        output.public_exponent.as_mut_ptr(), output.private_exponent.as_mut_ptr(),
        output.p.as_mut_ptr(), output.q.as_mut_ptr(), fill,
        (&mut source as *mut Random<'_>).cast(), scratch.as_mut_ptr(), scratch.len()) };
    unsafe { super::tc_secure_zero(scratch.as_mut_ptr().cast(), core::mem::size_of_val(&scratch)) };
    let mut status = status;
    if status == 0 {
        status = unsafe { mc_tc_rsa_derive_crt(bits, output.modulus.as_ptr(),
            output.public_exponent.as_ptr(), output.private_exponent.as_ptr(),
            output.p.as_ptr(), output.q.as_ptr(), output.dp.as_mut_ptr(),
            output.dq.as_mut_ptr(), output.q_inverse.as_mut_ptr(),
            scratch.as_mut_ptr(), scratch.len()) };
        unsafe { super::tc_secure_zero(scratch.as_mut_ptr().cast(), core::mem::size_of_val(&scratch)) };
    }
    if status == 0 { Ok(()) } else {
        *output = KeyPairComponents::new();
        Err(Error::OperationFailed)
    }
}

fn magnitude(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
    &bytes[first..]
}

fn length_bytes(length: usize) -> usize {
    if length < 128 { 1 } else if length < 256 { 2 } else { 3 }
}

fn integer_size(bytes: &[u8]) -> usize {
    let bytes = magnitude(bytes);
    let length = bytes.len() + usize::from(bytes[0] & 0x80 != 0);
    1 + length_bytes(length) + length
}

fn put_length(output: &mut [u8], position: &mut usize, length: usize) {
    if length < 128 {
        output[*position] = length as u8;
        *position += 1;
    } else if length < 256 {
        output[*position..*position + 2].copy_from_slice(&[0x81, length as u8]);
        *position += 2;
    } else {
        output[*position..*position + 3].copy_from_slice(&[0x82, (length >> 8) as u8, length as u8]);
        *position += 3;
    }
}

fn put_integer(output: &mut [u8], position: &mut usize, bytes: &[u8]) {
    let bytes = magnitude(bytes);
    output[*position] = 2;
    *position += 1;
    let sign_pad = bytes[0] & 0x80 != 0;
    put_length(output, position, bytes.len() + usize::from(sign_pad));
    if sign_pad { output[*position] = 0; *position += 1; }
    output[*position..*position + bytes.len()].copy_from_slice(bytes);
    *position += bytes.len();
}

fn encode_sequence(output: &mut [u8], integers: &[&[u8]]) -> Result<usize, Error> {
    let body = integers.iter().map(|bytes| integer_size(bytes)).sum::<usize>();
    let total = 1 + length_bytes(body) + body;
    if output.len() < total { return Err(Error::InvalidLength); }
    let mut position = 0;
    output[position] = 0x30;
    position += 1;
    put_length(output, &mut position, body);
    for bytes in integers { put_integer(output, &mut position, bytes); }
    Ok(total)
}

impl KeyPairComponents {
    /// Encode PKCS#1 `RSAPublicKey` DER into caller-owned storage.
    pub fn encode_public_der(&self, bits: usize, output: &mut [u8]) -> Result<usize, Error> {
        if !matches!(bits, 1024 | 2048) { return Err(Error::InvalidLength); }
        encode_sequence(output, &[&self.modulus[..bits / 8], &self.public_exponent])
    }

    /// Encode PKCS#1 `RSAPrivateKey` DER with complete CRT parameters.
    pub fn encode_private_der(&self, bits: usize, output: &mut [u8]) -> Result<usize, Error> {
        if !matches!(bits, 1024 | 2048) { return Err(Error::InvalidLength); }
        let version = [0u8];
        let full = bits / 8;
        let half = bits / 16;
        encode_sequence(output, &[&version, &self.modulus[..full], &self.public_exponent,
            &self.private_exponent[..full], &self.p[..half], &self.q[..half],
            &self.dp[..half], &self.dq[..half], &self.q_inverse[..half]])
    }
}

fn item<'a>(bytes: &'a [u8], offset: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if bytes.get(*offset).copied()? != tag { return None; }
    *offset += 1;
    let first = *bytes.get(*offset)?;
    *offset += 1;
    let len = if first < 0x80 {
        first as usize
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 2 || bytes.get(*offset)? == &0 { return None; }
        let mut value = 0usize;
        for _ in 0..count {
            value = value.checked_mul(256)?.checked_add(*bytes.get(*offset)? as usize)?;
            *offset += 1;
        }
        if value < 128 { return None; }
        value
    };
    let end = offset.checked_add(len)?;
    let value = bytes.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn integer<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let value = item(bytes, offset, 0x02)?;
    let (&first, tail) = value.split_first()?;
    if first == 0 {
        if tail.is_empty() || tail[0] < 0x80 { return None; }
        Some(tail)
    } else if first & 0x80 == 0 {
        Some(value)
    } else {
        None
    }
}

fn sequence(bytes: &[u8]) -> Option<&[u8]> {
    let mut offset = 0;
    let value = item(bytes, &mut offset, 0x30)?;
    (offset == bytes.len()).then_some(value)
}

fn public_parts(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let body = sequence(der)?;
    let mut offset = 0;
    let n = integer(body, &mut offset)?;
    let e = integer(body, &mut offset)?;
    (offset == body.len()).then_some((n, e))
}

type PrivateParts<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn private_parts(der: &[u8]) -> Option<PrivateParts<'_>> {
    let body = sequence(der)?;
    let mut offset = 0;
    if item(body, &mut offset, 0x02)? != [0] { return None; }
    let n = integer(body, &mut offset)?;
    let e = integer(body, &mut offset)?;
    let d = integer(body, &mut offset)?;
    let p = integer(body, &mut offset)?;
    let q = integer(body, &mut offset)?;
    for _ in 0..3 { integer(body, &mut offset)?; }
    (offset == body.len()).then_some((n, e, d, p, q))
}

struct Random<'a>(&'a mut dyn FnMut(&mut [u8]) -> bool);

extern "C" fn fill(context: *mut c_void, output: *mut u8, len: usize) -> i32 {
    let random = unsafe { &mut *context.cast::<Random<'_>>() };
    let bytes = unsafe { core::slice::from_raw_parts_mut(output, len) };
    if (random.0)(bytes) { 0 } else { -1 }
}

/// Sign a SHA-256 digest with an RSA-1024/2048 PKCS#1 private key.
/// The RNG provides blinding and key-validation draws. Output is cleared on error.
pub fn sign_pkcs1v15_sha256_der(
    private_der: &[u8], bits: usize, hash: &[u8; 32], signature: &mut [u8],
    random: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<(), Error> {
    signature.fill(0);
    if (bits != 1024 && bits != 2048) || signature.len() != bits / 8 {
        return Err(Error::InvalidLength);
    }
    let (n, e, d, p, q) = private_parts(private_der).ok_or(Error::InvalidLength)?;
    if n.len() != bits / 8 { return Err(Error::InvalidLength); }
    let mut scratch = Scratch::new();
    let mut source = Random(random);
    let status = unsafe { mc_tc_rsa_sign_sha256(
        n.as_ptr(), n.len(), e.as_ptr(), e.len(), d.as_ptr(), d.len(),
        p.as_ptr(), p.len(), q.as_ptr(), q.len(), hash.as_ptr(),
        signature.as_mut_ptr(), signature.len(), fill,
        (&mut source as *mut Random<'_>).cast(), scratch.0.as_mut_ptr(), WORKSPACE_WORDS,
    ) };
    if status == 0 { Ok(()) } else {
        signature.fill(0);
        Err(Error::OperationFailed)
    }
}

/// Verify a SHA-256 digest against a PKCS#1 public key and fixed-width signature.
pub fn verify_pkcs1v15_sha256_der(
    public_der: &[u8], bits: usize, hash: &[u8; 32], signature: &[u8],
) -> Result<bool, Error> {
    if (bits != 1024 && bits != 2048) || signature.len() != bits / 8 {
        return Err(Error::InvalidLength);
    }
    let (n, e) = public_parts(public_der).ok_or(Error::InvalidLength)?;
    if n.len() != bits / 8 { return Err(Error::InvalidLength); }
    let mut scratch = Scratch::new();
    let status = unsafe { mc_tc_rsa_verify_sha256(
        n.as_ptr(), n.len(), e.as_ptr(), e.len(), hash.as_ptr(), signature.as_ptr(),
        signature.len(), scratch.0.as_mut_ptr(), WORKSPACE_WORDS,
    ) };
    match status {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(Error::OperationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::io::Read;

    #[test]
    fn bounded_keygen_is_usable_and_rng_failure_clears_components() {
        let mut generated = KeyPairComponents::new();
        let mut os_random = std::fs::File::open("/dev/urandom").unwrap();
        let mut random = |bytes: &mut [u8]| os_random.read_exact(bytes).is_ok();
        generate_key_pair(1024, &mut generated, &mut random).unwrap();
        assert_eq!(generated.public_exponent, [1, 0, 1]);
        assert_eq!(generated.modulus[0] & 0x80, 0x80);
        let mut signature = [0u8; 128];
        let mut scratch = Scratch::new();
        let mut source = Random(&mut random);
        let status = unsafe { mc_tc_rsa_sign_sha256(
            generated.modulus.as_ptr(), 128, generated.public_exponent.as_ptr(), 3,
            generated.private_exponent.as_ptr(), 128, generated.p.as_ptr(), 64,
            generated.q.as_ptr(), 64, HASH.as_ptr(), signature.as_mut_ptr(), 128,
            fill, (&mut source as *mut Random<'_>).cast(), scratch.0.as_mut_ptr(), WORKSPACE_WORDS,
        ) };
        assert_eq!(status, 0);
        let status = unsafe { mc_tc_rsa_verify_sha256(
            generated.modulus.as_ptr(), 128, generated.public_exponent.as_ptr(), 3,
            HASH.as_ptr(), signature.as_ptr(), 128, scratch.0.as_mut_ptr(), WORKSPACE_WORDS,
        ) };
        assert_eq!(status, 0);
        let mut public_der = [0u8; 300];
        let public_len = generated.encode_public_der(1024, &mut public_der).unwrap();
        assert_eq!(public_parts(&public_der[..public_len]),
            Some((&generated.modulus[..128], &generated.public_exponent[..])));
        let mut private_der = [0u8; 1200];
        let private_len = generated.encode_private_der(1024, &mut private_der).unwrap();
        assert!(private_parts(&private_der[..private_len]).is_some());
        assert_eq!(verify_pkcs1v15_sha256_der(&public_der[..public_len], 1024,
            &HASH, &signature), Ok(true));
        assert!(generated.encode_private_der(1024, &mut private_der[..16]).is_err());
        assert_eq!(generate_key_pair(1024, &mut generated, &mut |_| false), Err(Error::OperationFailed));
        assert!(generated.modulus.iter().all(|byte| *byte == 0));
        assert!(generated.private_exponent.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn generated_2048_bit_pair_encodes_complete_der() {
        let mut generated = KeyPairComponents::new();
        let mut os_random = std::fs::File::open("/dev/urandom").unwrap();
        let mut random = |bytes: &mut [u8]| os_random.read_exact(bytes).is_ok();
        generate_key_pair(2048, &mut generated, &mut random).unwrap();
        let mut public_der = [0u8; 300];
        let public_len = generated.encode_public_der(2048, &mut public_der).unwrap();
        let mut private_der = [0u8; 1200];
        let private_len = generated.encode_private_der(2048, &mut private_der).unwrap();
        assert_eq!(public_parts(&public_der[..public_len]),
            Some((&generated.modulus[..], &generated.public_exponent[..])));
        assert!(private_parts(&private_der[..private_len]).is_some());
        assert!(generated.dp.iter().any(|byte| *byte != 0));
        assert!(generated.dq.iter().any(|byte| *byte != 0));
        assert!(generated.q_inverse.iter().any(|byte| *byte != 0));
    }

    const HASH: [u8; 32] = [
        0x03,0x89,0x3d,0xcb,0x24,0x32,0x79,0x9e,0x20,0x64,0xcb,0xe9,0x0e,0x2c,0xd3,0x74,
        0xbd,0x8b,0x85,0x77,0xc7,0xf9,0x00,0x32,0x31,0xa7,0x6a,0xbc,0x64,0x60,0x1b,0x69,
    ];

    fn vector(bits: usize, private: &[u8], public: &[u8], expected: &[u8]) {
        let mut os_random = std::fs::File::open("/dev/urandom").unwrap();
        let mut random = |bytes: &mut [u8]| os_random.read_exact(bytes).is_ok();
        let mut signature = [0xa5; 256];
        sign_pkcs1v15_sha256_der(private, bits, &HASH, &mut signature[..bits / 8], &mut random)
            .unwrap();
        assert_eq!(&signature[..bits / 8], expected);
        assert_eq!(verify_pkcs1v15_sha256_der(public, bits, &HASH, expected), Ok(true));
        signature[0] ^= 1;
        assert_eq!(verify_pkcs1v15_sha256_der(public, bits, &HASH, &signature[..bits / 8]), Ok(false));
        signature.fill(0xa5);
        assert_eq!(sign_pkcs1v15_sha256_der(&private[..10], bits, &HASH,
            &mut signature[..bits / 8], &mut random), Err(Error::InvalidLength));
        assert!(signature[..bits / 8].iter().all(|byte| *byte == 0));
        assert_eq!(verify_pkcs1v15_sha256_der(&public[..10], bits, &HASH, expected),
            Err(Error::InvalidLength));
    }

    #[test]
    fn openssl_pkcs1_v15_sha256_1024_and_2048() {
        vector(1024, include_bytes!("../testdata/rsa/private1024.der"),
            include_bytes!("../testdata/rsa/public1024.der"),
            include_bytes!("../testdata/rsa/signature1024.bin"));
        vector(2048, include_bytes!("../testdata/rsa/private2048.der"),
            include_bytes!("../testdata/rsa/public2048.der"),
            include_bytes!("../testdata/rsa/signature2048.bin"));
    }
}
