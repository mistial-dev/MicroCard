//! Primitives from RustCrypto; SCP03 v1.1.2 §§4.1.4–4.1.5.
use crate::{Error, Result};
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use alloc::vec::Vec;
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn zeroizing_buffer(length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::Quota)?;
    output.resize(length, 0);
    Ok(output)
}

/// Apply the provider failure contract after an operation that may have
/// partially written caller-owned storage.
pub fn clear_output_on_error<T>(output: &mut [u8], result: Result<T>) -> Result<T> {
    if result.is_err() {
        output.zeroize();
    }
    result
}

/// Native cryptographic operations available to the portable runtime.
///
/// Board implementations override supported operations with hardware-backed
/// implementations. Default methods provide the native Rust fallback and keep
/// provider selection outside managed code.
pub trait CryptoProvider {
    /// Fixed-size provider outputs use caller-owned storage so hardware backends
    /// do not need a second bridge buffer. Callers initialize output to zero;
    /// errors must not expose a partial result and must leave it all-zero.
    /// The same rule applies to every variable-size output buffer below.
    fn sha256_into(&mut self, data: &[u8], output: &mut [u8; 32]) -> Result<()> {
        let value = sha256(data);
        *output = value;
        Ok(())
    }

    fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32]> {
        let mut output = [0; 32];
        self.sha256_into(data, &mut output)?;
        Ok(output)
    }

    fn hmac_sha256_into(
        &mut self,
        key: &[u8],
        data: &[u8],
        output: &mut [u8; 32],
    ) -> Result<()> {
        let value = Zeroizing::new(hmac(key, data));
        *output = *value;
        Ok(())
    }

    fn hmac_sha256(&mut self, key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
        let mut output = Zeroizing::new([0; 32]);
        self.hmac_sha256_into(key, data, &mut output)?;
        Ok(*output)
    }

    fn aes_cmac_into(
        &mut self,
        key: &[u8; 16],
        data: &[u8],
        output: &mut [u8; 16],
    ) -> Result<()> {
        self.aes_cmac_parts_into(key, &[data], output)
    }

    fn aes_cmac_parts_into(
        &mut self,
        key: &[u8; 16],
        parts: &[&[u8]],
        output: &mut [u8; 16],
    ) -> Result<()> {
        let value = Zeroizing::new(cmac_parts(key, parts));
        *output = *value;
        Ok(())
    }

    fn aes_cmac(&mut self, key: &[u8; 16], data: &[u8]) -> Result<[u8; 16]> {
        let mut output = Zeroizing::new([0; 16]);
        self.aes_cmac_parts_into(key, &[data], &mut output)?;
        Ok(*output)
    }

    fn aes128_encrypt_block_in_place(
        &mut self,
        key: &[u8; 16],
        block: &mut [u8; 16],
    ) -> Result<()> {
        let value = Zeroizing::new(crate::crypto::block(key, *block));
        *block = *value;
        Ok(())
    }

    fn aes128_encrypt_block(&mut self, key: &[u8; 16], mut block: [u8; 16]) -> Result<[u8; 16]> {
        let mut output = Zeroizing::new(block);
        block.zeroize();
        self.aes128_encrypt_block_in_place(key, &mut output)?;
        Ok(*output)
    }

    fn aes_cbc_encrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let result = encrypt_into(key, iv, data, output);
        clear_output_on_error(output, result)
    }

    fn aes_cbc_decrypt(
        &mut self,
        key: &[u8; 16],
        iv: [u8; 16],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let result = decrypt_into(key, iv, data, output);
        clear_output_on_error(output, result)
    }

    fn aes_ccm_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let result = ccm_encrypt_into(key, nonce, aad, plaintext, output);
        clear_output_on_error(output, result)
    }

    fn aes_ccm_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        let result = ccm_decrypt_into(key, nonce, aad, ciphertext, output);
        clear_output_on_error(output, result)
    }

    fn aes_ccm_decrypt_in_place(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize> {
        ccm_decrypt_in_place(key, nonce, aad, ciphertext)
    }

    fn p256_public_key_into(
        &mut self,
        private_key: &[u8; 32],
        output: &mut [u8; 65],
    ) -> Result<()> {
        output.fill(0);
        let value = p256_public_key(private_key)?;
        *output = value;
        Ok(())
    }

    fn p256_public_key(&mut self, private_key: &[u8; 32]) -> Result<[u8; 65]> {
        let mut output = [0; 65];
        self.p256_public_key_into(private_key, &mut output)?;
        Ok(output)
    }

    fn p256_ecdsa_sign_into(
        &mut self,
        private_key: &[u8; 32],
        message: &[u8],
        output: &mut [u8; 64],
    ) -> Result<()> {
        output.fill(0);
        let value = p256_ecdsa_sign(private_key, message)?;
        *output = value;
        Ok(())
    }

    fn p256_ecdsa_sign(&mut self, private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
        let mut output = [0; 64];
        self.p256_ecdsa_sign_into(private_key, message, &mut output)?;
        Ok(output)
    }

    fn p256_ecdsa_verify(
        &mut self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        Ok(p256_ecdsa_verify(public_key, message, signature))
    }

    fn p256_ecdh_into(
        &mut self,
        private_key: &[u8; 32],
        peer_public_key: &[u8],
        output: &mut [u8; 32],
    ) -> Result<()> {
        output.fill(0);
        let value = Zeroizing::new(p256_ecdh(private_key, peer_public_key)?);
        *output = *value;
        Ok(())
    }

    fn p256_ecdh(
        &mut self,
        private_key: &[u8; 32],
        peer_public_key: &[u8],
    ) -> Result<[u8; 32]> {
        let mut output = Zeroizing::new([0; 32]);
        self.p256_ecdh_into(private_key, peer_public_key, &mut output)?;
        Ok(*output)
    }
}

/// Portable native provider used by the simulator and as the board fallback.
#[derive(Default)]
pub struct SoftwareCrypto;

impl CryptoProvider for SoftwareCrypto {}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    cmac_parts(key, &[data])
}

pub fn cmac_parts(key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <Cmac<Aes128> as Mac>::new_from_slice(key).unwrap();
    for part in parts {
        m.update(part);
    }
    m.finalize().into_bytes().into()
}
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().into()
}
pub fn block(key: &[u8; 16], mut b: [u8; 16]) -> [u8; 16] {
    Aes128::new(key.into()).encrypt_block((&mut b).into());
    b
}
pub(crate) fn cbc_encrypted_len(input_len: usize) -> Result<usize> {
    input_len
        .checked_div(16)
        .and_then(|blocks| blocks.checked_add(1))
        .and_then(|blocks| blocks.checked_mul(16))
        .ok_or(Error::Bounds)
}

pub fn cbc_pad_into(data: &[u8], output: &mut [u8]) -> Result<usize> {
    let required = cbc_encrypted_len(data.len())?;
    if output.len() < required {
        return Err(Error::Bounds);
    }
    output[..data.len()].copy_from_slice(data);
    output[data.len()] = 0x80;
    output[data.len() + 1..required].fill(0);
    Ok(required)
}

pub fn cbc_unpad_in_place(output: &mut [u8]) -> Result<usize> {
    let index = output.iter().rposition(|value| *value != 0).ok_or_else(|| {
        output.zeroize();
        Error::Authentication
    })?;
    if output[index] != 0x80 {
        output.zeroize();
        return Err(Error::Authentication);
    }
    output[index..].zeroize();
    Ok(index)
}

pub fn encrypt_into(
    key: &[u8; 16],
    mut iv: [u8; 16],
    data: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let required = cbc_pad_into(data, output)?;
    let out = &mut output[..required];
    for chunk in out.chunks_exact_mut(16) {
        for i in 0..16 {
            chunk[i] ^= iv[i]
        }
        iv = block(key, chunk.try_into().unwrap());
        chunk.copy_from_slice(&iv);
    }
    Ok(required)
}

pub fn encrypt(key: &[u8; 16], mut iv: [u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let padded = data
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(15))
        .map(|length| length / 16 * 16)
        .ok_or(Error::Bounds)?;
    let mut out = zeroizing_buffer(padded)?;
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    for chunk in out.chunks_exact_mut(16) {
        for i in 0..16 {
            chunk[i] ^= iv[i];
        }
        iv = block(key, chunk.try_into().unwrap());
        chunk.copy_from_slice(&iv);
    }
    Ok(core::mem::take(&mut *out))
}

pub fn decrypt_into(
    key: &[u8; 16],
    mut iv: [u8; 16],
    data: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(Error::Authentication);
    }
    if output.len() < data.len() {
        return Err(Error::Bounds);
    }
    let c = Aes128::new(key.into());
    let out = &mut output[..data.len()];
    out.copy_from_slice(data);
    for chunk in out.chunks_exact_mut(16) {
        let next: [u8; 16] = chunk.try_into().unwrap();
        c.decrypt_block(chunk.into());
        for i in 0..16 {
            chunk[i] ^= iv[i]
        }
        iv = next;
    }
    cbc_unpad_in_place(out)
}

pub fn decrypt(key: &[u8; 16], iv: [u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = zeroizing_buffer(data.len())?;
    let length = decrypt_into(key, iv, data, &mut out)?;
    out.truncate(length);
    Ok(core::mem::take(&mut *out))
}
/// GP SCP03 §4.1.5, counter-mode CMAC KDF with one output block.
pub fn derive(key: &[u8; 16], constant: u8, bits: u16, context: &[u8]) -> [u8; 16] {
    let mut prefix = [0; 16];
    prefix[11] = constant;
    prefix[13..15].copy_from_slice(&bits.to_be_bytes());
    prefix[15] = 1;
    cmac_parts(key, &[&prefix, context])
}

/// AES-CCM, 13-byte nonce and 16-byte tag. Nonces must be unique per key.
pub fn ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let length = plaintext.len().checked_add(16).ok_or(Error::Bounds)?;
    let mut output = zeroizing_buffer(length)?;
    ccm_encrypt_into(key, nonce, aad, plaintext, &mut output)?;
    Ok(core::mem::take(&mut *output))
}

pub fn ccm_encrypt_into(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    use ccm::{
        aead::AeadInPlace,
        consts::{U13, U16},
    };
    let required = plaintext.len().checked_add(16).ok_or(Error::Bounds)?;
    if output.len() < required {
        return Err(Error::Bounds);
    }
    let c = ccm::Ccm::<Aes128, U16, U13>::new(key.into());
    output[..plaintext.len()].copy_from_slice(plaintext);
    let tag = match c.encrypt_in_place_detached(nonce.into(), aad, &mut output[..plaintext.len()]) {
        Ok(tag) => tag,
        Err(_) => {
            output[..required].zeroize();
            return Err(Error::Native);
        }
    };
    output[plaintext.len()..required].copy_from_slice(&tag);
    Ok(required)
}
pub fn ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let length = ciphertext
        .len()
        .checked_sub(16)
        .ok_or(Error::Authentication)?;
    let mut output = zeroizing_buffer(length)?;
    ccm_decrypt_into(key, nonce, aad, ciphertext, &mut output)?;
    Ok(core::mem::take(&mut *output))
}

pub fn ccm_decrypt_into(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    use ccm::{
        aead::{AeadInPlace, Tag},
        consts::{U13, U16},
    };
    type AesCcm = ccm::Ccm<Aes128, U16, U13>;
    let length = ciphertext
        .len()
        .checked_sub(16)
        .ok_or(Error::Authentication)?;
    if output.len() < length {
        return Err(Error::Bounds);
    }
    let c = AesCcm::new(key.into());
    let (message, tag) = ciphertext.split_at(length);
    output[..length].copy_from_slice(message);
    if c.decrypt_in_place_detached(
        nonce.into(),
        aad,
        &mut output[..length],
        Tag::<AesCcm>::from_slice(tag),
    )
    .is_err()
    {
        output[..length].zeroize();
        return Err(Error::Authentication);
    }
    Ok(length)
}

pub fn ccm_decrypt_in_place(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &mut [u8],
) -> Result<usize> {
    use ccm::{
        aead::{AeadInPlace, Tag},
        consts::{U13, U16},
    };
    type AesCcm = ccm::Ccm<Aes128, U16, U13>;
    let length = ciphertext
        .len()
        .checked_sub(16)
        .ok_or(Error::Authentication)?;
    let (message, tag) = ciphertext.split_at_mut(length);
    let c = AesCcm::new(key.into());
    if c.decrypt_in_place_detached(
        nonce.into(),
        aad,
        message,
        Tag::<AesCcm>::from_slice(tag),
    )
    .is_err()
    {
        message.zeroize();
        return Err(Error::Authentication);
    }
    Ok(length)
}

/// Uncompressed SEC1 public key bytes, which is the only encoding a signed package carries.
pub const P256_PUBLIC_KEY_BYTES: usize = 65;
/// Fixed-width IEEE P1363 signature bytes.
pub const P256_SIGNATURE_BYTES: usize = 64;

/// Half the P-256 group order, as 32 big-endian bytes.
///
/// A signature with `s` above this is the malleable twin of one below it. Comparing bytes
/// rather than parsing a scalar keeps this check identical on a card that has no software
/// P-256 implementation linked at all.
const P256_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The identity a domain binds to, which is the digest of the signer's key.
///
/// A package carries the whole uncompressed key so verification needs no point
/// decompression. What persists is this digest, which keeps every stored identity the width
/// it has always been.
pub fn signer_identity(public_key: &[u8; P256_PUBLIC_KEY_BYTES]) -> [u8; 32] {
    sha256(public_key)
}

/// The P-256 group order, as 32 big-endian bytes.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Sign for a package, choosing the low form of the two signatures that verify.
///
/// The signer does not pick a form on its own, and measurement puts roughly half of its
/// output in the high one. A card that accepted both would let one signed package have two
/// encodings with two digests, and a registry identity is derived from that digest, so the
/// same package could be installed twice under different names. Every packager has to agree
/// on this, in every language.
pub fn p256_ecdsa_sign_package(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    let mut signature = p256_ecdsa_sign(private_key, message)?;
    if signature[32..] > P256_HALF_ORDER[..] {
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let difference =
                i16::from(P256_ORDER[index]) - i16::from(signature[32 + index]) - borrow;
            signature[32 + index] = difference.rem_euclid(256) as u8;
            borrow = i16::from(difference < 0);
        }
    }
    Ok(signature)
}

/// Whether a key and signature are in the exact shape a signed package may carry.
///
/// Two things this pins that a plain verify would let through. The software verifier accepts
/// compressed SEC1 and the CryptoCell one refuses it, so a compressed key would verify on the
/// simulator and be rejected by the board. And ECDSA admits two signatures for every message,
/// so an untouched package can be handed back with a different signature that still verifies.
/// Its digest would differ, which is what dependency digest pinning and the rollback check
/// compare. Requiring the low form removes that.
pub fn p256_signature_acceptable(public_key: &[u8], signature: &[u8]) -> bool {
    public_key.len() == P256_PUBLIC_KEY_BYTES
        && public_key[0] == 0x04
        && signature.len() == P256_SIGNATURE_BYTES
        && signature[32..] <= P256_HALF_ORDER[..]
        && signature[..32].iter().any(|byte| *byte != 0)
        && signature[32..].iter().any(|byte| *byte != 0)
}

/// Validate a P-256 private scalar before dispatching to a hardware provider.
pub fn p256_private_key_valid(private_key: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    // Subtract the order across every byte. A final borrow means the scalar is smaller.
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let difference = u16::from(private_key[index])
            .wrapping_sub(u16::from(P256_ORDER[index]) + borrow);
        borrow = difference >> 15;
    }
    bool::from(!private_key.ct_eq(&[0; 32]) & (borrow as u8).ct_eq(&1))
}

/// Return an uncompressed SEC1 public key without exposing the private scalar.
pub fn p256_public_key(private_key: &[u8; 32]) -> Result<[u8; 65]> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::from_slice(private_key).map_err(|_| Error::Storage)?;
    secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Native)
}

/// Produce a fixed-width IEEE P1363 ECDSA/SHA-256 signature.
pub fn p256_ecdsa_sign(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64]> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let signing_key = SigningKey::from_slice(private_key).map_err(|_| Error::Storage)?;
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().into())
}

/// Verify an uncompressed or compressed SEC1 key and fixed-width signature.
pub fn p256_ecdsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    VerifyingKey::from_sec1_bytes(public_key)
        .ok()
        .zip(Signature::from_slice(signature).ok())
        .is_some_and(|(key, signature)| key.verify(message, &signature).is_ok())
}

/// Derive the raw 32-byte P-256 ECDH shared secret.
pub fn p256_ecdh(private_key: &[u8; 32], peer_public_key: &[u8]) -> Result<[u8; 32]> {
    let secret = p256::SecretKey::from_slice(private_key).map_err(|_| Error::Storage)?;
    let peer = p256::PublicKey::from_sec1_bytes(peer_public_key)
        .map_err(|_| Error::Authentication)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut output = [0; 32];
    output.copy_from_slice(shared.raw_secret_bytes());
    Ok(output)
}

#[cfg(test)]
mod p256_tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |value| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("hex fixture"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn standards_known_answers_cover_native_symmetric_primitives() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        let message = hex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );

        // FIPS 180-4 SHA-256 example and RFC 4231 section 4.2.
        assert_eq!(
            sha256(b"abc").as_slice(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            hmac(&[0x0b; 20], b"Hi There").as_slice(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );

        // RFC 4493 section 4 covers empty, complete and partial final blocks.
        for (length, expected) in [
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(cmac(&key, &message[..length]).as_slice(), hex(expected));
        }
        assert_eq!(
            cmac_parts(&key, &[&message[..16], &message[16..40]]).as_slice(),
            hex("dfa66747de9ae63030ca32611497c827")
        );

        // NIST SP 800-38A appendices F.1 and F.2, first AES-128 block.
        let plaintext: [u8; 16] = message[..16].try_into().unwrap();
        assert_eq!(
            block(&key, plaintext).as_slice(),
            hex("3ad77bb40d7a3660a89ecaf32466ef97")
        );
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let mut ciphertext = [0; 32];
        let encrypted = encrypt_into(&key, iv, &plaintext, &mut ciphertext).unwrap();
        assert_eq!(encrypted, 32);
        assert_eq!(encrypt(&key, iv, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            &ciphertext[..16],
            hex("7649abac8119b246cee98e9b12e9197d")
        );
        let mut recovered = [0; 32];
        let recovered_length =
            decrypt_into(&key, iv, &ciphertext[..encrypted], &mut recovered).unwrap();
        assert_eq!(&recovered[..recovered_length], plaintext);

        // NIST CAVP CCM-VADT AES-128, Alen=0, Count=0.
        let ccm_key: [u8; 16] = hex("d24a3d3dde8c84830280cb87abad0bb3")
            .try_into()
            .unwrap();
        let nonce: [u8; 13] = hex("f1100035bb24a8d26004e0e24b")
            .try_into()
            .unwrap();
        let payload = hex("7c86135ed9c2a515aaae0e9a208133897269220f30870006");
        let expected = hex(
            "1faeb0ee2ca2cd52f0aa3966578344f24e69b742c4ab37ab\
             1123301219c70599b7c373ad4b3ad67b",
        );
        let encrypted = ccm_encrypt(&ccm_key, &nonce, &[], &payload).unwrap();
        assert_eq!(encrypted, expected);
        assert_eq!(ccm_decrypt(&ccm_key, &nonce, &[], &encrypted).unwrap(), payload);
    }

    #[test]
    fn provider_failure_clears_complete_caller_output() {
        let mut output = [0xa5; 17];
        assert_eq!(
            clear_output_on_error::<()>(&mut output, Err(Error::Native)),
            Err(Error::Native)
        );
        assert_eq!(output, [0; 17]);

        output.fill(0x5a);
        assert_eq!(clear_output_on_error(&mut output, Ok(7)), Ok(7));
        assert_eq!(output, [0x5a; 17]);
    }

    #[test]
    fn fixed_outputs_dispatch_through_caller_owned_buffers() {
        let key = [0x11; 16];
        assert_eq!(
            cmac_parts(&key, &[b"split ", b"message"]),
            cmac(&key, b"split message")
        );
        struct DirectProvider {
            calls: usize,
        }
        impl CryptoProvider for DirectProvider {
            fn sha256_into(&mut self, _: &[u8], output: &mut [u8; 32]) -> Result<()> {
                self.calls += 1;
                output.fill(1);
                Ok(())
            }
            fn hmac_sha256_into(
                &mut self,
                _: &[u8],
                _: &[u8],
                output: &mut [u8; 32],
            ) -> Result<()> {
                self.calls += 1;
                output.fill(2);
                Ok(())
            }
            fn aes_cmac_parts_into(
                &mut self,
                _: &[u8; 16],
                _: &[&[u8]],
                output: &mut [u8; 16],
            ) -> Result<()> {
                self.calls += 1;
                output.fill(3);
                Ok(())
            }
            fn aes128_encrypt_block_in_place(
                &mut self,
                _: &[u8; 16],
                block: &mut [u8; 16],
            ) -> Result<()> {
                self.calls += 1;
                block.fill(7);
                Ok(())
            }
            fn p256_public_key_into(
                &mut self,
                _: &[u8; 32],
                output: &mut [u8; 65],
            ) -> Result<()> {
                self.calls += 1;
                output.fill(4);
                Ok(())
            }
            fn p256_ecdsa_sign_into(
                &mut self,
                _: &[u8; 32],
                _: &[u8],
                output: &mut [u8; 64],
            ) -> Result<()> {
                self.calls += 1;
                output.fill(5);
                Ok(())
            }
            fn p256_ecdh_into(
                &mut self,
                _: &[u8; 32],
                _: &[u8],
                output: &mut [u8; 32],
            ) -> Result<()> {
                self.calls += 1;
                output.fill(6);
                Ok(())
            }
        }

        let mut provider = DirectProvider { calls: 0 };
        assert_eq!(provider.sha256(b"input").unwrap(), [1; 32]);
        assert_eq!(provider.hmac_sha256(b"key", b"input").unwrap(), [2; 32]);
        assert_eq!(provider.aes_cmac(&[0; 16], b"input").unwrap(), [3; 16]);
        assert_eq!(provider.aes128_encrypt_block(&[0; 16], [0; 16]).unwrap(), [7; 16]);
        assert_eq!(provider.p256_public_key(&[1; 32]).unwrap(), [4; 65]);
        assert_eq!(provider.p256_ecdsa_sign(&[1; 32], b"input").unwrap(), [5; 64]);
        assert_eq!(provider.p256_ecdh(&[1; 32], &[2; 65]).unwrap(), [6; 32]);
        assert_eq!(provider.calls, 7);
    }

    #[test]
    fn ccm_decryption_reuses_and_clears_the_input_buffer() {
        let key = [0x11; 16];
        let nonce = [0x22; 13];
        let plaintext = b"authenticated journal state";
        let ciphertext = ccm_encrypt(&key, &nonce, b"header", plaintext).unwrap();
        let mut recovered = ciphertext.clone();
        let buffer = recovered.as_ptr();

        let written = ccm_decrypt_in_place(&key, &nonce, b"header", &mut recovered).unwrap();

        assert_eq!(&recovered[..written], plaintext);
        assert_eq!(recovered.as_ptr(), buffer);

        let mut tampered = ciphertext;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            ccm_decrypt_in_place(&key, &nonce, b"header", &mut tampered),
            Err(Error::Authentication)
        );
        assert!(tampered[..plaintext.len()].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rfc6979_p256_signature_and_ecdh() {
        let private: [u8; 32] = hex(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        )
        .try_into()
        .unwrap();
        assert!(p256_private_key_valid(&private));
        assert!(!p256_private_key_valid(&[0; 32]));
        assert!(!p256_private_key_valid(&[0xff; 32]));
        let expected = hex(concat!(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        ));
        let signature = p256_ecdsa_sign(&private, b"sample").unwrap();
        assert_eq!(signature, expected.as_slice());
        let public = p256_public_key(&private).unwrap();
        assert!(p256_ecdsa_verify(&public, b"sample", &signature));
        assert!(!p256_ecdsa_verify(&public, b"changed", &signature));
        assert!(!p256_ecdsa_verify(&[0; 65], b"sample", &signature));

        let peer_private = [2; 32];
        let peer_public = p256_public_key(&peer_private).unwrap();
        assert_eq!(
            p256_ecdh(&private, &peer_public).unwrap(),
            p256_ecdh(&peer_private, &public).unwrap()
        );
        assert_eq!(p256_ecdh(&private, &[0; 65]), Err(Error::Authentication));
        assert_eq!(p256_public_key(&[0; 32]), Err(Error::Storage));
    }
}

#[cfg(test)]
mod signature_shape_tests {
    use super::*;

    #[test]
    fn scalar_order_boundaries_match_the_reference_parser() {
        let mut below = P256_ORDER;
        below[31] -= 1;
        let mut above = P256_ORDER;
        above[31] += 1;
        let mut one = [0; 32];
        one[31] = 1;
        for (value, expected) in [
            ([0; 32], false), (one, true), (below, true),
            (P256_ORDER, false), (above, false), ([0xff; 32], false),
        ] {
            assert_eq!(p256_private_key_valid(&value), expected);
            assert_eq!(p256_private_key_valid(&value), p256::SecretKey::from_slice(&value).is_ok());
        }
        for index in 0..32 {
            for byte in 0..=255 {
                let mut value = P256_ORDER;
                value[index] = byte;
                assert_eq!(p256_private_key_valid(&value), p256::SecretKey::from_slice(&value).is_ok());
            }
        }
    }

    fn sign(seed: u8, message: &[u8]) -> ([u8; 65], [u8; 64]) {
        let private = [seed; 32];
        (
            p256_public_key(&private).unwrap(),
            p256_ecdsa_sign(&private, message).unwrap(),
        )
    }

    #[test]
    fn only_an_uncompressed_key_and_a_low_signature_are_accepted() {
        let (key, signature) = sign(0x31, b"package");
        assert!(p256_signature_acceptable(&key, &signature));
        assert!(p256_ecdsa_verify(&key, b"package", &signature));

        // A compressed SEC1 key. The software verifier accepts one and the card's hardware
        // refuses it, so a package may only ever carry the uncompressed form.
        let mut compressed = [0; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&key[1..33]);
        assert!(!p256_signature_acceptable(&compressed, &signature));

        // The right length with the wrong leading byte.
        let mut mislabelled = key;
        mislabelled[0] = 0x03;
        assert!(!p256_signature_acceptable(&mislabelled, &signature));

        // Wrong widths on either half.
        assert!(!p256_signature_acceptable(&key[..64], &signature));
        assert!(!p256_signature_acceptable(&key, &signature[..63]));
    }

    #[test]
    fn the_malleable_twin_of_a_signature_is_refused() {
        let (key, signature) = sign(0x5a, b"package");
        assert!(p256_signature_acceptable(&key, &signature));

        // s' = n - s verifies just as well as s, so accepting both would let an untouched
        // package come back with a different digest.
        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut borrow = 0i16;
        let mut high = signature;
        for index in (0..32).rev() {
            let difference = order[index] as i16 - signature[32 + index] as i16 - borrow;
            high[32 + index] = difference.rem_euclid(256) as u8;
            borrow = i16::from(difference < 0);
        }
        // The twin still verifies, which is exactly why the shape check has to reject it.
        assert!(p256_ecdsa_verify(&key, b"package", &high));
        assert!(!p256_signature_acceptable(&key, &high));
    }

    #[test]
    fn a_zero_half_is_refused() {
        let (key, signature) = sign(0x77, b"package");
        let mut zero_r = signature;
        zero_r[..32].fill(0);
        assert!(!p256_signature_acceptable(&key, &zero_r));
        let mut zero_s = signature;
        zero_s[32..].fill(0);
        assert!(!p256_signature_acceptable(&key, &zero_s));
    }
}
