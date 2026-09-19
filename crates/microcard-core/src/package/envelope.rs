//! Engine-independent MP05 signed envelope. The image follows the signed descriptor.
use crate::{crypto::CryptoProvider, Error, Result};
use alloc::vec::Vec;

pub const MAGIC: &[u8; 4] = b"MP05";
pub const CONTEXT: &[u8] = b"MicroCard signed package v5\0";
pub const HEADER_BYTES: usize = 12 + CONTEXT.len();
pub const DIGEST_BYTES: usize = 32;
pub const KEY_BYTES: usize = crate::crypto::P256_PUBLIC_KEY_BYTES;
pub const SIGNATURE_BYTES: usize = crate::crypto::P256_SIGNATURE_BYTES;
pub const OVERHEAD_BYTES: usize = HEADER_BYTES + DIGEST_BYTES + KEY_BYTES + SIGNATURE_BYTES;

/// Borrowed authenticated bytes. Engine-specific manifest and image validation is still required.
#[derive(Debug)]
pub struct Envelope<'a> {
    pub manifest: &'a [u8],
    pub image: &'a [u8],
    pub key: [u8; KEY_BYTES],
    pub signer: [u8; DIGEST_BYTES],
    pub image_digest: [u8; DIGEST_BYTES],
    pub package_digest: [u8; DIGEST_BYTES],
}

impl<'a> Envelope<'a> {
    pub fn verify(raw: &'a [u8], provider: &mut impl CryptoProvider) -> Result<Self> {
        if raw.len() < OVERHEAD_BYTES
            || raw.len() > super::MAX_PACKAGE_BYTES
            || &raw[..4] != MAGIC
            || &raw[4..4 + CONTEXT.len()] != CONTEXT
        {
            return Err(Error::Format);
        }
        let lengths = 4 + CONTEXT.len();
        let manifest_length =
            u32::from_le_bytes(raw[lengths..lengths + 4].try_into().unwrap()) as usize;
        let image_length =
            u32::from_le_bytes(raw[lengths + 4..HEADER_BYTES].try_into().unwrap()) as usize;
        let manifest_end = HEADER_BYTES
            .checked_add(manifest_length)
            .ok_or(Error::Format)?;
        let image_start = OVERHEAD_BYTES
            .checked_add(manifest_length)
            .ok_or(Error::Format)?;
        if image_start.checked_add(image_length) != Some(raw.len()) {
            return Err(Error::Format);
        }
        let key_start = manifest_end + DIGEST_BYTES;
        let signature_start = key_start + KEY_BYTES;
        let image_digest: [u8; DIGEST_BYTES] = raw[manifest_end..key_start].try_into().unwrap();
        let key: [u8; KEY_BYTES] = raw[key_start..signature_start].try_into().unwrap();
        let signature = &raw[signature_start..image_start];
        if !crate::crypto::p256_signature_acceptable(&key, signature) {
            return Err(Error::Signature);
        }
        if !provider.p256_ecdsa_verify(&key, &raw[..signature_start], signature)? {
            return Err(Error::Signature);
        }
        let image = &raw[image_start..];
        if provider.sha256(image)? != image_digest {
            return Err(Error::Signature);
        }
        let signer = provider.sha256(&key)?;
        let package_digest = provider.sha256(raw)?;
        Ok(Self {
            manifest: &raw[HEADER_BYTES..manifest_end],
            image,
            key,
            signer,
            image_digest,
            package_digest,
        })
    }
}

/// Construct exactly the contiguous bytes covered by the signature. Callers append the
/// 64-byte signature followed by the image whose length and digest are recorded here.
pub fn signing_prefix(
    manifest: &[u8],
    image_length: usize,
    image_digest: &[u8; 32],
    key: &[u8; KEY_BYTES],
) -> Result<Vec<u8>> {
    let total = OVERHEAD_BYTES
        .checked_add(manifest.len())
        .and_then(|n| n.checked_add(image_length))
        .ok_or(Error::Quota)?;
    if total > super::MAX_PACKAGE_BYTES {
        return Err(Error::Quota);
    }
    if key[0] != 4 {
        return Err(Error::Signature);
    }
    let capacity = HEADER_BYTES + manifest.len() + DIGEST_BYTES + KEY_BYTES;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Quota)?;
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(CONTEXT);
    output.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    output.extend_from_slice(&(image_length as u32).to_le_bytes());
    output.extend_from_slice(manifest);
    output.extend_from_slice(image_digest);
    output.extend_from_slice(key);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, SoftwareCrypto};

    fn signed() -> Vec<u8> {
        let manifest = b"\x81\x01";
        let image = b"MC04 image for envelope tests";
        let private = [7; 32];
        let key = crypto::p256_public_key(&private).unwrap();
        let mut prefix =
            signing_prefix(manifest, image.len(), &crypto::sha256(image), &key).unwrap();
        let signature = crypto::p256_ecdsa_sign_package(&private, &prefix).unwrap();
        prefix.extend_from_slice(&signature);
        prefix.extend_from_slice(image);
        prefix
    }

    #[test]
    fn independent_python_vector_matches_rust_signing_and_verification() {
        let vector: serde_json::Value = serde_json::from_str(include_str!("../../../../format/package-envelope-v5.json")).unwrap();
        let field = |name: &str| -> Vec<u8> {
            let text = vector[name].as_str().unwrap();
            (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i+2], 16).unwrap()).collect()
        };
        let raw = field("package");
        let envelope = Envelope::verify(&raw, &mut SoftwareCrypto).unwrap();
        assert_eq!(envelope.manifest, field("manifest"));
        assert_eq!(envelope.image, field("image"));
        let key: [u8; KEY_BYTES] = field("key").try_into().unwrap();
        let seed: [u8; 32] = field("seed").try_into().unwrap();
        let mut expected = signing_prefix(envelope.manifest, envelope.image.len(), &crypto::sha256(envelope.image), &key).unwrap();
        let signature = crypto::p256_ecdsa_sign_package(&seed, &expected).unwrap();
        expected.extend(signature); expected.extend(envelope.image);
        assert_eq!(raw, expected);
    }

    #[test]
    fn descriptor_signature_covers_every_byte_and_image_digest() {
        let raw = signed();
        let envelope = Envelope::verify(&raw, &mut SoftwareCrypto).unwrap();
        assert_eq!(envelope.manifest, b"\x81\x01");
        assert_eq!(envelope.image, b"MC04 image for envelope tests");
        assert_eq!(envelope.manifest.as_ptr(), raw[HEADER_BYTES..].as_ptr());
        assert_eq!(envelope.image.as_ptr(), raw[OVERHEAD_BYTES + 2..].as_ptr());
        for index in 0..raw.len() {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert!(
                Envelope::verify(&changed, &mut SoftwareCrypto).is_err(),
                "{index}"
            );
        }
        for end in 0..raw.len() {
            assert!(Envelope::verify(&raw[..end], &mut SoftwareCrypto).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(matches!(
            Envelope::verify(&trailing, &mut SoftwareCrypto),
            Err(Error::Format)
        ));
        let mut old = raw;
        old[..4].copy_from_slice(b"MP04");
        assert!(matches!(
            Envelope::verify(&old, &mut SoftwareCrypto),
            Err(Error::Format)
        ));
    }

    #[test]
    fn provider_failure_is_not_retried_and_malformed_lengths_are_bounded() {
        struct Failed;
        impl CryptoProvider for Failed {
            fn p256_ecdsa_verify(&mut self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
                Err(Error::Native)
            }
        }
        assert!(matches!(
            Envelope::verify(&signed(), &mut Failed),
            Err(Error::Native)
        ));
        let mut raw = signed();
        raw[HEADER_BYTES - 8..HEADER_BYTES - 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Envelope::verify(&raw, &mut Failed),
            Err(Error::Format)
        ));
        assert_eq!(
            signing_prefix(&[], usize::MAX, &[0; 32], &[4; KEY_BYTES]),
            Err(Error::Quota)
        );
        assert_eq!(
            signing_prefix(
                &[],
                super::super::MAX_PACKAGE_BYTES,
                &[0; 32],
                &[4; KEY_BYTES]
            ),
            Err(Error::Quota)
        );
    }
}
