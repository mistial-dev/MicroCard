//! Signed Java Card load files. Authorization against domain state remains a caller duty.
use crate::{
    cbor::{Decoder, Encoder},
    crypto::CryptoProvider,
    envelope::Envelope,
    Error, Result,
};
use alloc::vec::Vec;
use microcard_engine_jcvm::{applet::Sizes, cap::LoadFile, link::Linked, verify};

pub const MAX_PACKAGE_BYTES: usize = 60 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 128;
// OpenFIPS201 validates peer EC points in bytecode before provider ECDH.
pub const MAX_EXECUTION_WORK: u32 = 4_000_000;

#[derive(Clone, Debug)]
pub struct Manifest<'a> {
    pub domain: &'a [u8],
    pub incarnation: [u8; 16],
    pub package: &'a [u8],
    pub package_version: [u8; 2],
    pub version: u32,
    pub sizes: Sizes,
}

impl<'a> Manifest<'a> {
    fn validate(&self) -> Result<()> {
        if !(5..=16).contains(&self.domain.len())
            || !(5..=16).contains(&self.package.len())
            || self.version == 0
        {
            return Err(Error::Format);
        }
        if !(512..=65536).contains(&self.sizes.heap_bytes)
            || !self.sizes.heap_bytes.is_multiple_of(2)
            || !(8..=8192).contains(&self.sizes.frame_words)
            || self.sizes.buffer_bytes != 261
            || !(1..=MAX_EXECUTION_WORK).contains(&self.sizes.budget)
        {
            return Err(Error::Quota);
        }
        Ok(())
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Format);
        }
        let mut decoder = Decoder::new(bytes);
        decoder.record(8)?;
        if decoder.unsigned()? != 1 || decoder.unsigned()? != 1 {
            return Err(Error::Unsupported);
        }
        let domain = decoder.bytes(16)?;
        let incarnation = decoder.fixed()?;
        let package = decoder.bytes(16)?;
        decoder.record(2)?;
        let package_version = [decoder.number()?, decoder.number()?];
        let version = decoder.number()?;
        decoder.record(4)?;
        let sizes = Sizes {
            heap_bytes: decoder.number()?,
            frame_words: decoder.number()?,
            buffer_bytes: decoder.number()?,
            budget: decoder.number()?,
        };
        decoder.finish()?;
        let manifest = Self {
            domain,
            incarnation,
            package,
            package_version,
            version,
            sizes,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = Encoder::new(MAX_MANIFEST_BYTES);
        encoder.array(8)?;
        encoder.unsigned(1)?;
        encoder.unsigned(1)?;
        encoder.bytes(self.domain)?;
        encoder.bytes(&self.incarnation)?;
        encoder.bytes(self.package)?;
        encoder.array(2)?;
        for value in self.package_version {
            encoder.unsigned(u64::from(value))?;
        }
        encoder.unsigned(u64::from(self.version))?;
        encoder.array(4)?;
        for value in [
            self.sizes.heap_bytes as u64,
            self.sizes.frame_words as u64,
            u64::from(self.sizes.buffer_bytes),
            u64::from(self.sizes.budget),
        ] {
            encoder.unsigned(value)?;
        }
        Ok(encoder.finish())
    }
}

pub struct Package<'a> {
    pub envelope: Envelope<'a>,
    pub manifest: Manifest<'a>,
    pub report: verify::Report,
}

impl<'a> Package<'a> {
    /// Verify signature, exact CAP identity, imports, and bytecode before activation.
    /// Caller-owned scratch bounds the verifier's instruction map.
    pub fn verify(
        raw: &'a [u8],
        provider: &mut impl CryptoProvider,
        scratch: &mut [u8],
    ) -> Result<Self> {
        let envelope = Envelope::verify_bounded(raw, MAX_PACKAGE_BYTES, provider)?;
        let manifest = Manifest::decode(envelope.manifest)?;
        let file = LoadFile::parse(envelope.image).map_err(engine_error)?;
        let header = file.header().map_err(engine_error)?;
        if header.package_aid != manifest.package
            || [header.package_major, header.package_minor] != manifest.package_version
        {
            return Err(Error::Format);
        }
        Linked::new(&file)
            .and_then(|linked| linked.imports_resolve())
            .map_err(engine_error)?;
        let report = verify::verify(&file, scratch).map_err(engine_error)?;
        if usize::from(report.max_frame_words) > manifest.sizes.frame_words {
            return Err(Error::Quota);
        }
        Ok(Self {
            envelope,
            manifest,
            report,
        })
    }
}

fn engine_error(error: microcard_engine_jcvm::Error) -> Error {
    match error {
        microcard_engine_jcvm::Error::Unsupported => Error::Unsupported,
        microcard_engine_jcvm::Error::Quota => Error::Quota,
        _ => Error::Format,
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::{
        crypto::{self, SoftwareCrypto},
        envelope,
    };

    #[test]
    fn golden_manifest_and_signed_cap_require_the_declared_identity_and_profile() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../format/jcvm-manifest-cbor-v1.json"))
                .unwrap();
        let hex = vector["hex"].as_str().unwrap();
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let manifest = Manifest::decode(&bytes).unwrap();
        assert_eq!(manifest.domain, &[0xa0, 0, 0, 1, 0x51, 0, 0, 0]);
        assert_eq!(manifest.package_version, [1, 10]);
        assert_eq!(manifest.sizes.heap_bytes, 65536);
        assert_eq!(manifest.encode().unwrap(), bytes);
        for cut in 0..bytes.len() {
            assert!(Manifest::decode(&bytes[..cut]).is_err());
        }
        for (offset, value) in [(0, 0x89), (1, 2), (2, 0)] {
            let mut invalid = bytes.clone();
            invalid[offset] = value;
            assert!(Manifest::decode(&invalid).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
        for budget in [1, MAX_EXECUTION_WORK] {
            let mut bounded = manifest.clone();
            bounded.sizes.budget = budget;
            assert_eq!(Manifest::decode(&bounded.encode().unwrap()).unwrap().sizes.budget, budget);
        }
        for budget in [0, MAX_EXECUTION_WORK + 1] {
            let mut invalid = manifest.clone();
            invalid.sizes.budget = budget;
            assert_eq!(invalid.encode(), Err(Error::Quota));
        }
        let mut oversized = manifest.clone();
        oversized.sizes.heap_bytes += 1;
        assert_eq!(oversized.encode(), Err(Error::Quota));

        let image = include_bytes!(
            "../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let file = LoadFile::parse(image).unwrap();
        let header = file.header().unwrap();
        let mut actual = Manifest {
            package: header.package_aid,
            package_version: [header.package_major, header.package_minor],
            ..manifest
        };
        let key = crypto::p256_public_key(&[7; 32]).unwrap();
        let sign = |manifest: &Manifest| {
            let mut raw = envelope::signing_prefix_bounded(
                &manifest.encode().unwrap(),
                image.len(),
                &crypto::sha256(image),
                &key,
                MAX_PACKAGE_BYTES,
            )
            .unwrap();
            raw.extend(crypto::p256_ecdsa_sign_package(&[7; 32], &raw).unwrap());
            raw.extend(image);
            raw
        };
        let raw = sign(&actual);
        let mut scratch = alloc::vec![0; 16384];
        let verified = Package::verify(&raw, &mut SoftwareCrypto, &mut scratch).unwrap();
        assert_eq!(verified.envelope.image, image);
        assert!(verified.report.methods > 0);
        assert!(
            Envelope::verify(&raw, &mut SoftwareCrypto).is_err(),
            "MC04 keeps its smaller bound"
        );
        actual.package_version[1] = actual.package_version[1].wrapping_add(1);
        assert!(matches!(
            Package::verify(&sign(&actual), &mut SoftwareCrypto, &mut scratch),
            Err(Error::Format)
        ));
        actual.package_version = [header.package_major, header.package_minor];
        actual.package = &[0xa0; 5];
        assert!(matches!(
            Package::verify(&sign(&actual), &mut SoftwareCrypto, &mut scratch),
            Err(Error::Format)
        ));
    }
}
