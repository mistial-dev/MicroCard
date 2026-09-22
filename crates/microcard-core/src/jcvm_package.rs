//! A verified Java Card Load File Data Block. SCP03 authorizes loading; the
//! CAP verifier and authenticated registry authorize execution.
use crate::{crypto::CryptoProvider, Error, Result};
use microcard_engine_jcvm::{applet::Sizes, cap::LoadFile, link::Linked, verify};

pub const MAX_PACKAGE_BYTES: usize = 60 * 1024;
// OpenFIPS201 validates peer EC points in bytecode before provider ECDH.
pub const MAX_EXECUTION_WORK: u32 = 4_000_000;

#[derive(Clone, Debug)]
pub struct Manifest<'a> {
    pub domain: &'a [u8],
    pub incarnation: [u8; 16],
    pub package: &'a [u8],
    pub package_version: [u8; 2],
    /// Monotonic replacement version derived from the CAP header.
    pub version: u32,
    pub sizes: Sizes,
}

pub struct Package<'a> {
    pub image: &'a [u8],
    pub digest: [u8; 32],
    pub manifest: Manifest<'a>,
    pub report: verify::Report,
}

impl<'a> Package<'a> {
    /// Verify a raw LFDB before activation. Domain and quotas come from the
    /// authenticated management context, never from applet-controlled bytes.
    pub fn verify(
        raw: &'a [u8],
        domain: &'a [u8],
        incarnation: [u8; 16],
        provider: &mut impl CryptoProvider,
        scratch: &mut [u8],
    ) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_PACKAGE_BYTES {
            return Err(Error::Quota);
        }
        if !(5..=16).contains(&domain.len()) {
            return Err(Error::Format);
        }
        let file = LoadFile::parse(raw).map_err(engine_error)?;
        let header = file.header().map_err(engine_error)?;
        Linked::new(&file)
            .and_then(|linked| linked.imports_resolve())
            .map_err(engine_error)?;
        let report = verify::verify(&file, scratch).map_err(engine_error)?;
        // These are board-profile maxima. GP may later grant smaller per-load
        // quotas, but an unsigned CAP cannot raise them.
        let sizes = Sizes {
            heap_bytes: 65536,
            frame_words: 8192,
            buffer_bytes: 261,
            budget: MAX_EXECUTION_WORK,
        };
        if usize::from(report.max_frame_words) > sizes.frame_words {
            return Err(Error::Quota);
        }
        let manifest = Manifest {
            domain,
            incarnation,
            package: header.package_aid,
            package_version: [header.package_major, header.package_minor],
            version: ((u32::from(header.package_major) << 8)
                | u32::from(header.package_minor)) + 1,
            sizes,
        };
        Ok(Self {
            image: raw,
            digest: provider.sha256(raw)?,
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
    use crate::crypto::SoftwareCrypto;

    #[test]
    fn raw_cap_identity_and_digest_come_from_verified_bytes() {
        let image = include_bytes!(
            "../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let domain = &crate::globalplatform::ISD_AID;
        let mut scratch = [0; 16384];
        let package = Package::verify(image, domain, [1; 16], &mut SoftwareCrypto, &mut scratch)
            .unwrap();
        let header = LoadFile::parse(image).unwrap().header().unwrap();
        assert_eq!(package.image, image);
        assert_eq!(package.digest, crate::crypto::sha256(image));
        assert_eq!(package.manifest.package, header.package_aid);
        assert_eq!(package.manifest.package_version,
            [header.package_major, header.package_minor]);
        assert!(Package::verify(&image[..image.len() - 1], domain, [1; 16],
            &mut SoftwareCrypto, &mut scratch).is_err());
        assert!(Package::verify(b"MP05", domain, [1; 16],
            &mut SoftwareCrypto, &mut scratch).is_err());
    }
}
