mod manifest_cbor;
use crate::{Error, Result, crypto::CryptoProvider};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
pub const CONTEXT: &[u8] = b"MicroCard signed package v4\0";
pub const HEADER_BYTES: usize = 12 + CONTEXT.len();
/// The uncompressed SEC1 signer key and the P1363 signature that follow the image.
pub const SUFFIX_BYTES: usize = crate::crypto::P256_PUBLIC_KEY_BYTES + crate::crypto::P256_SIGNATURE_BYTES;
pub const MAX_PACKAGE_BYTES: usize = 16 * 1024;
pub const MAX_STORAGE_DECLARATIONS: usize = 64;
pub const MAX_DECLARED_BLOB_BYTES: u16 = 2048;

pub(crate) fn valid_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssemblyEntry {
    pub aid: String,
    pub process: u16,
    pub install: Option<u16>,
    pub uninstall: Option<u16>,
    pub select: Option<u16>,
    pub deselect: Option<u16>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub domain: String,
    pub incarnation: [u8; 16],
    pub assembly: String,
    pub assembly_version: [u16; 4],
    pub version: u32,
    pub export: DependencyExport,
    pub entry_points: Vec<AssemblyEntry>,
    pub dependencies: Vec<Dependency>,
    pub capabilities: Vec<u8>,
    pub storage: Vec<StorageDeclaration>,
    pub limits: Limits,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageDeclaration {
    pub key: i32,
    pub kind: u8,
    pub max_bytes: u16,
}
impl StorageDeclaration {
    pub(crate) fn valid(&self) -> bool {
        self.key >= 0
            && matches!((self.kind, self.max_bytes), (1, 0) | (2, 1..=MAX_DECLARED_BLOB_BYTES))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DependencyExport {
    pub access: u8,
    pub key: Option<[u8; 32]>,
}
impl DependencyExport {
    pub fn allows(&self, provider: [u8; 32], consumer: [u8; 32]) -> bool {
        match self.access {
            1 => true,
            2 => provider == consumer,
            3 => self.key == Some(consumer),
            _ => false,
        }
    }
    // A pinned peer is named by the hash of its key rather than by the key, so there is no
    // point to validate. A hash that names no real key simply never matches one.
    fn valid(&self) -> bool {
        matches!((self.access, self.key), (0..=2, None) | (3, Some(_)))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub min: Option<[u16; 4]>,
    pub min_inclusive: bool,
    pub max: Option<[u16; 4]>,
    pub max_inclusive: bool,
}
impl VersionRange {
    pub fn matches(&self, version: [u16; 4]) -> bool {
        self.min
            .is_none_or(|min| version > min || self.min_inclusive && version == min)
            && self
                .max
                .is_none_or(|max| version < max || self.max_inclusive && version == max)
    }
    fn valid(&self) -> bool {
        if self.min.is_none() && self.min_inclusive || self.max.is_none() && self.max_inclusive {
            return false;
        }
        match (self.min, self.max) {
            (Some(min), Some(max)) => {
                min < max || min == max && self.min_inclusive && self.max_inclusive
            }
            _ => true,
        }
    }
    fn strictly_before(&self, next: &Self) -> bool {
        match (self.max, next.min) {
            (Some(max), Some(min)) => {
                max < min || max == min && !self.max_inclusive && !next.min_inclusive
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub assembly: String,
    pub ranges: Vec<VersionRange>,
    pub package_version: u32,
    pub signer: Option<[u8; 32]>,
    pub digest: Option<[u8; 32]>,
    pub scope: u8,
}
impl Dependency {
    pub fn matches(&self, provider: &Package) -> bool {
        self.matches_parts(&provider.manifest, provider.signer, provider.digest)
    }
    pub fn matches_view(&self, provider: &PackageView<'_>) -> bool {
        self.matches_parts(&provider.manifest, provider.signer, provider.digest)
    }
    pub(crate) fn matches_parts(&self, manifest: &Manifest, signer: [u8; 32], digest: [u8; 32]) -> bool {
        self.assembly == manifest.assembly
            && self
                .ranges
                .iter()
                .any(|range| range.matches(manifest.assembly_version))
            && (self.package_version == 0 || self.package_version == manifest.version)
            && self.signer.is_none_or(|expected| expected == signer)
            && self.digest.is_none_or(|expected| expected == digest)
    }
    fn valid(&self, consumer: &str) -> bool {
        let shape_valid = valid_identifier(&self.assembly)
            && self.assembly != consumer
            && self.scope <= 2
            && !self.ranges.is_empty()
            && self.ranges.len() <= 8
            && self.ranges.iter().all(VersionRange::valid)
            && self
                .ranges
                .windows(2)
                .all(|pair| pair[0].strictly_before(&pair[1]));
        shape_valid
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub arena: u32,
    pub stack: u16,
    pub frames: u8,
    pub instructions: u32,
}
#[derive(Clone, Debug)]
pub struct Package {
    pub manifest: Manifest,
    image: core::ops::Range<usize>,
    pub key: [u8; crate::crypto::P256_PUBLIC_KEY_BYTES],
    /// SHA-256 of the signer key, which is the identity a domain binds to.
    pub signer: [u8; 32],
    pub digest: [u8; 32],
    pub raw: Vec<u8>,
}

#[derive(Debug)]
pub struct PackageView<'a> {
    pub manifest: Manifest,
    pub image: &'a [u8],
    pub key: [u8; crate::crypto::P256_PUBLIC_KEY_BYTES],
    /// SHA-256 of the signer key, which is the identity a domain binds to.
    pub signer: [u8; 32],
    pub digest: [u8; 32],
    pub raw: &'a [u8],
}

impl<'a> PackageView<'a> {
    /// Verify a package while retaining its signed envelope and assembly as
    /// borrowed slices. The manifest remains owned because JSON decoding
    /// unescapes strings and builds bounded dependency records.
    #[cfg(feature = "software-crypto")]
    pub fn verify(bytes: &'a [u8]) -> Result<Self> {
        let mut provider = crate::crypto::SoftwareCrypto;
        Self::verify_with(bytes, &mut provider)
    }

    /// Verify a package through the active native provider. Device trust
    /// boundaries use this entry point so hardware and software providers
    /// share the same format and authorization checks.
    pub fn verify_with(bytes: &'a [u8], provider: &mut impl CryptoProvider) -> Result<Self> {
        Self::verify_with_expected_digest(bytes, provider, None)
    }

    pub(crate) fn verify_with_expected_digest(
        bytes: &'a [u8],
        provider: &mut impl CryptoProvider,
        expected_digest: Option<&[u8; 32]>,
    ) -> Result<Self> {
        if bytes.len() < HEADER_BYTES + SUFFIX_BYTES
            || bytes.len() > MAX_PACKAGE_BYTES
            || &bytes[..4] != b"MP04"
            || &bytes[4..4 + CONTEXT.len()] != CONTEXT
        {
            return Err(Error::Format);
        }
        let lengths = 4 + CONTEXT.len();
        let n = u32::from_le_bytes(bytes[lengths..lengths + 4].try_into().unwrap()) as usize;
        let k = u32::from_le_bytes(bytes[lengths + 4..HEADER_BYTES].try_into().unwrap()) as usize;
        if n > 16384 || k > 65536 || HEADER_BYTES + n + k + SUFFIX_BYTES != bytes.len() {
            return Err(Error::Format);
        }
        let end = HEADER_BYTES + n + k;
        let signed = end + crate::crypto::P256_PUBLIC_KEY_BYTES;
        let key: [u8; crate::crypto::P256_PUBLIC_KEY_BYTES] =
            bytes[end..signed].try_into().unwrap();
        // Pin the encoding and reject the malleable signature before dispatching, so a
        // software and a hardware provider answer this identically.
        if !crate::crypto::p256_signature_acceptable(&key, &bytes[signed..]) {
            return Err(Error::Signature);
        }
        // The argument order differs from the signature scheme this replaced.
        if !provider.p256_ecdsa_verify(&key, &bytes[..signed], &bytes[signed..])? {
            return Err(Error::Signature);
        }
        let mut signer = [0; 32];
        provider.sha256_into(&key, &mut signer)?;
        let manifest: Manifest = serde_json::from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + n])
            .map_err(|_| Error::Format)?;
        manifest.validate_shape()?;
        if manifest.limits.arena != 16384
            || manifest.limits.stack != 256
            || manifest.limits.frames != 32
            || manifest.limits.instructions != 100000
        {
            return Err(Error::Quota);
        }
        if serde_json::to_vec(&manifest).map_err(|_| Error::Format)?
            != bytes[HEADER_BYTES..HEADER_BYTES + n]
        {
            return Err(Error::Format);
        }
        let image_bytes = &bytes[HEADER_BYTES + n..end];
        if !image_bytes.starts_with(b"MC04") {
            return Err(Error::Format);
        }
        let assembly = crate::assembly::Assembly::parse(image_bytes)?;
        let identity = assembly.identity()?;
        if identity.name != manifest.assembly
            || identity.version != manifest.assembly_version
            || identity.flags != 0
        {
            return Err(Error::Unauthorized);
        }
        for a in &manifest.entry_points {
            if a.aid.len() < 10
                || a.aid.len() > 32
                || !a.aid.len().is_multiple_of(2)
                || !a
                    .aid
                    .bytes()
                    .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_lowercase())
            {
                return Err(Error::Format);
            }
            for id in [
                Some(a.process),
                a.install,
                a.uninstall,
                a.select,
                a.deselect,
            ]
            .into_iter()
            .flatten()
            {
                assembly.validate_lifecycle(id)?;
            }
        }
        for c in &manifest.capabilities {
            crate::native_abi::signature(*c)?;
        }
        assembly.validate_imports(&manifest.capabilities)?;
        let digest = provider.sha256(bytes)?;
        if expected_digest.is_some_and(|expected| *expected != digest) {
            return Err(Error::Signature);
        }
        Ok(Self {
            manifest,
            image: image_bytes,
            key,
            signer,
            digest,
            raw: bytes,
        })
    }
}

impl Package {
    #[cfg(feature = "software-crypto")]
    pub fn verify(bytes: &[u8]) -> Result<Self> {
        let verified = PackageView::verify(bytes)?;
        let image_start = (verified.image.as_ptr() as usize)
            .checked_sub(bytes.as_ptr() as usize)
            .ok_or(Error::Bounds)?;
        let image_end = image_start
            .checked_add(verified.image.len())
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Bounds)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(verified.raw.len())
            .map_err(|_| Error::Quota)?;
        raw.extend_from_slice(verified.raw);
        Ok(Self {
            manifest: verified.manifest,
            image: image_start..image_end,
            key: verified.key,
            signer: verified.signer,
            digest: verified.digest,
            raw,
        })
    }

    pub fn image(&self) -> &[u8] {
        &self.raw[self.image.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SignatureProvider(Result<bool>);
    impl CryptoProvider for SignatureProvider {
        fn p256_ecdsa_verify(&mut self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            self.0.clone()
        }
    }

    /// An envelope whose key and signature are the right shape, so verification reaches the
    /// provider rather than stopping at the shape check before it.
    fn envelope() -> Vec<u8> {
        let mut bytes = Vec::from(b"MP04" as &[u8]);
        bytes.extend_from_slice(CONTEXT);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.resize(HEADER_BYTES, 0);
        let mut key = [0x11; crate::crypto::P256_PUBLIC_KEY_BYTES];
        key[0] = 0x04;
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&[0x11; crate::crypto::P256_SIGNATURE_BYTES]);
        bytes
    }

    #[test]
    fn a_previous_format_container_is_refused_by_its_magic() {
        let mut bytes = envelope();
        bytes[..4].copy_from_slice(b"MP03");
        assert!(matches!(
            PackageView::verify_with(&bytes, &mut SignatureProvider(Ok(true))),
            Err(Error::Format)
        ));
    }

    #[test]
    fn a_misshapen_key_or_signature_never_reaches_the_provider() {
        // A provider that would answer yes. The shape check has to refuse first.
        let mut compressed = envelope();
        compressed[HEADER_BYTES] = 0x02;
        assert!(matches!(
            PackageView::verify_with(&compressed, &mut SignatureProvider(Ok(true))),
            Err(Error::Signature)
        ));
        let mut high = envelope();
        high[HEADER_BYTES + crate::crypto::P256_PUBLIC_KEY_BYTES + 32] = 0xff;
        assert!(matches!(
            PackageView::verify_with(&high, &mut SignatureProvider(Ok(true))),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn provider_signature_failures_are_not_downgraded() {
        let bytes = envelope();
        assert!(matches!(
            PackageView::verify_with(&bytes, &mut SignatureProvider(Ok(false))),
            Err(Error::Signature)
        ));
        assert!(matches!(
            PackageView::verify_with(&bytes, &mut SignatureProvider(Err(Error::Native))),
            Err(Error::Native)
        ));
    }

    #[test]
    fn embedded_identifiers_are_bounded_ascii_and_json_unescaped() {
        for valid in ["a", "mscorlib", "MicroCard.Cryptography", "selected-buffer", "A_1"] {
            assert!(valid_identifier(valid), "{valid}");
        }
        for invalid in ["", ".hidden", "bad/name", "bad\\name", "bad\"name", "bad name", "é"] {
            assert!(!valid_identifier(invalid), "{invalid}");
        }
        assert!(valid_identifier(&"a".repeat(64)));
        assert!(!valid_identifier(&"a".repeat(65)));
    }
}
