//! Fixed-field manifest representation for the next package envelope.
use super::*;
use crate::cbor::{Decoder, Encoder};

fn number<T: TryFrom<u64>>(d: &mut Decoder<'_>) -> Result<T> {
    T::try_from(d.unsigned()?).map_err(|_| Error::Format)
}
fn owned(value: &str) -> Result<String> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| Error::Quota)?;
    output.push_str(value);
    Ok(output)
}
fn identifier(d: &mut Decoder<'_>) -> Result<String> {
    let value = d.text(64)?;
    if !valid_identifier(value) {
        return Err(Error::Format);
    }
    owned(value)
}
fn version(d: &mut Decoder<'_>) -> Result<[u16; 4]> {
    d.record(4)?;
    Ok([number(d)?, number(d)?, number(d)?, number(d)?])
}
fn write_version(e: &mut Encoder, value: [u16; 4]) -> Result<()> {
    e.array(4)?;
    for part in value {
        e.unsigned(u64::from(part))?;
    }
    Ok(())
}
fn optional<T>(
    d: &mut Decoder<'_>,
    read: impl FnOnce(&mut Decoder<'_>) -> Result<T>,
) -> Result<Option<T>> {
    if d.null() {
        Ok(None)
    } else {
        read(d).map(Some)
    }
}
fn write_optional<T>(
    e: &mut Encoder,
    value: Option<T>,
    write: impl FnOnce(&mut Encoder, T) -> Result<()>,
) -> Result<()> {
    match value {
        Some(value) => write(e, value),
        None => e.null(),
    }
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes(N)?.try_into().map_err(|_| Error::Format)
}
fn list<T>(
    d: &mut Decoder<'_>,
    maximum: usize,
    mut read: impl FnMut(&mut Decoder<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let count = d.array(maximum)?;
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| Error::Quota)?;
    for _ in 0..count {
        output.push(read(d)?);
    }
    Ok(output)
}
fn aid(d: &mut Decoder<'_>) -> Result<String> {
    let bytes = d.bytes(16)?;
    if bytes.len() < 5 {
        return Err(Error::Format);
    }
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len() * 2)
        .map_err(|_| Error::Quota)?;
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(output)
}
fn write_aid(e: &mut Encoder, value: &str) -> Result<()> {
    if !(10..=32).contains(&value.len()) || !value.len().is_multiple_of(2) {
        return Err(Error::Format);
    }
    let mut bytes = [0; 16];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::Format),
        };
        bytes[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    e.bytes(&bytes[..value.len() / 2])
}

impl Manifest {
    /// Decode a bounded version-1 CBOR manifest, without a generic value tree.
    /// Package authorization and image-specific validation remain the verifier's job.
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(Error::Format);
        }
        let mut d = Decoder::new(bytes);
        d.record(12)?;
        if d.unsigned()? != 1 {
            return Err(Error::Format);
        }
        let domain = identifier(&mut d)?;
        let incarnation = fixed(&mut d)?;
        let assembly = identifier(&mut d)?;
        let assembly_version = version(&mut d)?;
        let package_version = number(&mut d)?;
        d.record(2)?;
        let export = DependencyExport {
            access: number(&mut d)?,
            key: optional(&mut d, fixed)?,
        };
        let entry_points = list(&mut d, 4, |d| {
            d.record(6)?;
            Ok(AssemblyEntry {
                aid: aid(d)?,
                process: number(d)?,
                install: optional(d, number)?,
                uninstall: optional(d, number)?,
                select: optional(d, number)?,
                deselect: optional(d, number)?,
            })
        })?;
        let dependencies = list(&mut d, 16, |d| {
            d.record(6)?;
            let assembly = identifier(d)?;
            let ranges = list(d, 8, |d| {
                d.record(4)?;
                Ok(VersionRange {
                    min: optional(d, version)?,
                    min_inclusive: d.boolean()?,
                    max: optional(d, version)?,
                    max_inclusive: d.boolean()?,
                })
            })?;
            Ok(Dependency {
                assembly,
                ranges,
                package_version: number(d)?,
                signer: optional(d, fixed)?,
                digest: optional(d, fixed)?,
                scope: number(d)?,
            })
        })?;
        let bytes = d.bytes(35)?;
        let mut capabilities = Vec::new();
        capabilities
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Quota)?;
        capabilities.extend_from_slice(bytes);
        let storage = list(&mut d, MAX_STORAGE_DECLARATIONS, |d| {
            d.record(3)?;
            Ok(StorageDeclaration {
                key: number(d)?,
                kind: number(d)?,
                max_bytes: number(d)?,
            })
        })?;
        d.record(4)?;
        let limits = Limits {
            arena: number(&mut d)?,
            stack: number(&mut d)?,
            frames: number(&mut d)?,
            instructions: number(&mut d)?,
        };
        d.finish()?;
        let manifest = Self {
            domain,
            incarnation,
            assembly,
            assembly_version,
            version: package_version,
            export,
            entry_points,
            dependencies,
            capabilities,
            storage,
            limits,
        };
        manifest.validate_shape()?;
        Ok(manifest)
    }

    pub(super) fn validate_shape(&self) -> Result<()> {
        if !valid_identifier(&self.domain)
            || !valid_identifier(&self.assembly)
            || self.version == 0
            || self.assembly_version == [0; 4]
            || !self.export.valid()
            || self.entry_points.len() > 4
            || self.dependencies.len() > 16
            || !self
                .dependencies
                .iter()
                .all(|dependency| dependency.valid(&self.assembly))
            || !self
                .dependencies
                .windows(2)
                .all(|pair| pair[0].assembly < pair[1].assembly)
            || self.capabilities.len() > 35
            || !self.capabilities.windows(2).all(|pair| pair[0] < pair[1])
            || self.storage.len() > MAX_STORAGE_DECLARATIONS
            || !self.storage.iter().all(StorageDeclaration::valid)
            || !self
                .storage
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
            || self.entry_points.iter().enumerate().any(|(i, entry)| {
                self.entry_points[..i]
                    .iter()
                    .any(|other| other.aid == entry.aid)
            })
        {
            return Err(Error::Format);
        }
        Ok(())
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let mut e = Encoder::new(MAX_PACKAGE_BYTES);
        e.array(12)?;
        e.unsigned(1)?;
        e.text(&self.domain)?;
        e.bytes(&self.incarnation)?;
        e.text(&self.assembly)?;
        write_version(&mut e, self.assembly_version)?;
        e.unsigned(u64::from(self.version))?;
        e.array(2)?;
        e.unsigned(u64::from(self.export.access))?;
        write_optional(&mut e, self.export.key, |e, value| e.bytes(&value))?;
        e.array(self.entry_points.len())?;
        for entry in &self.entry_points {
            e.array(6)?;
            write_aid(&mut e, &entry.aid)?;
            e.unsigned(u64::from(entry.process))?;
            for method in [entry.install, entry.uninstall, entry.select, entry.deselect] {
                write_optional(&mut e, method, |e, value| e.unsigned(u64::from(value)))?;
            }
        }
        e.array(self.dependencies.len())?;
        for dependency in &self.dependencies {
            e.array(6)?;
            e.text(&dependency.assembly)?;
            e.array(dependency.ranges.len())?;
            for range in &dependency.ranges {
                e.array(4)?;
                write_optional(&mut e, range.min, write_version)?;
                e.boolean(range.min_inclusive)?;
                write_optional(&mut e, range.max, write_version)?;
                e.boolean(range.max_inclusive)?;
            }
            e.unsigned(u64::from(dependency.package_version))?;
            write_optional(&mut e, dependency.signer, |e, value| e.bytes(&value))?;
            write_optional(&mut e, dependency.digest, |e, value| e.bytes(&value))?;
            e.unsigned(u64::from(dependency.scope))?;
        }
        e.bytes(&self.capabilities)?;
        e.array(self.storage.len())?;
        for declaration in &self.storage {
            e.array(3)?;
            e.unsigned(declaration.key as u64)?;
            e.unsigned(u64::from(declaration.kind))?;
            e.unsigned(u64::from(declaration.max_bytes))?;
        }
        e.array(4)?;
        e.unsigned(u64::from(self.limits.arena))?;
        e.unsigned(u64::from(self.limits.stack))?;
        e.unsigned(u64::from(self.limits.frames))?;
        e.unsigned(u64::from(self.limits.instructions))?;
        Ok(e.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Vec<(Manifest, Vec<u8>)> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../../format/manifest-cbor-v1.json")).unwrap();
        vectors
            .as_array()
            .unwrap()
            .iter()
            .map(|vector| {
                let manifest = serde_json::from_value(vector["manifest"].clone()).unwrap();
                let hex = vector["hex"].as_str().unwrap();
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                (manifest, bytes)
            })
            .collect()
    }

    #[test]
    fn shared_vectors_match_and_every_truncation_is_rejected() {
        for (manifest, bytes) in vectors() {
            assert_eq!(manifest.encode_cbor().unwrap(), bytes);
            assert_eq!(Manifest::decode_cbor(&bytes).unwrap(), manifest);
            for end in 0..bytes.len() {
                assert_eq!(
                    Manifest::decode_cbor(&bytes[..end]),
                    Err(Error::Format),
                    "{end}"
                );
            }
            let mut extra = bytes.clone();
            extra.push(0);
            assert_eq!(Manifest::decode_cbor(&extra), Err(Error::Format));
            let mut version = bytes.clone();
            version[1] = 2;
            assert_eq!(Manifest::decode_cbor(&version), Err(Error::Format));
            let mut fields = bytes.clone();
            fields[0] = 0x8d;
            assert_eq!(Manifest::decode_cbor(&fields), Err(Error::Format));
            let mut overlong = alloc::vec![0x98, 12];
            overlong.extend_from_slice(&bytes[1..]);
            assert_eq!(Manifest::decode_cbor(&overlong), Err(Error::Format));
            assert!(bytes.len() < serde_json::to_vec(&manifest).unwrap().len());
        }
    }

    #[test]
    fn duplicates_and_invalid_semantic_shapes_are_rejected() {
        let (manifest, bytes) = vectors().pop().unwrap();
        let mut duplicate = manifest.clone();
        duplicate
            .entry_points
            .push(duplicate.entry_points[0].clone());
        assert_eq!(duplicate.encode_cbor(), Err(Error::Format));
        let mut duplicate = manifest.clone();
        duplicate
            .dependencies
            .push(duplicate.dependencies[0].clone());
        assert_eq!(duplicate.encode_cbor(), Err(Error::Format));
        let mut duplicate = manifest.clone();
        duplicate.storage.push(duplicate.storage[0]);
        assert_eq!(duplicate.encode_cbor(), Err(Error::Format));
        let mut invalid = manifest.clone();
        invalid.entry_points[0].aid = "f04d430001".into();
        assert_eq!(invalid.encode_cbor(), Err(Error::Format));
        let mut invalid = manifest.clone();
        invalid.dependencies[0].ranges.clear();
        assert_eq!(invalid.encode_cbor(), Err(Error::Format));
        let mut invalid = manifest.clone();
        invalid.export.key = None;
        assert_eq!(invalid.encode_cbor(), Err(Error::Format));
        let mut bad = bytes.clone();
        let index = bad.windows(4).position(|w| w == [0x43, 1, 2, 35]).unwrap();
        bad[index + 2] = 1;
        assert_eq!(Manifest::decode_cbor(&bad), Err(Error::Format));
        let mut overflow = bytes.clone();
        let index = overflow
            .windows(3)
            .position(|w| w == [0x19, 0xff, 0xff])
            .unwrap();
        overflow.splice(index..index + 3, [0x1a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(Manifest::decode_cbor(&overflow), Err(Error::Format));
    }
}
