//! Domain policy and GlobalPlatform registry encoding.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct DomainPolicy {
    pub(super) capabilities: Vec<u8>,
    pub(super) max_assemblies: u8,
    pub(super) max_instances: u8,
    pub(super) max_int_records: u16,
    pub(super) max_blob_records: u8,
    pub(super) max_blob_bytes: u16,
    pub(super) max_key_slots: u8,
    pub(super) max_package_bytes: u16,
}

impl DomainPolicy {
    pub(super) fn standard() -> Result<Self> {
        let mut capabilities = Vec::new();
        capabilities
            .try_reserve_exact(crate::native_abi::CAPABILITIES.len())
            .map_err(|_| Error::Quota)?;
        capabilities.extend_from_slice(crate::native_abi::CAPABILITIES);
        Ok(Self {
            capabilities,
            max_assemblies: MAX_ASSEMBLIES_PER_DOMAIN,
            max_instances: MAX_INSTANCES_PER_DOMAIN,
            max_int_records: MAX_INT_RECORDS as u16,
            max_blob_records: MAX_BLOB_RECORDS as u8,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            max_package_bytes: 16384,
        })
    }

    pub(super) fn valid(&self) -> bool {
        self.capabilities.windows(2).all(|pair| pair[0] < pair[1])
            && self
                .capabilities
                .iter()
                .all(|id| crate::native_abi::valid_capability(*id))
            && (1..=MAX_ASSEMBLIES_PER_DOMAIN).contains(&self.max_assemblies)
            && (1..=MAX_INSTANCES_PER_DOMAIN).contains(&self.max_instances)
            && (1..=MAX_INT_RECORDS as u16).contains(&self.max_int_records)
            && (1..=MAX_BLOB_RECORDS as u8).contains(&self.max_blob_records)
            && (1..=8192).contains(&self.max_blob_bytes)
            && (1..=8).contains(&self.max_key_slots)
            && (108..=16384).contains(&self.max_package_bytes)
    }

    pub(super) fn wire(&self) -> Result<Vec<u8>> {
        let capabilities = self
            .capabilities
            .iter()
            .fold(0u64, |bits, id| bits | (1u64 << id));
        let mut out = Vec::new();
        out.try_reserve_exact(19).map_err(|_| Error::Quota)?;
        out.push(1);
        out.extend(capabilities.to_le_bytes());
        out.extend([self.max_assemblies, self.max_instances]);
        out.extend(self.max_int_records.to_le_bytes());
        out.push(self.max_blob_records);
        out.extend(self.max_blob_bytes.to_le_bytes());
        out.push(self.max_key_slots);
        out.extend(self.max_package_bytes.to_le_bytes());
        Ok(out)
    }

    pub(super) fn request(data: &[u8]) -> Result<(String, Self)> {
        if data.len() < 20 || data[0] != 1 {
            return Err(Error::Format);
        }
        let name_len = data[1] as usize;
        if name_len == 0 || name_len > 64 || data.len() != 20 + name_len {
            return Err(Error::Format);
        }
        let identifier = core::str::from_utf8(&data[2..2 + name_len]).map_err(|_| Error::Format)?;
        if !crate::package::valid_identifier(identifier) {
            return Err(Error::Format);
        }
        let p = &data[2 + name_len..];
        let bits = u64::from_le_bytes(p[..8].try_into().unwrap());
        let identifier = fallible_string(identifier)?;
        let mut capabilities = Vec::new();
        capabilities
            .try_reserve_exact(bits.count_ones() as usize)
            .map_err(|_| Error::Quota)?;
        capabilities.extend(
            (0..64)
                .filter(|id| bits & (1u64 << id) != 0)
                .map(|id| id as u8),
        );
        let policy = Self {
            capabilities,
            max_assemblies: p[8],
            max_instances: p[9],
            max_int_records: u16::from_le_bytes(p[10..12].try_into().unwrap()),
            max_blob_records: p[12],
            max_blob_bytes: u16::from_le_bytes(p[13..15].try_into().unwrap()),
            max_key_slots: p[15],
            max_package_bytes: u16::from_le_bytes(p[16..18].try_into().unwrap()),
        };
        if !policy.valid() {
            return Err(Error::Format);
        }
        Ok((identifier, policy))
    }
}

pub(super) fn insert_unique_registry_aid(
    values: &mut Vec<RegistryAid>,
    value: RegistryAid,
) -> bool {
    if values.contains(&value) {
        return false;
    }
    values.push(value);
    true
}

pub(super) enum RegistryEntry<'a> {
    Isd {
        owned: bool,
    },
    Ssd {
        domain: &'a Domain,
    },
    Instance {
        domain_id: &'a str,
        domain: &'a Domain,
        assembly: &'a str,
    },
    Load {
        domain_id: &'a str,
        domain: &'a Domain,
        assembly: &'a str,
    },
}

pub(super) fn visit_registry<'a>(
    state: &'a State,
    p1: u8,
    mut visit: impl FnMut(&[u8], RegistryEntry<'a>) -> Result<()>,
) -> Result<()> {
    match p1 {
        0x80 => visit(
            &crate::globalplatform::ISD_AID,
            RegistryEntry::Isd {
                owned: state.is_owned(),
            },
        ),
        0x40 => {
            for domain in state.domains.values() {
                visit(
                    domain.registry_aid.as_slice(),
                    RegistryEntry::Ssd { domain },
                )?;
            }
            for (domain_id, domain) in core::iter::once(("ISD", &state.isd)).chain(
                state
                    .domains
                    .iter()
                    .map(|(id, domain)| (id.as_str(), domain)),
            ) {
                for (aid_text, assembly) in domain.instances.iter() {
                    let (aid, aid_len) = decode_aid(aid_text)?;
                    visit(
                        &aid[..aid_len],
                        RegistryEntry::Instance {
                            domain_id,
                            domain,
                            assembly,
                        },
                    )?;
                }
            }
            Ok(())
        }
        0x20 | 0x10 => {
            for (domain_id, domain) in core::iter::once(("ISD", &state.isd)).chain(
                state
                    .domains
                    .iter()
                    .map(|(id, domain)| (id.as_str(), domain)),
            ) {
                for assembly in domain.image_refs.keys() {
                    let digest = domain.versions.get(assembly).ok_or(Error::Storage)?.1;
                    let aid = crate::globalplatform::synthetic_aid(0x4c, &digest);
                    visit(
                        &aid,
                        RegistryEntry::Load {
                            domain_id,
                            domain,
                            assembly,
                        },
                    )?;
                }
            }
            Ok(())
        }
        _ => Err(Error::Format),
    }
}

pub(super) fn registry_record(p1: u8, aid: &[u8], entry: RegistryEntry<'_>) -> Result<Vec<u8>> {
    use crate::globalplatform::{push_tlv, synthetic_aid, template, ISD_AID};
    let mut body = Vec::new();
    push_tlv(&mut body, &[0x4f], aid)?;
    match entry {
        RegistryEntry::Isd { owned } => {
            // GP 2.3.1 Tables 11-6 and 11-7: OP_READY/SECURED and SD privilege.
            push_tlv(&mut body, &[0x9f, 0x70], &[if owned { 0x0f } else { 0x01 }])?;
            push_tlv(&mut body, &[0xc5], &[0x80, 0x00, 0x00])?;
        }
        RegistryEntry::Ssd { domain } => {
            // A pinned SSD is represented as PERSONALIZED; an empty SSD is SELECTABLE.
            push_tlv(
                &mut body,
                &[0x9f, 0x70],
                &[if domain.key.is_some() { 0x0f } else { 0x07 }],
            )?;
            push_tlv(&mut body, &[0xc5], &[0x80, 0x00, 0x00])?;
            push_tlv(&mut body, &[0xcc], &ISD_AID)?;
        }
        RegistryEntry::Instance {
            domain_id,
            domain,
            assembly,
        } => {
            let digest = domain.versions.get(assembly).ok_or(Error::Storage)?.1;
            let load_aid = synthetic_aid(0x4c, &digest);
            let (domain_aid, domain_aid_len) = registry_domain_aid(domain_id, domain);
            push_tlv(&mut body, &[0x9f, 0x70], &[0x07])?;
            push_tlv(&mut body, &[0xc5], &[0x00, 0x00, 0x00])?;
            push_tlv(&mut body, &[0xc4], &load_aid)?;
            push_tlv(&mut body, &[0xcc], &domain_aid[..domain_aid_len])?;
        }
        RegistryEntry::Load {
            domain_id,
            domain,
            assembly,
        } => {
            let package = domain.package_metadata(assembly)?;
            if package.manifest.assembly != assembly {
                return Err(Error::Storage);
            }
            push_tlv(&mut body, &[0x9f, 0x70], &[0x01])?;
            let mut version = [0; 8];
            for (index, component) in package.manifest.assembly_version.iter().enumerate() {
                version[index * 2..index * 2 + 2].copy_from_slice(&component.to_be_bytes());
            }
            push_tlv(&mut body, &[0xce], &version)?;
            if p1 == 0x10 {
                for module in &package.manifest.entry_points {
                    let (module_aid, module_len) = decode_aid(&module.aid)?;
                    push_tlv(&mut body, &[0x84], &module_aid[..module_len])?;
                }
            }
            let (domain_aid, domain_aid_len) = registry_domain_aid(domain_id, domain);
            push_tlv(&mut body, &[0xcc], &domain_aid[..domain_aid_len])?;
        }
    }
    template(body)
}

fn registry_domain_aid(domain_id: &str, domain: &Domain) -> ([u8; 16], usize) {
    if domain_id == "ISD" {
        let mut aid = [0; 16];
        aid[..crate::globalplatform::ISD_AID.len()]
            .copy_from_slice(&crate::globalplatform::ISD_AID);
        (aid, crate::globalplatform::ISD_AID.len())
    } else {
        (
            domain.registry_aid.padded(),
            domain.registry_aid.as_slice().len(),
        )
    }
}

pub(super) fn decode_aid(text: &str) -> Result<([u8; 16], usize)> {
    if !(10..=32).contains(&text.len()) || !text.len().is_multiple_of(2) {
        return Err(Error::Format);
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut aid = [0; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        aid[index] = nibble(pair[0])
            .zip(nibble(pair[1]))
            .map(|(high, low)| high << 4 | low)
            .ok_or(Error::Format)?;
    }
    Ok((aid, text.len() / 2))
}

pub(super) fn management_names(data: &[u8]) -> Result<(&str, &str)> {
    let mut decoder = crate::cbor::Decoder::new(data);
    decoder.record(3)?;
    if decoder.unsigned()? != 1 {
        return Err(Error::Format);
    }
    let first = decoder.text(64)?;
    let second = decoder.text(64)?;
    if !crate::package::valid_identifier(first) || !crate::package::valid_identifier(second) {
        return Err(Error::Format);
    }
    decoder.finish()?;
    Ok((first, second))
}

pub(super) fn management_names_wire(first: &str, second: &str) -> Result<Vec<u8>> {
    if !crate::package::valid_identifier(first) || !crate::package::valid_identifier(second) {
        return Err(Error::Format);
    }
    let mut encoder = crate::cbor::Encoder::new(134);
    encoder.array(3)?;
    encoder.unsigned(1)?;
    encoder.text(first)?;
    encoder.text(second)?;
    Ok(encoder.finish())
}

pub(crate) fn encode_aid(value: &[u8]) -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let capacity = value.len().checked_mul(2).ok_or(Error::Quota)?;
    let mut text = String::new();
    text.try_reserve_exact(capacity).map_err(|_| Error::Quota)?;
    for byte in value {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(text)
}
