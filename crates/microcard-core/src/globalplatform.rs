//! MicroCard GlobalPlatform registry profile.
//!
//! GlobalPlatform Card Specification 2.3.1, §11.4 defines GET STATUS and
//! Appendix H.1.3 assigns the default Issuer Security Domain AID.
use crate::{Error, Result};
use alloc::vec::Vec;

pub const ISD_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];
pub const MAX_AID_BYTES: usize = 16;
const SSD_PACKAGE_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50];
const SSD_MODULE_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x41];
// GP 2.3.1 Appendix H, format 1. The final OID announces SCP03 i=20:
// random S8 challenge, R-MAC support, and no response encryption.
const RECOGNITION_DATA: [u8; 38] = [
    0x73, 0x24, 0x06, 0x07, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 0x01, 0x60, 0x0c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xfc, 0x6b, 0x02, 0x02, 0x03, 0x01, 0x64, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xfc, 0x6b, 0x04, 0x03, 0x20,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StatusCursor {
    pub p1: u8,
    pub next: usize,
    aid: [u8; MAX_AID_BYTES],
    aid_len: u8,
}

impl StatusCursor {
    pub fn first(p1: u8, p2: u8, data: &[u8]) -> Result<Self> {
        if !matches!(p1, 0x80 | 0x40 | 0x20 | 0x10) || p2 != 0x02 {
            return Err(Error::Format);
        }
        let filter = parse_aid_qualifier(data)?;
        let mut aid = [0; MAX_AID_BYTES];
        aid[..filter.len()].copy_from_slice(filter);
        Ok(Self {
            p1,
            next: 0,
            aid,
            aid_len: filter.len() as u8,
        })
    }

    pub fn matches_next(&self, p1: u8, p2: u8, data: &[u8]) -> bool {
        p1 == self.p1 && p2 == 0x03 && parse_aid_qualifier(data).ok() == Some(self.filter())
    }

    pub fn filter(&self) -> &[u8] {
        &self.aid[..usize::from(self.aid_len)]
    }
}

fn parse_aid_qualifier(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 2 || data[0] != 0x4f {
        return Err(Error::Format);
    }
    let length = usize::from(data[1]);
    if length > MAX_AID_BYTES || data.len() < 2 + length {
        return Err(Error::Format);
    }
    // Additional well-formed search qualifiers are ignored as permitted by
    // GP 2.3.1 §11.4.2.3. Indefinite and multi-byte lengths are not accepted.
    let mut offset = 2 + length;
    while offset < data.len() {
        let tag_bytes = if data[offset] & 0x1f == 0x1f { 2 } else { 1 };
        if offset + tag_bytes + 1 > data.len() {
            return Err(Error::Format);
        }
        let value_len = usize::from(data[offset + tag_bytes]);
        offset = offset
            .checked_add(tag_bytes + 1 + value_len)
            .ok_or(Error::Bounds)?;
        if offset > data.len() {
            return Err(Error::Format);
        }
    }
    Ok(&data[2..2 + length])
}

pub(crate) fn is_isd_select(command: &crate::apdu::Command) -> bool {
    command.cla == 0x00
        && command.ins == 0xa4
        && command.p1 == 0x04
        && matches!(command.p2, 0x00 | 0x0c)
        && (command.data.is_empty() || command.data.as_ref() == ISD_AID)
}

pub(crate) fn isd_fci() -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response.try_reserve_exact(62).map_err(|_| Error::Quota)?;
    response.extend_from_slice(&[0x6f, 0x36, 0x84, 0x08]);
    response.extend_from_slice(&ISD_AID);
    response.extend_from_slice(&[0xa5, 0x2a]);
    response.extend_from_slice(&RECOGNITION_DATA);
    // A conservative command-data ceiling after short-APDU secure messaging.
    response.extend_from_slice(&[0x9f, 0x65, 0x01, 0xe0]);
    response.extend_from_slice(&[0x90, 0x00]);
    Ok(response)
}

pub(crate) fn card_recognition_data() -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response.try_reserve_exact(44).map_err(|_| Error::Quota)?;
    response.extend_from_slice(&[0x66, RECOGNITION_DATA.len() as u8]);
    response.extend_from_slice(&RECOGNITION_DATA);
    Ok(response)
}

pub(crate) fn get_data(command: &crate::apdu::Command) -> Result<Option<Vec<u8>>> {
    if command.ins != 0xca || !command.data.is_empty() {
        return Ok(None);
    }
    if command.p1 == 0x00 && command.p2 == 0x66 {
        return card_recognition_data().map(Some);
    }
    Ok(None)
}

pub(crate) fn ssd_install_aid<'a>(command: &'a crate::apdu::Command<'_>) -> Result<&'a [u8]> {
    if command.ins != 0xe6 || command.p1 != 0x0c || command.p2 != 0 {
        return Err(Error::Format);
    }
    let mut offset = 0usize;
    let package = take_lv(&command.data, &mut offset)?;
    let module = take_lv(&command.data, &mut offset)?;
    let instance = take_lv(&command.data, &mut offset)?;
    let privileges = take_lv(&command.data, &mut offset)?;
    let parameters = take_lv(&command.data, &mut offset)?;
    let install_token = take_lv(&command.data, &mut offset)?;
    if offset != command.data.len()
        || package != SSD_PACKAGE_AID
        || module != SSD_MODULE_AID
        || !(5..=MAX_AID_BYTES).contains(&instance.len())
        || privileges.is_empty()
        || privileges.len() > 3
        || privileges[0] != 0x80
        || privileges[1..].iter().any(|byte| *byte != 0)
        || !matches!(parameters, [0xc9, 0] | [0xc9, 4, 0x81, 2, 3, 0x20])
        || !install_token.is_empty()
    {
        return Err(Error::Format);
    }
    Ok(instance)
}

pub(crate) struct ApplicationInstall<'a> {
    pub load_aid: &'a [u8],
    pub module_aid: &'a [u8],
    pub instance_aid: &'a [u8],
}

pub(crate) fn application_install<'a>(
    command: &'a crate::apdu::Command<'_>,
) -> Result<ApplicationInstall<'a>> {
    if command.ins != 0xe6 || command.p1 != 0x0c || command.p2 != 0 {
        return Err(Error::Format);
    }
    let mut offset = 0usize;
    let load_aid = take_lv(&command.data, &mut offset)?;
    let module_aid = take_lv(&command.data, &mut offset)?;
    let instance_aid = take_lv(&command.data, &mut offset)?;
    let privileges = take_lv(&command.data, &mut offset)?;
    let parameters = take_lv(&command.data, &mut offset)?;
    let token = take_lv(&command.data, &mut offset)?;
    if offset != command.data.len()
        || !(5..=MAX_AID_BYTES).contains(&load_aid.len())
        || !(5..=MAX_AID_BYTES).contains(&module_aid.len())
        || instance_aid != module_aid
        || !matches!(privileges, [0] | [0, 0, 0])
        || parameters != [0xc9, 0]
        || !token.is_empty()
    {
        return Err(Error::Format);
    }
    Ok(ApplicationInstall {
        load_aid,
        module_aid,
        instance_aid,
    })
}

pub(crate) struct LoadRequest<'a> {
    pub load_aid: &'a [u8],
    pub domain_aid: &'a [u8],
    pub hash: [u8; 32],
}

pub(crate) fn load_request<'a>(
    command: &'a crate::apdu::Command<'_>,
) -> Result<LoadRequest<'a>> {
    if command.ins != 0xe6 || command.p1 != 0x02 || command.p2 != 0 {
        return Err(Error::Format);
    }
    let mut offset = 0usize;
    let load_aid = take_lv(&command.data, &mut offset)?;
    let domain_aid = take_lv(&command.data, &mut offset)?;
    let hash = take_lv(&command.data, &mut offset)?;
    let parameters = take_lv(&command.data, &mut offset)?;
    let token = take_lv(&command.data, &mut offset)?;
    if offset != command.data.len()
        || !(5..=MAX_AID_BYTES).contains(&load_aid.len())
        || !(5..=MAX_AID_BYTES).contains(&domain_aid.len())
        || hash.len() != 32
        || !parameters.is_empty()
        || !token.is_empty()
    {
        return Err(Error::Format);
    }
    Ok(LoadRequest {
        load_aid,
        domain_aid,
        hash: hash.try_into().unwrap(),
    })
}

/// Parse the C4 Load File Data Block prefix from the first LOAD command.
/// Later command data contains only the remaining value bytes.
pub(crate) fn load_file_data(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.first().copied() != Some(0xc4) {
        return Err(Error::Format);
    }
    let first = *data.get(1).ok_or(Error::Format)?;
    let (length, header) = match first {
        0..=0x7f => (usize::from(first), 2),
        0x81 => {
            let value = usize::from(*data.get(2).ok_or(Error::Format)?);
            if value < 0x80 {
                return Err(Error::Format);
            }
            (value, 3)
        }
        0x82 => {
            let value = usize::from(u16::from_be_bytes([
                *data.get(2).ok_or(Error::Format)?,
                *data.get(3).ok_or(Error::Format)?,
            ]));
            if value < 0x100 {
                return Err(Error::Format);
            }
            (value, 4)
        }
        _ => return Err(Error::Format),
    };
    if length > crate::package::MAX_PACKAGE_BYTES {
        return Err(Error::Quota);
    }
    Ok((length, &data[header..]))
}

pub(crate) fn delete_aid<'a>(command: &'a crate::apdu::Command<'_>) -> Result<&'a [u8]> {
    if command.ins != 0xe4 || command.p1 != 0 || !matches!(command.p2, 0 | 0x80) {
        return Err(Error::Format);
    }
    if command.data.len() < 2 || command.data[0] != 0x4f {
        return Err(Error::Format);
    }
    let length = usize::from(command.data[1]);
    if !(5..=MAX_AID_BYTES).contains(&length) || command.data.len() != length + 2 {
        return Err(Error::Format);
    }
    Ok(&command.data[2..])
}

fn take_lv<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let length = usize::from(*data.get(*offset).ok_or(Error::Format)?);
    *offset = offset.checked_add(1).ok_or(Error::Bounds)?;
    let end = offset.checked_add(length).ok_or(Error::Bounds)?;
    let value = data.get(*offset..end).ok_or(Error::Format)?;
    *offset = end;
    Ok(value)
}

pub(crate) fn aid_matches(candidate: &[u8], filter: &[u8]) -> bool {
    filter.is_empty() || candidate.starts_with(filter)
}

pub(crate) fn synthetic_aid(kind: u8, stable: &[u8]) -> [u8; 16] {
    debug_assert!(stable.len() >= 10);
    let mut aid = [0; 16];
    aid[..6].copy_from_slice(&[0xa0, 0x00, 0x00, 0x01, 0x51, kind]);
    aid[6..].copy_from_slice(&stable[..10]);
    aid
}

pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) -> Result<()> {
    if value.len() > 255 {
        return Err(Error::Quota);
    }
    let length_bytes = if value.len() < 0x80 { 1 } else { 2 };
    let additional = tag
        .len()
        .checked_add(length_bytes)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or(Error::Quota)?;
    out.try_reserve_exact(additional)
        .map_err(|_| Error::Quota)?;
    out.extend_from_slice(tag);
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        out.extend_from_slice(&[0x81, value.len() as u8]);
    }
    out.extend_from_slice(value);
    Ok(())
}

pub(crate) fn template(body: Vec<u8>) -> Result<Vec<u8>> {
    let encoded_len = 1usize
        .checked_add(if body.len() < 0x80 { 1 } else { 2 })
        .and_then(|length| length.checked_add(body.len()))
        .ok_or(Error::Quota)?;
    if encoded_len > 220 {
        return Err(Error::Quota);
    }
    let mut out = Vec::new();
    push_tlv(&mut out, &[0xe3], &body)?;
    debug_assert_eq!(out.len(), encoded_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_cursor_requires_modern_tlv_format_and_preserves_filter() {
        let first = StatusCursor::first(0x40, 0x02, &[0x4f, 5, 0xa0, 0, 0, 1, 0x51]).unwrap();
        assert_eq!(first.filter(), &[0xa0, 0, 0, 1, 0x51]);
        assert!(first.matches_next(0x40, 0x03, &[0x4f, 5, 0xa0, 0, 0, 1, 0x51]));
        assert!(!first.matches_next(0x20, 0x03, &[0x4f, 0]));
        assert!(StatusCursor::first(0x40, 0x00, &[0x4f, 0]).is_err());
    }

    #[test]
    fn ignored_qualifiers_still_have_to_be_bounded_tlvs() {
        assert!(StatusCursor::first(0x20, 0x02, &[0x4f, 0, 0x5c, 1, 0x4f]).is_ok());
        assert!(StatusCursor::first(0x20, 0x02, &[0x4f, 0, 0x5c, 2, 0x4f]).is_err());
    }

    #[test]
    fn recognition_data_announces_gp_231_and_scp03_i20() {
        let data = card_recognition_data().unwrap();
        assert_eq!(&data[..4], &[0x66, 38, 0x73, 36]);
        assert!(data.windows(12).any(|value| {
            value == [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 2, 2, 3, 1]
        }));
        assert!(data.ends_with(&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xfc, 0x6b, 4, 3, 0x20]));
    }

    #[test]
    fn tlv_quota_rejection_preserves_existing_output() {
        let mut output = alloc::vec![0xa5, 0x5a];
        let before = output.clone();

        assert_eq!(push_tlv(&mut output, &[0x4f], &[0; 256]), Err(Error::Quota));
        assert_eq!(output, before);
    }

    #[test]
    fn management_parsers_accept_only_the_profiled_ssd_shape() {
        let aid = [0xf0, 0x4d, 0x43, 0x53, 0x44];
        let mut data = Vec::new();
        for value in [
            SSD_PACKAGE_AID,
            SSD_MODULE_AID,
            &aid,
            &[0x80],
            &[0xc9, 4, 0x81, 2, 3, 0x20],
        ] {
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
        data.push(0); // No install token in this profile.
        let install = crate::apdu::Command {
            cla: 0x80,
            ins: 0xe6,
            p1: 0x0c,
            p2: 0,
            data: data.into(),
            le: None,
        };
        assert_eq!(ssd_install_aid(&install).unwrap(), aid);

        let delete = crate::apdu::Command {
            cla: 0x80,
            ins: 0xe4,
            p1: 0,
            p2: 0,
            data: [0x4f, 5, 0xf0, 0x4d, 0x43, 0x53, 0x44].to_vec().into(),
            le: None,
        };
        assert_eq!(delete_aid(&delete).unwrap(), aid);

        let load_aid = [0xa0; 16];
        let mut application_data = Vec::new();
        for value in [&load_aid[..], &aid, &aid, &[0][..], &[0xc9, 0], &[]] {
            application_data.push(value.len() as u8);
            application_data.extend_from_slice(value);
        }
        let application = crate::apdu::Command {
            cla: 0x80,
            ins: 0xe6,
            p1: 0x0c,
            p2: 0,
            data: application_data.into(),
            le: None,
        };
        let parsed = application_install(&application).unwrap();
        assert_eq!(parsed.load_aid, load_aid);
        assert_eq!(parsed.module_aid, aid);
        assert_eq!(parsed.instance_aid, aid);
    }

    #[test]
    fn load_parsers_require_canonical_profile_fields_and_c4_length() {
        let load_aid = [0xa0; 16];
        let domain_aid = ISD_AID;
        let hash = [0x5a; 32];
        let mut data = Vec::new();
        for value in [&load_aid[..], &domain_aid, &hash, &[], &[]] {
            data.push(value.len() as u8);
            data.extend_from_slice(value);
        }
        let command = crate::apdu::Command {
            cla: 0x80,
            ins: 0xe6,
            p1: 0x02,
            p2: 0,
            data: data.into(),
            le: None,
        };
        let request = load_request(&command).unwrap();
        assert_eq!(request.load_aid, load_aid);
        assert_eq!(request.domain_aid, domain_aid);
        assert_eq!(request.hash, hash);
        assert_eq!(
            load_file_data(&[0xc4, 0x81, 0x80, 1]).unwrap(),
            (128, &[1][..])
        );
        assert_eq!(load_file_data(&[0xc4, 0x7f]).unwrap(), (127, &[][..]));
        assert_eq!(load_file_data(&[0xc4, 0x81, 0x7f]), Err(Error::Format));
        assert_eq!(load_file_data(&[0xd4, 0]), Err(Error::Format));
    }
}
