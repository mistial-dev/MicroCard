//! Bounded definite-length TLV primitives shared by management and native services.

/// Decode a minimal definite length of at most 65535 bytes. Values may follow later.
pub fn length(input: &[u8]) -> Option<(usize, usize)> {
    match *input.first()? {
        first @ 0..=0x7f => Some((usize::from(first), 1)),
        0x81 => {
            let value = usize::from(*input.get(1)?);
            (value >= 128).then_some((value, 2))
        }
        0x82 => {
            let value = usize::from(u16::from_be_bytes([*input.get(1)?, *input.get(2)?]));
            (value >= 256).then_some((value, 3))
        }
        _ => None,
    }
}

/// Read one object; offsets are relative to the supplied bounded input slice.
/// DER checks primitive canonical forms, not recursive constructed contents.
pub fn read(input: &[u8], der: bool) -> Option<[i32; 5]> {
    let first = *input.first()?;
    if first == 0 {
        return None;
    }
    let mut tag = i32::from(first);
    let mut cursor = 1;
    if first & 31 == 31 {
        let next = *input.get(cursor)?;
        cursor += 1;
        if next & 127 == 0 {
            return None;
        }
        tag = (tag << 8) | i32::from(next);
        if next & 128 != 0 {
            let last = *input.get(cursor)?;
            cursor += 1;
            if last & 128 != 0 {
                return None;
            }
            tag = (tag << 8) | i32::from(last);
        } else if next < 31 {
            return None;
        }
    }
    if der && cursor == 1 && first & 0xc0 == 0 {
        let number = first & 31;
        if number == 0
            || ((1..=6).contains(&number) && first & 32 != 0)
            || (matches!(number, 16 | 17) && first & 32 == 0)
        {
            return None;
        }
    }
    let (size, octets) = length(input.get(cursor..)?)?;
    cursor += octets;
    let end = cursor.checked_add(size)?;
    let value = input.get(cursor..end)?;
    if der && !canonical_value(tag, value) {
        return None;
    }
    Some([tag, cursor as i32, cursor as i32, size as i32, end as i32])
}

fn canonical_value(tag: i32, value: &[u8]) -> bool {
    match tag {
        1 => matches!(value, [0] | [255]),
        2 => match value {
            [] => false,
            [first, second, ..] => {
                !(*first == 0 && second & 128 == 0 || *first == 255 && second & 128 != 0)
            }
            _ => true,
        },
        3 => match value.split_first() {
            Some((&unused, rest)) if unused <= 7 => {
                unused == 0 || !rest.is_empty() && value[value.len() - 1] & ((1 << unused) - 1) == 0
            }
            _ => false,
        },
        5 => value.is_empty(),
        6 => {
            if value.is_empty() {
                return false;
            }
            let mut first = true;
            for &byte in value {
                if first && byte == 128 {
                    return false;
                }
                first = byte & 128 == 0;
            }
            first
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_headers_and_der_canonical_values() {
        for input in [
            &[4, 1, 0xaa][..],
            &[0x9f, 0x1f, 1, 0xaa],
            &[0x9f, 0x81, 0, 1, 0xaa],
        ] {
            let parsed = read(input, true).unwrap();
            assert_eq!(parsed[4] as usize, input.len());
            for end in 0..input.len() {
                assert!(read(&input[..end], false).is_none());
            }
        }
        assert_eq!(read(&[4, 1, 0xaa, 0], true), Some([4, 2, 2, 1, 3]));
        for input in [
            &[0, 0][..],
            &[0x9f, 0x1e, 0],
            &[0x9f, 0x80, 0, 0],
            &[0x9f, 0x81, 0x80, 0],
            &[4, 0x80],
            &[4, 0x81, 0x7f],
            &[4, 0x82, 0, 0xff],
        ] {
            assert!(read(input, false).is_none(), "{input:?}");
        }
        for (input, valid) in [
            (&[1, 1, 0][..], true),
            (&[1, 1, 0xff], true),
            (&[1, 1, 1], false),
            (&[2, 0], false),
            (&[2, 2, 0, 0x80], true),
            (&[2, 2, 0, 1], false),
            (&[2, 2, 0xff, 0x80], false),
            (&[2, 2, 0xff, 0x7f], true),
            (&[3, 1, 0], true),
            (&[3, 1, 1], false),
            (&[3, 2, 3, 0xf8], true),
            (&[3, 2, 3, 0xff], false),
            (&[3, 2, 8, 0], false),
            (&[5, 0], true),
            (&[5, 1, 0], false),
            (&[6, 0], false),
            (&[6, 2, 0x81, 0], true),
            (&[6, 1, 0x81], false),
            (&[6, 2, 0x80, 0], false),
            (&[0x21, 0], false),
            (&[0x10, 0], false),
            (&[0x30, 0], true),
        ] {
            assert!(read(input, false).is_some(), "BER {input:?}");
            assert_eq!(read(input, true).is_some(), valid, "DER {input:?}");
        }
        for (header, expected) in [
            (&[127][..], (127, 1)),
            (&[0x81, 128], (128, 2)),
            (&[0x82, 1, 0], (256, 3)),
            (&[0x82, 255, 255], (65535, 3)),
        ] {
            assert_eq!(length(header), Some(expected));
        }
    }
}
