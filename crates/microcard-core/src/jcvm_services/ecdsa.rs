//! Bounded Java Card ECDSA encoding: a DER sequence of two positive integers.

pub(super) fn encode(raw: &[u8; 64], output: &mut [u8; 72]) -> usize {
    output.fill(0);
    output[0] = 0x30;
    let mut cursor = 2;
    for scalar in raw.chunks_exact(32) {
        let first = scalar.iter().position(|byte| *byte != 0).unwrap_or(31);
        let scalar = &scalar[first..];
        let padding = usize::from(scalar[0] & 0x80 != 0);
        output[cursor] = 2;
        output[cursor + 1] = (scalar.len() + padding) as u8;
        cursor += 2 + padding;
        output[cursor..cursor + scalar.len()].copy_from_slice(scalar);
        cursor += scalar.len();
    }
    output[1] = (cursor - 2) as u8;
    cursor
}

pub(super) fn decode(input: &[u8]) -> Option<[u8; 64]> {
    if !(8..=72).contains(&input.len()) || input[0] != 0x30 || input[1] as usize != input.len() - 2 {
        return None;
    }
    let mut output = [0; 64];
    let mut cursor = 2;
    for scalar in output.chunks_exact_mut(32) {
        if input.get(cursor) != Some(&2) { return None; }
        let length = *input.get(cursor + 1)? as usize;
        cursor += 2;
        if !(1..=33).contains(&length) { return None; }
        let encoded = input.get(cursor..cursor + length)?;
        cursor += length;
        if encoded[0] & 0x80 != 0 { return None; }
        let value = if encoded.len() > 1 && encoded[0] == 0 {
            if encoded[1] & 0x80 == 0 { return None; }
            &encoded[1..]
        } else { encoded };
        if value.len() > 32 { return None; }
        scalar[32 - value.len()..].copy_from_slice(value);
    }
    (cursor == input.len()).then_some(output)
}

#[cfg(all(test, feature = "software-p256"))]
mod tests {
    use super::*;

    #[test]
    fn der_matches_independent_encoding_and_rejects_noncanonical_or_unbounded_input() {
        for (first, value) in [(31, 1), (31, 0x7f), (31, 0x80), (0, 1), (0, 0x7f), (0, 0x80)] {
            let mut raw = [0; 64];
            raw[first] = value;
            raw[32 + first] = value;
            let reference = p256::ecdsa::Signature::from_slice(&raw).unwrap().to_der();
            let mut encoded = [0xaa; 72];
            let length = encode(&raw, &mut encoded);
            assert_eq!(&encoded[..length], reference.as_bytes());
            assert_eq!(decode(&encoded[..length]), Some(raw));
            assert!(encoded[length..].iter().all(|byte| *byte == 0));
        }
        for invalid in [
            &b"\x30\x06\x02\x01\x80\x02\x01\x01"[..], // negative integer
            &b"\x30\x07\x02\x02\x00\x01\x02\x01\x01"[..], // redundant sign byte
            &b"\x30\x81\x06\x02\x01\x01\x02\x01\x01"[..], // nonminimal length
            &b"\x30\x06\x02\x01\x01\x02\x01\x01\x00"[..], // trailing byte
            &b"\x30\x06\x04\x01\x01\x02\x01\x01"[..], // wrong tag
            &b"\x30\x06\x02\x21\x01\x02\x01\x01"[..], // truncated integer
            &b"\x30\x06\x02\x00\x01\x02\x01\x01"[..], // empty integer
        ] { assert_eq!(decode(invalid), None); }
        let mut oversized = [1; 72];
        oversized[..4].copy_from_slice(&[0x30, 70, 2, 33]);
        assert_eq!(decode(&oversized), None);
    }
}
