//! Recovery checks for private security-object fields.
//! The VM validates heap structure and references before these checks run.
use super::*;
use crate::natives;

fn saved_bytes(saved_heap: &[u8], start: usize, length: usize) -> Result<&[u8]> {
    let end = start.checked_add(length).ok_or(Error::Format)?;
    saved_heap.get(start..end).ok_or(Error::Format)
}

fn saved_word(saved_heap: &[u8], start: usize) -> Result<u16> {
    let bytes = saved_bytes(saved_heap, start, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn validate_saved_security(
    class: ClassId,
    payload: &[u8],
    saved_heap: &[u8],
) -> Result<()> {
    // NEW can be durable before KeyPair's constructor runs. Only
    // the exact zero state is unconstructed, never a partial pair.
    if class == ClassId::KeyPair && payload.iter().all(|byte| *byte == 0) {
        return Ok(());
    }
    let word = |at: usize| u16::from_be_bytes([payload[at * 2], payload[at * 2 + 1]]);
    let material = word(2);
    if class == ClassId::Signature {
        signature::validate_saved_signature(payload, saved_heap)?;
    }
    if class == ClassId::KeyPair {
        let private = word(5);
        let rsa = word(0) == 2;
        if !(rsa && matches!(word(1), 1024 | 2048)
            || word(0) == 5 && matches!(word(1), 256 | 384))
            || material == 0 || private == 0 {
            return Err(Error::Format);
        }
        for (reference, expected) in [
            (material, if rsa { ClassId::RSAPublicKey } else { ClassId::ECPublicKey }),
            (private, if rsa { ClassId::RSAPrivateCrtKey } else { ClassId::ECPrivateKey }),
        ] {
            let start = reference as usize;
            let object = saved_bytes(saved_heap, start, heap::HEADER + STATE_WORDS as usize * 2)?;
            let key_class = u16::from_be_bytes([object[0], object[1]]);
            if natives::api_class(key_class).map(|entry| entry.id) != Some(expected)
                || object[4] != heap::KIND_OBJECT
                || u16::from_be_bytes([object[2], object[3]]) != 6
                || u16::from_be_bytes([
                    object[heap::HEADER + SIZE * 2],
                    object[heap::HEADER + SIZE * 2 + 1],
                ]) != word(1)
            {
                return Err(Error::Type);
            }
        }
    }
    if class == ClassId::KeyAgreement {
        if word(0) != 3 || word(3) > 1 || (word(3) == 1 && material == 0) {
            return Err(Error::Format);
        }
        if material != 0 {
            let start = material as usize;
            let object = saved_bytes(saved_heap, start, heap::HEADER + STATE_WORDS as usize * 2)?;
            let key_class = u16::from_be_bytes([object[0], object[1]]);
            if natives::api_class(key_class).map(|entry| entry.id) != Some(ClassId::ECPrivateKey)
                || object[4] != heap::KIND_OBJECT
                || u16::from_be_bytes([object[2], object[3]]) != 6
                || !matches!(u16::from_be_bytes([
                    object[heap::HEADER + SIZE * 2],
                    object[heap::HEADER + SIZE * 2 + 1],
                ]), 256 | 384)
            {
                return Err(Error::Type);
            }
        }
    }
    if class == ClassId::Cipher {
        let kind = word(0);
        let des = cipher::is_des(kind);
        let pending = word(5);
        if !(matches!(kind, 13 | 14 | 22..=27 | 240)
            || cfg!(feature = "des-legacy") && matches!(kind, 1..=8))
            || pending == 0
            || word(3) > 1
            || (word(3) == 1 && (material == 0 || !matches!(word(4), 1 | 2)))
        {
            return Err(Error::Format);
        }
        let header = saved_bytes(saved_heap, pending as usize, heap::HEADER)?;
        if u16::from_be_bytes([header[2], header[3]]) != cipher::state_bytes(kind) as u16
            || header[4] != heap::KIND_BYTE | (heap::CLEAR_ON_RESET << 4)
        {
            return Err(Error::Format);
        }
        if material != 0 {
            let start = material as usize;
            let object = saved_bytes(saved_heap, start, heap::HEADER + STATE_WORDS as usize * 2)?;
            let key_class = u16::from_be_bytes([object[0], object[1]]);
            let key_size = object.get(heap::HEADER + 2..heap::HEADER + 4);
            let valid_key_size = if des {
                matches!(key_size, Some(&[0, 64] | &[0, 128] | &[0, 192]))
            } else {
                key_size == Some(&[0, 128])
            };
            if natives::api_class(key_class).map(|entry| entry.id)
                != Some(if des { ClassId::DESKey } else { ClassId::AESKey })
                || object[4] != heap::KIND_OBJECT
                || u16::from_be_bytes([object[2], object[3]]) != 6
                || !valid_key_size
            {
                return Err(Error::Type);
            }
        }
    }
    let pin = matches!(
        class,
        ClassId::OwnerPIN | ClassId::OwnerPINx | ClassId::OwnerPINxWithPredecrement
    );
    if pin {
        pin::validate_saved(class, payload, saved_heap)?;
    }
    let ec = matches!(class, ClassId::ECPublicKey | ClassId::ECPrivateKey);
    let rsa = matches!(class, ClassId::RSAPublicKey | ClassId::RSAPrivateKey
        | ClassId::RSAPrivateCrtKey);
    if ec
        && (!natives::ec_key_kind(word(0))
            || !matches!(word(1), 256 | 384)
            || word(3) != 0
            || (class == ClassId::ECPublicKey) != (word(0) == 11))
    {
        return Err(Error::Format);
    }
    if material != 0 && class.is_key() {
        let header = saved_bytes(saved_heap, material as usize, heap::HEADER)?;
        let length = u16::from_be_bytes([header[2], header[3]]);
        if header[4] & 0x0f != heap::KIND_BYTE {
            return Err(Error::Type);
        }
        if rsa {
            if !matches!(word(1), 1024 | 2048) || header[4] != heap::KIND_BYTE {
                return Err(Error::Format);
            }
            let expected = if class == ClassId::RSAPublicKey { word(1) / 8 }
                else { rsa::PRIVATE_BYTES as u16 };
            if length != expected { return Err(Error::Format); }
            if class == ClassId::RSAPrivateCrtKey {
                let start = material as usize + heap::HEADER;
                let der_length = saved_word(saved_heap, start)?;
                if word(3) == 1 && (der_length == 0 || der_length as usize > rsa::PRIVATE_BYTES - 2) {
                    return Err(Error::Format);
                }
                if word(3) == 1 {
                    let der = saved_bytes(saved_heap, start + 2, der_length as usize)?;
                    let (n, e) = rsa::private_public_parts(der).ok_or(Error::Format)?;
                    if n.len() != word(1) as usize / 8 || e != [1, 0, 1] {
                        return Err(Error::Format);
                    }
                }
            }
        } else if ec {
            let event = natives::ec_key_clear_event(word(0));
            let expected = match (word(0) == 11, word(1) == 384) {
                (true, false) => 66, (true, true) => 98,
                (false, false) => 33, (false, true) => 49,
            };
            if header[4] >> 4 != event || length != expected {
                return Err(Error::Format);
            }
            let flags = saved_bytes(saved_heap, material as usize + heap::HEADER, 1)?[0];
            if flags & 0x80 != 0 {
                return Err(Error::Format);
            }
        } else {
            let event = natives::symmetric_key_clear_event(word(0));
            let prefix = u16::from(event != 0);
            if header[4] >> 4 != event || (event != 0 && word(3) != 0) {
                return Err(Error::Format);
            }
            if length <= prefix || length > 64 + prefix {
                return Err(Error::Bounds);
            }
        }
    }
    if rsa {
        let kind = word(0);
        let valid = if class == ClassId::RSAPublicKey {
            kind == 4 && word(3) <= 3 && (word(3) & 1 == 0 || material != 0)
                && (word(3) & 2 == 0 || word(5) != 0)
        } else if class == ClassId::RSAPrivateCrtKey {
            kind == 6 && word(3) <= 1 && (word(3) == 0 || material != 0)
                || matches!(kind, 24 | 25) && word(3) == 0 && material == 0
        } else {
            matches!(kind, 5 | 22 | 23) && word(3) == 0 && material == 0
        };
        if !valid || !matches!(word(1), 1024 | 2048) { return Err(Error::Format); }
        if class == ClassId::RSAPublicKey && word(5) != 0 {
            let start = word(5) as usize;
            let header = saved_bytes(saved_heap, start, heap::HEADER)?;
            if header[4] != heap::KIND_BYTE
                || u16::from_be_bytes([header[2], header[3]]) != 3 {
                return Err(Error::Format);
            }
            if word(3) & 2 != 0
                && saved_bytes(saved_heap, start + heap::HEADER, 3)? != [1, 0, 1] {
                return Err(Error::Format);
            }
        }
        if class == ClassId::RSAPublicKey && word(3) & 1 != 0 {
            let start = material as usize + heap::HEADER;
            let bytes = saved_bytes(saved_heap, start, word(1) as usize / 8)?;
            if bytes[0] & 0x80 == 0 || bytes[bytes.len() - 1] & 1 == 0 {
                return Err(Error::Format);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_rsa_exponent_reference_is_a_format_error() {
        let mut payload = [0u8; STATE_WORDS as usize * 2];
        payload[KIND * 2..KIND * 2 + 2].copy_from_slice(&4u16.to_be_bytes());
        payload[SIZE * 2..SIZE * 2 + 2].copy_from_slice(&2048u16.to_be_bytes());
        payload[PENDING * 2..PENDING * 2 + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(validate_saved_security(ClassId::RSAPublicKey, &payload, &[0; 32]),
            Err(Error::Format));
    }

    #[test]
    fn p384_recovery_checks_key_material_length_and_pair_sizes() {
        let mut slab = [0; 512];
        let mut heap = Heap::new(&mut slab).unwrap();
        let public = new_native(&mut heap, ClassId::ECPublicKey, STATE_WORDS, 1).unwrap();
        let private = new_native(&mut heap, ClassId::ECPrivateKey, STATE_WORDS, 1).unwrap();
        for (key, kind, length) in [(public, 11, 98), (private, 12, 49)] {
            let material = heap.new_array(heap::KIND_BYTE, length, 1).unwrap();
            heap.put_word(key, KIND, kind).unwrap();
            heap.put_word(key, SIZE, 384).unwrap();
            heap.put_word(key, MATERIAL, material).unwrap();
        }
        let pair = new_native(&mut heap, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        heap.put_word(pair, KIND, 5).unwrap();
        heap.put_word(pair, SIZE, 384).unwrap();
        heap.put_word(pair, MATERIAL, public).unwrap();
        heap.put_word(pair, PENDING, private).unwrap();
        let image = heap.image().to_vec();
        for (class, reference) in [(ClassId::ECPublicKey, public),
            (ClassId::ECPrivateKey, private), (ClassId::KeyPair, pair)] {
            let start = reference as usize + heap::HEADER;
            validate_saved_security(class, &image[start..start + STATE_WORDS as usize * 2], &image).unwrap();
        }
        let mut wrong_length = image.clone();
        let material = heap.get_word(private, MATERIAL).unwrap() as usize;
        wrong_length[material + 3] = 48;
        let key_start = private as usize + heap::HEADER;
        assert_eq!(validate_saved_security(ClassId::ECPrivateKey,
            &wrong_length[key_start..key_start + STATE_WORDS as usize * 2], &wrong_length),
            Err(Error::Format));
        let mut wrong_size = image.clone();
        wrong_size[private as usize + heap::HEADER + SIZE * 2] = 1;
        wrong_size[private as usize + heap::HEADER + SIZE * 2 + 1] = 0;
        let start = pair as usize + heap::HEADER;
        assert_eq!(validate_saved_security(ClassId::KeyPair,
            &wrong_size[start..start + STATE_WORDS as usize * 2], &wrong_size), Err(Error::Type));
    }
}
