//! Recovery checks for private security-object fields.
//! The VM validates heap structure and references before these checks run.
use super::*;
use crate::natives;

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
        if word(0) != 5 || !matches!(word(1), 256 | 384) || material == 0 || private == 0 {
            return Err(Error::Format);
        }
        for (reference, expected) in [
            (material, ClassId::ECPublicKey),
            (private, ClassId::ECPrivateKey),
        ] {
            let start = reference as usize;
            let key_class = u16::from_be_bytes([saved_heap[start], saved_heap[start + 1]]);
            if natives::api_class(key_class).map(|entry| entry.id) != Some(expected)
                || saved_heap[start + 4] != heap::KIND_OBJECT
                || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
                || u16::from_be_bytes([
                    saved_heap[start + heap::HEADER + SIZE * 2],
                    saved_heap[start + heap::HEADER + SIZE * 2 + 1],
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
            let key_class = u16::from_be_bytes([saved_heap[start], saved_heap[start + 1]]);
            if natives::api_class(key_class).map(|entry| entry.id) != Some(ClassId::ECPrivateKey)
                || saved_heap[start + 4] != heap::KIND_OBJECT
                || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
                || !matches!(u16::from_be_bytes([
                    saved_heap[start + heap::HEADER + SIZE * 2],
                    saved_heap[start + heap::HEADER + SIZE * 2 + 1],
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
        let header = &saved_heap[pending as usize..pending as usize + heap::HEADER];
        if u16::from_be_bytes([header[2], header[3]]) != cipher::state_bytes(kind) as u16
            || header[4] != heap::KIND_BYTE | (heap::CLEAR_ON_RESET << 4)
        {
            return Err(Error::Format);
        }
        if material != 0 {
            let start = material as usize;
            let key_class = u16::from_be_bytes([saved_heap[start], saved_heap[start + 1]]);
            let key_size = saved_heap.get(start + heap::HEADER + 2..start + heap::HEADER + 4);
            let valid_key_size = if des {
                matches!(key_size, Some(&[0, 64] | &[0, 128] | &[0, 192]))
            } else {
                key_size == Some(&[0, 128])
            };
            if natives::api_class(key_class).map(|entry| entry.id)
                != Some(if des { ClassId::DESKey } else { ClassId::AESKey })
                || saved_heap[start + 4] != heap::KIND_OBJECT
                || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
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
    if ec
        && (!natives::ec_key_kind(word(0))
            || !matches!(word(1), 256 | 384)
            || word(3) != 0
            || (class == ClassId::ECPublicKey) != (word(0) == 11))
    {
        return Err(Error::Format);
    }
    if material != 0 && class.is_key() {
        let header = &saved_heap[material as usize..material as usize + heap::HEADER];
        let length = u16::from_be_bytes([header[2], header[3]]);
        if header[4] & 0x0f != heap::KIND_BYTE {
            return Err(Error::Type);
        }
        if ec {
            let event = natives::ec_key_clear_event(word(0));
            let expected = match (word(0) == 11, word(1) == 384) {
                (true, false) => 66, (true, true) => 98,
                (false, false) => 33, (false, true) => 49,
            };
            if header[4] >> 4 != event || length != expected {
                return Err(Error::Format);
            }
            let flags = saved_heap[material as usize + heap::HEADER];
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
