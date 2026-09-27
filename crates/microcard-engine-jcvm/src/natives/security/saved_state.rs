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
        if word(0) != 5 || word(1) != 256 || material == 0 || private == 0 {
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
            {
                return Err(Error::Type);
            }
        }
    }
    if class == ClassId::Cipher {
        let pending = word(5);
        if !matches!(word(0), 13 | 14)
            || pending == 0
            || word(3) > 1
            || (word(3) == 1 && (material == 0 || !matches!(word(4), 1 | 2)))
        {
            return Err(Error::Format);
        }
        let header = &saved_heap[pending as usize..pending as usize + heap::HEADER];
        if u16::from_be_bytes([header[2], header[3]]) != if word(0) == 13 { 32 } else { 16 }
            || header[4] != heap::KIND_BYTE | (heap::CLEAR_ON_RESET << 4)
        {
            return Err(Error::Format);
        }
        if material != 0 {
            let start = material as usize;
            let key_class = u16::from_be_bytes([saved_heap[start], saved_heap[start + 1]]);
            if natives::api_class(key_class).map(|entry| entry.id) != Some(ClassId::AESKey)
                || saved_heap[start + 4] != heap::KIND_OBJECT
                || u16::from_be_bytes([saved_heap[start + 2], saved_heap[start + 3]]) != 6
                || saved_heap.get(start + heap::HEADER + 2..start + heap::HEADER + 4)
                    != Some(&[0, 128])
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
            || word(1) != 256
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
            if header[4] >> 4 != event || length != if word(0) == 11 { 66 } else { 33 } {
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
