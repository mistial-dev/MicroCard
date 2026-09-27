use super::*;

/// Construct a supported algorithm holder and its reset-scoped backing state.
pub(super) fn get_instance(
    class: ClassId,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
) -> Result<Native> {
    // Every one of these takes an algorithm, and all but RandomData also take
    // whether the instance is shared.
    let external = class != ClassId::RandomData && frame.pop_short()? != 0;
    let algorithm = frame.pop_short()?;
    // Java Card byte constants arrive as signed shorts. ALG_AES_CTR is -16.
    let id = (-128..=255).contains(&algorithm).then_some(algorithm as u8);
    let supported = match id {
        Some(id) if !external => match class {
            ClassId::MessageDigest => host.supports_digest(id),
            ClassId::Checksum => matches!(id, 1 | 2),
            // setSeed uses the same platform SHA-256 boundary as the rest of the
            // card, so a random holder is complete only when both services exist.
            ClassId::RandomData => host.supports_random(id) && host.supports_digest(4),
            ClassId::Cipher => {
                (matches!(id, 13 | 14 | 22..=27 | 240)
                    || cfg!(feature = "des-legacy") && matches!(id, 1..=8))
                    && host.supports_cipher(id)
            }
            ClassId::KeyAgreement => id == 3 && host.supports_agreement(id),
            ClassId::Signature => {
                (matches!(id, 18 | 33 | 34 | 40) && host.supports_signature(id))
                    || (cfg!(feature = "des-legacy") && matches!(id, 2..=8 | 19 | 20 | 47 | 48))
            }
            _ => false,
        },
        _ => false,
    };
    if !supported {
        let exception = super::super::new_exception(heap, ClassId::CryptoException, context)?;
        heap.put_word_unconditional(exception, super::super::REASON_FIELD, 3)?; // NO_SUCH_ALGORITHM
        return Ok(Native::Threw(exception));
    }
    let pending_bytes = (class == ClassId::Cipher)
        .then_some(cipher::state_bytes(id.ok_or(Error::Format)? as u16) as u16);
    let random_state = (class == ClassId::RandomData).then_some(random::RANDOM_STATE_BYTES);
    let checksum_state = (class == ClassId::Checksum).then_some(4);
    let extra = pending_bytes.or(random_state).or(checksum_state);
    let allocations = [
        (heap::KIND_OBJECT, STATE_WORDS),
        (heap::KIND_BYTE, extra.unwrap_or(0)),
    ];
    let count = if extra.is_some() { 2 } else { 1 };
    if let Err(error) = heap.check_allocations(&allocations[..count]) {
        if error != Error::Quota {
            return Err(error);
        }
        let exception = super::super::new_exception(heap, ClassId::SystemException, context)?;
        heap.put_word_unconditional(exception, super::super::REASON_FIELD, 5)?; // NO_RESOURCE
        return Ok(Native::Threw(exception));
    }
    let instance = new_native(heap, class, STATE_WORDS, context)?;
    heap.put_word(instance, KIND, id.ok_or(Error::Format)? as u16)?;
    if let Some(bytes) = pending_bytes {
        let pending =
            heap.new_transient_array(heap::KIND_BYTE, bytes, context, heap::CLEAR_ON_RESET)?;
        heap.put_word(instance, PENDING, pending)?;
    }
    if let Some(bytes) = checksum_state {
        let state =
            heap.new_transient_array(heap::KIND_BYTE, bytes, context, heap::CLEAR_ON_RESET)?;
        heap.put_word(instance, MATERIAL, state)?;
    }
    if let Some(bytes) = random_state {
        random::init_instance(heap, host, context, instance, algorithm as u8, bytes)?;
    }
    frame.push_reference(instance)?;
    Ok(Native::Returned)
}
