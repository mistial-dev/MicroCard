use super::*;

pub(super) const RANDOM_STATE_BYTES: u16 = 33; // Seeded flag followed by a SHA-256 chain value.
const PSEUDO_INIT_DOMAIN: &[u8] = b"MicroCard JCVM PRNG init v1";
const PSEUDO_SEED_DOMAIN: &[u8] = b"MicroCard JCVM PRNG seed v1";
const PSEUDO_STEP_DOMAIN: &[u8] = b"MicroCard JCVM PRNG step v1";
const SECURE_SEED_DOMAIN: &[u8] = b"MicroCard JCVM secure seed v1";
const SECURE_MASK_DOMAIN: &[u8] = b"MicroCard JCVM secure mask v1";

#[derive(Clone, Copy)]
enum RandomService {
    Secure,
    Pseudo,
}

impl RandomService {
    fn from_algorithm(algorithm: u8) -> Result<Self> {
        match algorithm {
            1 => Ok(Self::Pseudo),
            2 => Ok(Self::Secure),
            _ => Err(Error::Unsupported),
        }
    }
}

fn random_domain_hash(
    host: &mut dyn crate::host::Host,
    domain: &[u8],
    material: &[u8; 32],
    output: &mut [u8; 32],
) -> Result<()> {
    if domain.len() > 32 {
        return Err(Error::Format);
    }
    let mut input = Zeroizing::new([0u8; 64]);
    input[..domain.len()].copy_from_slice(domain);
    input[32..].copy_from_slice(material);
    if host.digest(4, &input[..], &mut output[..])? != output.len() {
        return Err(Error::Format);
    }
    Ok(())
}

fn store_pseudo_chain(heap: &mut Heap, state: u16, chain: &[u8; 32]) -> Result<()> {
    let mut encoded = Zeroizing::new([0u8; RANDOM_STATE_BYTES as usize]);
    encoded[0] = 1;
    encoded[1..].copy_from_slice(chain);
    heap.write_bytes_unconditional(state, 0, &encoded[..])
}

fn store_secure_chain(heap: &mut Heap, state: u16, chain: &[u8; 32]) -> Result<()> {
    let destination = heap.byte_slice_mut(state, 0, RANDOM_STATE_BYTES as usize)?;
    destination[0] = 1;
    destination[1..].copy_from_slice(chain);
    Ok(())
}

pub(super) fn init_instance(
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    context: heap::Context,
    instance: u16,
    algorithm: u8,
    bytes: u16,
) -> Result<()> {
    let service = RandomService::from_algorithm(algorithm)?;
    let state = match service {
        RandomService::Pseudo => heap.new_array(heap::KIND_BYTE, bytes, context)?,
        RandomService::Secure => {
            heap.new_transient_array(heap::KIND_BYTE, bytes, context, heap::CLEAR_ON_RESET)?
        }
    };
    heap.put_word(instance, MATERIAL, state)?;
    if matches!(service, RandomService::Pseudo) {
        let mut entropy = Zeroizing::new([0u8; 32]);
        host.random(&mut entropy[..])?;
        let mut chain = Zeroizing::new([0u8; 32]);
        random_domain_hash(host, PSEUDO_INIT_DOMAIN, &entropy, &mut chain)?;
        store_pseudo_chain(heap, state, &chain)?;
    }
    Ok(())
}

pub(super) fn call(
    method: MethodId,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    budget: &mut u32,
) -> Result<Native> {
    match method {
        MethodId::generateData | MethodId::nextBytes => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(array, context)?;
            if length < 0 || offset < 0 {
                return Err(Error::Bounds);
            }
            if length == 0 {
                return crypto_exception(heap, context, 1);
            }
            heap.byte_slice(array, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let mut staged = StagedBytes::new(length as usize)?;
            let result = staged.as_mut();
            let algorithm = word_field(heap, this, KIND)? as u8;
            let service = RandomService::from_algorithm(algorithm)?;
            let state = heap.get_word(this, MATERIAL)?;
            let seeded =
                state != NULL && heap.byte_slice(state, 0, RANDOM_STATE_BYTES as usize)?[0] != 0;
            match service {
                RandomService::Pseudo => {
                    if !seeded {
                        return Err(Error::Format);
                    }
                    let mut chain = Zeroizing::new([0u8; 32]);
                    chain.copy_from_slice(heap.byte_slice(state, 1, 32)?);
                    for output in result.chunks_mut(32) {
                        let mut next = Zeroizing::new([0u8; 32]);
                        random_domain_hash(host, PSEUDO_STEP_DOMAIN, &chain, &mut next)?;
                        let count = output.len();
                        output.copy_from_slice(&next[..count]);
                        *chain = *next;
                    }
                    // This state is intentionally outside Java Card transaction rollback.
                    store_pseudo_chain(heap, state, &chain)?;
                }
                RandomService::Secure => {
                    host.random(result)?;
                    if seeded {
                        let mut chain = Zeroizing::new([0u8; 32]);
                        chain.copy_from_slice(heap.byte_slice(state, 1, 32)?);
                        for output in result.chunks_mut(32) {
                            let mut next = Zeroizing::new([0u8; 32]);
                            random_domain_hash(host, SECURE_MASK_DOMAIN, &chain, &mut next)?;
                            for (byte, mask) in output.iter_mut().zip(next.iter()) {
                                *byte ^= mask;
                            }
                            *chain = *next;
                        }
                        store_secure_chain(heap, state, &chain)?;
                    }
                }
            }
            heap.byte_slice_mut(array, offset as usize, length as usize)?
                .copy_from_slice(result);
            if method == MethodId::nextBytes {
                frame.push_short(offset.wrapping_add(length))?;
            }
        }
        MethodId::setSeed => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(source, context)?;
            if length < 0 || offset < 0 {
                return Err(Error::Bounds);
            }
            let seed = heap.byte_slice(source, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let algorithm = word_field(heap, this, KIND)? as u8;
            let service = RandomService::from_algorithm(algorithm)?;
            let mut seed_digest = Zeroizing::new([0u8; 32]);
            if host.digest(4, seed, &mut seed_digest[..])? != 32 {
                return Err(Error::Format);
            }
            let mut chain = Zeroizing::new([0u8; 32]);
            match service {
                RandomService::Pseudo => {
                    random_domain_hash(host, PSEUDO_SEED_DOMAIN, &seed_digest, &mut chain)?;
                }
                RandomService::Secure => {
                    let mut entropy = Zeroizing::new([0u8; 32]);
                    host.random(&mut entropy[..])?;
                    for (byte, seed_byte) in entropy.iter_mut().zip(seed_digest.iter()) {
                        *byte ^= seed_byte;
                    }
                    random_domain_hash(host, SECURE_SEED_DOMAIN, &entropy, &mut chain)?;
                }
            }
            let state = heap.get_word(this, MATERIAL)?;
            match service {
                RandomService::Pseudo => store_pseudo_chain(heap, state, &chain)?,
                RandomService::Secure => store_secure_chain(heap, state, &chain)?,
            }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
