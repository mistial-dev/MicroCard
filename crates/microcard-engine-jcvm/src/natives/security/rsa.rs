//! Generated RSA CRT keys and imported 65537 public keys.
use super::*;
use crate::host::SHA256_STATE_BYTES;

pub(super) const PRIVATE_BYTES: usize = 1202;
const PUBLIC_MAX: usize = 300;

fn der_item<'a>(bytes: &'a [u8], offset: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if *bytes.get(*offset)? != tag { return None; }
    *offset += 1;
    let first = *bytes.get(*offset)?;
    *offset += 1;
    let length = if first < 128 { first as usize } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 2 { return None; }
        let mut length = 0usize;
        for _ in 0..count {
            length = length.checked_mul(256)?.checked_add(*bytes.get(*offset)? as usize)?;
            *offset += 1;
        }
        if length < 128 || count == 2 && length < 256 { return None; }
        length
    };
    let value = bytes.get(*offset..offset.checked_add(length)?)?;
    *offset += length;
    Some(value)
}

fn der_integer<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let value = der_item(bytes, offset, 2)?;
    let (&first, tail) = value.split_first()?;
    if first == 0 {
        if tail.is_empty() { Some(value) }
        else if tail[0] & 0x80 != 0 { Some(tail) }
        else { None }
    } else if first & 0x80 == 0 { Some(value) }
    else { None }
}

fn private_part(der: &[u8], part: usize) -> Option<&[u8]> {
    let mut outer = 0;
    let body = der_item(der, &mut outer, 0x30)?;
    if outer != der.len() { return None; }
    let mut offset = 0;
    if der_integer(body, &mut offset)? != [0] { return None; }
    for index in 0..8 {
        let value = der_integer(body, &mut offset)?;
        if index == part { return Some(value); }
    }
    None
}

fn public_parts(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut outer = 0;
    let body = der_item(der, &mut outer, 0x30)?;
    if outer != der.len() { return None; }
    let mut offset = 0;
    let n = der_integer(body, &mut offset)?;
    let e = der_integer(body, &mut offset)?;
    (offset == body.len()).then_some((n, e))
}

pub(super) fn private_public_parts(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut outer = 0;
    let body = der_item(der, &mut outer, 0x30)?;
    if outer != der.len() { return None; }
    let mut offset = 0;
    if der_integer(body, &mut offset)? != [0] { return None; }
    let n = der_integer(body, &mut offset)?;
    let e = der_integer(body, &mut offset)?;
    for _ in 0..6 {
        if der_integer(body, &mut offset)?.is_empty() { return None; }
    }
    (offset == body.len()).then_some((n, e))
}

fn stored_private<'a>(heap: &'a Heap, key: u16) -> Result<&'a [u8]> {
    let material = heap.get_word(key, MATERIAL)?;
    let storage = heap.byte_slice(material, 0, PRIVATE_BYTES)?;
    let length = u16::from_be_bytes([storage[0], storage[1]]) as usize;
    if length == 0 || length > PRIVATE_BYTES - 2 { return Err(Error::Format); }
    Ok(&storage[2..2 + length])
}

fn put_length(output: &mut [u8], at: &mut usize, length: usize) {
    if length < 128 {
        output[*at] = length as u8; *at += 1;
    } else if length < 256 {
        output[*at..*at + 2].copy_from_slice(&[0x81, length as u8]); *at += 2;
    } else {
        output[*at..*at + 3].copy_from_slice(&[0x82, (length >> 8) as u8, length as u8]);
        *at += 3;
    }
}

fn encode_public(modulus: &[u8], output: &mut [u8; PUBLIC_MAX]) -> Result<usize> {
    if !matches!(modulus.len(), 128 | 256) { return Err(Error::Format); }
    let n_length = modulus.len() + 1;
    let n_header = if n_length < 256 { 2 } else { 3 };
    let body = 1 + n_header + n_length + 5;
    let mut at = 0;
    output[at] = 0x30; at += 1;
    put_length(output, &mut at, body);
    output[at] = 2; at += 1;
    put_length(output, &mut at, n_length);
    output[at] = 0; at += 1;
    output[at..at + modulus.len()].copy_from_slice(modulus); at += modulus.len();
    output[at..at + 5].copy_from_slice(&[2, 3, 1, 0, 1]); at += 5;
    Ok(at)
}

fn public_modulus<'a>(heap: &'a Heap, key: u16) -> Result<&'a [u8]> {
    let bits = word_field(heap, key, SIZE)? as usize;
    let material = heap.get_word(key, MATERIAL)?;
    heap.byte_slice(material, 0, bits / 8)
}

pub(super) fn initialized(heap: &Heap, key: u16) -> Result<bool> {
    Ok(match word_field(heap, key, KIND)? {
        4 => word_field(heap, key, READY)? == 3,
        6 => word_field(heap, key, READY)? == 1,
        _ => false,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn key_call(class: ClassId, method: MethodId, heap: &mut Heap,
    frame: &mut Frame, context: heap::Context) -> Result<Option<Native>> {
    if !matches!(class, ClassId::RSAPublicKey | ClassId::RSAPrivateKey
        | ClassId::RSAPrivateCrtKey) { return Ok(None); }
    if class != ClassId::RSAPublicKey && matches!(method,
        MethodId::setModulus | MethodId::setExponent | MethodId::setP | MethodId::setQ
        | MethodId::setDP1 | MethodId::setDQ1 | MethodId::setPQ) {
        for _ in 0..4 { frame.pop_raw()?; }
        return crypto_exception(heap, context, 5).map(Some);
    }
    if method == MethodId::clearKey && class == ClassId::RSAPublicKey {
        let key = frame.pop_reference()?;
        heap.check_access(key, context)?;
        let modulus = heap.get_word(key, MATERIAL)?;
        let exponent = heap.get_word(key, PENDING)?;
        let mut writes = [(key, READY * 2, 2); 3];
        let mut count = 1;
        for array in [modulus, exponent] {
            if array != NULL {
                let length = heap.info(array)?.length as usize;
                writes[count] = (array, 0, length); count += 1;
            }
        }
        heap.prepare_payload_writes(&writes[..count])?;
        for array in [modulus, exponent] {
            if array != NULL {
                let length = heap.info(array)?.length as usize;
                heap.byte_slice_mut(array, 0, length)?.fill(0);
            }
        }
        heap.put_word(key, READY, 0)?;
        return Ok(Some(Native::Returned));
    }
    let setter = matches!(method, MethodId::setModulus | MethodId::setExponent);
    let getter = matches!(method, MethodId::getModulus | MethodId::getExponent
        | MethodId::getP | MethodId::getQ | MethodId::getDP1 | MethodId::getDQ1 | MethodId::getPQ);
    if !setter && !getter { return Ok(None); }
    if setter {
        let length = frame.pop_short()?;
        let offset = frame.pop_short()?;
        let source = frame.pop_reference()?;
        let key = frame.pop_reference()?;
        heap.check_access(key, context)?;
        heap.check_access(source, context)?;
        if class != ClassId::RSAPublicKey || offset < 0 || length < 0 {
            return crypto_exception(heap, context, 5).map(Some);
        }
        let modulus = method == MethodId::setModulus;
        let bits = word_field(heap, key, SIZE)? as usize;
        let expected = if modulus { bits / 8 } else { 3 };
        if length as usize != expected { return crypto_exception(heap, context, 1).map(Some); }
        let source = heap.byte_slice(source, offset as usize, expected)?;
        if if modulus { source[0] & 0x80 == 0 || source[expected - 1] & 1 == 0 }
            else { source != [1, 0, 1] } {
            return crypto_exception(heap, context, 1).map(Some);
        }
        let mut staging = Zeroizing::new([0u8; 256]);
        staging[..expected].copy_from_slice(source);
        let field = if modulus { MATERIAL } else { PENDING };
        let old = heap.get_word(key, field)?;
        if old == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, expected as u16)])?;
            heap.prepare_payload_writes(&[(key, field * 2, 2), (key, READY * 2, 2)])?;
        } else {
            heap.byte_slice(old, 0, expected)?;
            heap.prepare_payload_writes(&[(old, 0, expected), (key, READY * 2, 2)])?;
        }
        let array = if old == NULL {
            let array = heap.new_array(heap::KIND_BYTE, expected as u16, context)?;
            heap.put_word(key, field, array)?;
            array
        } else { old };
        heap.byte_slice_mut(array, 0, expected)?.copy_from_slice(&staging[..expected]);
        let mask = if modulus { 1 } else { 2 };
        heap.put_word(key, READY, word_field(heap, key, READY)? | mask)?;
        return Ok(Some(Native::Returned));
    }
    let offset = frame.pop_short()?;
    let destination = frame.pop_reference()?;
    let key = frame.pop_reference()?;
    heap.check_access(key, context)?;
    heap.check_access(destination, context)?;
    if offset < 0 { return Err(Error::Bounds); }
    if !initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
    let bytes = if class == ClassId::RSAPublicKey {
        if method == MethodId::getModulus {
            public_modulus(heap, key)?
        } else if method == MethodId::getExponent {
            heap.byte_slice(heap.get_word(key, PENDING)?, 0, 3)?
        } else { return crypto_exception(heap, context, 5).map(Some); }
    } else if class == ClassId::RSAPrivateCrtKey {
        let index = match method {
            MethodId::getP => 3, MethodId::getQ => 4,
            MethodId::getDP1 => 5, MethodId::getDQ1 => 6, MethodId::getPQ => 7,
            _ => return crypto_exception(heap, context, 5).map(Some),
        };
        private_part(stored_private(heap, key)?, index).ok_or(Error::Format)?
    } else { return crypto_exception(heap, context, 5).map(Some); };
    let mut staging = Zeroizing::new([0u8; 256]);
    let length = bytes.len();
    staging[..length].copy_from_slice(bytes);
    heap.byte_slice_mut(destination, offset as usize, length)?
        .copy_from_slice(&staging[..length]);
    frame.push_short(length as i16)?;
    Ok(Some(Native::Returned))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn key_pair_call(method: MethodId, signature: Signature, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, context: heap::Context,
    budget: &mut u32) -> Result<Option<Native>> {
    if method == MethodId::Constructor {
        let (this, public, private, bits) = if signature.key_pair_references() {
            let private = frame.pop_reference()?;
            let public = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if word_field(heap, public, KIND)? != 4 || word_field(heap, private, KIND)? != 6 {
                frame.push_reference(this)?;
                frame.push_reference(public)?;
                frame.push_reference(private)?;
                return Ok(None);
            }
            let bits = word_field(heap, public, SIZE)?;
            if bits != word_field(heap, private, SIZE)? || !matches!(bits, 1024 | 2048)
                || !host.supports_rsa_keygen() {
                return crypto_exception(heap, context, 3).map(Some);
            }
            for key in [this, public, private] { heap.check_access(key, context)?; }
            (this, public, private, bits)
        } else {
            let bits = frame.pop_short()?;
            let algorithm = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if algorithm != 2 {
                frame.push_reference(this)?;
                frame.push_short(algorithm)?;
                frame.push_short(bits)?;
                return Ok(None);
            }
            if !matches!(bits, 1024 | 2048) || !host.supports_rsa_keygen() {
                return crypto_exception(heap, context, 3).map(Some);
            }
            heap.check_access(this, context)?;
            heap.check_allocations(&[(heap::KIND_OBJECT, STATE_WORDS); 2])?;
            heap.prepare_payload_writes(&[(this, KIND * 2, 6), (this, PENDING * 2, 2)])?;
            let public = new_native(heap, ClassId::RSAPublicKey, STATE_WORDS, context)?;
            let private = new_native(heap, ClassId::RSAPrivateCrtKey, STATE_WORDS, context)?;
            for (key, kind) in [(public, 4), (private, 6)] {
                heap.put_word(key, KIND, kind)?;
                heap.put_word(key, SIZE, bits as u16)?;
            }
            (this, public, private, bits as u16)
        };
        heap.prepare_payload_writes(&[(this, KIND * 2, 6), (this, PENDING * 2, 2)])?;
        heap.put_word(this, KIND, 2)?;
        heap.put_word(this, SIZE, bits)?;
        heap.put_word(this, MATERIAL, public)?;
        heap.put_word(this, PENDING, private)?;
        return Ok(Some(Native::Returned));
    }
    if !matches!(method, MethodId::getPublic | MethodId::getPrivate | MethodId::genKeyPair) {
        return Ok(None);
    }
    let this = frame.peek_reference(0)?;
    if word_field(heap, this, KIND)? != 2 { return Ok(None); }
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    let public = heap.get_word(this, MATERIAL)?;
    let private = heap.get_word(this, PENDING)?;
    if method != MethodId::genKeyPair {
        frame.push_reference(if method == MethodId::getPublic { public } else { private })?;
        return Ok(Some(Native::Returned));
    }
    for key in [public, private] { heap.check_access(key, context)?; }
    let bits = word_field(heap, this, SIZE)? as usize;
    *budget = budget.checked_sub((bits / 8 + PRIVATE_BYTES + 3) as u32).ok_or(Error::Quota)?;
    let fields = [(public, MATERIAL, bits / 8), (public, PENDING, 3),
        (private, MATERIAL, PRIVATE_BYTES)];
    let mut allocations = [(heap::KIND_BYTE, 0); 3];
    let mut alloc_count = 0;
    let mut writes = [(0, 0, 0); 5];
    let mut write_count = 0;
    for (key, field, length) in fields {
        let current = heap.get_word(key, field)?;
        if current == NULL {
            allocations[alloc_count] = (heap::KIND_BYTE, length as u16); alloc_count += 1;
            writes[write_count] = (key, field * 2, 2);
        } else {
            heap.byte_slice(current, 0, length)?;
            writes[write_count] = (current, 0, length);
        }
        write_count += 1;
    }
    writes[write_count] = (public, READY * 2, 2); write_count += 1;
    writes[write_count] = (private, READY * 2, 2); write_count += 1;
    heap.check_allocations(&allocations[..alloc_count])?;
    heap.prepare_payload_writes(&writes[..write_count])?;
    let mut private_der = Zeroizing::new([0u8; PRIVATE_BYTES - 2]);
    let mut public_der = Zeroizing::new([0u8; PUBLIC_MAX]);
    let (private_len, public_len) = host.rsa_generate(bits, &mut private_der[..], &mut public_der[..])?;
    if private_len == 0 || private_len > private_der.len() || public_len == 0
        || public_len > public_der.len() { return Err(Error::Format); }
    let (n, e) = public_parts(&public_der[..public_len]).ok_or(Error::Format)?;
    if n.len() != bits / 8 || e != [1, 0, 1] { return Err(Error::Format); }
    let (private_n, private_e) = private_public_parts(&private_der[..private_len])
        .ok_or(Error::Format)?;
    if private_n != n || private_e != e { return Err(Error::Format); }
    let mut references = [NULL; 3];
    for (index, (key, field, length)) in fields.into_iter().enumerate() {
        let current = heap.get_word(key, field)?;
        references[index] = if current == NULL {
            let array = heap.new_array(heap::KIND_BYTE, length as u16, context)?;
            heap.put_word(key, field, array)?;
            array
        } else { current };
    }
    heap.byte_slice_mut(references[0], 0, n.len())?.copy_from_slice(n);
    heap.byte_slice_mut(references[1], 0, 3)?.copy_from_slice(e);
    let stored = heap.byte_slice_mut(references[2], 0, PRIVATE_BYTES)?;
    stored.fill(0);
    stored[..2].copy_from_slice(&(private_len as u16).to_be_bytes());
    stored[2..2 + private_len].copy_from_slice(&private_der[..private_len]);
    heap.put_word(public, READY, 3)?;
    heap.put_word(private, READY, 1)?;
    Ok(Some(Native::Returned))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn signature_call(method: MethodId, signature: Signature, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, context: heap::Context,
    budget: &mut u32) -> Result<Option<Native>> {
    if method == MethodId::setInitialDigest {
        for _ in 0..7 { frame.pop_raw()?; }
        return crypto_exception(heap, context, 5).map(Some);
    }
    if matches!(method, MethodId::getAlgorithm | MethodId::getMessageDigestAlgorithm
        | MethodId::getCipherAlgorithm | MethodId::getPaddingAlgorithm) {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        frame.push_short(match method {
            MethodId::getAlgorithm => 40,
            MethodId::getMessageDigestAlgorithm => 4,
            MethodId::getCipherAlgorithm => 3,
            MethodId::getPaddingAlgorithm => 7,
            _ => unreachable!(),
        })?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::init {
        if signature.init_vector() {
            frame.pop_short()?; frame.pop_short()?; frame.pop_reference()?;
        }
        let mode = frame.pop_short()?;
        let key = frame.pop_reference()?;
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        heap.check_access(key, context)?;
        let kind = word_field(heap, key, KIND)?;
        let bits = word_field(heap, key, SIZE)?;
        if signature.init_vector() || word_field(heap, this, KIND)? != 40
            || !matches!(bits, 1024 | 2048)
            || !((mode == 1 && kind == 6) || (mode == 2 && kind == 4)) {
            return crypto_exception(heap, context, 1).map(Some);
        }
        if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
        let state = heap.get_word(this, PENDING)?;
        if state == NULL {
            heap.check_allocations(&[(heap::KIND_BYTE, SHA256_STATE_BYTES as u16)])?;
        } else { heap.byte_slice(state, 0, SHA256_STATE_BYTES)?; }
        heap.prepare_payload_writes(&[(this, MATERIAL * 2, (PENDING + 1 - MATERIAL) * 2)])?;
        let state = if state == NULL {
            heap.new_transient_array(heap::KIND_BYTE, SHA256_STATE_BYTES as u16,
                context, heap::CLEAR_ON_RESET)?
        } else { state };
        heap.byte_slice_mut(state, 0, SHA256_STATE_BYTES)?.fill(0);
        heap.put_word(this, PENDING, state)?;
        heap.put_word(this, MATERIAL, key)?;
        heap.put_word(this, COUNTER, mode as u16)?;
        heap.put_word(this, READY, 1)?;
        return Ok(Some(Native::Returned));
    }
    if method == MethodId::getLength {
        let this = frame.pop_reference()?;
        heap.check_access(this, context)?;
        if word_field(heap, this, READY)? != 1 { return crypto_exception(heap, context, 4).map(Some); }
        let key = heap.get_word(this, MATERIAL)?;
        if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
        frame.push_short((word_field(heap, key, SIZE)? / 8) as i16)?;
        return Ok(Some(Native::Returned));
    }
    let update = method == MethodId::update;
    let verify = matches!(method, MethodId::verify | MethodId::verifyPreComputedHash);
    let prehashed = matches!(method, MethodId::signPreComputedHash
        | MethodId::verifyPreComputedHash);
    if !update && !verify && !matches!(method, MethodId::sign | MethodId::signPreComputedHash) {
        return Ok(None);
    }
    let signature_length = if verify { frame.pop_short()? } else { 0 };
    let (signature_array, signature_offset) = if update { (NULL, 0) }
        else { let offset = frame.pop_short()?; (frame.pop_reference()?, offset) };
    let length = frame.pop_short()?;
    let offset = frame.pop_short()?;
    let input = frame.pop_reference()?;
    let this = frame.pop_reference()?;
    heap.check_access(this, context)?;
    heap.check_access(input, context)?;
    if word_field(heap, this, READY)? != 1
        || (!update && word_field(heap, this, COUNTER)? != if verify { 2 } else { 1 }) {
        return crypto_exception(heap, context, 4).map(Some);
    }
    let key = heap.get_word(this, MATERIAL)?;
    heap.check_access(key, context)?;
    if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2).map(Some); }
    if length < 0 || offset < 0 || signature_offset < 0 || signature_length < 0 {
        return Err(Error::Bounds);
    }
    if prehashed && length != 32 { return crypto_exception(heap, context, 5).map(Some); }
    let key_bits = word_field(heap, key, SIZE)? as usize;
    let output_length = key_bits / 8;
    if !update {
        heap.check_access(signature_array, context)?;
        heap.byte_slice(signature_array, signature_offset as usize,
            if verify { signature_length as usize } else { output_length })?;
    }
    let input = heap.byte_slice(input, offset as usize, length as usize)?;
    *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
    let pending = heap.get_word(this, PENDING)?;
    let mut state = Zeroizing::new([0u8; SHA256_STATE_BYTES]);
    state.copy_from_slice(heap.byte_slice(pending, 0, SHA256_STATE_BYTES)?);
    let mut digest = Zeroizing::new([0u8; 32]);
    if prehashed { digest.copy_from_slice(input); state.fill(0); }
    else { host.sha256_stream(&mut state, input,
        if update { None } else { Some(&mut digest) })?; }
    if update {
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.copy_from_slice(&state[..]);
        return Ok(Some(Native::Returned));
    }
    if verify {
        let valid = if signature_length as usize != output_length { false } else {
            let modulus = public_modulus(heap, key)?;
            let mut public_der = Zeroizing::new([0u8; PUBLIC_MAX]);
            let der_length = encode_public(modulus, &mut public_der)?;
            let signature = heap.byte_slice(signature_array, signature_offset as usize, output_length)?;
            host.rsa_pkcs1v15_sha256_verify(&public_der[..der_length], key_bits, &digest, signature)?
        };
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(i16::from(valid))?;
    } else {
        let private_der = stored_private(heap, key)?;
        let mut encoded = Zeroizing::new([0u8; 256]);
        host.rsa_pkcs1v15_sha256_sign(private_der, key_bits, &digest,
            &mut encoded[..output_length])?;
        heap.byte_slice_mut(signature_array, signature_offset as usize, output_length)?
            .copy_from_slice(&encoded[..output_length]);
        heap.byte_slice_mut(pending, 0, SHA256_STATE_BYTES)?.fill(0);
        frame.push_short(output_length as i16)?;
    }
    Ok(Some(Native::Returned))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVATE: &[u8] = include_bytes!("../../../../microcard-tiny-crypto/testdata/rsa/private1024.der");
    const PUBLIC: &[u8] = include_bytes!("../../../../microcard-tiny-crypto/testdata/rsa/public1024.der");
    const PRIVATE_2048: &[u8] = include_bytes!("../../../../microcard-tiny-crypto/testdata/rsa/private2048.der");
    const PUBLIC_2048: &[u8] = include_bytes!("../../../../microcard-tiny-crypto/testdata/rsa/public2048.der");

    struct Provider { fail_sign: bool, bad_der: bool }
    impl crate::host::Host for Provider {
        fn supports_rsa_keygen(&self) -> bool { true }
        fn rsa_generate(&mut self, bits: usize, private: &mut [u8],
            public: &mut [u8]) -> Result<(usize, usize)> {
            let (private_key, public_key) = match bits {
                1024 => (PRIVATE, PUBLIC),
                2048 => (PRIVATE_2048, PUBLIC_2048),
                _ => return Err(Error::Unsupported),
            };
            private[..private_key.len()].copy_from_slice(private_key);
            public[..public_key.len()].copy_from_slice(public_key);
            if self.bad_der {
                private[private_key.len()] = 0;
                return Ok((private_key.len() + 1, public_key.len()));
            }
            Ok((private_key.len(), public_key.len()))
        }
        fn sha256_stream(&mut self, state: &mut [u8; SHA256_STATE_BYTES],
            input: &[u8], output: Option<&mut [u8; 32]>) -> Result<()> {
            for byte in input { state[0] = state[0].wrapping_add(*byte); }
            if let Some(output) = output {
                output.fill(state[0]);
                state.fill(0);
            }
            Ok(())
        }
        fn rsa_pkcs1v15_sha256_sign(&mut self, _: &[u8], _: usize,
            hash: &[u8; 32], signature: &mut [u8]) -> Result<()> {
            if self.fail_sign { signature.fill(0x42); return Err(Error::Unauthorized); }
            signature.fill(hash[0]);
            Ok(())
        }
        fn rsa_pkcs1v15_sha256_verify(&mut self, _: &[u8], _: usize,
            hash: &[u8; 32], signature: &[u8]) -> Result<bool> {
            Ok(signature.iter().all(|byte| *byte == hash[0]))
        }
    }

    fn method_signature(class: ClassId, method: MethodId, plain: bool) -> Signature {
        crate::jcvm_api::PACKAGES.iter().flat_map(|package| package.classes)
            .find(|entry| entry.id == class).unwrap().methods.iter()
            .find(|entry| entry.id == method &&
                (method != MethodId::Constructor || entry.signature.key_pair_references() != plain)
                && (method != MethodId::init || entry.signature.init_vector() != plain))
            .unwrap().signature
    }

    #[test]
    fn generated_crt_pair_imported_public_and_signature_survive_reset() {
        let mut slab = [0u8; 8192];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut host = Provider { fail_sign: false, bad_der: true };
        let pair = new_native(&mut heap, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        let mut words = [0u16; 16];
        let mut tags = [0u8; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let pair_signature = method_signature(ClassId::KeyPair, MethodId::Constructor, true);
        frame.push_reference(pair).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(1024).unwrap();
        assert!(matches!(key_pair_call(MethodId::Constructor, pair_signature,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        let public = heap.get_word(pair, MATERIAL).unwrap();
        let private = heap.get_word(pair, PENDING).unwrap();
        frame.push_reference(pair).unwrap();
        assert!(matches!(key_pair_call(MethodId::genKeyPair, pair_signature,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Err(Error::Format)));
        assert!(!initialized(&heap, public).unwrap());
        assert!(!initialized(&heap, private).unwrap());
        host.bad_der = false;
        frame.push_reference(pair).unwrap();
        assert!(matches!(key_pair_call(MethodId::genKeyPair, pair_signature,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        assert!(initialized(&heap, public).unwrap());
        assert!(initialized(&heap, private).unwrap());
        assert_eq!(stored_private(&heap, private).unwrap(), PRIVATE);
        let (n, _) = public_parts(PUBLIC).unwrap();
        assert_eq!(public_modulus(&heap, public).unwrap(), n);

        let imported = new_native(&mut heap, ClassId::RSAPublicKey, STATE_WORDS, 1).unwrap();
        heap.put_word(imported, KIND, 4).unwrap();
        heap.put_word(imported, SIZE, 1024).unwrap();
        let source = heap.new_array(heap::KIND_BYTE, 128, 1).unwrap();
        heap.byte_slice_mut(source, 0, 128).unwrap().copy_from_slice(n);
        frame.push_reference(imported).unwrap();
        frame.push_reference(source).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(128).unwrap();
        assert!(matches!(key_call(ClassId::RSAPublicKey, MethodId::setModulus,
            &mut heap, &mut frame, 1), Ok(Some(Native::Returned))));
        assert!(!initialized(&heap, imported).unwrap());
        heap.byte_slice_mut(source, 0, 3).unwrap().copy_from_slice(&[1, 0, 1]);
        frame.push_reference(imported).unwrap();
        frame.push_reference(source).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(3).unwrap();
        assert!(matches!(key_call(ClassId::RSAPublicKey, MethodId::setExponent,
            &mut heap, &mut frame, 1), Ok(Some(Native::Returned))));
        assert!(initialized(&heap, imported).unwrap());

        let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
        heap.put_word(signer, KIND, 40).unwrap();
        let init = method_signature(ClassId::Signature, MethodId::init, true);
        let data = heap.new_array(heap::KIND_BYTE, 256, 1).unwrap();
        heap.byte_slice_mut(data, 0, 3).unwrap().copy_from_slice(b"abc");
        frame.push_reference(signer).unwrap();
        frame.push_reference(private).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(signature_call(MethodId::init, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        frame.push_reference(signer).unwrap();
        frame.push_reference(data).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(signature_call(MethodId::update, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        heap.byte_slice_mut(data, 128, 128).unwrap().fill(0xaa);
        host.fail_sign = true;
        for fail in [true, false] {
            frame.push_reference(signer).unwrap();
            frame.push_reference(data).unwrap();
            frame.push_short(2).unwrap();
            frame.push_short(1).unwrap();
            frame.push_reference(data).unwrap();
            frame.push_short(128).unwrap();
            let result = signature_call(MethodId::sign, init, &mut heap, &mut host,
                &mut frame, 1, &mut 4096);
            if fail {
                assert!(matches!(result, Err(Error::Unauthorized)));
                assert_eq!(heap.byte_slice(data, 128, 128).unwrap(), &[0xaa; 128]);
                host.fail_sign = false;
            } else {
                assert!(matches!(result, Ok(Some(Native::Returned))));
                assert_eq!(frame.pop_short(), Ok(128));
            }
        }
        let expected = b"abc".iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        assert_eq!(heap.byte_slice(data, 128, 128).unwrap(), &[expected; 128]);
        heap.clear_transient(heap::CLEAR_ON_RESET, 1).unwrap();
        assert!(initialized(&heap, private).unwrap());
        assert!(initialized(&heap, imported).unwrap());
        frame.push_reference(signer).unwrap();
        frame.push_reference(imported).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(signature_call(MethodId::init, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        frame.push_reference(signer).unwrap();
        frame.push_reference(data).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(3).unwrap();
        frame.push_reference(data).unwrap();
        frame.push_short(128).unwrap();
        frame.push_short(128).unwrap();
        assert!(matches!(signature_call(MethodId::verify, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        assert_eq!(frame.pop_short(), Ok(1));
        let image = heap.image();
        for (key, class) in [(pair, ClassId::KeyPair), (public, ClassId::RSAPublicKey),
            (private, ClassId::RSAPrivateCrtKey), (signer, ClassId::Signature)] {
            let payload = &image[key as usize + heap::HEADER..key as usize + heap::HEADER + 12];
            assert_eq!(saved_state::validate_saved_security(class, payload, image), Ok(()));
        }
    }

    #[test]
    fn rsa_2048_generation_and_prehashed_sign_verify() {
        let mut slab = [0u8; 8192];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut host = Provider { fail_sign: false, bad_der: false };
        let mut words = [0u16; 16];
        let mut tags = [0u8; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        let pair = new_native(&mut heap, ClassId::KeyPair, STATE_WORDS, 1).unwrap();
        let pair_signature = method_signature(ClassId::KeyPair, MethodId::Constructor, true);
        frame.push_reference(pair).unwrap();
        frame.push_short(2).unwrap();
        frame.push_short(2048).unwrap();
        assert!(matches!(key_pair_call(MethodId::Constructor, pair_signature,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        frame.push_reference(pair).unwrap();
        assert!(matches!(key_pair_call(MethodId::genKeyPair, pair_signature,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        let private = heap.get_word(pair, PENDING).unwrap();
        let public = heap.get_word(pair, MATERIAL).unwrap();
        assert_eq!(stored_private(&heap, private).unwrap(), PRIVATE_2048);
        let signer = new_native(&mut heap, ClassId::Signature, STATE_WORDS, 1).unwrap();
        heap.put_word(signer, KIND, 40).unwrap();
        let init = method_signature(ClassId::Signature, MethodId::init, true);
        let array = heap.new_array(heap::KIND_BYTE, 320, 1).unwrap();
        heap.byte_slice_mut(array, 0, 32).unwrap().fill(0x11);
        frame.push_reference(signer).unwrap();
        frame.push_reference(private).unwrap();
        frame.push_short(1).unwrap();
        assert!(matches!(signature_call(MethodId::init, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        frame.push_reference(signer).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(32).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(64).unwrap();
        assert!(matches!(signature_call(MethodId::signPreComputedHash, init,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        assert_eq!(frame.pop_short(), Ok(256));
        frame.push_reference(signer).unwrap();
        frame.push_reference(public).unwrap();
        frame.push_short(2).unwrap();
        assert!(matches!(signature_call(MethodId::init, init, &mut heap, &mut host,
            &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        frame.push_reference(signer).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(32).unwrap();
        frame.push_reference(array).unwrap();
        frame.push_short(64).unwrap();
        frame.push_short(256).unwrap();
        assert!(matches!(signature_call(MethodId::verifyPreComputedHash, init,
            &mut heap, &mut host, &mut frame, 1, &mut 4096), Ok(Some(Native::Returned))));
        assert_eq!(frame.pop_short(), Ok(1));
        let image = heap.image();
        for (key, class) in [(pair, ClassId::KeyPair), (public, ClassId::RSAPublicKey),
            (private, ClassId::RSAPrivateCrtKey), (signer, ClassId::Signature)] {
            let payload = &image[key as usize + heap::HEADER..key as usize + heap::HEADER + 12];
            assert_eq!(saved_state::validate_saved_security(class, payload, image), Ok(()));
        }
    }

    #[test]
    fn raw_private_import_is_rejected_as_unsupported() {
        let mut slab = [0u8; 512];
        let mut heap = Heap::new(&mut slab).unwrap();
        let mut words = [0u16; 16];
        let mut tags = [0u8; 8];
        let mut frame = Frame::new(&mut words, &mut tags, 0, 8).unwrap();
        frame.push_short(6).unwrap();
        frame.push_short(1024).unwrap();
        frame.push_short(0).unwrap();
        let Native::Threw(exception) = key::call(ClassId::KeyBuilder, MethodId::buildKey,
            &mut heap, &mut Provider { fail_sign: false, bad_der: false }, &mut frame, 1).unwrap()
            else { panic!("CRT import was advertised"); };
        assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(3));

        let private = new_native(&mut heap, ClassId::RSAPrivateCrtKey, STATE_WORDS, 1).unwrap();
        let source = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        frame.push_reference(private).unwrap();
        frame.push_reference(source).unwrap();
        frame.push_short(0).unwrap();
        frame.push_short(64).unwrap();
        let Some(Native::Threw(exception)) = key_call(ClassId::RSAPrivateCrtKey,
            MethodId::setP, &mut heap, &mut frame, 1).unwrap() else {
            panic!("CRT setter was accepted");
        };
        assert_eq!(heap.get_word(exception, crate::natives::REASON_FIELD), Ok(5));
    }
}
