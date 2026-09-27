use super::*;

const STATE_BYTES: usize = 2 + 256;

pub(super) fn init(heap: &mut Heap, host: &dyn crate::host::Host,
    this: u16, key: u16, mode: i16, has_iv: bool, context: heap::Context) -> Result<Native> {
    heap.check_access(key, context)?;
    let class = super::super::api_class(heap.info(key)?.class).map(|class| class.id);
    let private = class == Some(ClassId::RSAPrivateCrtKey) && word_field(heap, key, KIND)? == 6;
    let public = class == Some(ClassId::RSAPublicKey) && word_field(heap, key, KIND)? == 4;
    let bits = word_field(heap, key, SIZE)?;
    if has_iv || !matches!(mode, 1 | 2) || !(private || public)
        || !matches!(bits, 1024 | 2048) || !host.supports_cipher(12) {
        return crypto_exception(heap, context, 1);
    }
    if !rsa::initialized(heap, key)? { return crypto_exception(heap, context, 2); }
    let pending = heap.get_word(this, PENDING)?;
    heap.byte_slice(pending, 0, STATE_BYTES)?;
    heap.prepare_payload_writes(&[(this, MATERIAL * 2, (COUNTER + 1 - MATERIAL) * 2)])?;
    heap.byte_slice_mut(pending, 0, STATE_BYTES)?.fill(0);
    heap.put_word(this, MATERIAL, key)?;
    heap.put_word(this, COUNTER, mode as u16)?;
    heap.put_word(this, READY, 1)?;
    Ok(Native::Returned)
}

pub(super) struct Request {
    pub this: u16,
    pub input: u16,
    pub offset: i16,
    pub length: i16,
    pub output: u16,
    pub out_offset: i16,
}

pub(super) fn process(method: MethodId, heap: &mut Heap,
    host: &mut dyn crate::host::Host, frame: &mut Frame, request: Request,
    context: heap::Context, budget: &mut u32) -> Result<Native> {
    let Request { this, input, offset, length, output, out_offset } = request;
    if word_field(heap, this, READY)? == 0 { return crypto_exception(heap, context, 4); }
    let key = heap.get_word(this, MATERIAL)?;
    for reference in [key, input, output] { heap.check_access(reference, context)?; }
    if !rsa::initialized(heap, key)? { return crypto_exception(heap, context, 2); }
    if offset < 0 || length < 0 || out_offset < 0 { return Err(Error::Bounds); }
    let bits = word_field(heap, key, SIZE)? as usize;
    if !matches!(bits, 1024 | 2048) { return Err(Error::Format); }
    let width = bits / 8;
    let pending = heap.get_word(this, PENDING)?;
    let state = heap.byte_slice(pending, 0, STATE_BYTES)?;
    let count = u16::from_be_bytes([state[0], state[1]]) as usize;
    if count > width { return Err(Error::Format); }
    let total = count.checked_add(length as usize).ok_or(Error::Bounds)?;
    heap.byte_slice(input, offset as usize, length as usize)?;
    if total > width { return crypto_exception(heap, context, 5); }
    *budget = budget.checked_sub((total + width) as u32).ok_or(Error::Quota)?;
    if method == MethodId::update {
        heap.copy_bytes(input, offset as usize, pending, 2 + count, length as usize)?;
        heap.byte_slice_mut(pending, 0, 2)?.copy_from_slice(&(total as u16).to_be_bytes());
        frame.push_short(0)?;
        return Ok(Native::Returned);
    }
    if total != width { return crypto_exception(heap, context, 5); }
    heap.byte_slice(output, out_offset as usize, width)?;
    let mut message = Zeroizing::new([0u8; 256]);
    message[..count].copy_from_slice(&state[2..2 + count]);
    message[count..width].copy_from_slice(heap.byte_slice(input, offset as usize, length as usize)?);
    let kind = word_field(heap, key, KIND)?;
    let mut public_der = Zeroizing::new([0u8; rsa::PUBLIC_MAX]);
    let private_der = if kind == 6 { Some(rsa::stored_private(heap, key)?) } else { None };
    let modulus = if let Some(private) = private_der {
        rsa::private_public_parts(private).ok_or(Error::Format)?.0
    } else {
        rsa::public_modulus(heap, key)?
    };
    if &message[..width] >= modulus { return crypto_exception(heap, context, 5); }
    let mut result = Zeroizing::new([0u8; 256]);
    if let Some(private) = private_der {
        host.rsa_raw_private(private, bits, &message[..width], &mut result[..width])?;
    } else {
        let public_len = rsa::encode_public(modulus, &mut public_der)?;
        host.rsa_raw_public(&public_der[..public_len], bits,
            &message[..width], &mut result[..width])?;
    }
    heap.byte_slice_mut(output, out_offset as usize, width)?.copy_from_slice(&result[..width]);
    heap.byte_slice_mut(pending, 0, STATE_BYTES)?.fill(0);
    frame.push_short(width as i16)?;
    Ok(Native::Returned)
}
