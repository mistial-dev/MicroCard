//! `javacard.security`, `javacardx.crypto` and the PIN, JCRE §5.
//!
//! These classes are objects with state, and the state lives on the heap like any other
//! object, so the firewall covers it. What they are not is algorithms: an operation that
//! needs one asks the host. Key and PIN fields currently occupy native heap objects;
//! protected-key service integration remains separate work.
use crate::jcvm_api::{ClassId, MethodId, Signature};
use super::{Jcre, Native, new_native, word_field};
use crate::vm::frame::{Frame, NULL};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};
extern crate alloc;
use zeroize::Zeroizing;
mod ec;
mod pin;
mod agreement;
mod key_pair;
mod signature;
mod secure_channel;
pub(crate) use ec::{clear_event as ec_key_clear_event, key_kind as ec_key_kind};

/// Words every object here carries. The meaning of each is per class and documented where
/// it is read, because these are not fields an applet can see.
pub const STATE_WORDS: u16 = 6;

/// Field zero of a key or a PIN, which is what kind it is.
const KIND: usize = 0;
/// Field one, a length in bits for a key and the current PIN length.
const SIZE: usize = 1;
/// Field two, the array holding the material or the PIN.
const MATERIAL: usize = 2;
/// Field three, whether a key has been set or a PIN has been verified.
const READY: usize = 3;
/// Field four, tries left on a PIN, or the padding mode of a cipher.
const COUNTER: usize = 4;
/// Reset-scoped cipher state: count/seen-input flag, fifteen pending bytes, then CBC IV.
const PENDING: usize = 5;

pub(crate) fn native_volatile_range(info: heap::Info) -> Result<Option<core::ops::Range<usize>>> {
    if info.kind != heap::KIND_OBJECT { return Ok(None); }
    let Some(class) = super::api_class(info.class) else { return Ok(None); };
    if class.id == ClassId::OwnerPIN {
        if info.length as usize <= READY { return Err(Error::Bounds); }
        return Ok(Some(READY * 2..READY * 2 + 2));
    }
    if info.length == 1 && super::is_exception_class(class) {
        // Runtime exception reasons reset; explicit six-word exceptions persist.
        return Ok(Some(0..2));
    }
    Ok(None)
}

pub(super) fn reset_native_volatile(heap: &mut Heap) -> Result<()> {
    heap.visit_objects(|_, info, payload| {
        if let Some(range) = native_volatile_range(info)? { payload[range].fill(0); }
        Ok(())
    })
}

// Persist unconditional PIN changes without publishing conditional heap/static writes.
pub(crate) fn checkpoint_committed(heap: &mut Heap, host: &mut dyn crate::host::Host, jcre: &Jcre,
        _context: heap::Context, statics: &[u8]) -> Result<()> {
    if jcre.installing { return Ok(()); }
    let instance = jcre.instance.ok_or(Error::Missing)?;
    let mut projected = Zeroizing::new(alloc::vec::Vec::new());
    let statics = if heap.transaction_remaining().is_some() {
        projected.try_reserve_exact(statics.len()).map_err(|_| Error::Quota)?;
        projected.extend_from_slice(statics);
        heap.project_statics(&mut projected)?;
        &projected[..]
    } else { statics };
    host.checkpoint(crate::applet::PersistentView {
        heap: heap.image(), statics, instance, buffer: jcre.buffer,
        projection: Some(heap),
    })?;
    heap.mark_checkpointed();
    Ok(())
}

/// The class a `KeyBuilder` type code builds, JCRE Table 5-1.
///
/// Transient symmetric keys keep their initialized flag with their transient bytes.
fn key_class(key_type: i16) -> Result<ClassId> {
    Ok(match key_type {
        1..=3 => ClassId::DESKey,
        4 => ClassId::RSAPublicKey,
        5 | 22 | 23 => ClassId::RSAPrivateKey,
        6 | 24 | 25 => ClassId::RSAPrivateCrtKey,
        7 => ClassId::DSAPublicKey,
        8 | 26 | 27 => ClassId::DSAPrivateKey,
        9 => ClassId::ECPublicKey,
        10 | 28 | 29 => ClassId::ECPrivateKey,
        11 => ClassId::ECPublicKey,
        12 | 30 | 31 => ClassId::ECPrivateKey,
        13..=15 => ClassId::AESKey,
        19..=21 => ClassId::HMACKey,
        _ => {
            super::report("javacard/security/KeyBuilder", "buildKey of an unknown type");
            return Err(Error::Unsupported);
        }
    })
}

pub(crate) fn symmetric_key_clear_event(kind: u16) -> u8 {
    match kind {
        1 | 13 | 19 => heap::CLEAR_ON_RESET,
        2 | 14 | 20 => heap::CLEAR_ON_DESELECT,
        _ => 0,
    }
}

fn key_initialized(heap: &Heap, key: u16) -> Result<bool> {
    if ec::key_kind(word_field(heap, key, KIND)?) {
        return ec::initialized(heap, key);
    }
    if symmetric_key_clear_event(word_field(heap, key, KIND)?) == 0 {
        return Ok(word_field(heap, key, READY)? != 0);
    }
    let material = heap.get_word(key, MATERIAL)?;
    Ok(material != NULL && heap.byte_slice(material, 0, 1)?[0] == 1)
}

/// Bytes a digest algorithm produces, JCRE §5.4.
pub fn digest_length(algorithm: u8) -> Result<usize> {
    Ok(match algorithm {
        1 | 3 => 20,
        2 => 16,
        4 | 9 => 32,
        5 | 10 => 48,
        6 | 11 => 64,
        7 | 8 => 28,
        _ => return Err(Error::Unsupported),
    })
}

fn crypto_exception(heap: &mut Heap, context: heap::Context, reason: u16) -> Result<Native> {
    let exception = super::new_exception(heap, ClassId::CryptoException, context)?;
    heap.put_word_unconditional(exception, super::REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}

/// The pieces are unrelated to each other, which is why they arrive separately rather
/// than as a struct that would exist only to be passed here.
#[allow(clippy::too_many_arguments)]
pub fn call(
    class: ClassId,
    method: MethodId,
    signature: Signature,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
    budget: &mut u32,
    statics: &[u8],
) -> Result<Native> {
    if class == ClassId::OwnerPIN {
        return pin::call(method, heap, host, frame, context, jcre, statics);
    }
    if let Some(result) = ec::call(class, method, heap, host, frame, context)? { return Ok(result); }
    if class == ClassId::KeyAgreement {
        if let Some(result) = agreement::call(method, heap, host, frame, context, budget)? { return Ok(result); }
    }
    if class == ClassId::Signature {
        if let Some(result) = signature::call(method, signature, heap, host, frame, context, budget)? { return Ok(result); }
    }
    if class == ClassId::KeyPair {
        return key_pair::call(method, signature, heap, host, frame, context, budget);
    }
    if class == ClassId::SecureChannel || class == ClassId::GPSystem && method == MethodId::getSecureChannel {
        return secure_channel::call(class, method, heap, host, frame, context, jcre);
    }
    match (class, method) {
        (ClassId::KeyBuilder, MethodId::buildKey) => {
            let _encryption = frame.pop_short()?;
            let length = frame.pop_short()?;
            let key_type = frame.pop_short()?;
            let name = key_class(key_type)?;
            if matches!(key_type, 9..=12 | 28..=31)
                && (!ec::key_kind(key_type as u16) || length != 256 || _encryption != 0
                    || host.p256_parameter(0).is_none()) {
                return crypto_exception(heap, context, 3);
            }
            let key = new_native(heap, name, STATE_WORDS, context)?;
            heap.put_word(key, KIND, key_type as u16)?;
            heap.put_word(key, SIZE, length as u16)?;
            frame.push_reference(key)?;
        }
        // Every key answers what it is and how long it is, and says whether it holds
        // anything yet, JCRE §5.3.
        (name, MethodId::getSize) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, SIZE)? as i16)?;
        }
        (name, MethodId::getType) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, KIND)? as i16)?;
        }
        (name, MethodId::isInitialized) if name.is_security() => {
            let key = frame.pop_reference()?;
            frame.push_short(i16::from(key_initialized(heap, key)?))?;
        }
        (name, MethodId::clearKey) if name.is_security() => {
            let key = frame.pop_reference()?;
            let kind = word_field(heap, key, KIND)?;
            let separate_flag = !ec::key_kind(kind) && symmetric_key_clear_event(kind) == 0;
            let material = heap.get_word(key, MATERIAL)?;
            if material != NULL {
                let length = heap.info(material)?.length as usize;
                if separate_flag {
                    heap.byte_slice(material, 0, length)?;
                    heap.prepare_payload_writes(&[(key, READY * 2, 2), (material, 0, length)])?;
                }
                heap.byte_slice_mut(material, 0, length)?.fill(0);
            }
            if separate_flag { heap.put_word(key, READY, 0)?; }
        }

        // Symmetric key material, JCRE §5.3. The bytes are copied into the key's own
        // array, which the applet cannot reach, so a key never sits in a buffer the applet
        // still holds a reference to.
        (ClassId::AESKey, MethodId::setKey)
        | (ClassId::DESKey, MethodId::setKey)
        | (ClassId::HMACKey, MethodId::setKey) => {
            let length = if class == ClassId::HMACKey {
                Some(frame.pop_short()?)
            } else {
                None
            };
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(source, context)?;
            let bits = word_field(heap, this, SIZE)? as usize;
            let bytes = length.map_or(bits / 8, |value| value.max(0) as usize);
            if offset < 0 || bytes == 0 || bytes > 64 {
                return Err(Error::Bounds);
            }
            let mut staging = Zeroizing::new([0u8; 64]);
            staging[..bytes].copy_from_slice(heap.byte_slice(source, offset as usize, bytes)?);
            let event = symmetric_key_clear_event(word_field(heap, this, KIND)?);
            let prefix = usize::from(event != 0);
            let material = match heap.get_word(this, MATERIAL)? {
                NULL => {
                    let array = if event == 0 {
                        heap.new_array(heap::KIND_BYTE, bytes as u16, context)?
                    } else {
                        heap.new_transient_array(heap::KIND_BYTE, (bytes + prefix) as u16, context, event)?
                    };
                    heap.put_word(this, MATERIAL, array)?;
                    array
                }
                array => array,
            };
            // Admit bytes and readiness together, including catch-and-commit failures.
            heap.byte_slice(material, 0, bytes + prefix)?;
            if event == 0 {
                heap.prepare_payload_writes(&[(this, READY * 2, 2), (material, 0, bytes)])?;
            }
            let destination = heap.byte_slice_mut(material, 0, bytes + prefix)?;
            destination[prefix..].copy_from_slice(&staging[..bytes]);
            if event == 0 { heap.put_word(this, READY, 1)?; }
            else { destination[0] = 1; }
        }
        (ClassId::AESKey, MethodId::getKey)
        | (ClassId::DESKey, MethodId::getKey)
        | (ClassId::HMACKey, MethodId::getKey) => {
            let offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(destination, context)?;
            if !key_initialized(heap, this)? {
                let exception = super::new_exception(heap, ClassId::CryptoException, context)?;
                heap.put_word_unconditional(exception, super::REASON_FIELD, 2)?; // UNINITIALIZED_KEY
                return Ok(Native::Threw(exception));
            }
            let material = heap.get_word(this, MATERIAL)?;
            let prefix = usize::from(symmetric_key_clear_event(word_field(heap, this, KIND)?) != 0);
            let bytes = (heap.info(material)?.length as usize).checked_sub(prefix).ok_or(Error::Format)?;
            if bytes > 64 || offset < 0 { return Err(Error::Bounds); }
            let mut staging = Zeroizing::new([0u8; 64]);
            staging[..bytes].copy_from_slice(heap.byte_slice(material, prefix, bytes)?);
            heap.byte_slice_mut(destination, offset as usize, bytes)?
                .copy_from_slice(&staging[..bytes]);
            frame.push_short(bytes as i16)?;
        }

        // The algorithm holders. Each is an object carrying what it was asked for, and the
        // operation itself is the host's to answer.
        (ClassId::MessageDigest, MethodId::getInstance)
        | (ClassId::RandomData, MethodId::getInstance)
        | (ClassId::Signature, MethodId::getInstance)
        | (ClassId::KeyAgreement, MethodId::getInstance)
        | (ClassId::Cipher, MethodId::getInstance) => {
            // Every one of these takes an algorithm, and all but RandomData also take
            // whether the instance is shared.
            let external = class != ClassId::RandomData && frame.pop_short()? != 0;
            let algorithm = frame.pop_short()?;
            let supported = match u8::try_from(algorithm) {
                Ok(id) if !external => match class {
                    ClassId::MessageDigest => host.supports_digest(id),
                    ClassId::RandomData => host.supports_random(id),
                    ClassId::Cipher => matches!(id, 13 | 14) && host.supports_cipher(id),
                    ClassId::KeyAgreement => id == 3 && host.supports_agreement(id),
                    ClassId::Signature => id == 33 && host.supports_signature(id),
                    _ => false,
                },
                _ => false,
            };
            if !supported {
                let exception = super::new_exception(heap, ClassId::CryptoException, context)?;
                heap.put_word_unconditional(exception, super::REASON_FIELD, 3)?; // NO_SUCH_ALGORITHM
                return Ok(Native::Threw(exception));
            }
            let pending_bytes = (class == ClassId::Cipher).then_some(if algorithm == 13 { 32 } else { 16 });
            if let Some(bytes) = pending_bytes {
                heap.check_allocations(&[(heap::KIND_OBJECT, STATE_WORDS), (heap::KIND_BYTE, bytes)])?;
            }
            let instance = new_native(heap, class, STATE_WORDS, context)?;
            heap.put_word(instance, KIND, algorithm as u16)?;
            if let Some(bytes) = pending_bytes {
                let pending = heap.new_transient_array(heap::KIND_BYTE, bytes, context, heap::CLEAR_ON_RESET)?;
                heap.put_word(instance, PENDING, pending)?;
            }
            frame.push_reference(instance)?;
        }
        (_, MethodId::getAlgorithm) => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, KIND)? as i16)?;
        }

        // GlobalPlatform, JCRE and GP 2.3 §6. The card content state is the applet's
        // lifecycle byte, which the runtime keeps rather than the applet.
        (ClassId::GPSystem, MethodId::getCVM) => {
            let _kind = frame.pop_short()?;
            // No global PIN, JCRE leaves this optional and the applet null checks it.
            frame.push_reference(NULL)?;
        }
        (ClassId::GPSystem, MethodId::getCardContentState) => {
            frame.push_short(jcre.lifecycle as i16)?;
        }
        (ClassId::GPSystem, MethodId::setCardContentState) => {
            let state = frame.pop_short()?;
            jcre.lifecycle = state as u8;
            frame.push_short(1)?;
        }
        (ClassId::MessageDigest, MethodId::doFinal) => {
            let out_offset = frame.pop_short()?;
            let output = frame.pop_reference()?;
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let algorithm = word_field(heap, this, KIND)? as u8;
            heap.check_access(input, context)?;
            heap.check_access(output, context)?;
            if length < 0 || offset < 0 || out_offset < 0 {
                return Err(Error::Bounds);
            }
            let expected = digest_length(algorithm)?;
            // Validate before invoking the provider. Fixed scratch allows overlapping
            // input/output without copying the message or publishing partial results.
            heap.byte_slice(output, out_offset as usize, expected)?;
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            let mut digest = Zeroizing::new([0u8; 64]);
            let written = host.digest(algorithm, message, &mut digest[..expected])?;
            if written != expected {
                return Err(Error::Format);
            }
            heap.byte_slice_mut(output, out_offset as usize, written)?
                .copy_from_slice(&digest[..written]);
            frame.push_short(written as i16)?;
        }
        (ClassId::MessageDigest, MethodId::getLength) => {
            let this = frame.pop_reference()?;
            let algorithm = word_field(heap, this, KIND)? as u8;
            frame.push_short(digest_length(algorithm)? as i16)?;
        }
        (ClassId::Cipher, MethodId::init) => {
            let vector = if signature.init_vector() {
                let length = frame.pop_short()?;
                let offset = frame.pop_short()?;
                let array = frame.pop_reference()?;
                Some((array, offset, length))
            } else { None };
            let mode = frame.pop_short()?;
            let key = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let cbc = word_field(heap, this, KIND)? == 13;
            let mut iv = Zeroizing::new([0u8; 16]);
            if let Some((array, offset, length)) = vector {
                if !cbc || length != 16 { return crypto_exception(heap, context, 1); }
                if offset < 0 { return Err(Error::Bounds); }
                heap.check_access(array, context)?;
                iv.copy_from_slice(heap.byte_slice(array, offset as usize, 16)?);
            }
            heap.check_access(key, context)?;
            if !matches!(mode, 1 | 2)
                || super::api_class(heap.info(key)?.class).map(|entry| entry.id) != Some(ClassId::AESKey)
                || word_field(heap, key, SIZE)? != 128 {
                return crypto_exception(heap, context, 1);
            }
            if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2); }
            let pending = heap.get_word(this, PENDING)?;
            heap.byte_slice(pending, 0, if cbc { 32 } else { 16 })?;
            heap.prepare_payload_writes(&[(this, MATERIAL * 2, (COUNTER + 1 - MATERIAL) * 2)])?;
            heap.byte_slice_mut(pending, 0, 16)?.fill(0);
            if cbc { heap.byte_slice_mut(pending, 16, 16)?.copy_from_slice(&iv[..]); }
            heap.put_word(this, MATERIAL, key)?;
            heap.put_word(this, COUNTER, mode as u16)?;
            heap.put_word(this, READY, 1)?;
        }
        (ClassId::Cipher, MethodId::update | MethodId::doFinal) => {
            let out_offset = frame.pop_short()?;
            let output = frame.pop_reference()?;
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let input = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if word_field(heap, this, READY)? == 0 { return crypto_exception(heap, context, 4); }
            let key = heap.get_word(this, MATERIAL)?;
            heap.check_access(key, context)?;
            if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2); }
            heap.check_access(input, context)?;
            heap.check_access(output, context)?;
            if length < 0 || offset < 0 || out_offset < 0 { return Err(Error::Bounds); }
            let pending = heap.get_word(this, PENDING)?;
            let mut prior = Zeroizing::new([0u8; 16]);
            prior.copy_from_slice(heap.byte_slice(pending, 0, 16)?);
            let count = (prior[0] & 0x0f) as usize;
            if prior[0] & 0x70 != 0 { return Err(Error::Format); }
            let total = count + length as usize;
            if method == MethodId::doFinal && (!total.is_multiple_of(16) || (total == 0 && prior[0] & 0x80 == 0)) {
                return crypto_exception(heap, context, 5);
            }
            let written = total / 16 * 16;
            if written > i16::MAX as usize { return Err(Error::Bounds); }
            heap.byte_slice(output, out_offset as usize, written)?;
            let message = heap.byte_slice(input, offset as usize, length as usize)?;
            let material = heap.get_word(key, MATERIAL)?;
            let prefix = usize::from(symmetric_key_clear_event(word_field(heap, key, KIND)?) != 0);
            let mut key_bytes = Zeroizing::new([0u8; 16]);
            key_bytes.copy_from_slice(heap.byte_slice(material, prefix, 16)?);
            // Stage output only: input may overlap it at any offset. A provider failure
            // must publish neither partial ciphertext nor updated streaming state.
            *budget = budget.checked_sub(total as u32).ok_or(Error::Quota)?;
            let mut result = Zeroizing::new(alloc::vec::Vec::new());
            result.try_reserve_exact(written).map_err(|_| Error::Quota)?;
            let byte = |at: usize| if at < count { prior[1 + at] } else { message[at - count] };
            for at in 0..written { result.push(byte(at)); }
            let cbc = word_field(heap, this, KIND)? == 13;
            let encrypt = word_field(heap, this, COUNTER)? == 2;
            let mut next_iv = Zeroizing::new([0u8; 16]);
            if cbc {
                let mut iv = Zeroizing::new([0u8; 16]);
                iv.copy_from_slice(heap.byte_slice(pending, 16, 16)?);
                *next_iv = *iv;
                if written != 0 {
                    if !encrypt { next_iv.copy_from_slice(&result[written - 16..]); }
                    host.aes128_cbc(&key_bytes, &iv, &mut result, encrypt)?;
                    if encrypt { next_iv.copy_from_slice(&result[written - 16..]); }
                }
                if method == MethodId::doFinal { next_iv.fill(0); }
            } else {
                for block in result.chunks_exact_mut(16) {
                    host.aes128_block(&key_bytes, block.try_into().map_err(|_| Error::Bounds)?, encrypt)?;
                }
            }
            let mut tail = Zeroizing::new([0u8; 16]);
            tail[0] = (total - written) as u8;
            if method == MethodId::update && (total != 0 || prior[0] & 0x80 != 0) { tail[0] |= 0x80; }
            for at in written..total { tail[1 + at - written] = byte(at); }
            heap.byte_slice_mut(output, out_offset as usize, written)?.copy_from_slice(&result);
            heap.byte_slice_mut(pending, 0, 16)?.copy_from_slice(&tail[..]);
            if cbc { heap.byte_slice_mut(pending, 16, 16)?.copy_from_slice(&next_iv[..]); }
            frame.push_short(written as i16)?;
        }
        (ClassId::RandomData, MethodId::generateData)
        | (ClassId::RandomData, MethodId::nextBytes) => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let array = frame.pop_reference()?;
            frame.pop_reference()?;
            heap.check_access(array, context)?;
            if length < 0 || offset < 0 {
                return Err(Error::Bounds);
            }
            if length == 0 { return crypto_exception(heap, context, 1); }
            heap.byte_slice(array, offset as usize, length as usize)?;
            *budget = budget.checked_sub(length as u32).ok_or(Error::Quota)?;
            // Straight into the applet's array, so the bytes never sit anywhere else.
            host.random(heap.byte_slice_mut(array, offset as usize, length as usize)?)?;
            if method == MethodId::nextBytes {
                frame.push_short(offset.wrapping_add(length))?;
            }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
