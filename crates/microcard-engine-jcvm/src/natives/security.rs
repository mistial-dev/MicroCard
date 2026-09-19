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

/// Words every object here carries. The meaning of each is per class and documented where
/// it is read, because these are not fields an applet can see.
pub const STATE_WORDS: u16 = 6;

/// Field zero of a key or a PIN, which is what kind it is.
const KIND: usize = 0;
/// Field one, a length in bits for a key and a try limit for a PIN.
const SIZE: usize = 1;
/// Field two, the array holding the material or the PIN.
const MATERIAL: usize = 2;
/// Field three, whether a key has been set or a PIN has been verified.
const READY: usize = 3;
/// Field four, tries left on a PIN, or the padding mode of a cipher.
const COUNTER: usize = 4;
/// Reset-scoped cipher pending bytes: count followed by at most fifteen bytes.
const PENDING: usize = 5;

pub(super) fn reset_pin_validations(heap: &mut Heap) -> Result<()> {
    heap.visit_objects(|_, info, payload| {
        if info.kind == heap::KIND_OBJECT && super::api_class(info.class)
            .is_some_and(|class| class.id == ClassId::OwnerPIN) {
            payload.get_mut(READY * 2..READY * 2 + 2).ok_or(Error::Bounds)?.fill(0);
        }
        Ok(())
    })
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
    heap.put_word(exception, super::REASON_FIELD, reason)?;
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
) -> Result<Native> {
    match (class, method) {
        (ClassId::KeyBuilder, MethodId::buildKey) => {
            let _encryption = frame.pop_short()?;
            let length = frame.pop_short()?;
            let key_type = frame.pop_short()?;
            let name = key_class(key_type)?;
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
            // The material goes before the flag, so a failure between the two leaves a key
            // that says it holds nothing rather than one that says it holds something it
            // no longer does.
            let material = heap.get_word(key, MATERIAL)?;
            if material != NULL {
                let length = heap.info(material)?.length as usize;
                heap.byte_slice_mut(material, 0, length)?.fill(0);
            }
            heap.put_word(key, READY, 0)?;
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
            heap.byte_slice_mut(material, prefix, bytes)?
                .copy_from_slice(&staging[..bytes]);
            // The flag shares the clearing event and snapshot rules of the key bytes.
            if event == 0 {
                heap.put_word(this, READY, 1)?;
            } else {
                heap.byte_slice_mut(material, 0, 1)?[0] = 1;
            }
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
                heap.put_word(exception, super::REASON_FIELD, 2)?; // UNINITIALIZED_KEY
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

        (ClassId::OwnerPIN, MethodId::Constructor) => {
            let max_size = frame.pop_short()?;
            let tries = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if tries < 1 || max_size < 1 {
                return Ok(Native::Threw(super::new_exception(
                    heap,
                    ClassId::PINException,
                    context,
                )?));
            }
            let material = heap.new_array(heap::KIND_BYTE, max_size as u16, context)?;
            heap.put_word(this, KIND, tries as u16)?;
            heap.put_word(this, SIZE, 0)?;
            heap.put_word(this, MATERIAL, material)?;
            heap.put_word(this, READY, 0)?;
            heap.put_word(this, COUNTER, tries as u16)?;
        }
        (ClassId::OwnerPIN, MethodId::update) => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let source = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(source, context)?;
            let material = heap.get_word(this, MATERIAL)?;
            if length < 0 || offset < 0 || length as u16 > heap.info(material)?.length {
                return Err(Error::Bounds);
            }
            let mut staging = [0u8; 32];
            let length = length as usize;
            if length > staging.len() {
                return Err(Error::Bounds);
            }
            staging[..length].copy_from_slice(heap.byte_slice(source, offset as usize, length)?);
            heap.byte_slice_mut(material, 0, length)?
                .copy_from_slice(&staging[..length]);
            heap.put_word(this, SIZE, length as u16)?;
            // Updating resets the counter and clears the validated flag, JCRE §5.1.
            let tries = heap.get_word(this, KIND)?;
            heap.put_word(this, COUNTER, tries)?;
            heap.put_word(this, READY, 0)?;
        }
        (ClassId::OwnerPIN, MethodId::check) => {
            let length = frame.pop_short()?;
            let offset = frame.pop_short()?;
            let candidate = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            let tries = heap.get_word(this, COUNTER)?;
            if tries == 0 {
                frame.push_short(0)?;
                return Ok(Native::Returned);
            }
            // The counter is decremented before the comparison, JCRE §5.1. A card cut off
            // mid check must not give the attempt back.
            heap.put_word(this, COUNTER, tries - 1)?;
            heap.put_word(this, READY, 0)?;
            let material = heap.get_word(this, MATERIAL)?;
            let stored = heap.get_word(this, SIZE)? as usize;
            let matched = if length < 0 || offset < 0 || length as usize != stored {
                false
            } else {
                heap.check_access(candidate, context)?;
                let mut equal = true;
                for at in 0..stored {
                    let left = heap.byte_slice(material, at, 1)?[0];
                    let right = heap.byte_slice(candidate, offset as usize + at, 1)?[0];
                    equal &= left == right;
                }
                equal
            };
            if matched {
                let limit = heap.get_word(this, KIND)?;
                heap.put_word(this, COUNTER, limit)?;
                heap.put_word(this, READY, 1)?;
            }
            frame.push_short(matched as i16)?;
        }
        (ClassId::OwnerPIN, MethodId::isValidated) => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, READY)? as i16)?;
        }
        (ClassId::OwnerPIN, MethodId::getTriesRemaining) => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, COUNTER)? as i16)?;
        }
        (ClassId::OwnerPIN, MethodId::reset) => {
            let this = frame.pop_reference()?;
            // Only the validated flag, JCRE §5.1. The counter survives, which is what
            // makes a PIN retry limit mean anything across resets.
            heap.put_word(this, READY, 0)?;
        }
        (ClassId::OwnerPIN, MethodId::resetAndUnblock) => {
            let this = frame.pop_reference()?;
            let limit = heap.get_word(this, KIND)?;
            heap.put_word(this, COUNTER, limit)?;
            heap.put_word(this, READY, 0)?;
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
                    ClassId::Cipher => id == 14 && host.supports_cipher(id),
                    _ => false,
                },
                _ => false,
            };
            if !supported {
                let exception = super::new_exception(heap, ClassId::CryptoException, context)?;
                heap.put_word(exception, super::REASON_FIELD, 3)?; // NO_SUCH_ALGORITHM
                return Ok(Native::Threw(exception));
            }
            let instance = new_native(heap, class, STATE_WORDS, context)?;
            heap.put_word(instance, KIND, algorithm as u16)?;
            if class == ClassId::Cipher {
                let pending = heap.new_transient_array(heap::KIND_BYTE, 16, context, heap::CLEAR_ON_RESET)?;
                heap.put_word(instance, PENDING, pending)?;
            }
            frame.push_reference(instance)?;
        }
        (ClassId::KeyPair, MethodId::Constructor) => {
            let length = frame.pop_short()?;
            let algorithm = frame.pop_short()?;
            let this = frame.pop_reference()?;
            heap.put_word(this, KIND, algorithm as u16)?;
            heap.put_word(this, SIZE, length as u16)?;
        }
        (_, MethodId::getAlgorithm) => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, KIND)? as i16)?;
        }

        // GlobalPlatform, JCRE and GP 2.3 §6. The card content state is the applet's
        // lifecycle byte, which the runtime keeps rather than the applet.
        (ClassId::GPSystem, MethodId::getSecureChannel) => {
            // The transport's management channel is not an applet-owned channel.
            // Refuse the unavailable service with a Java exception, never a dummy handle.
            let exception = super::new_exception(heap, ClassId::SystemException, context)?;
            heap.put_word(exception, super::REASON_FIELD, 5)?; // NO_RESOURCE
            return Ok(Native::Threw(exception));
        }
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
            let mut digest = Zeroizing::new([0u8; 64]);
            let written = host.digest(
                algorithm,
                heap.byte_slice(input, offset as usize, length as usize)?,
                &mut digest[..expected],
            )?;
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
            if signature.init_vector() {
                let _length = frame.pop_short()?;
                let _offset = frame.pop_short()?;
                let _vector = frame.pop_reference()?;
                frame.pop_short()?;
                frame.pop_reference()?;
                frame.pop_reference()?;
                return crypto_exception(heap, context, 1); // ECB has no IV.
            }
            let mode = frame.pop_short()?;
            let key = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(key, context)?;
            if !matches!(mode, 1 | 2)
                || super::api_class(heap.info(key)?.class).map(|entry| entry.id) != Some(ClassId::AESKey)
                || word_field(heap, key, SIZE)? != 128 {
                return crypto_exception(heap, context, 1);
            }
            if !key_initialized(heap, key)? { return crypto_exception(heap, context, 2); }
            let pending = heap.get_word(this, PENDING)?;
            heap.byte_slice_mut(pending, 0, 16)?.fill(0);
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
            let count = prior[0] as usize;
            if count > 15 { return Err(Error::Format); }
            let total = count + length as usize;
            if method == MethodId::doFinal && !total.is_multiple_of(16) {
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
            for start in (0..written).step_by(16) {
                let mut block = Zeroizing::new([0u8; 16]);
                for (at, value) in block.iter_mut().enumerate() { *value = byte(start + at); }
                host.aes128_block(&key_bytes, &mut block, word_field(heap, this, COUNTER)? == 2)?;
                result.extend_from_slice(&block[..]);
            }
            let mut tail = Zeroizing::new([0u8; 16]);
            tail[0] = (total - written) as u8;
            for at in written..total { tail[1 + at - written] = byte(at); }
            heap.byte_slice_mut(output, out_offset as usize, written)?.copy_from_slice(&result);
            heap.byte_slice_mut(pending, 0, 16)?.copy_from_slice(&tail[..]);
            frame.push_short(written as i16)?;
        }
        // An algorithm holder remembers the key and the direction it was given, and the
        // operation itself is the host's to answer.
        (ClassId::Signature, MethodId::init)
        | (ClassId::KeyAgreement, MethodId::init) => {
            // Both forms end with the mode or the key. The longer one also carries an
            // initialisation vector, which is taken and held with the key.
            if signature.init_vector() {
                let _length = frame.pop_short()?;
                let _offset = frame.pop_short()?;
                let _vector = frame.pop_reference()?;
            }
            let mode = if signature.init_mode() {
                frame.pop_short()?
            } else {
                0
            };
            let key = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if !key_initialized(heap, key)? {
                // Initialising with a key that holds nothing would leave an instance that
                // looks ready and is not.
                return Ok(Native::Threw(super::new_exception(
                    heap,
                    ClassId::CryptoException,
                    context,
                )?));
            }
            heap.put_word(this, MATERIAL, key)?;
            heap.put_word(this, COUNTER, mode as u16)?;
            heap.put_word(this, READY, 1)?;
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
            // Straight into the applet's array, so the bytes never sit anywhere else.
            host.random(heap.byte_slice_mut(array, offset as usize, length as usize)?)?;
            if method == MethodId::nextBytes {
                // nextBytes answers nothing, generateData answers the offset past the end.
            } else {
                frame.push_short(offset.wrapping_add(length))?;
            }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
