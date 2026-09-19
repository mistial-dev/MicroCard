//! `javacard.security`, `javacardx.crypto` and the PIN, JCRE §5.
//!
//! These classes are objects with state, and the state lives on the heap like any other
//! object, so the firewall covers it. What they are not is algorithms: an operation that
//! needs one asks the host. Key and PIN fields currently occupy native heap objects;
//! protected-key service integration remains separate work.
use super::{Jcre, Native, new_native, word_field};
use crate::vm::frame::{Frame, NULL};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};
extern crate alloc;

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

pub(super) fn reset_pin_validations(heap: &mut Heap) -> Result<()> {
    heap.visit_objects(|_, info, payload| {
        if info.kind == heap::KIND_OBJECT && super::api_class(info.class)
            .is_some_and(|class| class.name == "javacard/framework/OwnerPIN") {
            payload.get_mut(READY * 2..READY * 2 + 2).ok_or(Error::Bounds)?.fill(0);
        }
        Ok(())
    })
}

/// The class a `KeyBuilder` type code builds, JCRE Table 5-1.
///
/// The transient variants build the same class as their persistent counterpart. Nothing
/// here survives a reset yet, so the distinction is recorded in the type the key reports
/// and is otherwise not acted on.
fn key_class(key_type: i16) -> Result<&'static str> {
    Ok(match key_type {
        1..=3 => "javacard/security/DESKey",
        4 => "javacard/security/RSAPublicKey",
        5 | 22 | 23 => "javacard/security/RSAPrivateKey",
        6 | 24 | 25 => "javacard/security/RSAPrivateCrtKey",
        7 => "javacard/security/DSAPublicKey",
        8 | 26 | 27 => "javacard/security/DSAPrivateKey",
        9 => "javacard/security/ECPublicKey",
        10 | 28 | 29 => "javacard/security/ECPrivateKey",
        11 => "javacard/security/ECPublicKey",
        12 | 30 | 31 => "javacard/security/ECPrivateKey",
        13..=15 => "javacard/security/AESKey",
        19..=21 => "javacard/security/HMACKey",
        _ => {
            super::report("javacard/security/KeyBuilder", "buildKey of an unknown type");
            return Err(Error::Unsupported);
        }
    })
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

/// The pieces are unrelated to each other, which is why they arrive separately rather
/// than as a struct that would exist only to be passed here.
#[allow(clippy::too_many_arguments)]
pub fn call(
    class: &str,
    method: &str,
    method_descriptor: &str,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    frame: &mut Frame,
    context: heap::Context,
    jcre: &mut Jcre,
) -> Result<Native> {
    match (class, method) {
        ("javacard/security/KeyBuilder", "buildKey") => {
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
        (name, "getSize") if name.starts_with("javacard/security/") => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, SIZE)? as i16)?;
        }
        (name, "getType") if name.starts_with("javacard/security/") => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, KIND)? as i16)?;
        }
        (name, "isInitialized") if name.starts_with("javacard/security/") => {
            let key = frame.pop_reference()?;
            frame.push_short(word_field(heap, key, READY)? as i16)?;
        }
        (name, "clearKey") if name.starts_with("javacard/security/") => {
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
        ("javacard/security/AESKey", "setKey")
        | ("javacard/security/DESKey", "setKey")
        | ("javacard/security/HMACKey", "setKey") => {
            let length = if class == "javacard/security/HMACKey" {
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
            let mut staging = [0u8; 64];
            staging[..bytes].copy_from_slice(heap.byte_slice(source, offset as usize, bytes)?);
            let material = match heap.get_word(this, MATERIAL)? {
                NULL => {
                    let array = heap.new_array(heap::KIND_BYTE, bytes as u16, context)?;
                    heap.put_word(this, MATERIAL, array)?;
                    array
                }
                array => array,
            };
            heap.byte_slice_mut(material, 0, bytes)?
                .copy_from_slice(&staging[..bytes]);
            // The flag goes last, so a failure part way leaves a key that says it holds
            // nothing rather than one that says it holds a key it does not have.
            heap.put_word(this, READY, 1)?;
        }
        ("javacard/security/AESKey", "getKey")
        | ("javacard/security/DESKey", "getKey")
        | ("javacard/security/HMACKey", "getKey") => {
            let offset = frame.pop_short()?;
            let destination = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            heap.check_access(destination, context)?;
            if word_field(heap, this, READY)? == 0 {
                return Ok(Native::Threw(super::new_exception(
                    heap,
                    "javacard/security/CryptoException",
                    context,
                )?));
            }
            let material = heap.get_word(this, MATERIAL)?;
            let bytes = heap.info(material)?.length as usize;
            let mut staging = [0u8; 64];
            staging[..bytes].copy_from_slice(heap.byte_slice(material, 0, bytes)?);
            heap.byte_slice_mut(destination, offset.max(0) as usize, bytes)?
                .copy_from_slice(&staging[..bytes]);
            frame.push_short(bytes as i16)?;
        }

        ("javacard/framework/OwnerPIN", "<init>") => {
            let max_size = frame.pop_short()?;
            let tries = frame.pop_short()?;
            let this = frame.pop_reference()?;
            if tries < 1 || max_size < 1 {
                return Ok(Native::Threw(super::new_exception(
                    heap,
                    "javacard/framework/PINException",
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
        ("javacard/framework/OwnerPIN", "update") => {
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
        ("javacard/framework/OwnerPIN", "check") => {
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
        ("javacard/framework/OwnerPIN", "isValidated") => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, READY)? as i16)?;
        }
        ("javacard/framework/OwnerPIN", "getTriesRemaining") => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, COUNTER)? as i16)?;
        }
        ("javacard/framework/OwnerPIN", "reset") => {
            let this = frame.pop_reference()?;
            // Only the validated flag, JCRE §5.1. The counter survives, which is what
            // makes a PIN retry limit mean anything across resets.
            heap.put_word(this, READY, 0)?;
        }
        ("javacard/framework/OwnerPIN", "resetAndUnblock") => {
            let this = frame.pop_reference()?;
            let limit = heap.get_word(this, KIND)?;
            heap.put_word(this, COUNTER, limit)?;
            heap.put_word(this, READY, 0)?;
        }

        // The algorithm holders. Each is an object carrying what it was asked for, and the
        // operation itself is the host's to answer.
        ("javacard/security/MessageDigest", "getInstance")
        | ("javacard/security/RandomData", "getInstance")
        | ("javacard/security/Signature", "getInstance")
        | ("javacard/security/KeyAgreement", "getInstance")
        | ("javacardx/crypto/Cipher", "getInstance") => {
            // Every one of these takes an algorithm, and all but RandomData also take
            // whether the instance is shared.
            let external = class != "javacard/security/RandomData" && frame.pop_short()? != 0;
            let algorithm = frame.pop_short()?;
            let supported = match u8::try_from(algorithm) {
                Ok(id) if !external => match class {
                    "javacard/security/MessageDigest" => host.supports_digest(id),
                    "javacard/security/RandomData" => host.supports_random(id),
                    _ => false,
                },
                _ => false,
            };
            if !supported {
                let exception = super::new_exception(heap, "javacard/security/CryptoException", context)?;
                heap.put_word(exception, super::REASON_FIELD, 3)?; // NO_SUCH_ALGORITHM
                return Ok(Native::Threw(exception));
            }
            let instance = new_native(heap, class, STATE_WORDS, context)?;
            heap.put_word(instance, KIND, algorithm as u16)?;
            frame.push_reference(instance)?;
        }
        ("javacard/security/KeyPair", "<init>") => {
            let length = frame.pop_short()?;
            let algorithm = frame.pop_short()?;
            let this = frame.pop_reference()?;
            heap.put_word(this, KIND, algorithm as u16)?;
            heap.put_word(this, SIZE, length as u16)?;
        }
        (_, "getAlgorithm") => {
            let this = frame.pop_reference()?;
            frame.push_short(word_field(heap, this, KIND)? as i16)?;
        }

        // GlobalPlatform, JCRE and GP 2.3 §6. The card content state is the applet's
        // lifecycle byte, which the runtime keeps rather than the applet.
        ("org/globalplatform/GPSystem", "getCVM") => {
            let _kind = frame.pop_short()?;
            // No global PIN, JCRE leaves this optional and the applet null checks it.
            frame.push_reference(NULL)?;
        }
        ("org/globalplatform/GPSystem", "getCardContentState") => {
            frame.push_short(jcre.lifecycle as i16)?;
        }
        ("org/globalplatform/GPSystem", "setCardContentState") => {
            let state = frame.pop_short()?;
            jcre.lifecycle = state as u8;
            frame.push_short(1)?;
        }
        ("javacard/security/MessageDigest", "doFinal") => {
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
            // The message is copied out because the input and the output may be the same
            // array, and a digest written into what it is still reading would hash itself.
            let mut message = alloc::vec::Vec::new();
            message
                .try_reserve_exact(length as usize)
                .map_err(|_| Error::Quota)?;
            message.extend_from_slice(heap.byte_slice(input, offset as usize, length as usize)?);
            let mut digest = [0u8; 64];
            let written = host.digest(algorithm, &message, &mut digest)?;
            heap.byte_slice_mut(output, out_offset as usize, written)?
                .copy_from_slice(&digest[..written]);
            frame.push_short(written as i16)?;
        }
        ("javacard/security/MessageDigest", "getLength") => {
            let this = frame.pop_reference()?;
            let algorithm = word_field(heap, this, KIND)? as u8;
            frame.push_short(digest_length(algorithm)? as i16)?;
        }
        // An algorithm holder remembers the key and the direction it was given, and the
        // operation itself is the host's to answer.
        ("javacardx/crypto/Cipher", "init")
        | ("javacard/security/Signature", "init")
        | ("javacard/security/KeyAgreement", "init") => {
            // Both forms end with the mode or the key. The longer one also carries an
            // initialisation vector, which is taken and held with the key.
            let descriptor = method_descriptor;
            if descriptor.contains("[BSS") {
                let _length = frame.pop_short()?;
                let _offset = frame.pop_short()?;
                let _vector = frame.pop_reference()?;
            }
            let mode = if descriptor.ends_with("B)V") || descriptor.contains("SB") {
                frame.pop_short()?
            } else {
                0
            };
            let key = frame.pop_reference()?;
            let this = frame.pop_reference()?;
            if word_field(heap, key, READY)? == 0 {
                // Initialising with a key that holds nothing would leave an instance that
                // looks ready and is not.
                return Ok(Native::Threw(super::new_exception(
                    heap,
                    "javacard/security/CryptoException",
                    context,
                )?));
            }
            heap.put_word(this, MATERIAL, key)?;
            heap.put_word(this, COUNTER, mode as u16)?;
            heap.put_word(this, READY, 1)?;
        }
        ("javacard/security/RandomData", "generateData")
        | ("javacard/security/RandomData", "nextBytes") => {
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
            if method == "nextBytes" {
                // nextBytes answers nothing, generateData answers the offset past the end.
            } else {
                frame.push_short(offset.wrapping_add(length))?;
            }
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
