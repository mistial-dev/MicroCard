//! `javacard.security`, `javacardx.crypto` and the PIN, JCRE §5.
//!
//! These classes are objects with state, and the state lives on the heap like any other
//! object, so the firewall covers it. What they are not is algorithms: an operation that
//! needs one asks the host. Key and PIN fields currently occupy native heap objects;
//! protected-key service integration remains separate work.
use super::{new_native, word_field, Jcre, Native};
use crate::host::SHA256_STATE_BYTES;
use crate::jcvm_api::{ClassId, MethodId, Signature};
use crate::vm::frame::{Frame, NULL};
use crate::vm::heap::{self, Heap};
use crate::{Error, Result};
extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroizing;
mod agreement;
mod checksum;
mod cipher;
mod digest;
mod factory;
pub use digest::digest_length;
pub(crate) use digest::release_one_shot_digests;
mod ec;
mod key;
mod key_pair;
use key::key_initialized;
pub(crate) use key::symmetric_key_clear_event;
mod pin;
mod random;
mod saved_state;
mod secure_channel;
mod signature;
pub(crate) use ec::{clear_event as ec_key_clear_event, key_kind as ec_key_kind};
pub(super) use saved_state::validate_saved_security;

/// Words every object here carries. The meaning of each is per class and documented where
/// it is read, because these are not fields an applet can see.
pub const STATE_WORDS: u16 = 6;

/// Field zero of a key or a PIN, which is what kind it is.
pub(super) const KIND: usize = 0;
/// Field one, a length in bits for a key and the current PIN length.
const SIZE: usize = 1;
/// Field two, the array holding the material or the PIN.
const MATERIAL: usize = 2;
/// Field three, whether a key has been set or a PIN has been verified.
const READY: usize = 3;
/// Field four, tries left on a PIN, or the padding mode of a cipher.
pub(super) const COUNTER: usize = 4;
/// Reset-scoped cipher state: count/seen-input flag, fifteen pending bytes, then CBC IV.
const PENDING: usize = 5;
// Most APDU crypto results fit here. Larger Java Card arrays still use bounded
// staging so a provider failure cannot expose a partial write to the applet.
struct StagedBytes {
    inline: Zeroizing<[u8; 256]>,
    overflow: Option<Zeroizing<Vec<u8>>>,
    length: usize,
}

impl StagedBytes {
    fn new(length: usize) -> Result<Self> {
        let overflow = if length > 256 {
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.try_reserve_exact(length).map_err(|_| Error::Quota)?;
            bytes.resize(length, 0);
            Some(bytes)
        } else {
            None
        };
        Ok(Self {
            inline: Zeroizing::new([0; 256]),
            overflow,
            length,
        })
    }

    fn as_mut(&mut self) -> &mut [u8] {
        match &mut self.overflow {
            Some(bytes) => bytes.as_mut_slice(),
            None => &mut self.inline[..self.length],
        }
    }
}

pub(crate) fn native_volatile_range(info: heap::Info) -> Result<Option<core::ops::Range<usize>>> {
    if info.kind != heap::KIND_OBJECT {
        return Ok(None);
    }
    let Some(class) = super::api_class(info.class) else {
        return Ok(None);
    };
    if matches!(
        class.id,
        ClassId::OwnerPIN | ClassId::OwnerPINx | ClassId::OwnerPINxWithPredecrement
    ) {
        if info.length as usize <= READY {
            return Err(Error::Bounds);
        }
        return Ok(Some(READY * 2..READY * 2 + 2));
    }
    if info.length == 1 && super::is_exception_class(class) {
        // Runtime exception reasons reset; explicit six-word exceptions persist.
        return Ok(Some(0..2));
    }
    Ok(None)
}

/// Native state uses heap handles too. Recovery and object deletion must trace
/// these words with the same rules as Java reference fields.
pub(crate) fn visit_native_reference_offsets(
    info: heap::Info,
    payload_len: usize,
    mut visit: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    if info.kind != heap::KIND_OBJECT || info.length != STATE_WORDS {
        return Ok(());
    }
    let Some(class) = super::api_class(info.class) else {
        return Ok(());
    };
    if payload_len != STATE_WORDS as usize * 2 {
        return Err(Error::Format);
    }
    visit(MATERIAL * 2)?;
    if matches!(
        class.id,
        ClassId::Cipher
            | ClassId::MessageDigest
            | ClassId::Signature
            | ClassId::KeyPair
            | ClassId::OwnerPINxWithPredecrement
    ) {
        visit(PENDING * 2)?;
    }
    Ok(())
}

pub(super) fn reset_native_volatile(heap: &mut Heap) -> Result<()> {
    digest::release_one_shot_digests(heap)?;
    heap.visit_objects(|_, info, payload| {
        if let Some(range) = native_volatile_range(info)? {
            payload[range].fill(0);
        }
        Ok(())
    })
}

// Persist unconditional PIN changes without publishing conditional heap/static writes.
pub(crate) fn ensure_checkpoint_capacity(
    count: u32,
    host: &mut dyn crate::host::Host,
    jcre: &Jcre,
) -> Result<()> {
    if !jcre.installing && count != 0 {
        host.ensure_checkpoint_capacity(count)?;
    }
    Ok(())
}

pub(crate) fn checkpoint_committed(
    changed: bool,
    heap: &mut Heap,
    host: &mut dyn crate::host::Host,
    jcre: &Jcre,
    _context: heap::Context,
    statics: &[u8],
) -> Result<()> {
    if jcre.installing || !changed || !heap.has_uncheckpointed_writes() {
        return Ok(());
    }
    let instance = jcre.instance.ok_or(Error::Missing)?;
    let mut projected = Zeroizing::new(alloc::vec::Vec::new());
    let statics = if heap.transaction_remaining().is_some() {
        projected
            .try_reserve_exact(statics.len())
            .map_err(|_| Error::Quota)?;
        projected.extend_from_slice(statics);
        heap.project_statics(&mut projected)?;
        &projected[..]
    } else {
        statics
    };
    host.checkpoint(
        crate::applet::PersistentView {
            heap: heap.image(),
            statics,
            instance,
            buffer: jcre.buffer,
            projection: Some(heap),
        },
        crate::host::CheckpointReason::OwnerPin,
    )?;
    heap.mark_checkpointed();
    Ok(())
}

fn crypto_exception(heap: &mut Heap, context: heap::Context, reason: u16) -> Result<Native> {
    let exception = super::new_exception(heap, ClassId::CryptoException, context)?;
    heap.put_word_unconditional(exception, super::REASON_FIELD, reason)?;
    Ok(Native::Threw(exception))
}

fn system_no_resource(heap: &mut Heap, context: heap::Context) -> Result<Native> {
    let exception = super::new_exception(heap, ClassId::SystemException, context)?;
    heap.put_word_unconditional(exception, super::REASON_FIELD, 5)?;
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
    if matches!(
        class,
        ClassId::PIN | ClassId::OwnerPIN | ClassId::OwnerPINx | ClassId::OwnerPINxWithPredecrement
    ) {
        return pin::call(class, method, heap, host, frame, context, jcre, statics);
    }
    if class == ClassId::OwnerPINBuilder && method == MethodId::buildOwnerPIN {
        return pin::build(heap, frame, context);
    }
    // Optional factories still have a defined Java Card failure contract. Consume their
    // complete argument list and report NO_SUCH_ALGORITHM instead of falling through to
    // a VM-level unimplemented-method failure.
    let unavailable_factory_arguments = match (class, method) {
        (ClassId::MessageDigest, MethodId::getInitializedMessageDigestInstance) => Some(2),
        (ClassId::InitializedMessageDigest_OneShot, MethodId::open)
        | (ClassId::RandomData_OneShot, MethodId::open) => Some(1),
        (ClassId::Signature_OneShot, MethodId::open) => Some(3),
        (ClassId::Cipher_OneShot, MethodId::open) => Some(2),
        (ClassId::Cipher, MethodId::getInstance) if signature.combined_factory() => Some(3),
        _ => None,
    };
    if let Some(arguments) = unavailable_factory_arguments {
        for _ in 0..arguments {
            frame.pop_short()?;
        }
        return crypto_exception(heap, context, 3);
    }
    if class == ClassId::Signature
        && method == MethodId::getInstance
        && signature.combined_factory()
    {
        let external = frame.pop_short()? != 0;
        let padding = frame.pop_short()?;
        let cipher = frame.pop_short()?;
        let digest = frame.pop_short()?;
        if external || (digest, cipher, padding) != (0, 6, 1) || !host.supports_signature(18) {
            return crypto_exception(heap, context, 3);
        }
        if let Err(error) = heap.check_allocations(&[(heap::KIND_OBJECT, STATE_WORDS)]) {
            if error != Error::Quota {
                return Err(error);
            }
            return system_no_resource(heap, context);
        }
        let instance = new_native(heap, class, STATE_WORDS, context)?;
        heap.put_word(instance, KIND, 18)?;
        frame.push_reference(instance)?;
        return Ok(Native::Returned);
    }
    if class == ClassId::MessageDigest_OneShot && method == MethodId::open {
        let algorithm = frame.pop_short()?;
        if !matches!(algorithm, 1 | 4 | 5 | 6 | 7) || !host.supports_digest(algorithm as u8) {
            return crypto_exception(heap, context, 3); // NO_SUCH_ALGORITHM
        }
        // This platform offers one live temporary digest at a time.
        let (occupied, reusable) = digest::one_shot_slot(heap)?;
        if occupied {
            return system_no_resource(heap, context);
        }
        // Reuse only after the prior applet entry point returned. A local
        // reference held after close must remain invalid for that call.
        let instance = if let Some(reusable) = reusable {
            reusable
        } else {
            if let Err(error) = heap.check_allocations(&[(heap::KIND_OBJECT, STATE_WORDS)]) {
                if error != Error::Quota {
                    return Err(error);
                }
                return system_no_resource(heap, context);
            }
            new_native(heap, class, STATE_WORDS, 0)?
        };
        heap.put_word(instance, KIND, algorithm as u16)?;
        heap.put_word(instance, SIZE, 0)?;
        heap.put_word(instance, COUNTER, context as u16)?;
        heap.put_word(instance, READY, 1)?;
        frame.push_reference(instance)?;
        return Ok(Native::Returned);
    }
    if class == ClassId::Checksum {
        if let Some(result) = checksum::call(method, heap, frame, context, budget)? {
            return Ok(result);
        }
    }
    if let Some(result) = ec::call(class, method, heap, host, frame, context)? {
        return Ok(result);
    }
    if class == ClassId::KeyAgreement {
        if let Some(result) = agreement::call(method, heap, host, frame, context, budget)? {
            return Ok(result);
        }
    }
    if class == ClassId::Signature {
        if let Some(result) =
            signature::call(method, signature, heap, host, frame, context, budget)?
        {
            return Ok(result);
        }
    }
    if class == ClassId::KeyPair {
        return key_pair::call(method, signature, heap, host, frame, context, budget);
    }
    if class == ClassId::SecureChannel
        || class == ClassId::GPSystem && method == MethodId::getSecureChannel
    {
        return secure_channel::call(class, method, heap, host, frame, context, jcre);
    }
    if matches!(
        class,
        ClassId::MessageDigest | ClassId::MessageDigest_OneShot
    ) && matches!(
        method,
        MethodId::reset | MethodId::update | MethodId::doFinal | MethodId::getLength
    ) {
        return digest::call(method, heap, host, frame, context, budget);
    }
    if class == ClassId::Cipher
        && matches!(
            method,
            MethodId::init | MethodId::update | MethodId::doFinal
        )
    {
        return cipher::call(method, signature, heap, host, frame, context, budget);
    }
    if class == ClassId::RandomData
        && matches!(
            method,
            MethodId::generateData | MethodId::nextBytes | MethodId::setSeed
        )
    {
        return random::call(method, heap, host, frame, context, budget);
    }
    if matches!(
        method,
        MethodId::buildKey
            | MethodId::getSize
            | MethodId::getType
            | MethodId::isInitialized
            | MethodId::clearKey
            | MethodId::setKey
            | MethodId::getKey
    ) {
        return key::call(class, method, heap, host, frame, context);
    }
    if method == MethodId::getInstance
        && matches!(
            class,
            ClassId::MessageDigest
                | ClassId::Checksum
                | ClassId::RandomData
                | ClassId::Signature
                | ClassId::KeyAgreement
                | ClassId::Cipher
        )
    {
        return factory::get_instance(class, heap, host, frame, context);
    }
    match (class, method) {
        (_, MethodId::getAlgorithm) => {
            let this = frame.pop_reference()?;
            if digest::one_shot_digest(heap, this, context)? && word_field(heap, this, READY)? == 0
            {
                return crypto_exception(heap, context, 5);
            }
            frame.push_short(word_field(heap, this, KIND)? as i16)?;
        }
        (ClassId::MessageDigest_OneShot, MethodId::close) => {
            let this = frame.pop_reference()?;
            digest::one_shot_digest(heap, this, context)?;
            heap.put_word_unconditional(this, READY, 0)?;
        }

        // GlobalPlatform, JCRE and GP 2.3 §6. The card content state is the applet's
        // lifecycle byte, which the runtime keeps rather than the applet.
        (ClassId::GPSystem, MethodId::getCVM) => {
            let _kind = frame.pop_short()?;
            // No global PIN, JCRE leaves this optional and the applet null checks it.
            frame.push_reference(NULL)?;
        }
        (ClassId::GPSystem, MethodId::getCardContentState) => {
            frame.push_short(heap.lifecycle()? as i16)?;
        }
        (ClassId::GPSystem, MethodId::setCardContentState) => {
            let state = frame.pop_short()?;
            let previous = if jcre.installing {
                None
            } else {
                Some(heap.lifecycle()?)
            };
            if !jcre.installing
                && Heap::valid_lifecycle(state as u8)
                && previous != Some(state as u8)
            {
                ensure_checkpoint_capacity(1, host, jcre)?;
            }
            let accepted = !jcre.installing && heap.set_lifecycle(state as u8)?;
            if accepted {
                checkpoint_committed(
                    previous != Some(state as u8),
                    heap,
                    host,
                    jcre,
                    context,
                    statics,
                )?;
            }
            frame.push_short(i16::from(accepted))?;
        }
        _ => return Ok(Native::Unimplemented),
    }
    Ok(Native::Returned)
}
