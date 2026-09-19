//! Engine state only. The storage layer must authenticate it and bind it to the code image.
use super::*;
use crate::cap::ClassRef;

pub struct PersistentState<'a> {
    pub heap: &'a [u8],
    pub statics: &'a [u8],
    pub instance: Reference,
}

/// RAM-only reset-scoped array contents. Bind this to the installation that produced it.
/// Dropping it wipes all retained payloads; it must never enter persistent storage.
pub struct VolatileState {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    heap_used: usize,
    instance: Reference,
}

impl VolatileState {
    pub fn bytes(&self) -> usize { self.bytes.len() }
}

impl Card {
    /// Retain only CLEAR_ON_RESET payloads after deselection, within a caller-owned quota.
    pub fn retain_volatile(&mut self, maximum: usize) -> Result<VolatileState> {
        let instance = self.instance.ok_or(Error::Missing)?;
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        let mut size = 0usize;
        heap.visit_objects(|reference, info, payload| {
            if reference != self.buffer && info.clear_event == heap::CLEAR_ON_RESET {
                size = size.checked_add(5 + payload.len()).ok_or(Error::Quota)?;
            }
            Ok(())
        })?;
        if size > maximum { return Err(Error::Quota); }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(size).map_err(|_| Error::Quota)?;
        heap.visit_objects(|reference, info, payload| {
            if reference != self.buffer && info.clear_event == heap::CLEAR_ON_RESET {
                bytes.extend_from_slice(&reference.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                bytes.push(info.kind);
                bytes.extend_from_slice(payload);
            }
            Ok(())
        })?;
        Ok(VolatileState { bytes, heap_used: self.heap_used, instance })
    }

    /// Apply a RAM snapshot only to the identical recovered heap layout. Validate the
    /// complete snapshot first so a mismatch cannot partly restore another applet's data.
    pub fn restore_volatile(&mut self, saved: &VolatileState) -> Result<()> {
        if self.heap_used != saved.heap_used || self.instance != Some(saved.instance) {
            return Err(Error::Format);
        }
        let mut heap = Heap::resume(&mut self.heap, self.heap_used)?;
        for apply in [false, true] {
            let mut at = 0usize;
            heap.visit_objects(|reference, info, payload| {
                if reference != self.buffer && info.clear_event == heap::CLEAR_ON_RESET {
                    let header = saved.bytes.get(at..at + 5).ok_or(Error::Format)?;
                    if header[..2] != reference.to_be_bytes()
                        || header[2..4] != (payload.len() as u16).to_be_bytes()
                        || header[4] != info.kind { return Err(Error::Format); }
                    at += 5;
                    let value = saved.bytes.get(at..at + payload.len()).ok_or(Error::Format)?;
                    if apply { payload.copy_from_slice(value); }
                    at += payload.len();
                }
                Ok(())
            })?;
            if at != saved.bytes.len() { return Err(Error::Format); }
        }
        Ok(())
    }

    pub fn persistent_heap_bytes(&self) -> usize {
        self.heap_used
    }

    /// Immutable metadata accompanying the sanitized heap written by save_into.
    pub fn persistent_metadata(&self) -> Result<(Reference, &[u8])> {
        Ok((self.instance.ok_or(Error::Missing)?, &self.statics))
    }

    /// Save into the caller's staging buffer, without copying execution frames or code.
    /// The buffer contains secrets and must be encrypted and cleared by its owner.
    pub fn save_into<'a>(&'a self, output: &'a mut [u8]) -> Result<PersistentState<'a>> {
        let result = (|| {
            let (instance, _) = self.persistent_metadata()?;
            if output.len() != self.heap_used {
                return Err(Error::Bounds);
            }
            output.copy_from_slice(&self.heap[..self.heap_used]);
            let mut heap = Heap::resume(output, self.heap_used)?;
            heap.clear_transient(heap::CLEAR_ON_RESET, self.context)?;
            heap.byte_slice_mut(self.buffer, 0, self.sizes.buffer_bytes as usize)?
                .fill(0);
            natives::reset_pin_validations(&mut heap)?;
            Ok(instance)
        })();
        match result {
            Ok(instance) => Ok(PersistentState {
                heap: output,
                statics: &self.statics,
                instance,
            }),
            Err(error) => {
                output.zeroize();
                Err(error)
            }
        }
    }

    /// Restore already authenticated state for the exact verified load file.
    /// No installation code runs, and no volatile values are reconstructed from storage.
    pub fn restore(file: &LoadFile, sizes: Sizes, saved: PersistentState<'_>) -> Result<Self> {
        if saved.heap.len() > sizes.heap_bytes
            || saved.statics.len() != file.static_fields()?.image_size as usize
        {
            return Err(Error::Bounds);
        }
        let mut card = Self::new(file, sizes)?;
        // Runtime objects have deterministic handles and a zeroed APDU buffer.
        if saved.heap.get(..card.runtime_bytes) != Some(&card.heap[..card.runtime_bytes]) {
            return Err(Error::Format);
        }
        card.heap[..saved.heap.len()].copy_from_slice(saved.heap);
        card.heap_used = saved.heap.len();
        card.statics.copy_from_slice(saved.statics);
        let mut heap = Heap::resume(&mut card.heap, card.heap_used)?;
        let mut starts = Vec::new();
        reserve(&mut starts, card.heap_used.div_ceil(16))?;
        heap.visit_objects(|reference, info, payload| {
            if info.owner != card.context {
                return Err(Error::Firewall);
            }
            if info.clear_event != 0 && payload.iter().any(|byte| *byte != 0) {
                return Err(Error::Format);
            }
            starts[reference as usize / 16] |= 1 << ((reference as usize / 2) % 8);
            Ok(())
        })?;
        let valid_reference = |reference: Reference| -> Result<()> {
            if reference == 0 {
                return Ok(());
            }
            if !reference.is_multiple_of(2)
                || starts
                    .get(reference as usize / 16)
                    .is_none_or(|byte| byte & (1 << ((reference as usize / 2) % 8)) == 0)
            {
                return Err(Error::Bounds);
            }
            Ok(())
        };
        valid_reference(saved.instance)?;
        if saved.instance == 0 {
            return Err(Error::Missing);
        }
        let linked = Linked::new(file)?;
        linked.imports_resolve()?;
        heap.visit_objects(|_, info, payload| {
            if info.kind == heap::KIND_REFERENCE {
                for word in payload.chunks_exact(2) {
                    valid_reference(u16::from_be_bytes([word[0], word[1]]))?;
                }
            } else if info.kind == heap::KIND_BOOLEAN {
                if payload.iter().any(|value| *value > 1) {
                    return Err(Error::Format);
                }
            } else if info.kind == heap::KIND_OBJECT {
                if natives::is_native_class(info.class) {
                    let class = natives::api_class(info.class).ok_or(Error::Format)?;
                    let exception = class.id == ClassId::Throwable
                        || class.supers.contains(&ClassId::Throwable);
                    if info.length != 6
                        && !(info.length == 1
                            && (exception || class.id == ClassId::APDU))
                    {
                        return Err(Error::Format);
                    }
                    if info.length == 6 {
                        let word =
                            |at: usize| u16::from_be_bytes([payload[at * 2], payload[at * 2 + 1]]);
                        let material = word(2);
                        valid_reference(material)?;
                        if class.id == ClassId::Cipher {
                            let pending = word(5);
                            valid_reference(pending)?;
                            if !matches!(word(0), 13 | 14) || pending == 0 || word(3) > 1
                                || (word(3) == 1 && (material == 0 || !matches!(word(4), 1 | 2))) {
                                return Err(Error::Format);
                            }
                            let header = &saved.heap[pending as usize..pending as usize + heap::HEADER];
                            if u16::from_be_bytes([header[2], header[3]]) != if word(0) == 13 { 32 } else { 16 }
                                || header[4] != heap::KIND_BYTE | (heap::CLEAR_ON_RESET << 4) {
                                return Err(Error::Format);
                            }
                            if material != 0 {
                                let start = material as usize;
                                let key_class = u16::from_be_bytes([saved.heap[start], saved.heap[start + 1]]);
                                if natives::api_class(key_class).map(|entry| entry.id) != Some(ClassId::AESKey)
                                    || saved.heap[start + 4] != heap::KIND_OBJECT
                                    || u16::from_be_bytes([saved.heap[start + 2], saved.heap[start + 3]]) != 6
                                    || saved.heap.get(start + heap::HEADER + 2..start + heap::HEADER + 4) != Some(&[0, 128]) {
                                    return Err(Error::Type);
                                }
                            }
                        }
                        let pin = class.id == ClassId::OwnerPIN;
                        let ec = matches!(class.id, ClassId::ECPublicKey | ClassId::ECPrivateKey);
                        if ec && (!natives::ec_key_kind(word(0)) || word(1) != 256
                            || word(3) != 0
                            || (class.id == ClassId::ECPublicKey) != (word(0) == 11)) {
                            return Err(Error::Format);
                        }
                        if material != 0 && (pin || class.id.is_key()) {
                            let header =
                                &saved.heap[material as usize..material as usize + heap::HEADER];
                            let length = u16::from_be_bytes([header[2], header[3]]);
                            if header[4] & 0x0f != heap::KIND_BYTE {
                                return Err(Error::Type);
                            }
                            if pin {
                                if word(0) == 0
                                    || word(4) > word(0)
                                    || word(1) > length
                                    || word(1) > 32
                                {
                                    return Err(Error::Format);
                                }
                            } else if ec {
                                let event = natives::ec_key_clear_event(word(0));
                                if header[4] >> 4 != event
                                    || length != if word(0) == 11 { 66 } else { 33 } {
                                    return Err(Error::Format);
                                }
                                let flags = saved.heap[material as usize + heap::HEADER];
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
                        if pin
                            && (word(3) != 0
                                || (material == 0 && payload.iter().any(|byte| *byte != 0)))
                        {
                            return Err(Error::Format);
                        }
                    }
                } else {
                    if linked.instance_words(info.class)? != info.length {
                        return Err(Error::Format);
                    }
                    let mut class = ClassRef::Internal(info.class);
                    for _ in 0..=u8::MAX {
                        let ClassRef::Internal(offset) = class else {
                            return Ok(());
                        };
                        let declaration = linked.classes().at(offset)?;
                        if declaration.is_interface() {
                            return Err(Error::Format);
                        }
                        let inherited = match declaration.super_class {
                            ClassRef::Internal(parent) => linked.instance_words(parent)?,
                            _ => 0,
                        };
                        for index in 0..u16::from(declaration.reference_count) {
                            let at = (usize::from(inherited)
                                + usize::from(declaration.first_reference_token)
                                + usize::from(index))
                                * 2;
                            let word = payload.get(at..at + 2).ok_or(Error::Bounds)?;
                            valid_reference(u16::from_be_bytes([word[0], word[1]]))?;
                        }
                        class = declaration.super_class;
                    }
                    return Err(Error::Format);
                }
            }
            Ok(())
        })?;
        check_applet(&linked, &heap, saved.instance)?;
        let references = file.static_fields()?.reference_count as usize * 2;
        for word in card
            .statics
            .get(..references)
            .ok_or(Error::Bounds)?
            .chunks_exact(2)
        {
            valid_reference(u16::from_be_bytes([word[0], word[1]]))?;
        }
        card.instance = Some(saved.instance);
        Ok(card)
    }
}
