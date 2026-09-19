//! Engine state only. The storage layer must authenticate it and bind it to the code image.
use super::*;
use crate::cap::ClassRef;

pub struct PersistentState<'a> {
    pub heap: &'a [u8],
    pub statics: &'a [u8],
    pub instance: Reference,
}

impl Card {
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
                        let pin = class.id == ClassId::OwnerPIN;
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
                            } else if length > 64 {
                                return Err(Error::Bounds);
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
