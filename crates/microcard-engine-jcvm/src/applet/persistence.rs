//! Engine state only. The storage layer must authenticate it and bind it to the code image.
use super::*;
use crate::cap::ClassRef;

pub struct PersistentState<'a> {
    pub heap: &'a [u8],
    pub statics: &'a [u8],
    pub instance: Reference,
}

/// Borrowed live state at a durable boundary. Saving sanitizes volatile contents into
/// the storage layer's existing staging buffer, without cloning the running card.
#[derive(Clone, Copy)]
pub struct PersistentView<'a> {
    pub(crate) heap: &'a [u8],
    pub(crate) statics: &'a [u8],
    pub(crate) instance: Reference,
    pub(crate) buffer: Reference,
    pub(crate) projection: Option<&'a Heap<'a>>,
}

/// Projects sorted heap ranges while validating each object only once.
pub struct PersistentCursor<'a> {
    view: PersistentView<'a>,
    cursor: usize,
    last_end: usize,
    found_buffer: bool,
}

impl PersistentCursor<'_> {
    pub fn save_range(&mut self, at: usize, output: &mut [u8]) -> Result<()> {
        let result = (|| {
            let total = self.view.heap_bytes();
            let end = at
                .checked_add(output.len())
                .filter(|end| *end <= total)
                .ok_or(Error::Bounds)?;
            if at < self.last_end {
                return Err(Error::Bounds);
            }
            if let Some(heap) = self.view.projection {
                heap.project_heap_range(at, output)?;
            } else {
                output.copy_from_slice(self.view.heap.get(at..end).ok_or(Error::Bounds)?);
            }
            while self.cursor < total {
                let reference = u16::try_from(self.cursor).map_err(|_| Error::Bounds)?;
                let info = heap::Info::read(self.view.heap, total, reference)?;
                let payload = self.cursor + heap::HEADER;
                let length = info.length as usize * info.element_size();
                let next = (payload + length).next_multiple_of(2);
                if reference == self.view.buffer {
                    if info.kind != heap::KIND_BYTE {
                        return Err(Error::Type);
                    }
                    self.found_buffer = true;
                }
                if next <= at {
                    self.cursor = next;
                    continue;
                }
                if self.cursor >= end {
                    break;
                }
                let clear = if reference == self.view.buffer || info.clear_event != 0 {
                    Some(0..length)
                } else {
                    natives::native_volatile_range(info)?
                };
                if let Some(range) = clear {
                    let lo = at.max(payload + range.start);
                    let hi = end.min(payload + range.end);
                    if lo < hi {
                        output[lo - at..hi - at].fill(0);
                    }
                }
                if next > end {
                    break;
                }
                self.cursor = next;
            }
            self.last_end = end;
            Ok(())
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    pub fn finish(mut self) -> Result<()> {
        let total = self.view.heap_bytes();
        while self.cursor < total {
            let reference = u16::try_from(self.cursor).map_err(|_| Error::Bounds)?;
            let info = heap::Info::read(self.view.heap, total, reference)?;
            if reference == self.view.buffer {
                if info.kind != heap::KIND_BYTE {
                    return Err(Error::Type);
                }
                self.found_buffer = true;
            }
            self.cursor = (self.cursor + heap::HEADER + info.length as usize * info.element_size())
                .next_multiple_of(2);
        }
        if self.cursor != total || !self.found_buffer {
            return Err(Error::Format);
        }
        Ok(())
    }
}

impl<'a> PersistentView<'a> {
    pub fn heap_bytes(self) -> usize {
        self.projection
            .map_or(self.heap.len(), Heap::committed_bytes)
    }

    /// The runtime's version and pending-deletion marker live outside objects
    /// and are never part of a Java transaction.
    pub fn heap_header(self) -> Result<u8> {
        self.heap.first().copied().ok_or(Error::Bounds)
    }

    /// A deletion request serviced in this APDU may set and clear only the
    /// runtime marker. If its final value matches flash, nothing changed.
    pub fn same_state_after_deletion_request(
        self,
        before_length: usize,
        before_header: u8,
    ) -> Result<bool> {
        let Some(writes) = self.pending_writes() else {
            return Ok(false);
        };
        Ok(self.heap_bytes() == before_length
            && self.heap_header()? == before_header
            && !writes.snapshot_required()
            && writes.static_range().is_none()
            && writes.heap_ranges().eq(core::iter::once(0..1)))
    }

    pub fn cursor(self) -> Result<PersistentCursor<'a>> {
        let total = self.heap_bytes();
        if total < 2 || !total.is_multiple_of(2) {
            return Err(Error::Bounds);
        }
        Ok(PersistentCursor {
            view: self,
            cursor: 2,
            last_end: 0,
            found_buffer: false,
        })
    }

    pub fn metadata(self) -> (Reference, &'a [u8]) {
        (self.instance, self.statics)
    }

    /// None means this view has no live write tracker and requires a full snapshot.
    pub fn pending_writes(self) -> Option<heap::PendingWrites> {
        self.projection
            .map(|heap| heap.pending_writes().for_committed_heap(self.heap_bytes()))
    }

    /// Copy a sanitized window without allocating a complete heap projection.
    pub fn save_range(self, at: usize, output: &mut [u8]) -> Result<()> {
        let result = (|| {
            let mut cursor = self.cursor()?;
            cursor.save_range(at, output)?;
            cursor.finish()
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    pub fn save_into<'b>(self, output: &'b mut [u8]) -> Result<PersistentState<'b>>
    where
        'a: 'b,
    {
        if output.len() != self.heap_bytes() {
            output.zeroize();
            return Err(Error::Bounds);
        }
        self.save_range(0, output)?;
        Ok(PersistentState {
            heap: output,
            statics: self.statics,
            instance: self.instance,
        })
    }
}

/// RAM-only reset-scoped array contents. Bind this to the installation that produced it.
/// Dropping it wipes all retained payloads; it must never enter persistent storage.
pub struct VolatileState {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    heap_used: usize,
    instance: Reference,
}

impl VolatileState {
    pub fn bytes(&self) -> usize {
        self.bytes.len()
    }
}

impl AppletInstance {
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
        if size > maximum {
            return Err(Error::Quota);
        }
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
        Ok(VolatileState {
            bytes,
            heap_used: self.heap_used,
            instance,
        })
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
                        || header[4] != info.kind
                    {
                        return Err(Error::Format);
                    }
                    at += 5;
                    let value = saved
                        .bytes
                        .get(at..at + payload.len())
                        .ok_or(Error::Format)?;
                    if apply {
                        payload.copy_from_slice(value);
                    }
                    at += payload.len();
                }
                Ok(())
            })?;
            if at != saved.bytes.len() {
                return Err(Error::Format);
            }
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

    pub fn persistent_view(&self) -> Result<PersistentView<'_>> {
        Ok(PersistentView {
            heap: &self.heap[..self.heap_used],
            statics: &self.statics,
            instance: self.instance.ok_or(Error::Missing)?,
            buffer: self.buffer,
            projection: None,
        })
    }

    /// Save into the caller's staging buffer, without copying execution frames or code.
    /// The buffer contains secrets and must be encrypted and cleared by its owner.
    pub fn save_into<'a>(&'a self, output: &'a mut [u8]) -> Result<PersistentState<'a>> {
        match self.persistent_view() {
            Ok(view) => view.save_into(output),
            Err(error) => {
                output.zeroize();
                Err(error)
            }
        }
    }

    /// Validate borrowed state with only the load file's initial runtime layout.
    pub fn validate_persistent(
        file: &LoadFile,
        mut sizes: Sizes,
        saved: PersistentState<'_>,
    ) -> Result<()> {
        if saved.heap.len() > sizes.heap_bytes {
            return Err(Error::Bounds);
        }
        // Bound initial objects from the same exception inventory and static arrays
        // used by new(). No spare heap, execution frames, or saved-heap copy is needed.
        let mut initial =
            2usize + (heap::HEADER + usize::from(sizes.buffer_bytes)).next_multiple_of(2);
        initial = initial
            .checked_add((1 + natives::runtime_exception_classes().count()) * (heap::HEADER + 2))
            .ok_or(Error::Quota)?;
        for array in file.static_fields()?.array_inits() {
            initial = initial
                .checked_add((heap::HEADER + array.values.len()).next_multiple_of(2))
                .ok_or(Error::Quota)?;
        }
        sizes.heap_bytes = initial.min(saved.heap.len());
        sizes.frame_words = 0;
        Self::new(file, sizes)?.validate_saved(file, &saved)
    }

    /// Restore already authenticated state for the exact verified load file.
    /// No installation code runs, and no volatile values are reconstructed from storage.
    pub fn restore(file: &LoadFile, sizes: Sizes, saved: PersistentState<'_>) -> Result<Self> {
        let mut card = Self::restore_without_frames(file, sizes, saved)?;
        card.restore_execution_frames()?;
        Ok(card)
    }

    /// Restore state while leaving execution suspended. The caller must restore
    /// frames before invoking the applet, after releasing its snapshot buffer.
    pub fn restore_without_frames(
        file: &LoadFile,
        sizes: Sizes,
        saved: PersistentState<'_>,
    ) -> Result<Self> {
        if saved.heap.len() > sizes.heap_bytes {
            return Err(Error::Bounds);
        }
        let mut card = Self::new(
            file,
            Sizes {
                frame_words: 0,
                ..sizes
            },
        )?;
        card.sizes = sizes;
        card.validate_saved(file, &saved)?;
        card.heap[..saved.heap.len()].copy_from_slice(saved.heap);
        card.heap_used = saved.heap.len();
        card.statics.copy_from_slice(saved.statics);
        card.instance = Some(saved.instance);
        Ok(card)
    }

    fn validate_saved(&self, file: &LoadFile, saved: &PersistentState<'_>) -> Result<()> {
        if saved.statics.len() != self.statics.len()
            || saved.heap.len() < 2
            || saved.heap.len() > u16::MAX as usize
            || !saved.heap.len().is_multiple_of(2)
        {
            return Err(Error::Bounds);
        }
        // Runtime objects have deterministic handles and a zeroed APDU buffer.
        if !Heap::valid_version(saved.heap[0]) {
            return Err(Error::IncompatibleState);
        }
        if !Heap::valid_lifecycle(saved.heap[1])
            || saved.heap.get(2..self.runtime_bytes) != Some(&self.heap[2..self.runtime_bytes])
        {
            return Err(Error::Format);
        }
        let mut starts = Vec::new();
        reserve(&mut starts, saved.heap.len().div_ceil(16))?;
        visit_saved_objects(saved.heap, |reference, info, payload| {
            if info.owner != self.context {
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
        let storable_reference = |reference: Reference| -> Result<()> {
            valid_reference(reference)?;
            if reference != 0 {
                let at = reference as usize;
                let class = u16::from_be_bytes([saved.heap[at], saved.heap[at + 1]]);
                let words = u16::from_be_bytes([saved.heap[at + 2], saved.heap[at + 3]]);
                if reference == self.buffer || natives::is_temporary_native(class, words) {
                    return Err(Error::Firewall);
                }
            }
            Ok(())
        };
        valid_reference(saved.instance)?;
        if saved.instance == 0 {
            return Err(Error::Missing);
        }
        let linked = Linked::new(file)?;
        linked.imports_resolve()?;
        visit_saved_objects(saved.heap, |_, info, payload| {
            if info.kind == heap::KIND_REFERENCE {
                let component = if info.class == heap::ANY_REFERENCE_CLASS {
                    None
                } else {
                    let target = ClassRef::decode(info.class);
                    match target {
                        ClassRef::Internal(offset) => {
                            linked.classes().at(offset)?;
                        }
                        ClassRef::External { package, class } => {
                            linked.api_class(package, class)?;
                        }
                        ClassRef::None => return Err(Error::Format),
                    }
                    Some(target)
                };
                for word in payload.chunks_exact(2) {
                    let reference = u16::from_be_bytes([word[0], word[1]]);
                    storable_reference(reference)?;
                    if let Some(component) = component.filter(|_| reference != 0) {
                        let value = heap::Info::read(saved.heap, saved.heap.len(), reference)?;
                        let compatible = if value.is_array() {
                            linked.class_reference_is_object(component)?
                        } else {
                            linked.class_matches_target(value.class, component)?
                        };
                        if !compatible {
                            return Err(Error::Type);
                        }
                    }
                }
            } else if info.kind == heap::KIND_BOOLEAN {
                if payload.iter().any(|value| *value > 1) {
                    return Err(Error::Format);
                }
            } else if info.kind == heap::KIND_OBJECT {
                if natives::is_native_class(info.class) {
                    natives::validate_saved_native(info, payload, saved.heap, &valid_reference)?;
                } else {
                    if linked.instance_words(info.class)? != info.length {
                        return Err(Error::Format);
                    }
                    linked.visit_instance_reference_offsets(info.class, payload.len(), |at| {
                        storable_reference(u16::from_be_bytes([payload[at], payload[at + 1]]))
                    })?;
                }
            }
            Ok(())
        })?;
        check_applet(
            &linked,
            heap::Info::read(saved.heap, saved.heap.len(), saved.instance)?,
        )?;
        let references = file.static_fields()?.reference_count as usize * 2;
        for word in saved
            .statics
            .get(..references)
            .ok_or(Error::Bounds)?
            .chunks_exact(2)
        {
            storable_reference(u16::from_be_bytes([word[0], word[1]]))?;
        }
        Ok(())
    }
}

fn visit_saved_objects(
    bytes: &[u8],
    mut visit: impl FnMut(Reference, heap::Info, &[u8]) -> Result<()>,
) -> Result<()> {
    if bytes.len() < 2 || bytes.len() > u16::MAX as usize || !bytes.len().is_multiple_of(2) {
        return Err(Error::Bounds);
    }
    let mut at = 2;
    while at < bytes.len() {
        let info = heap::Info::read(bytes, bytes.len(), at as Reference)?;
        let end = at + heap::HEADER + usize::from(info.length) * info.element_size();
        visit(at as Reference, info, &bytes[at + heap::HEADER..end])?;
        at = end.next_multiple_of(2);
    }
    if at != bytes.len() {
        return Err(Error::Format);
    }
    Ok(())
}
