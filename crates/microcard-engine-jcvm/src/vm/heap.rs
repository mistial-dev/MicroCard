//! The object heap, JCVM 3.x §3.1 and JCRE §6.
//!
//! A reference is a byte offset into one slab, so the heap is position independent and can
//! be written to flash verbatim and read back without relocating anything. Offset zero is
//! never an object, which is what makes the null reference a zero word.
//!
//! Every object carries the context that owns it. The firewall check is a comparison of
//! that byte against the context of the code doing the access, JCRE §6.2, so isolation
//! costs one load and one compare rather than a table walk.
use super::frame::{NULL, Reference};
use crate::{Error, Result};
mod undo;
use undo::Undo;
mod writes;
pub use writes::PendingWrites;

/// Object kinds, which is the element type for an array.
pub const KIND_OBJECT: u8 = 0;
pub const KIND_BOOLEAN: u8 = 2;
pub const KIND_BYTE: u8 = 3;
pub const KIND_SHORT: u8 = 4;
pub const KIND_INT: u8 = 5;
pub const KIND_REFERENCE: u8 = 6;
pub const CLEAR_ON_RESET: u8 = 1;
pub const CLEAR_ON_DESELECT: u8 = 2;
const KIND_MASK: u8 = 0x0f;

/// Bytes of header every object carries: class or element type, length, kind and owner.
pub const HEADER: usize = 6;

/// The context that owns an object. Zero is the runtime environment itself, JCRE §6.1.3.
pub type Context = u8;

/// One slab of objects, allocated from the front.
///
/// There is no collector. Java Card makes object deletion a request the runtime may ignore,
/// and every call to it in the applets this engine targets is guarded by a check that the
/// card supports it, so a bump allocator is a complete implementation of the contract.
pub struct Heap<'a> {
    bytes: &'a mut [u8],
    next: usize,
    transaction: Option<(usize, Undo)>,
    aborted_allocations: bool,
    pending_writes: PendingWrites,
}

/// What an object is, read back from its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// The Class component offset for an object, or zero for an array.
    pub class: u16,
    /// Field words for an object, elements for an array.
    pub length: u16,
    pub kind: u8,
    pub owner: Context,
    pub clear_event: u8,
}

impl Info {
    pub(crate) fn read(bytes: &[u8], used: usize, reference: Reference) -> Result<Self> {
        if used > bytes.len() { return Err(Error::Bounds); }
        let at = reference as usize;
        if reference == NULL {
            return Err(Error::Null);
        }
        if !at.is_multiple_of(2) || at + HEADER > used {
            return Err(Error::Bounds);
        }
        let info = Info {
            class: u16::from_be_bytes([bytes[at], bytes[at + 1]]),
            length: u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]),
            kind: bytes[at + 4] & KIND_MASK,
            owner: bytes[at + 5],
            clear_event: bytes[at + 4] >> 4,
        };
        if !matches!(info.kind, KIND_OBJECT | KIND_BOOLEAN..=KIND_REFERENCE)
            || info.clear_event > CLEAR_ON_DESELECT
            || (info.kind == KIND_OBJECT && info.clear_event != 0)
            || (info.is_array() && info.class != 0)
        { return Err(Error::Format); }
        if at + HEADER + info.length as usize * info.element_size() > used { return Err(Error::Bounds); }
        Ok(info)
    }

    pub fn is_array(&self) -> bool {
        self.kind != KIND_OBJECT
    }

    /// Bytes one element occupies.
    pub fn element_size(&self) -> usize {
        match self.kind {
            KIND_BOOLEAN | KIND_BYTE => 1,
            KIND_INT => 4,
            // An object's fields are words, and so are short and reference elements.
            _ => 2,
        }
    }
}

impl<'a> Heap<'a> {
    /// Take a slab. The first two bytes are reserved so that no object can sit at offset
    /// zero, which is the null reference.
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        if bytes.len() < HEADER + 2 {
            return Err(Error::Quota);
        }
        Ok(Self { bytes, next: 2, transaction: None, aborted_allocations: false, pending_writes: PendingWrites::default() })
    }

    /// Take a slab that already holds objects, continuing from where it was left.
    ///
    /// The heap is position independent, so resuming is a matter of remembering how much
    /// was used. That is what lets one heap outlive the command that allocated in it.
    pub fn resume(bytes: &'a mut [u8], used: usize) -> Result<Self> {
        if used < 2 || used > bytes.len() || used > u16::MAX as usize || !used.is_multiple_of(2) {
            return Err(Error::Bounds);
        }
        Ok(Self { bytes, next: used, transaction: None, aborted_allocations: false, pending_writes: PendingWrites::default() })
    }

    /// Runtime-only header, outside applet-addressable objects and Java transactions.
    pub(crate) fn initialize_lifecycle(&mut self) {
        self.bytes[..2].copy_from_slice(&[1, 0x07]);
    }

    pub(crate) fn lifecycle(&self) -> Result<u8> {
        if self.bytes[0] != 1 || !Self::valid_lifecycle(self.bytes[1]) {
            return Err(Error::Format);
        }
        Ok(self.bytes[1])
    }

    pub(crate) fn valid_lifecycle(state: u8) -> bool {
        state < 0x80 && state & 7 == 7
    }

    pub(crate) fn set_lifecycle(&mut self, state: u8) -> Result<bool> {
        self.lifecycle()?;
        if !Self::valid_lifecycle(state) { return Ok(false); }
        if self.bytes[1] != state {
            self.bytes[1] = state;
            self.pending_writes.heap(1, 1);
        }
        Ok(true)
    }

    /// Start one bounded undo log for heap and static fields. The caller must end the
    /// transaction before releasing this heap view.
    pub fn begin_transaction(&mut self, capacity: usize) -> Result<()> {
        if self.aborted_allocations { return Err(Error::TransactionAborted); }
        if self.transaction.is_some() { return Err(Error::Inconsistent); }
        self.transaction = Some((self.next, Undo::new(capacity)?));
        Ok(())
    }

    pub fn transaction_remaining(&self) -> Option<usize> {
        self.transaction.as_ref().map(|(_, undo)| undo.remaining())
    }

    pub fn allocations_aborted(&self) -> bool { self.aborted_allocations }

    /// Persistent writes not yet acknowledged by a successful storage checkpoint.
    /// Mutable slice access is conservative: it counts as a possible write.
    pub fn has_uncheckpointed_writes(&self) -> bool { self.pending_writes.any() }

    pub fn pending_writes(&self) -> PendingWrites { self.pending_writes }

    pub fn mark_checkpointed(&mut self) { self.pending_writes = PendingWrites::default(); }

    pub(crate) fn committed_bytes(&self) -> usize {
        self.transaction.as_ref().map_or(self.next, |(start, _)| *start)
    }

    pub(crate) fn project_heap(&self, output: &mut [u8]) -> Result<()> {
        if output.len() != self.committed_bytes() { output.fill(0); return Err(Error::Bounds); }
        self.project_heap_range(0, output)
    }

    // Raw committed bytes; persistence must still sanitize volatile native state.
    pub(crate) fn project_heap_range(&self, at: usize, output: &mut [u8]) -> Result<()> {
        let result = (|| {
            let total = self.committed_bytes();
            let end = at.checked_add(output.len()).filter(|end| *end <= total).ok_or(Error::Bounds)?;
            output.copy_from_slice(&self.bytes[at..end]);
            if let Some((_, undo)) = &self.transaction {
                undo.project_range(output, at, total, false)?;
            }
            Ok(())
        })();
        if result.is_err() { output.fill(0); }
        result
    }

    pub(crate) fn project_statics(&self, output: &mut [u8]) -> Result<()> {
        if let Some((_, undo)) = &self.transaction { undo.project(output, true)?; }
        Ok(())
    }

    /// Project committed state into caller-owned staging without ending the live
    /// transaction. The returned length excludes allocations made since begin.
    /// Callers must sanitize transient contents before persisting this projection.
    pub fn copy_committed_state(&self, statics: &[u8], heap_output: &mut [u8], static_output: &mut [u8]) -> Result<usize> {
        if heap_output.len() != self.next || static_output.len() != statics.len() {
            heap_output.fill(0);
            static_output.fill(0);
            return Err(Error::Bounds);
        }
        let used = self.committed_bytes();
        self.project_heap(&mut heap_output[..used])?;
        heap_output[used..].fill(0);
        static_output.copy_from_slice(statics);
        self.project_statics(static_output)?;
        Ok(used)
    }

    pub fn commit_transaction(&mut self) -> Result<()> {
        self.transaction.take().ok_or(Error::Inconsistent)?;
        self.pending_writes.require_snapshot();
        Ok(())
    }

    /// Restore conditional payload writes. True means objects were allocated after
    /// begin: the caller must invalidate their references or terminate the session.
    /// New storage is cleared and allocation is locked until the caller ends the session.
    pub fn abort_transaction(&mut self, statics: &mut [u8]) -> Result<bool> {
        let (start, undo) = self.transaction.take().ok_or(Error::Inconsistent)?;
        undo.restore(self.bytes, statics);
        let allocated = self.next != start;
        if allocated {
            self.visit_objects(|_, info, payload| {
                if info.kind == KIND_REFERENCE && info.clear_event != 0 {
                    for slot in payload.chunks_exact_mut(2) {
                        if u16::from_be_bytes([slot[0], slot[1]]) as usize >= start { slot.fill(0); }
                    }
                }
                Ok(())
            })?;
            self.bytes[start..self.next].fill(0);
            self.next = start;
            self.aborted_allocations = true;
        }
        Ok(allocated)
    }

    pub fn remember_static(&mut self, at: usize, before: &[u8]) -> Result<()> {
        if let Some((_, undo)) = &mut self.transaction { undo.record(at, before, true)?; }
        else { self.pending_writes.statics(at, before.len()); }
        Ok(())
    }

    fn remember(&mut self, at: usize, length: usize, info: Info) -> Result<()> {
        if info.clear_event == 0 {
            if let Some((start, undo)) = &mut self.transaction {
                // Abort wipes the entire allocation tail; only pre-existing payloads
                // need before-images. Committed projections also exclude this tail.
                if at < *start { undo.record(at, &self.bytes[at..at + length], false)?; }
            } else { self.pending_writes.heap(at, length); }
        }
        Ok(())
    }

    /// Bytes handed out so far, which is what a writeback has to persist.
    pub fn used(&self) -> usize {
        self.next
    }

    /// The bytes themselves, for sealing and writing back.
    pub fn image(&self) -> &[u8] {
        &self.bytes[..self.next]
    }

    fn allocation_range(&self, next: usize, kind: u8, length: u16) -> Result<core::ops::Range<usize>> {
        let info = Info { class: 0, length, kind, owner: 0, clear_event: 0 };
        microcard_memory::allocation_range(
            next, HEADER, length as usize, info.element_size(), 2,
            self.bytes.len().min(u16::MAX as usize),
        ).ok_or(Error::Quota)
    }

    /// Check a compound allocation before publishing any of its references.
    pub(crate) fn check_allocations(&self, objects: &[(u8, u16)]) -> Result<()> {
        let mut next = self.next;
        for &(kind, length) in objects {
            next = self.allocation_range(next, kind, length)?.end;
        }
        Ok(())
    }

    fn allocate(&mut self, class: u16, length: u16, kind: u8, owner: Context) -> Result<Reference> {
        if self.aborted_allocations { return Err(Error::TransactionAborted); }
        let range = self.allocation_range(self.next, kind, length)?;
        let at = range.start;
        let end = range.end;
        self.bytes[at..end].fill(0);
        self.bytes[at..at + 2].copy_from_slice(&class.to_be_bytes());
        self.bytes[at + 2..at + 4].copy_from_slice(&length.to_be_bytes());
        self.bytes[at + 4] = kind;
        self.bytes[at + 5] = owner;
        self.next = end;
        // Transient payloads reset, but their headers and stable handles persist.
        // Transactional allocation tails are published only by commit.
        if self.transaction.is_none() { self.pending_writes.heap(at, end - at); }
        Ok(at as Reference)
    }

    /// An instance of a class, with `words` words of field, all zero.
    pub fn new_object(&mut self, class: u16, words: u16, owner: Context) -> Result<Reference> {
        self.allocate(class, words, KIND_OBJECT, owner)
    }

    /// An array of `length` elements, all zero or null.
    pub fn new_array(&mut self, kind: u8, length: u16, owner: Context) -> Result<Reference> {
        if !(KIND_BOOLEAN..=KIND_REFERENCE).contains(&kind) {
            return Err(Error::Format);
        }
        self.allocate(0, length, kind, owner)
    }

    pub fn new_transient_array(&mut self, kind: u8, length: u16, owner: Context, event: u8) -> Result<Reference> {
        if !matches!(event, CLEAR_ON_RESET | CLEAR_ON_DESELECT) { return Err(Error::Format); }
        let reference = self.new_array(kind, length, owner)?;
        self.bytes[reference as usize + 4] |= event << 4;
        Ok(reference)
    }

    pub fn transient_event(&self, reference: Reference) -> Result<u8> {
        if reference == NULL { return Ok(0); }
        Ok(self.info(reference)?.clear_event)
    }

    /// Visit allocated payloads without exposing their headers or allocating a reference list.
    pub fn visit_objects(&mut self, mut visit: impl FnMut(Reference, Info, &mut [u8]) -> Result<()>) -> Result<()> {
        // Maintenance visitors may mutate arbitrary payloads and cannot bypass undo.
        if self.transaction.is_some() { return Err(Error::Inconsistent); }
        let mut at = 2usize;
        while at < self.next {
            let info = self.info(at as Reference)?;
            let length = info.length as usize * info.element_size();
            let end = at + HEADER + length;
            visit(at as Reference, info, &mut self.bytes[at + HEADER..end])?;
            at = end.next_multiple_of(2);
        }
        if at != self.next { return Err(Error::Format); }
        Ok(())
    }

    /// Reset clears both transient kinds; deselection clears only that context's arrays.
    pub fn clear_transient(&mut self, event: u8, context: Context) -> Result<()> {
        if !matches!(event, CLEAR_ON_RESET | CLEAR_ON_DESELECT) { return Err(Error::Format); }
        self.visit_objects(|_, info, payload| {
            if info.clear_event != 0 && (event == CLEAR_ON_RESET || (info.clear_event == event && info.owner == context)) {
                payload.fill(0);
            }
            Ok(())
        })
    }

    /// Read an object's header.
    ///
    /// A reference that is null, misaligned or outside what has been allocated is refused
    /// here, so nothing downstream has to repeat the check.
    pub fn info(&self, reference: Reference) -> Result<Info> {
        Info::read(self.bytes, self.next, reference)
    }

    /// Check that `context` may touch this object, JCRE §6.2.
    pub fn check_access(&self, reference: Reference, context: Context) -> Result<Info> {
        let info = self.info(reference)?;
        // The runtime environment context reaches everything, which is how the API works on
        // an applet's own objects.
        if context != 0 && info.owner != context {
            return Err(Error::Firewall);
        }
        Ok(info)
    }

    fn slot(&self, reference: Reference, index: usize, want_array: bool) -> Result<(usize, Info)> {
        let info = self.info(reference)?;
        if info.is_array() != want_array {
            return Err(Error::Type);
        }
        if index >= info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + index * info.element_size();
        Ok((at, info))
    }

    pub fn get_word(&self, reference: Reference, index: usize) -> Result<u16> {
        let (at, _) = self.slot(reference, index, false)?;
        Ok(u16::from_be_bytes([self.bytes[at], self.bytes[at + 1]]))
    }

    pub fn put_word(&mut self, reference: Reference, index: usize, value: u16) -> Result<()> {
        let (at, info) = self.slot(reference, index, false)?;
        self.remember(at, 2, info)?;
        self.bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Runtime state such as a PIN presentation counter is never undone.
    pub fn put_word_unconditional(&mut self, reference: Reference, index: usize, value: u16) -> Result<()> {
        let (at, info) = self.slot(reference, index, false)?;
        if info.clear_event == 0 { self.pending_writes.heap(at, 2); }
        let value = value.to_be_bytes();
        if let Some((_, undo)) = &mut self.transaction { undo.preserve(at, &value); }
        self.bytes[at..at + 2].copy_from_slice(&value);
        Ok(())
    }

    pub fn put_int(&mut self, reference: Reference, index: usize, value: i32) -> Result<()> {
        let (at, info) = self.slot(reference, index, false)?;
        self.slot(reference, index + 1, false)?;
        self.remember(at, 4, info)?;
        self.bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    pub fn remember_object(&mut self, reference: Reference) -> Result<()> {
        let info = self.info(reference)?;
        self.remember(reference as usize + HEADER, info.length as usize * info.element_size(), info)
    }

    /// Read one array element, widened to a short.
    ///
    /// A byte element sign extends and a boolean does not, which is the difference between
    /// `baload` on a `byte[]` and on a `boolean[]`.
    pub fn array_get(&self, reference: Reference, index: usize) -> Result<i16> {
        let (at, info) = self.slot(reference, index, true)?;
        Ok(match info.kind {
            KIND_BOOLEAN => (self.bytes[at] != 0) as i16,
            KIND_BYTE => self.bytes[at] as i8 as i16,
            KIND_INT => return Err(Error::Type),
            _ => i16::from_be_bytes([self.bytes[at], self.bytes[at + 1]]),
        })
    }

    pub fn array_put(&mut self, reference: Reference, index: usize, value: i16) -> Result<()> {
        let (at, info) = self.slot(reference, index, true)?;
        if info.kind == KIND_INT { return Err(Error::Type); }
        self.remember(at, info.element_size(), info)?;
        match info.kind {
            KIND_BOOLEAN => self.bytes[at] = (value != 0) as u8,
            KIND_BYTE => self.bytes[at] = value as u8,
            KIND_INT => return Err(Error::Type),
            _ => self.bytes[at..at + 2].copy_from_slice(&value.to_be_bytes()),
        }
        Ok(())
    }

    pub fn array_get_int(&self, reference: Reference, index: usize) -> Result<i32> {
        let (at, info) = self.slot(reference, index, true)?;
        if info.kind != KIND_INT {
            return Err(Error::Type);
        }
        Ok(i32::from_be_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ]))
    }

    pub fn array_put_int(&mut self, reference: Reference, index: usize, value: i32) -> Result<()> {
        let (at, info) = self.slot(reference, index, true)?;
        if info.kind != KIND_INT {
            return Err(Error::Type);
        }
        self.remember(at, 4, info)?;
        self.bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// The bytes of a byte or boolean array, which is what the API layer works on.
    pub fn byte_slice(&self, reference: Reference, offset: usize, length: usize) -> Result<&[u8]> {
        let info = self.info(reference)?;
        if info.element_size() != 1 || !info.is_array() {
            return Err(Error::Type);
        }
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if end > info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + offset;
        Ok(&self.bytes[at..at + length])
    }

    /// Validate both complete ranges before an overlap-safe CPU copy.
    pub fn copy_bytes(
        &mut self,
        source: Reference,
        source_offset: usize,
        destination: Reference,
        destination_offset: usize,
        length: usize,
    ) -> Result<()> {
        self.copy_bytes_inner(source, source_offset, destination, destination_offset, length, true)
    }

    pub fn copy_bytes_unconditional(
        &mut self, source: Reference, source_offset: usize, destination: Reference,
        destination_offset: usize, length: usize,
    ) -> Result<()> {
        self.copy_bytes_inner(source, source_offset, destination, destination_offset, length, false)
    }

    fn copy_bytes_inner(
        &mut self, source: Reference, source_offset: usize, destination: Reference,
        destination_offset: usize, length: usize, conditional: bool,
    ) -> Result<()> {
        self.byte_slice(source, source_offset, length)?;
        self.byte_slice(destination, destination_offset, length)?;
        let info = self.info(destination)?;
        let source = source as usize + HEADER + source_offset;
        let destination = destination as usize + HEADER + destination_offset;
        if conditional { self.remember(destination, length, info)?; }
        microcard_memory::copy_bytes(self.bytes, source, destination, length).ok_or(Error::Bounds)?;
        if !conditional {
            if info.clear_event == 0 { self.pending_writes.heap(destination, length); }
            if let Some((_, undo)) = &mut self.transaction {
                undo.preserve(destination, &self.bytes[destination..destination + length]);
            }
        }
        Ok(())
    }

    pub fn fill_bytes_unconditional(&mut self, reference: Reference, offset: usize, length: usize, value: u8) -> Result<()> {
        self.byte_slice(reference, offset, length)?;
        let at = reference as usize + HEADER + offset;
        if self.info(reference)?.clear_event == 0 { self.pending_writes.heap(at, length); }
        self.bytes[at..at + length].fill(value);
        if let Some((_, undo)) = &mut self.transaction { undo.preserve(at, &self.bytes[at..at + length]); }
        Ok(())
    }

    /// Reserve before-images for a compound write before publishing any component.
    /// Spans use byte offsets into object or array payloads, excluding headers.
    /// Failure releases only these reservations, preserving earlier transaction writes.
    pub(crate) fn prepare_payload_writes(&mut self, spans: &[(Reference, usize, usize)]) -> Result<()> {
        for &(reference, offset, length) in spans {
            let info = self.info(reference)?;
            let end = offset.checked_add(length).ok_or(Error::Bounds)?;
            if end > info.length as usize * info.element_size() { return Err(Error::Bounds); }
        }
        let Some(remaining) = self.transaction_remaining() else { return Ok(()); };
        for &(reference, offset, length) in spans {
            let info = self.info(reference)?;
            if let Err(error) = self.remember(reference as usize + HEADER + offset, length, info) {
                if let Some((_, undo)) = &mut self.transaction { undo.rewind(remaining); }
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn byte_slice_mut(
        &mut self,
        reference: Reference,
        offset: usize,
        length: usize,
    ) -> Result<&mut [u8]> {
        let info = self.info(reference)?;
        if info.element_size() != 1 || !info.is_array() {
            return Err(Error::Type);
        }
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if end > info.length as usize {
            return Err(Error::Bounds);
        }
        let at = reference as usize + HEADER + offset;
        self.remember(at, length, info)?;
        Ok(&mut self.bytes[at..at + length])
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;

    #[test]
    fn rollback_covers_payload_writes_but_preserves_transients_and_unconditional_state() {
        let mut bytes = vec![0; 512];
        let mut heap = Heap::new(&mut bytes).unwrap();
        heap.initialize_lifecycle();
        assert_eq!(heap.lifecycle(), Ok(7));
        for state in 0..=u8::MAX {
            if state >= 0x80 || state & 7 != 7 {
                assert_eq!(heap.set_lifecycle(state), Ok(false));
                assert_eq!(heap.lifecycle(), Ok(7));
            }
        }
        let object = heap.new_object(1, 2, 1).unwrap();
        let array = heap.new_array(KIND_BYTE, 8, 1).unwrap();
        let short = heap.new_array(KIND_SHORT, 2, 1).unwrap();
        let integer = heap.new_array(KIND_INT, 2, 1).unwrap();
        let transient = heap.new_transient_array(KIND_BYTE, 1, 1, CLEAR_ON_RESET).unwrap();
        heap.byte_slice_mut(array, 0, 8).unwrap().copy_from_slice(b"abcdefgh");
        heap.put_word(object, 1, 3).unwrap();
        let original = heap.image().to_vec();
        assert!(heap.has_uncheckpointed_writes());
        heap.mark_checkpointed();

        heap.begin_transaction(128).unwrap();
        assert_eq!(heap.begin_transaction(128), Err(Error::Inconsistent));
        heap.put_word(object, 0, 9).unwrap();
        heap.put_word(object, 1, 5).unwrap();
        heap.array_put(array, 2, 42).unwrap();
        heap.byte_slice_mut(array, 1, 4).unwrap().fill(7);
        heap.copy_bytes(array, 0, array, 2, 6).unwrap();
        heap.array_put(short, 1, -20).unwrap();
        heap.array_put_int(integer, 0, -70000).unwrap();
        heap.array_put(transient, 0, 1).unwrap();
        assert!(!heap.has_uncheckpointed_writes(), "conditional and transient writes do not publish committed state");
        assert_eq!(heap.set_lifecycle(0x0f), Ok(true));
        heap.put_word_unconditional(object, 1, 2).unwrap();
        assert!(heap.has_uncheckpointed_writes());
        // Later conditional writes must restore the unconditional counter, not 3 or 5.
        heap.put_word(object, 1, 8).unwrap();
        let mut statics = [4, 5];
        heap.remember_static(0, &statics).unwrap();
        statics.fill(9);
        let mut projected = vec![0; heap.used()];
        let mut projected_statics = [0; 2];
        let remaining = heap.transaction_remaining();
        assert_eq!(heap.copy_committed_state(&statics, &mut projected, &mut projected_statics), Ok(heap.used()));
        assert_eq!(&projected[..2], &[1, 0x0f]);
        assert_eq!(projected_statics, [4, 5]);
        // Windows can split words and overlapping before-images without publishing
        // conditional values. They must agree with the existing full projection.
        for width in [1, 3, 7, 17] {
            let mut windowed = vec![0; projected.len()];
            for (index, chunk) in windowed.chunks_mut(width).enumerate() {
                heap.project_heap_range(index * width, chunk).unwrap();
            }
            assert_eq!(windowed, projected);
        }
        let mut invalid = [0xa5; 4];
        assert_eq!(heap.project_heap_range(usize::MAX, &mut invalid), Err(Error::Bounds));
        assert_eq!(invalid, [0; 4]);
        assert_eq!(statics, [9, 9]);
        assert_eq!(heap.get_word(object, 1), Ok(8));
        assert_eq!(heap.transaction_remaining(), remaining);
        assert!(!heap.abort_transaction(&mut statics).unwrap());
        assert_eq!(heap.lifecycle(), Ok(0x0f));
        let mut expected = original;
        expected[1] = 0x0f;
        expected[object as usize + HEADER + 2..object as usize + HEADER + 4]
            .copy_from_slice(&2u16.to_be_bytes());
        expected[transient as usize + HEADER] = 1;
        assert_eq!(heap.image(), expected);
        assert_eq!(projected, expected);
        assert_eq!(heap.abort_transaction(&mut []), Err(Error::Inconsistent));

        heap.mark_checkpointed();
        heap.begin_transaction(16).unwrap();
        heap.put_word(object, 0, 12).unwrap();
        assert!(!heap.has_uncheckpointed_writes());
        heap.commit_transaction().unwrap();
        assert!(heap.has_uncheckpointed_writes());
        assert_eq!(heap.get_word(object, 0), Ok(12));
        assert!(heap.pending_writes().snapshot_required());
        assert_eq!(heap.transaction_remaining(), None);
        assert_eq!(heap.copy_committed_state(&statics, &mut projected, &mut projected_statics), Ok(heap.used()));
        assert_eq!(projected, heap.image());
        assert_eq!(projected_statics, statics);
        assert_eq!(heap.copy_committed_state(&statics, &mut projected[..1], &mut projected_statics), Err(Error::Bounds));
        assert_eq!(projected[0], 0);
        assert_eq!(projected_statics, [0; 2]);
        heap.begin_transaction(0).unwrap();
        let created = heap.new_object(1, 1, 1).unwrap();
        heap.put_word(created, 0, 42).unwrap();
        assert_eq!(heap.put_word(object, 0, created), Err(Error::TransactionFull));
        heap.commit_transaction().unwrap();
        // Once committed, the same object must participate in later rollback.
        heap.begin_transaction(8).unwrap();
        heap.put_word(created, 0, 43).unwrap();
        assert_eq!(heap.transaction_remaining(), Some(0));
        assert!(!heap.abort_transaction(&mut []).unwrap());
        assert_eq!(heap.get_word(created, 0), Ok(42));
        assert_eq!(heap.get_word(object, 0), Ok(12));
    }

    #[test]
    fn undo_exhaustion_precedes_mutation_and_aborted_allocations_are_never_reused() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        assert!(!heap.has_uncheckpointed_writes());
        let array = heap.new_array(KIND_BYTE, 8, 1).unwrap();
        assert!(heap.has_uncheckpointed_writes());
        heap.mark_checkpointed();
        let transient = heap.new_transient_array(KIND_BYTE, 1, 1, CLEAR_ON_DESELECT).unwrap();
        assert!(heap.has_uncheckpointed_writes(), "transient allocation headers persist");
        assert_eq!(heap.pending_writes().heap_range(), Some(transient as usize..heap.used()));
        assert_eq!(heap.pending_writes().static_range(), None);
        assert!(!heap.pending_writes().snapshot_required());
        heap.mark_checkpointed();
        assert_eq!(heap.new_array(KIND_BYTE, u16::MAX, 1), Err(Error::Quota));
        assert!(!heap.has_uncheckpointed_writes());
        heap.begin_transaction(24).unwrap();
        heap.byte_slice_mut(array, 0, 4).unwrap().fill(1);
        assert_eq!(heap.prepare_payload_writes(&[(array, 4, 2), (array, 6, 2)]),
            Err(Error::TransactionFull));
        assert_eq!(heap.transaction_remaining(), Some(14));
        assert_eq!(heap.prepare_payload_writes(&[(array, 4, 2), (array, 8, 1)]), Err(Error::Bounds));
        assert_eq!(heap.transaction_remaining(), Some(14));
        heap.prepare_payload_writes(&[(array, 0, 4), (transient, 0, 1)]).unwrap();
        assert_eq!(heap.transaction_remaining(), Some(14));
        heap.array_put(transient, 0, 3).unwrap();
        assert!(!heap.abort_transaction(&mut []).unwrap());
        assert_eq!(heap.byte_slice(array, 0, 8).unwrap(), &[0; 8]);
        assert_eq!(heap.array_get(transient, 0), Ok(3));
        heap.begin_transaction(10).unwrap(); // Four payload bytes and six metadata bytes.
        heap.byte_slice_mut(array, 0, 4).unwrap().fill(1);
        assert_eq!(heap.transaction_remaining(), Some(0));
        heap.array_put(array, 1, 2).unwrap(); // Already saved, so no extra capacity.
        heap.array_put(transient, 0, 3).unwrap(); // Transient data consumes no undo.
        let before = heap.image().to_vec();
        assert_eq!(heap.copy_bytes(array, 0, array, 2, 4), Err(Error::TransactionFull));
        assert_eq!(heap.array_put(array, 8, 1), Err(Error::Bounds));
        assert_eq!(heap.image(), before);
        let created = heap.new_object(1, 1, 1).unwrap();
        heap.put_word(created, 0, 0x1234).unwrap();
        assert!(!heap.has_uncheckpointed_writes(), "an open transaction must not publish allocation tails");
        let created_array = heap.new_array(KIND_BYTE, 8, 1).unwrap();
        heap.copy_bytes(array, 0, created_array, 0, 8).unwrap();
        heap.byte_slice_mut(created_array, 0, 8).unwrap().fill(0x55);
        // An unconditional native write to a new transactional object still cannot
        // publish that object's allocation before the transaction commits.
        heap.put_word_unconditional(created, 0, 0x1234).unwrap();
        assert!(heap.pending_writes().heap_range().is_some());
        assert_eq!(heap.pending_writes().for_committed_heap(before.len()).heap_range(), None);
        assert_eq!(heap.transaction_remaining(), Some(0));
        let mut projected = vec![0; heap.used()];
        let used = heap.copy_committed_state(&[], &mut projected, &mut []).unwrap();
        assert_eq!(used, before.len());
        assert!(projected[used..].iter().all(|byte| *byte == 0));
        assert!(heap.info(created).is_ok(), "projection must not invalidate live objects");
        assert!(heap.abort_transaction(&mut []).unwrap(), "caller must invalidate new references");
        assert_eq!(heap.byte_slice(array, 0, 8).unwrap(), &[0; 8]);
        assert_eq!(heap.array_get(transient, 0), Ok(3));
        assert_eq!(heap.info(created), Err(Error::Bounds));
        assert_eq!(heap.new_object(1, 1, 1), Err(Error::TransactionAborted));
    }

    #[test]
    fn transient_events_clear_payloads_without_changing_handles_or_persistent_data() {
        let mut bytes = vec![0; 2048];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let mut arrays = alloc::vec::Vec::new();
        for kind in [KIND_BOOLEAN, KIND_BYTE, KIND_SHORT, KIND_INT, KIND_REFERENCE] {
            for owner in [1, 2] {
                for event in [0, CLEAR_ON_RESET, CLEAR_ON_DESELECT] {
                    let reference = if event == 0 { heap.new_array(kind, 3, owner).unwrap() }
                        else { heap.new_transient_array(kind, 3, owner, event).unwrap() };
                    if kind == KIND_INT { heap.array_put_int(reference, 0, 1).unwrap(); }
                    else { heap.array_put(reference, 0, 1).unwrap(); }
                    arrays.push((reference, event, owner, kind));
                }
            }
        }
        let used = heap.used();
        heap.clear_transient(CLEAR_ON_DESELECT, 1).unwrap();
        for &(reference, event, owner, kind) in &arrays {
            assert_eq!(heap.transient_event(reference).unwrap(), event);
            assert_eq!(heap.info(reference).unwrap().kind, kind);
            let value = if kind == KIND_INT { heap.array_get_int(reference, 0).unwrap() }
                else { i32::from(heap.array_get(reference, 0).unwrap()) };
            assert_eq!(value, i32::from(!(owner == 1 && event == CLEAR_ON_DESELECT)));
        }
        heap.clear_transient(CLEAR_ON_RESET, 0).unwrap();
        for (reference, event, _, kind) in arrays {
            let value = if kind == KIND_INT { heap.array_get_int(reference, 0).unwrap() }
                else { i32::from(heap.array_get(reference, 0).unwrap()) };
            assert_eq!(value, i32::from(event == 0));
        }
        for event in [0, 3, 255] {
            assert_eq!(heap.new_transient_array(KIND_BYTE, 3, 1, event), Err(Error::Format));
            assert_eq!(heap.clear_transient(event, 1), Err(Error::Format));
        }
        assert_eq!(heap.used(), used);
        assert_eq!(heap.transient_event(NULL), Ok(0));
    }

    #[test]
    fn an_object_reads_back_what_it_was_made_with() {
        let mut bytes = vec![0xaa; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(0x1234, 3, 7).unwrap();
        // Nothing sits at offset zero, so a zero word is always null and never an object.
        assert_ne!(object, NULL);
        let info = heap.info(object).unwrap();
        assert_eq!(info.class, 0x1234);
        assert_eq!(info.length, 3);
        assert_eq!(info.owner, 7);
        assert!(!info.is_array());
        // Fields start zero whatever the slab held, so a fresh object never shows the last
        // one's contents.
        assert_eq!(heap.get_word(object, 0).unwrap(), 0);
        heap.put_word(object, 2, 0x4321).unwrap();
        assert_eq!(heap.get_word(object, 2).unwrap(), 0x4321);
    }

    #[test]
    fn a_field_index_past_the_object_is_refused() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 2, 1).unwrap();
        assert_eq!(heap.get_word(object, 2), Err(Error::Bounds));
        assert_eq!(heap.put_word(object, 9, 0), Err(Error::Bounds));
    }

    #[test]
    fn the_null_reference_is_refused_before_anything_reads_it() {
        let mut bytes = vec![0; 64];
        let heap = Heap::new(&mut bytes).unwrap();
        assert_eq!(heap.info(NULL), Err(Error::Null));
        assert_eq!(heap.get_word(NULL, 0), Err(Error::Null));
    }

    #[test]
    fn a_reference_outside_what_was_allocated_is_refused() {
        let mut bytes = vec![0; 64];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 1, 1).unwrap();
        // Past the allocation point, and misaligned, which would read a header from the
        // middle of an object.
        assert_eq!(heap.info(heap.used() as u16), Err(Error::Bounds));
        assert_eq!(heap.info(object + 1), Err(Error::Bounds));
    }

    #[test]
    fn element_width_follows_the_array_type() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let bytes_array = heap.new_array(KIND_BYTE, 4, 1).unwrap();
        let shorts = heap.new_array(KIND_SHORT, 4, 1).unwrap();
        // A byte element sign extends on the way out. A boolean does not.
        heap.array_put(bytes_array, 0, -1).unwrap();
        assert_eq!(heap.array_get(bytes_array, 0).unwrap(), -1);
        heap.array_put(shorts, 3, -300).unwrap();
        assert_eq!(heap.array_get(shorts, 3).unwrap(), -300);
        let booleans = heap.new_array(KIND_BOOLEAN, 2, 1).unwrap();
        heap.array_put(booleans, 0, -1).unwrap();
        assert_eq!(heap.array_get(booleans, 0).unwrap(), 1);
    }

    #[test]
    fn an_int_array_is_read_as_ints_and_nothing_else() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let array = heap.new_array(KIND_INT, 2, 1).unwrap();
        heap.array_put_int(array, 1, -70_000).unwrap();
        assert_eq!(heap.array_get_int(array, 1).unwrap(), -70_000);
        // Reading it as a short would take half of one element.
        assert_eq!(heap.array_get(array, 1), Err(Error::Type));
        let shorts = heap.new_array(KIND_SHORT, 2, 1).unwrap();
        assert_eq!(heap.array_get_int(shorts, 0), Err(Error::Type));
    }

    #[test]
    fn an_array_and_an_object_are_not_interchangeable() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let object = heap.new_object(1, 2, 1).unwrap();
        let array = heap.new_array(KIND_SHORT, 2, 1).unwrap();
        // getfield on an array and an array load on an object are both type confusion.
        assert_eq!(heap.array_get(object, 0), Err(Error::Type));
        assert_eq!(heap.get_word(array, 0), Err(Error::Type));
        assert_eq!(heap.new_array(KIND_OBJECT, 1, 1), Err(Error::Format));
    }

    #[test]
    fn the_firewall_compares_the_owner_with_the_caller() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let mine = heap.new_object(1, 1, 3).unwrap();
        heap.check_access(mine, 3).unwrap();
        // Another applet's context cannot reach it, which is the whole firewall.
        assert_eq!(heap.check_access(mine, 4), Err(Error::Firewall));
        // The runtime environment reaches everything, which is how the API works on an
        // applet's own objects.
        heap.check_access(mine, 0).unwrap();
    }

    #[test]
    fn a_byte_array_hands_out_a_bounded_slice() {
        let mut bytes = vec![0; 256];
        let mut heap = Heap::new(&mut bytes).unwrap();
        let array = heap.new_array(KIND_BYTE, 8, 1).unwrap();
        heap.byte_slice_mut(array, 2, 3).unwrap().copy_from_slice(&[1, 2, 3]);
        assert_eq!(heap.byte_slice(array, 0, 8).unwrap(), &[0, 0, 1, 2, 3, 0, 0, 0]);
        assert_eq!(heap.byte_slice(array, 6, 3), Err(Error::Bounds));
        // A short array is not a byte array, whatever its length.
        let shorts = heap.new_array(KIND_SHORT, 8, 1).unwrap();
        assert_eq!(heap.byte_slice(shorts, 0, 1), Err(Error::Type));
    }

    #[test]
    fn a_heap_that_runs_out_refuses_rather_than_overwriting() {
        let mut bytes = vec![0; 32];
        let mut heap = Heap::new(&mut bytes).unwrap();
        heap.new_array(KIND_BYTE, 15, 1).unwrap();
        assert_eq!(heap.used(), 24); // Header and odd byte payload round to a word.
        let before = heap.image().to_vec();
        assert_eq!(heap.new_array(KIND_BYTE, 16, 1), Err(Error::Quota));
        assert_eq!(heap.new_array(KIND_INT, u16::MAX, 1), Err(Error::Quota));
        assert_eq!(heap.image(), before);
        assert_eq!(heap.new_array(KIND_BYTE, 2, 1).unwrap(), 24);
        assert_eq!(heap.used(), 32);
        assert_eq!(heap.new_object(1, 0, 1), Err(Error::Quota));
        // The slab has to hold at least one header.
        let mut tiny = vec![0; 4];
        assert!(Heap::new(&mut tiny).is_err());
    }
}
