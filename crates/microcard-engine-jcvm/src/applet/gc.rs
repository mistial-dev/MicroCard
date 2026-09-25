//! Requested object deletion at an idle applet boundary.
//!
//! References are slab offsets. Trace them before moving anything, rewrite the
//! live graph through a sorted old-to-new index, then compact in place. The
//! journal publishes the resulting heap as one authenticated snapshot.
use super::AppletInstance;
use crate::cap::LoadFile;
use crate::link::Linked;
use crate::natives;
use crate::vm::frame::Reference;
use crate::vm::heap::{self, Info};
use crate::{Error, Result};
use alloc::vec::Vec;

fn bitmap(bytes: usize) -> Result<Vec<u8>> {
    let mut bits = Vec::new();
    bits.try_reserve_exact(bytes.div_ceil(16)).map_err(|_| Error::Quota)?;
    bits.resize(bytes.div_ceil(16), 0);
    Ok(bits)
}

fn bit_is_set(bits: &[u8], reference: Reference) -> bool {
    bits.get(reference as usize / 16)
        .is_some_and(|byte| byte & (1 << ((reference as usize / 2) % 8)) != 0)
}

fn set_bit(bits: &mut [u8], reference: Reference) {
    bits[reference as usize / 16] |= 1 << ((reference as usize / 2) % 8);
}

fn object_end(at: usize, info: Info) -> Result<usize> {
    at.checked_add(heap::HEADER)
        .and_then(|at| at.checked_add(usize::from(info.length) * info.element_size()))
        .map(|end| end.next_multiple_of(2)).ok_or(Error::Bounds)
}

fn visit_reference_slots(linked: &Linked<'_>, info: Info, payload_at: usize,
        mut visit: impl FnMut(usize) -> Result<()>) -> Result<()> {
    let bytes = usize::from(info.length) * info.element_size();
    if info.kind == heap::KIND_REFERENCE {
        for at in (0..bytes).step_by(2) { visit(payload_at + at)?; }
    } else if info.kind == heap::KIND_OBJECT {
        if natives::is_native_class(info.class) {
            natives::visit_native_reference_offsets(info, bytes, |at| visit(payload_at + at))?;
        } else {
            linked.visit_instance_reference_offsets(info.class, bytes, |at| visit(payload_at + at))?;
        }
    }
    Ok(())
}

fn mark(reference: Reference, starts: &[u8], marked: &mut [u8], queue: &mut Vec<u32>) -> Result<()> {
    if reference == 0 { return Ok(()); }
    if !reference.is_multiple_of(2) || !bit_is_set(starts, reference) { return Err(Error::Bounds); }
    if !bit_is_set(marked, reference) {
        set_bit(marked, reference);
        queue.push(u32::from(reference));
    }
    Ok(())
}

fn relocated(reference: Reference, index: &[u32]) -> Result<Reference> {
    if reference == 0 { return Ok(0); }
    let position = index.binary_search_by_key(&reference, |entry| (entry >> 16) as u16)
        .map_err(|_| Error::Bounds)?;
    Ok(index[position] as u16)
}

fn rewrite_slot(bytes: &mut [u8], at: usize, index: &[u32]) -> Result<bool> {
    let old = bytes.get(at..at + 2).ok_or(Error::Bounds)?;
    let old = u16::from_be_bytes([old[0], old[1]]);
    let next = relocated(old, index)?;
    if next != old { bytes[at..at + 2].copy_from_slice(&next.to_be_bytes()); }
    Ok(next != old)
}

impl AppletInstance {
    pub(super) fn collect_unreachable(&mut self, file: &LoadFile) -> Result<bool> {
        let linked = Linked::new(file)?;
        let used = self.heap_used;
        let bytes = &mut self.heap[..used];
        let mut starts = bitmap(used)?;
        let mut marked = bitmap(used)?;
        let mut objects = 0usize;
        let mut at = 2usize;
        while at < used {
            let info = Info::read(bytes, used, at as Reference)?;
            set_bit(&mut starts, at as Reference);
            objects += 1;
            at = object_end(at, info)?;
        }
        if at != used { return Err(Error::Format); }
        // Reuse this bounded worklist as the relocation index after tracing.
        let mut queue = Vec::new();
        queue.try_reserve_exact(objects).map_err(|_| Error::Quota)?;
        at = 2;
        while at < self.runtime_bytes {
            mark(at as Reference, &starts, &mut marked, &mut queue)?;
            at = object_end(at, Info::read(bytes, used, at as Reference)?)?;
        }
        if at != self.runtime_bytes { return Err(Error::Format); }
        mark(self.instance.ok_or(Error::Missing)?, &starts, &mut marked, &mut queue)?;
        let static_references = usize::from(file.static_fields()?.reference_count) * 2;
        for slot in self.statics.get(..static_references).ok_or(Error::Bounds)?.chunks_exact(2) {
            mark(u16::from_be_bytes([slot[0], slot[1]]), &starts, &mut marked, &mut queue)?;
        }
        while let Some(reference) = queue.pop() {
            let reference = reference as Reference;
            let info = Info::read(bytes, used, reference)?;
            visit_reference_slots(&linked, info, reference as usize + heap::HEADER, |slot| {
                let word = bytes.get(slot..slot + 2).ok_or(Error::Bounds)?;
                mark(u16::from_be_bytes([word[0], word[1]]), &starts, &mut marked, &mut queue)
            })?;
        }
        let mut next = 2usize;
        at = 2;
        while at < used {
            let info = Info::read(bytes, used, at as Reference)?;
            let end = object_end(at, info)?;
            if bit_is_set(&marked, at as Reference) {
                queue.push(((at as u32) << 16) | next as u32);
                next += end - at;
            }
            at = end;
        }
        if next == used { return Ok(false); }
        // A dead suffix needs no relocation. Publish the shorter heap length
        // with the request-bit patch instead of copying live objects or writing
        // a full snapshot.
        if queue.iter().all(|entry| (entry >> 16) as u16 == *entry as u16) {
            bytes[next..].fill(0);
            self.heap_used = next;
            self.words.fill(0);
            self.tags.fill(0);
            return Ok(true);
        }
        // All fallible reference checks happen before the first mutation.
        at = 2;
        while at < used {
            let info = Info::read(bytes, used, at as Reference)?;
            let end = object_end(at, info)?;
            if bit_is_set(&marked, at as Reference) {
                visit_reference_slots(&linked, info, at + heap::HEADER, |slot| {
                    let word = bytes.get(slot..slot + 2).ok_or(Error::Bounds)?;
                    relocated(u16::from_be_bytes([word[0], word[1]]), &queue).map(|_| ())
                })?;
            }
            at = end;
        }
        for slot in self.statics.get(..static_references).ok_or(Error::Bounds)?.chunks_exact(2) {
            relocated(u16::from_be_bytes([slot[0], slot[1]]), &queue)?;
        }
        let old_instance = self.instance.ok_or(Error::Missing)?;
        let instance = relocated(old_instance, &queue)?;
        let apdu = relocated(self.apdu, &queue)?;
        let buffer = relocated(self.buffer, &queue)?;
        let mut writes = self.pending_writes;
        at = 2;
        while at < used {
            let info = Info::read(bytes, used, at as Reference)?;
            let end = object_end(at, info)?;
            if bit_is_set(&marked, at as Reference) {
                let destination = relocated(at as Reference, &queue)? as usize;
                visit_reference_slots(&linked, info, at + heap::HEADER, |slot| {
                    if rewrite_slot(bytes, slot, &queue)? && destination == at {
                        writes.heap(slot, 2);
                    }
                    Ok(())
                })?;
            }
            at = end;
        }
        for at in (0..static_references).step_by(2) {
            if rewrite_slot(&mut self.statics, at, &queue)? { writes.statics(at, 2); }
        }
        for entry in &queue {
            let old = (entry >> 16) as usize;
            let new = (*entry as u16) as usize;
            let info = Info::read(bytes, used, old as Reference)?;
            let end = object_end(old, info)?;
            if old != new {
                bytes.copy_within(old..end, new);
                writes.heap(new, end - old);
            }
        }
        bytes[next..].fill(0);
        self.heap_used = next;
        self.instance = Some(instance);
        self.apdu = apdu;
        self.buffer = buffer;
        self.words.fill(0);
        self.tags.fill(0);
        if instance != old_instance { writes.require_snapshot(); }
        self.pending_writes = writes;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ClassSpec, Package};
    use crate::vm::heap::Heap;
    use alloc::vec;

    struct Capture { heap: Vec<u8>, calls: usize, snapshot: bool, ranges: Vec<core::ops::Range<usize>> }
    impl crate::host::Host for Capture {
        fn checkpoint(&mut self, view: crate::applet::PersistentView<'_>, _: crate::host::CheckpointReason) -> Result<()> {
            self.snapshot = view.pending_writes().is_none_or(|writes| writes.snapshot_required());
            self.ranges = view.pending_writes().map_or_else(Vec::new, |writes| writes.heap_ranges().collect());
            self.heap = view.heap.to_vec();
            self.calls += 1;
            Ok(())
        }
    }

    #[test]
    fn deletion_compacts_only_unreachable_objects_and_rewrites_live_handles() {
        let package = Package {
            classes: vec![ClassSpec { declared_size: 1, reference_count: 1, ..ClassSpec::default() }],
            static_bytes: 2,
            static_references: 1,
            ..Package::default()
        }.build();
        let file = LoadFile::parse(&package).unwrap();
        let mut card = AppletInstance::new(&file, super::super::Sizes::default()).unwrap();
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let dead = heap.new_object(0, 1, 1).unwrap();
        let root = heap.new_object(0, 1, 1).unwrap();
        let native = heap.new_object(super::super::native_class_of(crate::jcvm_api::ClassId::AESKey).unwrap(), 6, 1).unwrap();
        let child = heap.new_object(0, 1, 1).unwrap();
        let static_root = heap.new_object(0, 1, 1).unwrap();
        let _last_dead = heap.new_object(0, 1, 1).unwrap();
        heap.put_word(root, 0, native).unwrap();
        heap.put_word(native, 2, child).unwrap();
        heap.put_word(child, 0, root).unwrap();
        heap.request_object_deletion().unwrap();
        card.pending_writes.merge(heap.pending_writes());
        card.heap_used = heap.used();
        card.instance = Some(root);
        card.statics[..2].copy_from_slice(&static_root.to_be_bytes());
        let before = card.heap_used;
        let mut host = Capture { heap: Vec::new(), calls: 0, snapshot: false, ranges: Vec::new() };
        card.service_object_deletion(&file, &mut host).unwrap();
        assert_eq!(host.calls, 1);
        assert!(host.snapshot);
        assert_eq!(host.heap, card.heap[..card.heap_used]);
        assert_eq!(host.heap[0], 3);
        assert_eq!(card.heap_used, before - 2 * (heap::HEADER + 2));
        let root = card.instance.unwrap();
        assert_eq!(root, dead);
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let native = heap.get_word(root, 0).unwrap();
        let child = heap.get_word(native, 2).unwrap();
        assert_eq!(heap.get_word(child, 0), Ok(root));
        let moved_static = u16::from_be_bytes(card.statics[..2].try_into().unwrap());
        assert_eq!(heap.info(moved_static).unwrap().class, 0);
        assert_ne!(moved_static, static_root);
        assert!(!card.pending_writes.any());
        assert!(!card.collect_unreachable(&file).unwrap());
    }

    #[test]
    fn deletion_recovers_a_full_slab_without_applet_heap_scratch() {
        let package = Package {
            classes: vec![ClassSpec { declared_size: 1, ..ClassSpec::default() }],
            ..Package::default()
        }.build();
        let file = LoadFile::parse(&package).unwrap();
        let mut card = AppletInstance::new(&file, super::super::Sizes {
            heap_bytes: 65_534, frame_words: 0, ..super::super::Sizes::default()
        }).unwrap();
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let root = heap.new_object(0, 1, 1).unwrap();
        let mut dead = 0;
        while heap.new_object(0, 1, 1).is_ok() { dead += 1; }
        assert!(dead > 7_000);
        heap.request_object_deletion().unwrap();
        card.pending_writes.merge(heap.pending_writes());
        card.heap_used = heap.used();
        card.instance = Some(root);
        // Model an earlier durable APDU: the request bit is already on flash.
        card.pending_writes = heap::PendingWrites::default();
        let mut host = Capture { heap: Vec::new(), calls: 0, snapshot: false, ranges: Vec::new() };
        card.service_object_deletion(&file, &mut host).unwrap();
        assert_eq!(host.calls, 1);
        assert!(!host.snapshot);
        assert_eq!(card.heap_used, card.runtime_bytes + heap::HEADER + 2);
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert!(heap.new_object(0, 1, 1).is_ok());
    }

    #[test]
    fn relocating_a_child_keeps_the_instance_and_uses_a_patch() {
        let package = Package {
            classes: vec![ClassSpec { declared_size: 1, reference_count: 1, ..ClassSpec::default() }],
            ..Package::default()
        }.build();
        let file = LoadFile::parse(&package).unwrap();
        let mut card = AppletInstance::new(&file, super::super::Sizes::default()).unwrap();
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let root = heap.new_object(0, 1, 1).unwrap();
        let dead = heap.new_object(0, 1, 1).unwrap();
        let child = heap.new_object(0, 1, 1).unwrap();
        heap.put_word(root, 0, child).unwrap();
        heap.request_object_deletion().unwrap();
        card.heap_used = heap.used();
        card.instance = Some(root);
        card.pending_writes = heap::PendingWrites::default();
        let before = card.heap[..card.heap_used].to_vec();
        let mut host = Capture { heap: Vec::new(), calls: 0, snapshot: false, ranges: Vec::new() };
        card.service_object_deletion(&file, &mut host).unwrap();
        assert_eq!(host.calls, 1);
        assert!(!host.snapshot);
        assert_eq!(card.instance, Some(root));
        assert_eq!(Heap::resume(&mut card.heap, card.heap_used).unwrap().get_word(root, 0), Ok(dead));
        let mut replayed = before;
        replayed.truncate(card.heap_used);
        for range in host.ranges {
            replayed[range.clone()].copy_from_slice(&host.heap[range]);
        }
        assert_eq!(replayed, host.heap, "tracked ranges must replay the compacted heap");
    }
}
