//! Compact command-local objects with stable handles and checked byte access.
use super::{MAX_TRANSIENT_BYTES, MAX_TRANSIENT_OBJECTS, RuntimeValue};
use crate::{Error, Result};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

const HEADER: usize = 6;
const HANDLE_BYTES: usize = 2;
const BYTES: u8 = 0;
const INTS: u8 = 1;
const STRUCT: u8 = 2;

pub struct Heap {
    data: Vec<u8>,
    pub(super) objects: Vec<u16>,
    pub(super) used: usize,
    generation: usize,
}

impl Zeroize for Heap {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.objects.zeroize();
        self.used = 0;
        // Reusing a cleared heap must not make a retired handle valid again.
        self.generation = self.generation.saturating_add(MAX_TRANSIENT_OBJECTS);
    }
}

impl Heap {
    pub(crate) fn new() -> Self {
        Self {
            data: Vec::new(),
            objects: Vec::new(),
            used: 0,
            generation: 0,
        }
    }

    fn allocate_object(
        &mut self,
        kind: u8,
        unit: u8,
        owner: u16,
        length: usize,
    ) -> Result<RuntimeValue> {
        if self.objects.len() >= MAX_TRANSIENT_OBJECTS {
            return Err(Error::Quota);
        }
        let handle = self
            .generation
            .checked_add(self.objects.len() + 1)
            .ok_or(Error::Quota)?;
        let length_word = u16::try_from(length).map_err(|_| Error::Quota)?;
        let handles = (self.objects.len() + 1) * HANDLE_BYTES;
        let range = microcard_memory::allocation_range(
            self.data.len(),
            HEADER,
            length,
            if kind == BYTES { 1 } else { 4 },
            2,
            MAX_TRANSIENT_BYTES - handles,
        )
        .ok_or(Error::Quota)?;
        self.objects
            .try_reserve_exact(1)
            .map_err(|_| Error::Quota)?;
        if range.end > self.data.capacity() {
            // Vec growth can release an unwiped copy of secrets. Move explicitly,
            // wiping the previous allocation before the allocator receives it.
            let capacity = range.end.next_power_of_two().min(MAX_TRANSIENT_BYTES);
            let mut next = Vec::new();
            next.try_reserve_exact(capacity).map_err(|_| Error::Quota)?;
            next.extend_from_slice(&self.data);
            self.data.zeroize();
            self.data = next;
        }
        self.data.resize(range.end, 0);
        let header = &mut self.data[range.start..range.start + HEADER];
        header[0] = kind;
        header[1] = unit;
        header[2..4].copy_from_slice(&owner.to_le_bytes());
        header[4..6].copy_from_slice(&length_word.to_le_bytes());
        self.objects.push(range.start as u16);
        self.used = range.end + handles;
        Ok(RuntimeValue::Ref(handle))
    }

    pub(super) fn allocate(&mut self, bytes: bool, length: usize) -> Result<RuntimeValue> {
        self.allocate_object(if bytes { BYTES } else { INTS }, 0, 0, length)
    }

    pub(super) fn allocate_struct(
        &mut self,
        unit: usize,
        owner: u16,
        fields: usize,
    ) -> Result<RuntimeValue> {
        self.allocate_object(
            STRUCT,
            u8::try_from(unit).map_err(|_| Error::Quota)?,
            owner,
            fields,
        )
    }

    pub fn allocate_bytes(&mut self, values: Vec<u8>) -> Result<RuntimeValue> {
        let values = Zeroizing::new(values);
        let handle = self.allocate(true, values.len())?;
        self.bytes_mut(handle)?.copy_from_slice(&values);
        Ok(handle)
    }

    fn info(&self, handle: RuntimeValue) -> Result<(usize, u8, usize)> {
        let RuntimeValue::Ref(handle) = handle else {
            return Err(Error::Format);
        };
        let index = handle
            .checked_sub(self.generation)
            .and_then(|index| index.checked_sub(1))
            .ok_or(Error::Bounds)?;
        let at = usize::from(*self.objects.get(index).ok_or(Error::Bounds)?);
        let header = self.data.get(at..at + HEADER).ok_or(Error::Bounds)?;
        let length = usize::from(u16::from_le_bytes([header[4], header[5]]));
        Ok((at, header[0], length))
    }

    pub fn bytes(&self, handle: RuntimeValue) -> Result<&[u8]> {
        let (at, kind, length) = self.info(handle)?;
        if kind != BYTES {
            return Err(Error::Format);
        }
        self.data
            .get(at + HEADER..at + HEADER + length)
            .ok_or(Error::Bounds)
    }

    pub fn bytes_mut(&mut self, handle: RuntimeValue) -> Result<&mut [u8]> {
        let (at, kind, length) = self.info(handle)?;
        if kind != BYTES {
            return Err(Error::Format);
        }
        self.data
            .get_mut(at + HEADER..at + HEADER + length)
            .ok_or(Error::Bounds)
    }

    pub(crate) fn copy_bytes(
        &mut self,
        source: RuntimeValue,
        source_offset: usize,
        destination: RuntimeValue,
        destination_offset: usize,
        length: usize,
    ) -> Result<()> {
        microcard_memory::byte_range(self.bytes(source)?.len(), source_offset, length)
            .ok_or(Error::Bounds)?;
        microcard_memory::byte_range(self.bytes(destination)?.len(), destination_offset, length)
            .ok_or(Error::Bounds)?;
        let source = self.info(source)?.0 + HEADER + source_offset;
        let destination = self.info(destination)?.0 + HEADER + destination_offset;
        microcard_memory::copy_bytes(&mut self.data, source, destination, length)
            .ok_or(Error::Bounds)
    }

    pub(super) fn array_length(&self, handle: RuntimeValue) -> Result<usize> {
        let (_, kind, length) = self.info(handle)?;
        if kind == STRUCT {
            return Err(Error::Format);
        }
        Ok(length)
    }

    fn array_slot(&self, handle: RuntimeValue, index: usize, bytes: bool) -> Result<usize> {
        let (at, kind, length) = self.info(handle)?;
        if kind != if bytes { BYTES } else { INTS } {
            return Err(Error::Format);
        }
        if index >= length {
            return Err(Error::Bounds);
        }
        Ok(at + HEADER + index * if bytes { 1 } else { 4 })
    }

    pub(super) fn array_get(&self, handle: RuntimeValue, index: usize, bytes: bool) -> Result<i32> {
        let at = self.array_slot(handle, index, bytes)?;
        Ok(if bytes {
            i32::from(self.data[at])
        } else {
            self.read_int(at)
        })
    }

    pub(super) fn array_set(
        &mut self,
        handle: RuntimeValue,
        index: usize,
        bytes: bool,
        value: i32,
    ) -> Result<()> {
        let at = self.array_slot(handle, index, bytes)?;
        if bytes {
            self.data[at] = value as u8;
        } else {
            self.write_int(at, value);
        }
        Ok(())
    }

    fn field_slot(
        &self,
        handle: RuntimeValue,
        unit: usize,
        owner: u16,
        index: u16,
    ) -> Result<usize> {
        let (at, kind, length) = self.info(handle)?;
        if kind != STRUCT
            || usize::from(self.data[at + 1]) != unit
            || u16::from_le_bytes([self.data[at + 2], self.data[at + 3]]) != owner
        {
            return Err(Error::Format);
        }
        if usize::from(index) >= length {
            return Err(Error::Bounds);
        }
        Ok(at + HEADER + usize::from(index) * 4)
    }

    pub(super) fn field_get(
        &self,
        handle: RuntimeValue,
        unit: usize,
        owner: u16,
        index: u16,
    ) -> Result<RuntimeValue> {
        Ok(RuntimeValue::Int(
            self.read_int(self.field_slot(handle, unit, owner, index)?),
        ))
    }

    pub(super) fn field_set(
        &mut self,
        handle: RuntimeValue,
        unit: usize,
        owner: u16,
        index: u16,
        value: RuntimeValue,
    ) -> Result<()> {
        let at = self.field_slot(handle, unit, owner, index)?;
        self.write_int(at, value.int()?);
        Ok(())
    }

    fn read_int(&self, at: usize) -> i32 {
        i32::from_le_bytes(self.data[at..at + 4].try_into().unwrap())
    }

    fn write_int(&mut self, at: usize, value: i32) {
        self.data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}
