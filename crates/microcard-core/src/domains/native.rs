//! MC04 native service dispatch, authorization and bounded output handling.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum NativeArgument<'a> {
    Int(i32),
    Bytes(&'a [u8]),
}

fn native_range(bytes: &[u8], offset: i32, length: i32) -> Result<&[u8]> {
    let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
    let end = offset.checked_add(length).ok_or(Error::Bounds)?;
    bytes.get(offset..end).ok_or(Error::Bounds)
}

impl NativeArgument<'_> {
    fn int(&self) -> Result<i32> {
        match self {
            Self::Int(value) => Ok(*value),
            Self::Bytes(_) => Err(Error::Format),
        }
    }

    fn bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(value) => Ok(value),
            Self::Int(_) => Err(Error::Format),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BufferResult {
    Void,
    Bytes(Vec<u8>),
    Scalar(i32),
}

impl<P: Platform> crate::mc04_vm::External for Host<'_, P> {
    fn resolve(&self, unit: usize, member: u16) -> Result<crate::mc04_vm::LinkedTarget> {
        let units = self.units.ok_or(Error::Unauthorized)?;
        let target = &units
            .get(unit)
            .ok_or(Error::Unauthorized)?
            .calls
            .iter()
            .find(|binding| binding.member == member)
            .ok_or(Error::Unauthorized)?
            .target;
        match target {
            CallTarget::ObjectConstructor => Ok(crate::mc04_vm::LinkedTarget::ObjectConstructor),
            CallTarget::CurrentDomain => Ok(crate::mc04_vm::LinkedTarget::CurrentDomain),
            CallTarget::DomainStorage => Ok(crate::mc04_vm::LinkedTarget::DomainStorage),
            CallTarget::DomainKeys => Ok(crate::mc04_vm::LinkedTarget::DomainKeys),
            CallTarget::Native(id) => Ok(crate::mc04_vm::LinkedTarget::Native(*id)),
            CallTarget::Managed { dependency, method } => {
                let digest = units
                    .get(unit)
                    .and_then(|unit| unit.bindings.get(usize::from(*dependency)))
                    .ok_or(Error::Storage)?
                    .digest;
                let mut matches = units.iter().enumerate().filter(|(_, unit)| {
                    unit.package.digest == digest
                });
                let (index, _) = matches.next().ok_or(Error::Missing)?;
                if matches.next().is_some() {
                    return Err(Error::Storage);
                }
                Ok(crate::mc04_vm::LinkedTarget::Managed {
                    unit: index,
                    method: *method,
                })
            }
        }
    }

    fn invoke(
        &mut self,
        unit: usize,
        member: u16,
        id: u8,
        arguments: &[crate::mc04_vm::RuntimeValue],
        heap: &mut crate::mc04_vm::Heap,
    ) -> Result<Option<crate::mc04_vm::RuntimeValue>> {
        use crate::mc04_vm::RuntimeValue::{Int, Opaque};
        fn scalar(value: Option<i32>) -> BufferResult {
            value.map_or(BufferResult::Void, BufferResult::Scalar)
        }
        if !self
            .units
            .and_then(|units| units.get(unit))
            .is_some_and(|unit| {
                unit.calls.iter().any(|binding| {
                    binding.member == member && binding.target == CallTarget::Native(id)
                })
            })
        {
            return Err(Error::Unauthorized);
        }
        if matches!(
            *self.transaction,
            TransactionDisposition::Commit | TransactionDisposition::Abort
        ) && !matches!(id, 2 | 13)
        {
            return Err(Error::Unauthorized);
        }
        self.capabilities = &self
            .units
            .and_then(|units| units.get(unit))
            .ok_or(Error::Unauthorized)?
            .package
            .manifest
            .capabilities;
        match (id, arguments) {
            (3, [Int(key)]) | (7, [Opaque(3), Int(key)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (4, [Int(key), Int(_)]) | (8, [Opaque(3), Int(key), Int(_)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (31 | 33 | 34, [Opaque(3), Int(key)]) => {
                self.authorize_storage(unit, *key, 2, None)?;
            }
            (32, [Opaque(3), Int(key), value]) => {
                self.authorize_storage(unit, *key, 2, Some(heap.bytes(*value)?.len()))?;
            }
            _ => {}
        }
        let result = match (id, arguments) {
            (2, [Int(value)]) => scalar(self.call(id, &[*value])?),
            (3, [Int(key)]) => scalar(self.call(3, &[*key])?),
            (4, [Int(key), Int(value)]) => scalar(self.call(4, &[*key, *value])?),
            (5 | 9 | 10, []) => scalar(self.call(id, &[])?),
            (11, []) => scalar(self.call(id, &[])?),
            (12, [destination, Int(destination_offset), Int(source_offset), Int(length)]) => {
                self.copy_command(
                    heap,
                    *destination,
                    *destination_offset,
                    *source_offset,
                    *length,
                )?;
                BufferResult::Void
            }
            (54, [input, Int(offset), Int(length), result, Int(result_offset), Int(der)]) => {
                let read = self.read_tlv(heap, *input, *offset, *length, *result, *result_offset, *der != 0)?;
                BufferResult::Scalar(i32::from(read))
            }
            (53, [source, Int(source_offset), destination, Int(destination_offset), Int(length)]) => {
                let copied = self.copy_bytes(heap, *source, *source_offset, *destination, *destination_offset, *length)?;
                BufferResult::Scalar(i32::from(copied))
            }
            (13, [source, Int(source_offset), Int(length)]) => {
                self.write_response(heap, *source, *source_offset, *length)?;
                BufferResult::Void
            }
            (6, [Int(resource), Int(value)]) => {
                if self.transaction.transaction_involved() {
                    return Err(Error::Unauthorized);
                }
                let result = scalar(self.call(6, &[*resource, *value])?);
                self.irreversible_output = true;
                result
            }
            (7, [Opaque(3), Int(key)]) => scalar(self.call(7, &[0, *key])?),
            (8, [Opaque(3), Int(key), Int(value)]) => scalar(self.call(8, &[0, *key, *value])?),
            (20, [input]) => self.buffers(20, &[heap.bytes(*input)?])?,
            (22, [Opaque(2), Int(slot), Int(algorithm)]) => self.key_call(
                22,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*slot),
                    NativeArgument::Int(*algorithm),
                ],
            )?,
            (23 | 24, [Opaque(2), Int(slot)]) => {
                self.key_call(id, &[NativeArgument::Int(0), NativeArgument::Int(*slot)])?
            }
            (25 | 26, [handle, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (27 | 28, [handle, iv, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*iv)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (29 | 30, [handle, nonce, aad, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*nonce)?),
                    NativeArgument::Bytes(heap.bytes(*aad)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (31, [Opaque(3), Int(key)]) => {
                self.key_call(31, &[NativeArgument::Int(0), NativeArgument::Int(*key)])?
            }
            (32, [Opaque(3), Int(key), value]) => self.key_call(
                32,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                ],
            )?,
            (52, [Opaque(3), Int(key), value, Int(offset), Int(length)]) => self.key_call(
                52,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (33 | 34, [Opaque(3), Int(key)]) => {
                self.key_call(id, &[NativeArgument::Int(0), NativeArgument::Int(*key)])?
            }
            (35, [handle]) => self.key_call(
                35,
                &[NativeArgument::Bytes(heap.bytes(*handle)?)],
            )?,
            (36, [handle, input, Int(offset), Int(length)]) => self.key_call(
                36,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (38, [handle, input]) => self.key_call(
                38,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (37, [public_key, data, signature]) => self.buffers(
                37,
                &[
                    heap.bytes(*public_key)?,
                    heap.bytes(*data)?,
                    heap.bytes(*signature)?,
                ],
            )?,
            (39, [destination, Int(offset), Int(length)]) => {
                self.fill_random(heap, *destination, *offset, *length)?;
                BufferResult::Void
            }
            (49, [input, Int(input_offset), Int(input_length), destination, Int(destination_offset)]) => {
                scalar(Some(self.sha256_into(
                    heap,
                    *input,
                    *input_offset,
                    *input_length,
                    *destination,
                    *destination_offset,
                )?))
            }
            (50, [Int(length)]) => BufferResult::Bytes(self.random_bytes(*length)?),
            (51, [left, Int(left_offset), Int(left_length), right, Int(right_offset), Int(right_length)]) => {
                scalar(Some(self.fixed_time_equals(
                    heap,
                    (*left, *left_offset, *left_length),
                    (*right, *right_offset, *right_length),
                )?))
            }
            (40, [Int(slot), pin, Int(pin_offset), Int(pin_length), Int(pin_retries), puk, Int(puk_offset), Int(puk_length), Int(puk_retries)]) => self
                .credential_call(
                    40,
                    &[
                        NativeArgument::Int(*slot),
                        NativeArgument::Bytes(heap.bytes(*pin)?),
                        NativeArgument::Int(*pin_offset),
                        NativeArgument::Int(*pin_length),
                        NativeArgument::Int(*pin_retries),
                        NativeArgument::Bytes(heap.bytes(*puk)?),
                        NativeArgument::Int(*puk_offset),
                        NativeArgument::Int(*puk_length),
                        NativeArgument::Int(*puk_retries),
                    ],
                )?,
            (41, [Int(slot), candidate, Int(offset), Int(length)]) => self.credential_call(
                41,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*candidate)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (42, [Int(slot)]) => {
                self.credential_call(42, &[NativeArgument::Int(*slot)])?
            }
            (43, [Int(slot), new_pin, Int(offset), Int(length)]) => self.credential_call(
                43,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*new_pin)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (44, [Int(slot), puk, Int(puk_offset), Int(puk_length), new_pin, Int(new_pin_offset), Int(new_pin_length)]) => self.credential_call(
                44,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*puk)?),
                    NativeArgument::Int(*puk_offset),
                    NativeArgument::Int(*puk_length),
                    NativeArgument::Bytes(heap.bytes(*new_pin)?),
                    NativeArgument::Int(*new_pin_offset),
                    NativeArgument::Int(*new_pin_length),
                ],
            )?,
            (45, [Int(slot), Int(kind)]) => self.credential_call(
                45,
                &[NativeArgument::Int(*slot), NativeArgument::Int(*kind)],
            )?,
            (46, [Opaque(3)]) => {
                self.begin_transaction()?;
                BufferResult::Void
            }
            (55, []) => {
                self.begin_transaction()?;
                BufferResult::Void
            }
            (47, [Opaque(3)]) => {
                self.transaction.commit()?;
                BufferResult::Void
            }
            (56, []) => {
                self.transaction.commit()?;
                BufferResult::Void
            }
            (48, [Opaque(3)]) => {
                self.transaction.abort()?;
                BufferResult::Void
            }
            (57, []) => {
                self.transaction.abort()?;
                BufferResult::Void
            }
            _ => return Err(Error::Unauthorized),
        };
        match result {
            BufferResult::Bytes(bytes) => Ok(Some(heap.allocate_bytes(bytes)?)),
            BufferResult::Scalar(value) => Ok(Some(Int(value))),
            BufferResult::Void => Ok(None),
        }
    }
}
impl<P: Platform> Host<'_, P> {
    fn begin_transaction(&mut self) -> Result<()> {
        if self.irreversible_output || *self.persistent_dirty {
            return Err(Error::Unauthorized);
        }
        let mut clone_context = crate::fallible_clone::CloneContext::new();
        let snapshot = StagedApplication::from_parts(
            self.store,
            self.blobs,
            self.keys,
            self.credentials,
            &mut clone_context,
        )?;
        #[cfg(test)]
        {
            *self.transaction_snapshots += 1;
            *self.transaction_clone_allocations += clone_context.allocations();
        }
        self.transaction.begin()?;
        *self.transaction_snapshot = Some(snapshot);
        Ok(())
    }

    pub(super) fn authorize_storage(
        &self,
        unit: usize,
        key: i32,
        kind: u8,
        value_length: Option<usize>,
    ) -> Result<()> {
        let package = &self
            .units
            .and_then(|units| units.get(unit))
            .ok_or(Error::Unauthorized)?
            .package;
        if package.manifest.incarnation != self.owner {
            return Err(Error::Unauthorized);
        }
        pub(super) fn find(schema: &[StorageDeclaration], key: i32) -> Option<&StorageDeclaration> {
            schema
                .binary_search_by_key(&key, |declaration| declaration.key)
                .ok()
                .map(|index| &schema[index])
        }
        let declaration = find(&package.manifest.storage, key).ok_or(Error::Unauthorized)?;
        if declaration.kind != kind || find(self.domain_schema, key) != Some(declaration) {
            return Err(Error::Unauthorized);
        }
        if value_length.is_some_and(|length| length > usize::from(declaration.max_bytes)) {
            return Err(Error::Quota);
        }
        Ok(())
    }

    pub(super) fn credential_call(&mut self, id: u8, args: &[NativeArgument<'_>]) -> Result<BufferResult> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let signature = crate::native_abi::signature(id)?;
        if args.len() != usize::from(signature.arguments) {
            return Err(Error::Bounds);
        }
        let byte_total = match id {
            40 => native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                .len()
                .checked_add(
                    native_range(args[5].bytes()?, args[6].int()?, args[7].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            41 | 43 => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len()
            }
            44 => native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                .len()
                .checked_add(
                    native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            _ => 0,
        };
        if byte_total > 96 {
            return Err(Error::Quota);
        }
        let cost = 64 + byte_total;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        let result = match id {
            40 => {
                self.credentials.create(
                    self.owner,
                    args[0].int()?,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    native_range(args[5].bytes()?, args[6].int()?, args[7].int()?)?,
                    (args[4].int()?, args[8].int()?),
                    self.platform,
                )?;
                *self.persistent_dirty = true;
                BufferResult::Void
            }
            41 => {
                let slot = args[0].int()?;
                let verified =
                    self.credentials
                        .verify_pin(
                            self.owner,
                            slot,
                            native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                            self.platform,
                        )?;
                if verified {
                    self.authorized_credentials.insert(slot)?;
                } else {
                    self.authorized_credentials.remove(slot);
                    self.record_credential_retry_floor(slot)?;
                }
                *self.persistent_dirty = true;
                BufferResult::Scalar(i32::from(verified))
            }
            42 => BufferResult::Scalar(i32::from(
                self.authorized_credentials.contains(args[0].int()?),
            )),
            43 => {
                let slot = args[0].int()?;
                if !self.authorized_credentials.contains(slot) {
                    return Err(Error::Unauthorized);
                }
                self.credentials.change_pin(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    self.platform,
                )?;
                *self.persistent_dirty = true;
                BufferResult::Void
            }
            44 => {
                let slot = args[0].int()?;
                let unblocked = self.credentials.unblock(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?,
                    self.platform,
                )?;
                if unblocked {
                    self.authorized_credentials.insert(slot)?;
                } else {
                    self.record_credential_retry_floor(slot)?;
                }
                *self.persistent_dirty = true;
                BufferResult::Scalar(i32::from(unblocked))
            }
            45 => {
                let (pin, puk) = self.credentials.retries(self.owner, args[0].int()?)?;
                BufferResult::Scalar(i32::from(match args[1].int()? {
                    0 => pin,
                    1 => puk,
                    _ => return Err(Error::Bounds),
                }))
            }
            _ => return Err(Error::Unauthorized),
        };
        Ok(result)
    }

    pub(super) fn record_credential_retry_floor(&mut self, slot: i32) -> Result<()> {
        let remaining = self.credentials.retries(self.owner, slot)?;
        self.credential_retry_floor.record(slot, remaining)
    }

    pub(super) fn key_call(&mut self, id: u8, args: &[NativeArgument<'_>]) -> Result<BufferResult> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let signature = crate::native_abi::signature(id)?;
        if args.len() != usize::from(signature.arguments) {
            return Err(Error::Bounds);
        }
        let mut complete_byte_total = 0usize;
        for argument in args {
            if let NativeArgument::Bytes(bytes) = argument {
                let argument_limit = if id == 32 {
                    usize::from(MAX_DECLARED_BLOB_BYTES)
                } else {
                    MAX_KEY_SERVICE_ARGUMENT_BYTES
                };
                if bytes.len() > argument_limit {
                    return Err(Error::Quota);
                }
                complete_byte_total = complete_byte_total
                    .checked_add(bytes.len())
                    .ok_or(Error::Quota)?;
            }
        }
        let byte_total = match id {
            36 => args[0]
                .bytes()?
                .len()
                .checked_add(
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            52 => native_range(args[2].bytes()?, args[3].int()?, args[4].int()?)?.len(),
            _ => complete_byte_total,
        };
        if byte_total > MAX_KEY_SERVICE_TOTAL_BYTES {
            return Err(Error::Quota);
        }
        let cost = if matches!(id, 35 | 36 | 38) { 512 } else { 32 } + byte_total / 16;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        // Management credentials never enter this store. A caller can access only its current SSD.
        let bytes = match id {
            22 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                if self.keys.len() >= self.max_key_slots {
                    return Err(Error::Quota);
                }
                let generated = self.keys
                    .generate(self.owner, args[1].int()?, args[2].int()?, |b| {
                        self.platform.random(b)
                    })?;
                *self.persistent_dirty = true;
                generated
            }
            23 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                self.keys.open(self.owner, args[1].int()?)?
            }
            24 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                self.keys.delete(args[1].int()?)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            25 => self.keys.hmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            26 => self.keys.cmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            27 | 28 => self.keys.cbc(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                args[2].bytes()?,
                id == 27,
                self.platform,
            )?,
            29 | 30 => {
                let buffers = [args[1].bytes()?, args[2].bytes()?, args[3].bytes()?];
                self.keys.ccm(
                    self.owner,
                    args[0].bytes()?,
                    &buffers,
                    id == 29,
                    self.platform,
                )?
            }
            35 => self.keys.p256_public_key(
                self.owner,
                args[0].bytes()?,
                self.platform,
            )?,
            36 => self.keys.p256_sign(
                self.owner,
                args[0].bytes()?,
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                self.platform,
            )?,
            38 => self.keys.p256_ecdh(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            31 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                match self.blobs.get(&args[1].int()?) {
                    Some(value) => Self::copy_buffer(value)?,
                    None => Vec::new(),
                }
            }
            32 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let key = args[1].int()?;
                let value = args[2].bytes()?;
                if value.len() > usize::from(MAX_DECLARED_BLOB_BYTES) {
                    return Err(Error::Quota);
                }
                let old = self.blobs.get(&key).map_or(0, Vec::len);
                let total = self.blobs.values().map(Vec::len).sum::<usize>() - old + value.len();
                if (!self.blobs.contains_key(&key) && self.blobs.len() >= self.max_blob_records)
                    || total > self.max_blob_bytes
                {
                    return Err(Error::Quota);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            52 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let key = args[1].int()?;
                let value = native_range(args[2].bytes()?, args[3].int()?, args[4].int()?)?;
                if value.len() > usize::from(MAX_DECLARED_BLOB_BYTES) {
                    return Err(Error::Quota);
                }
                let old = self.blobs.get(&key).map_or(0, Vec::len);
                let total = self.blobs.values().map(Vec::len).sum::<usize>() - old + value.len();
                if (!self.blobs.contains_key(&key) && self.blobs.len() >= self.max_blob_records)
                    || total > self.max_blob_bytes
                {
                    return Err(Error::Quota);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            33 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let mut removed = self.blobs.remove(&args[1].int()?).ok_or(Error::Missing)?;
                removed.zeroize();
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            34 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                return Ok(BufferResult::Scalar(
                    self.blobs.contains_key(&args[1].int()?) as i32,
                ));
            }
            _ => return Err(Error::Native),
        };
        Ok(BufferResult::Bytes(bytes))
    }

    pub(super) fn buffers(&mut self, id: u8, args: &[&[u8]]) -> Result<BufferResult> {
        let cost = if matches!(id, 21 | 37) { 512 } else { 1 }
            + args.iter().map(|value| value.len()).sum::<usize>() / 32;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        match id {
            20 if args.len() == 1 => {
                let mut output = crate::crypto::zeroizing_buffer(32)?;
                self.platform.sha256_into(
                    args[0],
                    output.as_mut_slice().try_into().unwrap(),
                )?;
                Ok(BufferResult::Bytes(core::mem::take(&mut *output)))
            }
            37 if args.len() == 3 => {
                let valid = self.platform.p256_ecdsa_verify(args[0], args[1], args[2])?;
                Ok(BufferResult::Scalar(valid as i32))
            }
            _ => Err(Error::Native),
        }
    }
    pub(super) fn copy_buffer(value: &[u8]) -> Result<Vec<u8>> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(value.len())
            .map_err(|_| Error::Quota)?;
        copy.extend_from_slice(value);
        Ok(copy)
    }
    pub(super) fn call(&mut self, id: u8, a: &[i32]) -> Result<Option<i32>> {
        self.charge(id, 0)?;
        let (id, a) = match id {
            7 => (3, &a[1..]),
            8 => (4, &a[1..]),
            _ => (id, a),
        };
        match id {
            9 => Ok(Some(self.level as i32)),
            10 => Ok(Some((self.level != 0) as i32)),
            11 => Ok(Some(i32::try_from(self.data.len()).map_err(|_| Error::Bounds)?)),
            2 => {
                self.sw = u16::try_from(a[0]).map_err(|_| Error::Bounds)?;
                Ok(None)
            }
            3 => Ok(Some(*self.store.get(&a[0]).unwrap_or(&0))),
            4 => {
                if !self.store.contains_key(&a[0]) && self.store.len() >= self.max_int_records {
                    return Err(Error::Quota);
                }
                self.store.insert(a[0], a[1])?;
                *self.persistent_dirty = true;
                Ok(None)
            }
            5 => {
                let mut b = [0; 4];
                self.platform.random(&mut b)?;
                Ok(Some(i32::from_le_bytes(b)))
            }
            6 => {
                self.platform.gpio(a[0], a[1])?;
                Ok(None)
            }
            _ => Err(Error::Native),
        }
    }

    pub(super) fn fill_random(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        destination: crate::mc04_vm::RuntimeValue,
        offset: i32,
        length: i32,
    ) -> Result<()> {
        if !self.capabilities.contains(&39) {
            return Err(Error::Unauthorized);
        }
        let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        let output = heap
            .bytes_mut(destination)?
            .get_mut(offset..end)
            .ok_or(Error::Bounds)?;
        let cost = length.checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        if let Err(error) = self.platform.random(output) {
            output.fill(0);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn sha256_into(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        input: crate::mc04_vm::RuntimeValue,
        input_offset: i32,
        input_length: i32,
        destination: crate::mc04_vm::RuntimeValue,
        destination_offset: i32,
    ) -> Result<i32> {
        if !self.capabilities.contains(&49) {
            return Err(Error::Unauthorized);
        }
        let input_offset = usize::try_from(input_offset).map_err(|_| Error::Bounds)?;
        let input_length = usize::try_from(input_length).map_err(|_| Error::Bounds)?;
        let input_end = input_offset.checked_add(input_length).ok_or(Error::Bounds)?;
        let destination_offset =
            usize::try_from(destination_offset).map_err(|_| Error::Bounds)?;
        let destination_end = destination_offset.checked_add(32).ok_or(Error::Bounds)?;
        heap.bytes(destination)?
            .get(destination_offset..destination_end)
            .ok_or(Error::Bounds)?;
        let input = heap
            .bytes(input)?
            .get(input_offset..input_end)
            .ok_or(Error::Bounds)?;
        let cost = input_length / 32 + 1;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        let mut digest = zeroize::Zeroizing::new([0u8; 32]);
        self.platform.sha256_into(input, &mut digest)?;
        heap.bytes_mut(destination)?[destination_offset..destination_end]
            .copy_from_slice(digest.as_slice());
        Ok(32)
    }

    pub(super) fn random_bytes(&mut self, length: i32) -> Result<Vec<u8>> {
        if !self.capabilities.contains(&50) {
            return Err(Error::Unauthorized);
        }
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        if length > 1024 {
            return Err(Error::Bounds);
        }
        let cost = length.checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        if length == 0 {
            self.budget -= cost;
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(|_| Error::Quota)?;
        output.resize(length, 0);
        self.budget -= cost;
        if let Err(error) = self.platform.random(&mut output) {
            output.zeroize();
            return Err(error);
        }
        Ok(output)
    }

    pub(super) fn fixed_time_equals(
        &mut self,
        heap: &crate::mc04_vm::Heap,
        left: (crate::mc04_vm::RuntimeValue, i32, i32),
        right: (crate::mc04_vm::RuntimeValue, i32, i32),
    ) -> Result<i32> {
        if !self.capabilities.contains(&51) {
            return Err(Error::Unauthorized);
        }
        let left_offset = usize::try_from(left.1).map_err(|_| Error::Bounds)?;
        let left_length = usize::try_from(left.2).map_err(|_| Error::Bounds)?;
        let right_offset = usize::try_from(right.1).map_err(|_| Error::Bounds)?;
        let right_length = usize::try_from(right.2).map_err(|_| Error::Bounds)?;
        if left_length > 1024 || right_length > 1024 {
            return Err(Error::Bounds);
        }
        let left_end = left_offset.checked_add(left_length).ok_or(Error::Bounds)?;
        let right_end = right_offset.checked_add(right_length).ok_or(Error::Bounds)?;
        let left = heap
            .bytes(left.0)?
            .get(left_offset..left_end)
            .ok_or(Error::Bounds)?;
        let right = heap
            .bytes(right.0)?
            .get(right_offset..right_end)
            .ok_or(Error::Bounds)?;
        let cost = left_length.max(right_length).checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        Ok((left.len() == right.len() && bool::from(left.ct_eq(right))) as i32)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn read_tlv(
        &mut self, heap: &mut crate::mc04_vm::Heap,
        input: crate::mc04_vm::RuntimeValue, offset: i32, length: i32,
        result: crate::mc04_vm::RuntimeValue, result_offset: i32, der: bool,
    ) -> Result<bool> {
        self.charge(54, 0)?;
        let (Ok(offset), Ok(length), Ok(result_offset)) = (
            usize::try_from(offset), usize::try_from(length), usize::try_from(result_offset),
        ) else { return Ok(false); };
        let Some(range) = microcard_memory::byte_range(heap.bytes(input)?.len(), offset, length) else { return Ok(false); };
        if microcard_memory::byte_range(heap.int_length(result)?, result_offset, 5).is_none() { return Ok(false); }
        self.budget = self.budget.checked_sub(length).ok_or(Error::Budget)?;
        let Some(mut parsed) = crate::tlv::read(&heap.bytes(input)?[range], der) else { return Ok(false); };
        parsed[2] += offset as i32;
        parsed[4] += offset as i32;
        heap.write_ints(result, result_offset, &parsed)?;
        Ok(true)
    }

    pub(super) fn copy_bytes(
        &mut self, heap: &mut crate::mc04_vm::Heap,
        source: crate::mc04_vm::RuntimeValue, source_offset: i32,
        destination: crate::mc04_vm::RuntimeValue, destination_offset: i32, length: i32,
    ) -> Result<bool> {
        self.charge(53, 0)?;
        let (Ok(source_offset), Ok(destination_offset), Ok(length)) = (
            usize::try_from(source_offset), usize::try_from(destination_offset), usize::try_from(length),
        ) else { return Ok(false); };
        if microcard_memory::byte_range(heap.bytes(source)?.len(), source_offset, length).is_none()
            || microcard_memory::byte_range(heap.bytes(destination)?.len(), destination_offset, length).is_none()
        { return Ok(false); }
        self.budget = self.budget.checked_sub(length).ok_or(Error::Budget)?;
        heap.copy_bytes(source, source_offset, destination, destination_offset, length)?;
        Ok(true)
    }

    pub(super) fn copy_command(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        destination: crate::mc04_vm::RuntimeValue,
        destination_offset: i32,
        source_offset: i32,
        length: i32,
    ) -> Result<()> {
        let destination_offset = usize::try_from(destination_offset).map_err(|_| Error::Bounds)?;
        let source_offset = usize::try_from(source_offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let source_end = source_offset.checked_add(length).ok_or(Error::Bounds)?;
        let destination_end = destination_offset.checked_add(length).ok_or(Error::Bounds)?;
        let source = self.data.get(source_offset..source_end).ok_or(Error::Bounds)?;
        heap.bytes(destination)?
            .get(destination_offset..destination_end)
            .ok_or(Error::Bounds)?;
        self.charge(12, length)?;
        heap.bytes_mut(destination)?[destination_offset..destination_end].copy_from_slice(source);
        Ok(())
    }

    pub(super) fn write_response(
        &mut self,
        heap: &crate::mc04_vm::Heap,
        source: crate::mc04_vm::RuntimeValue,
        source_offset: i32,
        length: i32,
    ) -> Result<()> {
        let source_offset = usize::try_from(source_offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let source_end = source_offset.checked_add(length).ok_or(Error::Bounds)?;
        let source = heap
            .bytes(source)?
            .get(source_offset..source_end)
            .ok_or(Error::Bounds)?;
        let output_end = self.out.len().checked_add(length).ok_or(Error::Bounds)?;
        if output_end > MAX_MANAGED_RESPONSE_BYTES {
            return Err(Error::Quota);
        }
        self.out.try_reserve(length).map_err(|_| Error::Quota)?;
        self.charge(13, length)?;
        self.out.extend_from_slice(source);
        Ok(())
    }

    pub(super) fn charge(&mut self, id: u8, bytes: usize) -> Result<()> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let cost = bytes.checked_add(1).ok_or(Error::Budget)?;
        self.budget = self.budget.checked_sub(cost).ok_or(Error::Budget)?;
        Ok(())
    }
}
