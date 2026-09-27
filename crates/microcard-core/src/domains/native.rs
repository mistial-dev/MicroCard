//! MC04 native service dispatch, authorization and bounded output handling.
use super::*;
use crate::native_abi::id::*;

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

impl<P: Platform> crate::mc04_vm::External for Host<'_, '_, P> {
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
                let mut matches = units
                    .iter()
                    .enumerate()
                    .filter(|(_, unit)| unit.package.digest == digest);
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
        ) && !matches!(
            id,
            RESPONSE_SERVICE_SET_STATUS | RESPONSE_SERVICE_WRITE | TRANSACTION_RUNTIME_CURRENT
        ) {
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
            (TRANSACTION_RUNTIME_CURRENT, []) => {
                return Ok(Some(
                    if matches!(
                        *self.transaction,
                        TransactionDisposition::Begun | TransactionDisposition::Active
                    ) {
                        Opaque(4)
                    } else {
                        crate::mc04_vm::RuntimeValue::Ref(0)
                    },
                ));
            }
            (TRANSACTION_RUNTIME_INFORMATION, [Opaque(4)])
                if matches!(
                    *self.transaction,
                    TransactionDisposition::Begun | TransactionDisposition::Active
                ) =>
            {
                return Ok(Some(Opaque(5)));
            }
            (TRANSACTION_INFORMATION_RUNTIME_STATUS, [Opaque(5)])
                if matches!(
                    *self.transaction,
                    TransactionDisposition::Begun | TransactionDisposition::Active
                ) =>
            {
                return Ok(Some(Int(0)));
            }
            _ => {}
        }
        match (id, arguments) {
            (STORAGE_SERVICE_GET_INT32, [Opaque(3), Int(key)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (STORAGE_SERVICE_SET_INT32, [Opaque(3), Int(key), Int(_)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (
                STORAGE_SERVICE_GET_BYTES
                | STORAGE_SERVICE_DELETE_BYTES
                | STORAGE_SERVICE_CONTAINS_BYTES,
                [Opaque(3), Int(key)],
            ) => {
                self.authorize_storage(unit, *key, 2, None)?;
            }
            (STORAGE_SERVICE_SET_BYTES_2_ARGS, [Opaque(3), Int(key), value]) => {
                self.authorize_storage(unit, *key, 2, Some(heap.bytes(*value)?.len()))?;
            }
            _ => {}
        }
        let result = match (id, arguments) {
            (RESPONSE_SERVICE_SET_STATUS, [Opaque(2), Int(value)]) => {
                scalar(self.call(id, &[*value])?)
            }
            (
                RANDOM_SERVICE_GET_INT32
                | SECURE_CHANNEL_SERVICE_SECURITY_LEVEL
                | SECURE_CHANNEL_SERVICE_IS_AUTHENTICATED,
                [Opaque(2)],
            ) => scalar(self.call(id, &[])?),
            (COMMAND_SERVICE_LENGTH, [Opaque(2)]) => scalar(self.call(id, &[])?),
            (
                COMMAND_SERVICE_COPY_TO,
                [Opaque(2), destination, Int(destination_offset), Int(source_offset), Int(length)],
            ) => {
                self.copy_command(
                    heap,
                    *destination,
                    *destination_offset,
                    *source_offset,
                    *length,
                )?;
                BufferResult::Void
            }
            (
                TLV_TRY_READ,
                [input, Int(offset), Int(length), result, Int(result_offset), Int(der)],
            ) => {
                let read = self.read_tlv(
                    heap,
                    *input,
                    *offset,
                    *length,
                    *result,
                    *result_offset,
                    *der != 0,
                )?;
                BufferResult::Scalar(i32::from(read))
            }
            (
                BUFFERS_COPY,
                [source, Int(source_offset), destination, Int(destination_offset), Int(length)],
            ) => {
                let copied = self.copy_bytes(
                    heap,
                    *source,
                    *source_offset,
                    *destination,
                    *destination_offset,
                    *length,
                )?;
                BufferResult::Scalar(i32::from(copied))
            }
            (RESPONSE_SERVICE_WRITE, [Opaque(2), source, Int(source_offset), Int(length)]) => {
                self.write_response(heap, *source, *source_offset, *length)?;
                BufferResult::Void
            }
            (RUNTIME_SERVICE_WRITE_HARDWARE, [Opaque(2), Int(resource), Int(value)]) => {
                if self.transaction.transaction_involved() {
                    return Err(Error::Unauthorized);
                }
                let result =
                    scalar(self.call(RUNTIME_SERVICE_WRITE_HARDWARE, &[*resource, *value])?);
                self.irreversible_output = true;
                result
            }
            (STORAGE_SERVICE_GET_INT32, [Opaque(3), Int(key)]) => {
                scalar(self.call(STORAGE_SERVICE_GET_INT32, &[*key])?)
            }
            (STORAGE_SERVICE_SET_INT32, [Opaque(3), Int(key), Int(value)]) => {
                scalar(self.call(STORAGE_SERVICE_SET_INT32, &[*key, *value])?)
            }
            (RUNTIME_SERVICE_SHA256, [input]) | (RUNTIME_SERVICE_SHA256, [Opaque(2), input]) => {
                self.buffers(RUNTIME_SERVICE_SHA256, &[heap.bytes(*input)?])?
            }
            (KEY_SERVICE_GENERATE, [Opaque(2), Int(slot), Int(algorithm)]) => self.key_call(
                KEY_SERVICE_GENERATE,
                &[NativeArgument::Int(*slot), NativeArgument::Int(*algorithm)],
            )?,
            (KEY_SERVICE_OPEN | KEY_SERVICE_DELETE, [Opaque(2), Int(slot)]) => {
                self.key_call(id, &[NativeArgument::Int(*slot)])?
            }
            (KEY_HANDLE_HMAC_SHA256 | KEY_HANDLE_AES_CMAC, [handle, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (KEY_HANDLE_ENCRYPT_CBC | KEY_HANDLE_DECRYPT_CBC, [handle, iv, input]) => self
                .key_call(
                    id,
                    &[
                        NativeArgument::Bytes(heap.bytes(*handle)?),
                        NativeArgument::Bytes(heap.bytes(*iv)?),
                        NativeArgument::Bytes(heap.bytes(*input)?),
                    ],
                )?,
            (KEY_HANDLE_ENCRYPT_CCM | KEY_HANDLE_DECRYPT_CCM, [handle, nonce, aad, input]) => self
                .key_call(
                    id,
                    &[
                        NativeArgument::Bytes(heap.bytes(*handle)?),
                        NativeArgument::Bytes(heap.bytes(*nonce)?),
                        NativeArgument::Bytes(heap.bytes(*aad)?),
                        NativeArgument::Bytes(heap.bytes(*input)?),
                    ],
                )?,
            (STORAGE_SERVICE_GET_BYTES, [Opaque(3), Int(key)]) => {
                self.key_call(STORAGE_SERVICE_GET_BYTES, &[NativeArgument::Int(*key)])?
            }
            (STORAGE_SERVICE_SET_BYTES_2_ARGS, [Opaque(3), Int(key), value]) => self.key_call(
                STORAGE_SERVICE_SET_BYTES_2_ARGS,
                &[
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                ],
            )?,
            (
                STORAGE_SERVICE_SET_BYTES_4_ARGS,
                [Opaque(3), Int(key), value, Int(offset), Int(length)],
            ) => self.key_call(
                STORAGE_SERVICE_SET_BYTES_4_ARGS,
                &[
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (
                STORAGE_SERVICE_DELETE_BYTES | STORAGE_SERVICE_CONTAINS_BYTES,
                [Opaque(3), Int(key)],
            ) => self.key_call(id, &[NativeArgument::Int(*key)])?,
            (KEY_HANDLE_EXPORT_P256_PUBLIC_KEY, [handle]) => self.key_call(
                KEY_HANDLE_EXPORT_P256_PUBLIC_KEY,
                &[NativeArgument::Bytes(heap.bytes(*handle)?)],
            )?,
            (KEY_HANDLE_SIGN_P256, [handle, input, Int(offset), Int(length)]) => self.key_call(
                KEY_HANDLE_SIGN_P256,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (KEY_HANDLE_DERIVE_P256, [handle, input]) => self.key_call(
                KEY_HANDLE_DERIVE_P256,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (RUNTIME_SERVICE_VERIFY_P256, [Opaque(2), public_key, data, signature]) => self
                .buffers(
                    RUNTIME_SERVICE_VERIFY_P256,
                    &[
                        heap.bytes(*public_key)?,
                        heap.bytes(*data)?,
                        heap.bytes(*signature)?,
                    ],
                )?,
            (RANDOM_SERVICE_FILL, [Opaque(2), destination, Int(offset), Int(length)]) => {
                self.fill_random(heap, *destination, *offset, *length)?;
                BufferResult::Void
            }
            (
                RUNTIME_SERVICE_SHA256_INTO,
                [Opaque(2), input, Int(input_offset), Int(input_length), destination, Int(destination_offset)],
            ) => scalar(Some(self.sha256_into(
                heap,
                *input,
                *input_offset,
                *input_length,
                *destination,
                *destination_offset,
            )?)),
            (RANDOM_SERVICE_GET_BYTES, [Int(length)])
            | (RANDOM_SERVICE_GET_BYTES, [Opaque(2), Int(length)]) => {
                BufferResult::Bytes(self.random_bytes(*length)?)
            }
            (
                RUNTIME_SERVICE_FIXED_TIME_EQUALS,
                [Opaque(2), left, Int(left_offset), Int(left_length), right, Int(right_offset), Int(right_length)],
            ) => scalar(Some(self.fixed_time_equals(
                heap,
                (*left, *left_offset, *left_length),
                (*right, *right_offset, *right_length),
            )?)),
            (
                CREDENTIAL_SERVICE_CREATE,
                [Opaque(2), Int(slot), pin, Int(pin_offset), Int(pin_length), Int(pin_retries), puk, Int(puk_offset), Int(puk_length), Int(puk_retries)],
            ) => self.credential_call(
                CREDENTIAL_SERVICE_CREATE,
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
            (
                CREDENTIAL_SERVICE_VERIFY,
                [Opaque(2), Int(slot), candidate, Int(offset), Int(length)],
            ) => self.credential_call(
                CREDENTIAL_SERVICE_VERIFY,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*candidate)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (CREDENTIAL_SERVICE_IS_VERIFIED, [Opaque(2), Int(slot)]) => self.credential_call(
                CREDENTIAL_SERVICE_IS_VERIFIED,
                &[NativeArgument::Int(*slot)],
            )?,
            (
                CREDENTIAL_SERVICE_CHANGE,
                [Opaque(2), Int(slot), new_pin, Int(offset), Int(length)],
            ) => self.credential_call(
                CREDENTIAL_SERVICE_CHANGE,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*new_pin)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (
                CREDENTIAL_SERVICE_UNBLOCK,
                [Opaque(2), Int(slot), puk, Int(puk_offset), Int(puk_length), new_pin, Int(new_pin_offset), Int(new_pin_length)],
            ) => self.credential_call(
                CREDENTIAL_SERVICE_UNBLOCK,
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
            (CREDENTIAL_SERVICE_RETRIES_REMAINING, [Opaque(2), Int(slot), Int(kind)]) => self
                .credential_call(
                    CREDENTIAL_SERVICE_RETRIES_REMAINING,
                    &[NativeArgument::Int(*slot), NativeArgument::Int(*kind)],
                )?,
            (TRANSACTION_SCOPE_RUNTIME_BEGIN, []) => {
                self.begin_transaction()?;
                BufferResult::Void
            }
            (TRANSACTION_SCOPE_RUNTIME_COMMIT, []) => {
                self.transaction.commit()?;
                BufferResult::Void
            }
            (TRANSACTION_SCOPE_RUNTIME_ABORT, []) => {
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
impl<P: Platform> Host<'_, '_, P> {
    pub(super) fn begin_transaction(&mut self) -> Result<()> {
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

    pub(super) fn credential_call(
        &mut self,
        id: u8,
        args: &[NativeArgument<'_>],
    ) -> Result<BufferResult> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let signature = crate::native_abi::signature(id)?;
        if args.len() != usize::from(signature.arguments) {
            return Err(Error::Bounds);
        }
        let byte_total = match id {
            CREDENTIAL_SERVICE_CREATE => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                    .len()
                    .checked_add(
                        native_range(args[5].bytes()?, args[6].int()?, args[7].int()?)?.len(),
                    )
                    .ok_or(Error::Quota)?
            }
            CREDENTIAL_SERVICE_VERIFY | CREDENTIAL_SERVICE_CHANGE => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len()
            }
            CREDENTIAL_SERVICE_UNBLOCK => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                    .len()
                    .checked_add(
                        native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?.len(),
                    )
                    .ok_or(Error::Quota)?
            }
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
            CREDENTIAL_SERVICE_CREATE => {
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
            CREDENTIAL_SERVICE_VERIFY => {
                let slot = args[0].int()?;
                let (verified, changed) = self.credentials.verify_pin(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    self.platform,
                )?;
                if verified {
                    self.authorized_credentials.insert(slot)?;
                    *self.persistent_dirty |= changed;
                } else {
                    self.authorized_credentials.remove(slot);
                    if changed {
                        self.checkpoint_credential_retry_floor(slot)?;
                    }
                }
                BufferResult::Scalar(i32::from(verified))
            }
            CREDENTIAL_SERVICE_IS_VERIFIED => BufferResult::Scalar(i32::from(
                self.authorized_credentials.contains(args[0].int()?),
            )),
            CREDENTIAL_SERVICE_CHANGE => {
                let slot = args[0].int()?;
                if !self.authorized_credentials.contains(slot) {
                    return Err(Error::Unauthorized);
                }
                let changed = self.credentials.change_pin(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    self.platform,
                )?;
                *self.persistent_dirty |= changed;
                BufferResult::Void
            }
            CREDENTIAL_SERVICE_UNBLOCK => {
                let slot = args[0].int()?;
                let (unblocked, changed) = self.credentials.unblock(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?,
                    self.platform,
                )?;
                if unblocked {
                    self.authorized_credentials.insert(slot)?;
                    *self.persistent_dirty |= changed;
                } else {
                    if changed {
                        self.checkpoint_credential_retry_floor(slot)?;
                    }
                }
                BufferResult::Scalar(i32::from(unblocked))
            }
            CREDENTIAL_SERVICE_RETRIES_REMAINING => {
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

    fn checkpoint_credential_retry_floor(&mut self, slot: i32) -> Result<()> {
        self.record_credential_retry_floor(slot)?;
        let ordinary_dirty = *self.persistent_dirty;
        // A failed checkpoint must take the unsafe-exit recovery path so RAM and reboot
        // select the same authoritative generation.
        *self.persistent_dirty = true;
        self.credential_checkpoint
            .as_deref_mut()
            .ok_or(Error::Storage)?
            .checkpoint(self.platform, &self.credential_retry_floor)?;
        *self.persistent_dirty = ordinary_dirty;
        Ok(())
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
                let argument_limit = if id == STORAGE_SERVICE_SET_BYTES_2_ARGS {
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
            KEY_HANDLE_SIGN_P256 => args[0]
                .bytes()?
                .len()
                .checked_add(native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len())
                .ok_or(Error::Quota)?,
            STORAGE_SERVICE_SET_BYTES_4_ARGS => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len()
            }
            _ => complete_byte_total,
        };
        if byte_total > MAX_KEY_SERVICE_TOTAL_BYTES {
            return Err(Error::Quota);
        }
        let cost = if matches!(
            id,
            KEY_HANDLE_EXPORT_P256_PUBLIC_KEY | KEY_HANDLE_SIGN_P256 | KEY_HANDLE_DERIVE_P256
        ) {
            512
        } else {
            32
        } + byte_total / 16;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        // Management credentials never enter this store. A caller can access only its current SSD.
        let bytes = match id {
            KEY_SERVICE_GENERATE => {
                if self.keys.len() >= self.max_key_slots {
                    return Err(Error::Quota);
                }
                let generated =
                    self.keys
                        .generate(self.owner, args[0].int()?, args[1].int()?, |b| {
                            self.platform.random(b)
                        })?;
                *self.persistent_dirty = true;
                generated
            }
            KEY_SERVICE_OPEN => self.keys.open(self.owner, args[0].int()?)?,
            KEY_SERVICE_DELETE => {
                self.keys.delete(args[0].int()?)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            KEY_HANDLE_HMAC_SHA256 => self.keys.hmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            KEY_HANDLE_AES_CMAC => self.keys.cmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            KEY_HANDLE_ENCRYPT_CBC | KEY_HANDLE_DECRYPT_CBC => self.keys.cbc(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                args[2].bytes()?,
                id == KEY_HANDLE_ENCRYPT_CBC,
                self.platform,
            )?,
            KEY_HANDLE_ENCRYPT_CCM | KEY_HANDLE_DECRYPT_CCM => {
                let buffers = [args[1].bytes()?, args[2].bytes()?, args[3].bytes()?];
                self.keys.ccm(
                    self.owner,
                    args[0].bytes()?,
                    &buffers,
                    id == KEY_HANDLE_ENCRYPT_CCM,
                    self.platform,
                )?
            }
            KEY_HANDLE_EXPORT_P256_PUBLIC_KEY => {
                self.keys
                    .p256_public_key(self.owner, args[0].bytes()?, self.platform)?
            }
            KEY_HANDLE_SIGN_P256 => self.keys.p256_sign(
                self.owner,
                args[0].bytes()?,
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                self.platform,
            )?,
            KEY_HANDLE_DERIVE_P256 => self.keys.p256_ecdh(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            STORAGE_SERVICE_GET_BYTES => match self.blobs.get(&args[0].int()?) {
                Some(value) => Self::copy_buffer(value)?,
                None => Vec::new(),
            },
            STORAGE_SERVICE_SET_BYTES_2_ARGS => {
                let key = args[0].int()?;
                let value = args[1].bytes()?;
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
                if self
                    .blobs
                    .get(&key)
                    .is_some_and(|old| old.as_slice() == value)
                {
                    return Ok(BufferResult::Void);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            STORAGE_SERVICE_SET_BYTES_4_ARGS => {
                let key = args[0].int()?;
                let value = native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?;
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
                if self
                    .blobs
                    .get(&key)
                    .is_some_and(|old| old.as_slice() == value)
                {
                    return Ok(BufferResult::Void);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            STORAGE_SERVICE_DELETE_BYTES => {
                let mut removed = self.blobs.remove(&args[0].int()?).ok_or(Error::Missing)?;
                removed.zeroize();
                *self.persistent_dirty = true;
                return Ok(BufferResult::Void);
            }
            STORAGE_SERVICE_CONTAINS_BYTES => {
                return Ok(BufferResult::Scalar(
                    self.blobs.contains_key(&args[0].int()?) as i32,
                ));
            }
            _ => return Err(Error::Native),
        };
        Ok(BufferResult::Bytes(bytes))
    }

    pub(super) fn buffers(&mut self, id: u8, args: &[&[u8]]) -> Result<BufferResult> {
        let cost = if id == RUNTIME_SERVICE_VERIFY_P256 {
            512
        } else {
            1
        } + args.iter().map(|value| value.len()).sum::<usize>() / 32;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        match id {
            RUNTIME_SERVICE_SHA256 if args.len() == 1 => {
                let mut output = crate::crypto::zeroizing_buffer(32)?;
                self.platform
                    .sha256_into(args[0], output.as_mut_slice().try_into().unwrap())?;
                Ok(BufferResult::Bytes(core::mem::take(&mut *output)))
            }
            RUNTIME_SERVICE_VERIFY_P256 if args.len() == 3 => {
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
        match id {
            SECURE_CHANNEL_SERVICE_SECURITY_LEVEL => Ok(Some(self.level as i32)),
            SECURE_CHANNEL_SERVICE_IS_AUTHENTICATED => Ok(Some((self.level != 0) as i32)),
            COMMAND_SERVICE_LENGTH => Ok(Some(
                i32::try_from(self.data.len()).map_err(|_| Error::Bounds)?,
            )),
            RESPONSE_SERVICE_SET_STATUS => {
                self.sw = u16::try_from(a[0]).map_err(|_| Error::Bounds)?;
                Ok(None)
            }
            STORAGE_SERVICE_GET_INT32 => Ok(Some(*self.store.get(&a[0]).unwrap_or(&0))),
            STORAGE_SERVICE_SET_INT32 => {
                if !self.store.contains_key(&a[0]) && self.store.len() >= self.max_int_records {
                    return Err(Error::Quota);
                }
                if self.store.get(&a[0]) != Some(&a[1]) {
                    self.store.insert(a[0], a[1])?;
                    *self.persistent_dirty = true;
                }
                Ok(None)
            }
            RANDOM_SERVICE_GET_INT32 => {
                let mut b = [0; 4];
                self.platform.random(&mut b)?;
                Ok(Some(i32::from_le_bytes(b)))
            }
            RUNTIME_SERVICE_WRITE_HARDWARE => {
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
        if !self.capabilities.contains(&RANDOM_SERVICE_FILL) {
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
        if !self.capabilities.contains(&RUNTIME_SERVICE_SHA256_INTO) {
            return Err(Error::Unauthorized);
        }
        let input_offset = usize::try_from(input_offset).map_err(|_| Error::Bounds)?;
        let input_length = usize::try_from(input_length).map_err(|_| Error::Bounds)?;
        let input_end = input_offset
            .checked_add(input_length)
            .ok_or(Error::Bounds)?;
        let destination_offset = usize::try_from(destination_offset).map_err(|_| Error::Bounds)?;
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
        if !self.capabilities.contains(&RANDOM_SERVICE_GET_BYTES) {
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
        if !self
            .capabilities
            .contains(&RUNTIME_SERVICE_FIXED_TIME_EQUALS)
        {
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
        let right_end = right_offset
            .checked_add(right_length)
            .ok_or(Error::Bounds)?;
        let left = heap
            .bytes(left.0)?
            .get(left_offset..left_end)
            .ok_or(Error::Bounds)?;
        let right = heap
            .bytes(right.0)?
            .get(right_offset..right_end)
            .ok_or(Error::Bounds)?;
        let cost = left_length
            .max(right_length)
            .checked_add(1)
            .ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        Ok((left.len() == right.len() && bool::from(left.ct_eq(right))) as i32)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn read_tlv(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        input: crate::mc04_vm::RuntimeValue,
        offset: i32,
        length: i32,
        result: crate::mc04_vm::RuntimeValue,
        result_offset: i32,
        der: bool,
    ) -> Result<bool> {
        self.charge(TLV_TRY_READ, 0)?;
        let (Ok(offset), Ok(length), Ok(result_offset)) = (
            usize::try_from(offset),
            usize::try_from(length),
            usize::try_from(result_offset),
        ) else {
            return Ok(false);
        };
        let Some(range) = microcard_memory::byte_range(heap.bytes(input)?.len(), offset, length)
        else {
            return Ok(false);
        };
        if microcard_memory::byte_range(heap.int_length(result)?, result_offset, 5).is_none() {
            return Ok(false);
        }
        self.budget = self.budget.checked_sub(length).ok_or(Error::Budget)?;
        let Some(mut parsed) = crate::tlv::read(&heap.bytes(input)?[range], der) else {
            return Ok(false);
        };
        parsed[2] += offset as i32;
        parsed[4] += offset as i32;
        heap.write_ints(result, result_offset, &parsed)?;
        Ok(true)
    }

    pub(super) fn copy_bytes(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        source: crate::mc04_vm::RuntimeValue,
        source_offset: i32,
        destination: crate::mc04_vm::RuntimeValue,
        destination_offset: i32,
        length: i32,
    ) -> Result<bool> {
        self.charge(BUFFERS_COPY, 0)?;
        let (Ok(source_offset), Ok(destination_offset), Ok(length)) = (
            usize::try_from(source_offset),
            usize::try_from(destination_offset),
            usize::try_from(length),
        ) else {
            return Ok(false);
        };
        if microcard_memory::byte_range(heap.bytes(source)?.len(), source_offset, length).is_none()
            || microcard_memory::byte_range(
                heap.bytes(destination)?.len(),
                destination_offset,
                length,
            )
            .is_none()
        {
            return Ok(false);
        }
        self.budget = self.budget.checked_sub(length).ok_or(Error::Budget)?;
        heap.copy_bytes(
            source,
            source_offset,
            destination,
            destination_offset,
            length,
        )?;
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
        let destination_end = destination_offset
            .checked_add(length)
            .ok_or(Error::Bounds)?;
        let source = self
            .data
            .get(source_offset..source_end)
            .ok_or(Error::Bounds)?;
        heap.bytes(destination)?
            .get(destination_offset..destination_end)
            .ok_or(Error::Bounds)?;
        self.charge(COMMAND_SERVICE_COPY_TO, length)?;
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
        self.charge(RESPONSE_SERVICE_WRITE, length)?;
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
