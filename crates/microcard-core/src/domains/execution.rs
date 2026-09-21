//! Application selection, invocation and execution transaction boundaries.
use super::*;

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Mc04Engine<F, P, S> {
    pub fn select(&mut self, aid: &str) -> Result<()> {
        self.select_with_cancel(aid, &mut || false)
    }
    pub(crate) fn select_with_cancel(
        &mut self,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.with_lifecycle_retry_floors(|card, retries| {
            card.select_with_retries(aid, should_cancel, retries)
        })
    }

    pub(super) fn select_with_retries(
        &mut self,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
        retries: &mut lifecycle::LifecycleRetries,
    ) -> Result<()> {
        self.abort_transaction();
        let (next, selected) = {
            let old = self
                .selected
                .as_ref()
                .map(|(id, incarnation, old_aid)| {
                    let domain = self.state.domains.get(id).ok_or(Error::Missing)?;
                    if domain.incarnation != *incarnation {
                        return Ok(None);
                    }
                    let assembly = domain.instances.get(old_aid).ok_or(Error::Missing)?;
                    let images = linking::BorrowedExecution::new(&self.state, self.journal.flash(),
                        &mut self.platform, id, assembly)?;
                    let entry = domain.package_metadata(assembly)?
                        .manifest
                        .entry_points
                        .iter()
                        .find(|entry| entry.aid == *old_aid)
                        .ok_or(Error::Missing)?
                        .deselect;
                    Ok(Some((domain, images, entry)))
                })
                .transpose()?
                .flatten();
            let (id, domain) = self
                .state
                .domains
                .iter()
                .find(|(_, domain)| domain.instances.contains_key(aid))
                .ok_or(Error::Missing)?;
            let assembly = domain.instances.get(aid).ok_or(Error::Missing)?;
            let images = linking::BorrowedExecution::new(&self.state, self.journal.flash(),
                &mut self.platform, id, assembly)?;
            let units = images.units()?;
            let entry = units[0]
                .package
                .manifest
                .entry_points
                .iter()
                .find(|entry| entry.aid == aid)
                .ok_or(Error::Missing)?
                .select;
            let selected = (
                fallible_string(id)?,
                domain.incarnation,
                fallible_string(aid)?,
            );
            let mut next = ApplicationChanges::new();
            if let Some((old_domain, old_images, Some(old_entry))) = old {
                let old_units = old_images.units()?;
                run_lifecycle(
                    next.view(old_domain)?,
                    &old_units[0].package,
                    Some(&old_units),
                    old_entry,
                    InvocationInput {
                        data: &[],
                        level: 0,
                    },
                    &mut self.platform,
                    &mut retries.control(old_domain.registry_aid, should_cancel)?,
                )?;
            }
            if let Some(entry) = entry {
                run_lifecycle(
                    next.view(domain)?,
                    &units[0].package,
                    Some(&units),
                    entry,
                    InvocationInput {
                        data: &[],
                        level: 0,
                    },
                    &mut self.platform,
                    &mut retries.control(domain.registry_aid, should_cancel)?,
                )?;
            }
            drop(units);
            drop(images);
            (next, selected)
        };
        self.commit_application_changes(next)?;
        self.selected = Some(selected);
        Ok(())
    }
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let selected = self.selected.take().ok_or(Error::Missing)?;
        let (id, inc, aid) = &selected;
        if !self
            .state
            .domains
            .get(id)
            .is_some_and(|d| d.incarnation == *inc && d.instances.contains_key(aid))
        {
            return Err(Error::Missing);
        }
        let result = self.invoke(aid, data);
        self.selected = Some(selected);
        result
    }
    pub fn invoke(&mut self, aid: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.invoke_context(aid, data, 0)
    }
    pub fn process_verified(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.process_verified_with_cancel(verified, &mut || false)
    }
    pub(crate) fn process_verified_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        let selected = self.selected.take().ok_or(Error::Missing)?;
        let (id, inc, aid) = &selected;
        if !self
            .state
            .domains
            .get(id)
            .is_some_and(|d| d.incarnation == *inc && d.instances.contains_key(aid))
        {
            return Err(Error::Missing);
        }
        let result = self.invoke_context_with_cancel(
            aid,
            &verified.command.data,
            verified.level,
            should_cancel,
        );
        self.selected = Some(selected);
        result
    }
    pub(super) fn invoke_context(&mut self, aid: &str, data: &[u8], level: u8) -> Result<Vec<u8>> {
        self.invoke_context_with_cancel(aid, data, level, &mut || false)
    }
    pub(super) fn invoke_context_with_cancel(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.invoke_context_with_metrics_and_cancel(aid, data, level, should_cancel)
            .map(|(output, _)| output)
    }
    #[cfg(test)]
    pub(super) fn invoke_context_with_metrics(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
    ) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
        self.invoke_context_with_metrics_and_cancel(aid, data, level, &mut || false)
    }
    pub(super) fn invoke_context_with_metrics_and_cancel(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
        if data.len() > 255 {
            self.transaction = None;
            return Err(Error::Bounds);
        }
        let mut found = self
            .state
            .domains
            .iter()
            .filter(|(_, d)| d.instances.contains_key(aid));
        let Some((domain_id, source)) = found.next() else {
            self.transaction = None;
            return Err(Error::Missing);
        };
        if found.next().is_some() {
            self.transaction = None;
            return Err(Error::Domain);
        }
        let source_assembly = source.instances.get(aid).ok_or(Error::Missing)?;
        let incarnation = source.incarnation;
        let domain_registry_aid = source.registry_aid;
        let images = match linking::BorrowedExecution::new(&self.state, self.journal.flash(),
            &mut self.platform, domain_id, source_assembly) {
            Ok(images) => images,
            Err(error) => { self.transaction = None; return Err(error); }
        };
        let units = match images.units() {
            Ok(units) => units,
            Err(error) => { self.transaction = None; return Err(error); }
        };
        let p = &units[0].package;
        let Some(a) = p
            .manifest
            .entry_points
            .iter()
            .find(|a| a.aid == aid)
        else {
            self.transaction = None;
            return Err(Error::Missing);
        };
        let process = a.process;
        let (mut next, mut transaction, commands_left, pending_owner) =
            match self.transaction.take() {
            Some(pending)
                if pending.owner.0 == domain_registry_aid
                    && pending.owner.1 == incarnation
                    && pending.owner.2.as_str() == aid =>
            {
                (
                    pending.state,
                    TransactionDisposition::Active,
                    pending.commands_left,
                    Some(pending.owner),
                )
            }
            Some(_) | None => (
                StagedApplication::new(source)?,
                TransactionDisposition::Inactive,
                MAX_TRANSACTION_COMMANDS,
                None,
            ),
        };
        let mut retry_floor = CredentialRetryFloors::default();
        let mut control = InvocationControl {
            retry_floor: &mut retry_floor,
            should_cancel,
            transaction: &mut transaction,
        };
        let execution = run_application_with_metrics_and_retry_floor(
            next.view(source),
            p,
            Some(&units),
            process,
            InvocationInput { data, level },
            &mut self.platform,
            &mut control,
        );
        let (out, metrics) = match execution {
            Ok(value) => value,
            Err(error) => {
                drop(units);
                drop(images);
                if !retry_floor.is_empty() {
                    self.commit_credential_retry_floor(domain_registry_aid, &retry_floor)?;
                }
                return Err(error);
            }
        };
        let retry_commit = !retry_floor.is_empty()
            && matches!(
                transaction,
                TransactionDisposition::Active
                    | TransactionDisposition::Begun
                    | TransactionDisposition::Abort
            );
        drop(units);
        drop(images);
        if retry_commit {
            self.commit_credential_retry_floor(domain_registry_aid, &retry_floor)?;
        }
        let begun_aid = (transaction == TransactionDisposition::Begun)
            .then(|| fallible_string(aid))
            .transpose()?;
        let transaction_owner = match transaction {
            TransactionDisposition::Begun => Some((
                domain_registry_aid,
                incarnation,
                begun_aid.ok_or(Error::Storage)?,
            )),
            TransactionDisposition::Active => pending_owner,
            _ => None,
        };
        match transaction {
            TransactionDisposition::Inactive | TransactionDisposition::Commit => {
                self.commit_application(domain_registry_aid, next)?;
            }
            TransactionDisposition::Begun => {
                self.transaction = Some(PendingTransaction {
                    owner: transaction_owner.ok_or(Error::Storage)?,
                    state: next,
                    commands_left: MAX_TRANSACTION_COMMANDS - 1,
                });
            }
            TransactionDisposition::Active if commands_left > 1 => {
                self.transaction = Some(PendingTransaction {
                    owner: transaction_owner.ok_or(Error::Storage)?,
                    state: next,
                    commands_left: commands_left - 1,
                });
            }
            TransactionDisposition::Active => return Err(Error::Budget),
            TransactionDisposition::Abort => {}
        }
        Ok((out, metrics))
    }
}
#[cfg(test)]
pub(super) fn run_context(
    d: &mut Domain,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    data: &[u8],
    platform: &mut impl Platform,
    level: u8,
) -> Result<Vec<u8>> {
    let mut retry_floor = CredentialRetryFloors::default();
    run_lifecycle(
        d.application_view(),
        p,
        units,
        entry,
        InvocationInput { data, level },
        platform,
        &mut lifecycle::LifecycleControl { retry_floor: &mut retry_floor, should_cancel: &mut || false },
    ).map(|(output, _)| output)
}
pub(super) fn run_lifecycle(
    d: ApplicationView<'_>,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    input: InvocationInput<'_>,
    platform: &mut impl Platform,
    lifecycle: &mut lifecycle::LifecycleControl<'_>,
) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
    let mut retry_floor = CredentialRetryFloors::default();
    let mut transaction = TransactionDisposition::Inactive;
    let mut control = InvocationControl {
        retry_floor: &mut retry_floor,
        should_cancel: lifecycle.should_cancel,
        transaction: &mut transaction,
    };
    let result =
        run_application_with_metrics_and_retry_floor(d, p, units, entry, input, platform, &mut control);
    for (slot, remaining) in retry_floor.iter() {
        lifecycle.retry_floor.record(slot, remaining)?;
    }
    if transaction != TransactionDisposition::Inactive {
        return Err(Error::Unauthorized);
    }
    result
}
#[derive(Clone, Copy)]
pub(super) struct InvocationInput<'a> {
    pub data: &'a [u8],
    pub level: u8,
}
struct InvocationControl<'a> {
    retry_floor: &'a mut CredentialRetryFloors,
    should_cancel: &'a mut dyn FnMut() -> bool,
    transaction: &'a mut TransactionDisposition,
}

fn managed_response_buffer() -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response
        .try_reserve_exact(MAX_MANAGED_RESPONSE_WITH_STATUS)
        .map_err(|_| Error::Quota)?;
    Ok(response)
}

fn run_application_with_metrics_and_retry_floor(
    d: ApplicationView<'_>,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    input: InvocationInput<'_>,
    platform: &mut impl Platform,
    control: &mut InvocationControl<'_>,
) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
    let mut host = Host {
        store: d.store,
        blobs: d.blobs,
        keys: d.keys,
        credentials: d.credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: d.incarnation,
        data: input.data,
        out: managed_response_buffer()?,
        sw: 0x9000,
        platform,
        budget: 1024,
        capabilities: &p.manifest().capabilities,
        domain_schema: d.storage_schema,
        max_int_records: d.policy.max_int_records as usize,
        max_blob_records: d.policy.max_blob_records as usize,
        max_blob_bytes: d.policy.max_blob_bytes as usize,
        max_key_slots: d.policy.max_key_slots as usize,
        level: input.level,
        units,
        transaction: control.transaction,
        irreversible_output: false,
    };
    let units = units.ok_or(Error::Storage)?;
    if units
        .first()
        .is_none_or(|unit| unit.package.digest != p.digest())
    {
        return Err(Error::Storage);
    }
    let mut vm_units = Vec::new();
    vm_units
        .try_reserve_exact(units.len())
        .map_err(|_| Error::Quota)?;
    for unit in units {
        vm_units.push(crate::mc04_vm::Unit {
            name: &unit.package.manifest.assembly,
            assembly: crate::assembly::Assembly::parse(unit.package.image)?,
        });
    }
    let execution = crate::mc04_vm::execute_program_with_metrics_and_cancel(
        &vm_units,
        0,
        entry,
        &[],
        &mut host,
        control.should_cancel,
    );
    *control.retry_floor = core::mem::take(&mut host.credential_retry_floor);
    let (_, metrics) = execution?;
    #[cfg(test)]
    let metrics = {
        let mut metrics = metrics;
        metrics.native_work_units = 1024 - host.budget;
        metrics
    };
    host.out.extend_from_slice(&host.sw.to_be_bytes());
    Ok((host.out, metrics))
}

