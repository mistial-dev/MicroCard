//! Authenticated GlobalPlatform and MicroCard management command handling.
use super::*;

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
    pub(crate) fn globalplatform_load_active(&self) -> bool {
        self.globalplatform_load.is_some()
    }
    /// Returns one bounded GlobalPlatform Registry record. The caller owns
    /// session-scoped continuation state; no cursor is persisted in flash.
    pub(crate) fn get_status_record(
        &self,
        p1: u8,
        index: usize,
        filter: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        let mut matching = 0usize;
        let mut selected = None;
        visit_registry(&self.state, p1, |aid, entry| {
            // GP 2.3.1 §11.4.2.1 requires the ISD search criterion to be ignored.
            if p1 == 0x80 || crate::globalplatform::aid_matches(aid, filter) {
                if matching == index {
                    selected = Some(registry_record(p1, aid, entry)?);
                }
                matching += 1;
            }
            Ok(())
        })?;
        let record = selected.ok_or(Error::Missing)?;
        Ok((record, matching > index + 1))
    }

    pub(crate) fn select_isd_with_cancel(
        &mut self,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.with_lifecycle_retry_floors(|card, retries| {
            card.select_isd_with_retries(should_cancel, retries)
        })
    }

    pub(super) fn select_isd_with_retries(
        &mut self,
        should_cancel: &mut dyn FnMut() -> bool,
        retries: &mut lifecycle::LifecycleRetries,
    ) -> Result<()> {
        self.abort_transaction();
        let Some(selected) = self.selected.take() else {
            return Ok(());
        };
        let (id, incarnation, aid) = &selected;
        let result = (|| {
            let Some(domain) = self.state.domains.get(id) else {
                return Ok(());
            };
            if domain.incarnation != *incarnation {
                return Ok(());
            }
            let assembly = domain.instances.get(aid).ok_or(Error::Missing)?;
            let images = linking::BorrowedExecution::new(&self.state, self.journal.flash(),
                &mut self.platform, id, assembly)?;
            let units = images.units()?;
            let deselect = units[0]
                .package
                .manifest
                .entry_points
                .iter()
                .find(|entry| entry.aid.as_str() == aid.as_str())
                .ok_or(Error::Missing)?
                .deselect;
            if let Some(entry) = deselect {
                let mut next = ApplicationChanges::new();
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
                drop(units);
                drop(images);
                self.commit_application_changes(next)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.selected = Some(selected);
        }
        result
    }

    /// GlobalPlatform-shaped management commands retain the same level-13
    /// authorization and transactional state changes as native management.
    #[cfg(test)]
    pub(crate) fn manage_globalplatform(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.manage_globalplatform_with_cancel(verified, &mut || false)
    }
    pub(crate) fn manage_globalplatform_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.abort_transaction();
        if verified.level & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        let command = verified.command;
        if command.ins == 0xe6 && command.p1 == 0x02 {
            let request = crate::globalplatform::load_request(&command)?;
            let load_aid = RegistryAid::new(request.load_aid)?;
            if self.state.registry_aid_reserved_by_non_assembly(load_aid) {
                return Err(Error::Busy);
            }
            let domain_aid = RegistryAid::new(request.domain_aid)?;
            self.state
                .domain_identifier_by_registry_aid(domain_aid)
                .ok_or(Error::Missing)?;
            self.abort_staging();
            self.globalplatform_load = Some(GlobalPlatformLoad {
                domain_aid,
                load_aid,
                hash: request.hash,
                receiver: crate::globalplatform::LoadReceiver::new(
                    crate::globalplatform::Payload::SignedPackage, MAX_PACKAGE_BYTES,
                ),
            });
            return fallible_filled(1, 0);
        }
        if command.ins == 0xe8 && self.globalplatform_load.is_some() {
            let result = self.continue_globalplatform_load(&command, should_cancel);
            if result.is_err() {
                self.abort_staging();
            }
            return result;
        }
        if command.ins == 0xe6 && command.p1 == 0x0c {
            if !self.state.is_owned() {
                return Err(Error::Unauthorized);
            }
            if let Ok(requested) = crate::globalplatform::ssd_install_aid(&command) {
                let requested = RegistryAid::new(requested)?;
                let in_use = self.state.registry_aid_in_use(requested);
                if in_use || self.state.domains.len() >= MAX_SSDS {
                    return Err(if in_use { Error::Busy } else { Error::Quota });
                }
                let identifier = encode_aid(requested.as_slice())?;
                let mut incarnation = [0; 16];
                self.platform.random(&mut incarnation)?;
                self.insert_domain(
                    identifier, Domain::new(incarnation, requested, DomainPolicy::standard()?),
                )?;
                return Ok(Vec::new());
            }
            let install = crate::globalplatform::application_install(&command)?;
            let load_aid = RegistryAid::new(install.load_aid)?;
            // The instance answers to its own AID, which GlobalPlatform lets differ from
            // the module AID so one module can back several instances.
            let aid = encode_aid(install.instance_aid)?;
            self.install_instance_exact(load_aid, &aid, should_cancel)?;
            return fallible_filled(1, 0);
        }

        let target = RegistryAid::new(crate::globalplatform::delete_aid(&command)?)?;
        if target == RegistryAid::isd() {
            return Err(Error::Unauthorized);
        }
        if let Some(index) = self.state.domains.iter()
            .position(|(_, domain)| domain.registry_aid == target)
        {
            self.remove_domain(index)?;
            self.abort_staging();
            return Ok(Vec::new());
        }

        let target_text = encode_aid(target.as_slice())?;
        let instance_delete = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .find(|(_, domain)| domain.instances.contains_key(&target_text))
            .map(|(identifier, _)| management_names_wire(identifier, target_text.as_str()))
            .transpose()?;
        if let Some(data) = instance_delete {
            return self.manage_with_cancel(
                Verified {
                    level: 0x13,
                    command: crate::apdu::Command {
                        cla: 0x80,
                        ins: 0xee,
                        p1: 0,
                        p2: 0,
                        data: data.into(),
                        le: None,
                    },
                },
                should_cancel,
            );
        }

        let assembly_delete = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .flat_map(|(identifier, domain)| {
                domain.assemblies.keys().filter_map(move |assembly| {
                    domain
                        .versions
                        .get(assembly)
                        .map(|(_, digest)| (identifier, assembly, digest))
                })
            })
            .find(|(_, _, digest)| RegistryAid::synthetic(0x4c, *digest) == target)
            .map(|(identifier, assembly, _)| management_names_wire(identifier, assembly.as_ref()))
            .transpose()?;
        if let Some(data) = assembly_delete {
            return self.manage_with_cancel(
                Verified {
                    level: 0x13,
                    command: crate::apdu::Command {
                        cla: 0x80,
                        ins: 0xf0,
                        p1: 0,
                        p2: 0,
                        data: data.into(),
                        le: None,
                    },
                },
                should_cancel,
            );
        }
        Err(Error::Missing)
    }

    pub(super) fn continue_globalplatform_load(
        &mut self,
        command: &crate::apdu::Command,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        let load = self.globalplatform_load.as_mut().ok_or(Error::Format)?;
        if !load.receiver.receive(command, &mut self.staging)? {
            return fallible_filled(1, 0);
        }
        let result = self.manage_with_cancel(
            Verified {
                level: 0x13,
                command: crate::apdu::Command {
                    cla: 0x80,
                    ins: 0xea,
                    p1: 0,
                    p2: 0,
                    data: Vec::new().into(),
                    le: None,
                },
            },
            should_cancel,
        );
        self.globalplatform_load = None;
        result?;
        fallible_filled(1, 0)
    }

    pub(super) fn install_instance_exact(
        &mut self,
        load_aid: RegistryAid,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.with_lifecycle_retry_floors(|card, retries| {
            card.install_instance_with_retries(load_aid, aid, should_cancel, retries)
        })
    }

    pub(super) fn install_instance_with_retries(
        &mut self,
        load_aid: RegistryAid,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
        retries: &mut lifecycle::LifecycleRetries,
    ) -> Result<()> {
        if should_cancel() { return Err(Error::Cancelled); }
        let (aid_bytes, aid_len) = decode_aid(aid)?;
        if self
            .state
            .registry_aid_in_use(RegistryAid::new(&aid_bytes[..aid_len])?)
        {
            return Err(Error::Busy);
        }
        let (domain_id, assembly, source) = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .flat_map(|(identifier, domain)| {
                domain.versions.iter().map(move |(assembly, (_, digest))| {
                    (
                        identifier,
                        assembly.as_ref(),
                        domain,
                        RegistryAid::synthetic(0x4c, digest),
                    )
                })
            })
            .find(|(_, _, _, candidate)| *candidate == load_aid)
            .map(|(identifier, assembly, domain, _)| (identifier, assembly, domain))
            .ok_or(Error::Missing)?;
        if source.instances.len() >= source.policy.max_instances as usize {
            return Err(Error::Quota);
        }
        let count = core::iter::once(&self.state.isd)
            .chain(self.state.domains.values())
            .map(|domain| domain.instances.len())
            .sum::<usize>();
        if count >= MAX_TOTAL_INSTANCES {
            return Err(Error::Quota);
        }
        let images = linking::BorrowedExecution::new(&self.state, self.journal.flash(),
            &mut self.platform, domain_id, assembly)?;
        let units = images.units()?;
        let package = &units[0].package;
        let entry = package
            .manifest
            .entry_points
            .iter()
            .find(|entry| entry.aid == aid)
            .ok_or(Error::Missing)?;
        let owner = source.registry_aid;
        let instance_aid = fallible_string(aid)?;
        let mut instances = source.instances.try_clone_with(&mut crate::fallible_clone::CloneContext::new())?;
        instances.reserve_entry()?;
        let mut application = None;
        if let Some(method) = entry.install {
            let mut staged = StagedApplication::new(source)?;
            run_lifecycle(
                staged.view(source), package, Some(&units), method,
                InvocationInput { data: &[], level: 0 }, &mut self.platform, &mut retries.control(source.registry_aid, should_cancel)?,
            )?;
            application = Some(staged);
        }
        let canonical = source.assemblies.get_key_value(assembly)
            .map(|(name, _)| Rc::clone(name)).ok_or(Error::Storage)?;
        instances.insert(instance_aid, canonical)?;
        if should_cancel() { return Err(Error::Cancelled); }
        drop(units);
        drop(images);
        self.commit_instance_lifecycle(owner, instances, application)
    }

    /// Bypasses SCP03 only in dedicated fuzz builds so stateful management paths remain reachable.
    #[cfg(feature = "fuzzing")]
    pub fn manage_fuzz_authenticated(&mut self, command: crate::apdu::Command) -> Result<Vec<u8>> {
        self.manage(Verified {
            command,
            level: 0x13,
        })
    }
    /// The verified APDU supplies both authority and parameters. No caller-provided domain override.
    pub fn manage(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.manage_with_cancel(verified, &mut || false)
    }
    pub(crate) fn manage_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.abort_transaction();
        if verified.level & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        let c = verified.command;
        if c.p1 != 0 || c.p2 != 0 {
            return Err(Error::Format);
        }
        match c.ins {
            0xe0 => {
                if !self.state.is_owned() {
                    return Err(Error::Unauthorized);
                }
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                if !crate::package::valid_identifier(id)
                    || id == "ISD"
                    || self.state.domains.contains_key(id)
                {
                    return Err(Error::Domain);
                }
                if self.state.domains.len() >= MAX_SSDS {
                    return Err(Error::Quota);
                }
                let mut incarnation = [0; 16];
                self.platform.random(&mut incarnation)?;
                let registry_aid = RegistryAid::synthetic(0x53, &incarnation);
                if self.state.registry_aid_in_use(registry_aid) {
                    return Err(Error::Busy);
                }
                let response = fallible_copy(&incarnation)?;
                self.insert_domain(
                    fallible_string(id)?,
                    Domain::new(incarnation, registry_aid, DomainPolicy::standard()?),
                )?;
                Ok(response)
            }
            0xe1 => {
                let (identifier, policy) = DomainPolicy::request(&c.data)?;
                self.update_domain_policy(&identifier, policy)?;
                Ok(Vec::new())
            }
            0xe2 => {
                if c.data.len() != 1 {
                    return Err(Error::Format);
                }
                let index = c.data[0] as usize;
                let total = self.state.domains.len() + 1;
                let (id, d) = if index == 0 {
                    ("ISD", &self.state.isd)
                } else {
                    let Some((id, d)) = self.state.domains.iter().nth(index - 1) else {
                        return Err(Error::Missing);
                    };
                    (id.as_str(), d)
                };
                // One bounded record per command, ordered by domain identifier.
                let capacity = 55usize.checked_add(id.len()).ok_or(Error::Quota)?;
                let mut out = Vec::new();
                out.try_reserve_exact(capacity)
                    .map_err(|_| Error::Quota)?;
                out.extend([1, total as u8, index as u8, id.len() as u8]);
                out.extend(id.as_bytes());
                out.extend(d.incarnation);
                out.push(u8::from(d.key.is_some()));
                out.extend(d.key.unwrap_or([0; 32]));
                out.extend([d.assemblies.len() as u8, d.instances.len() as u8]);
                out.extend(((d.store.len() + d.blobs.len()) as u16).to_le_bytes());
                Ok(out)
            }
            0xe3 => {
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                let policy = &self.state.domain(id).ok_or(Error::Domain)?.policy;
                policy.wire()
            }
            0xe4 => {
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                if id == "ISD" {
                    return Err(Error::Unauthorized);
                }
                let index = self.state.domains.position(id).map_err(|_| Error::Missing)?;
                self.remove_domain(index)?;
                self.staging.reset();
                Ok(Vec::new())
            }
            0xe6 => {
                if !c.data.is_empty() {
                    return Err(Error::Format);
                }
                self.staging.reset();
                Ok(Vec::new())
            }
            0xe8 => {
                if c.data.len() < 4 {
                    return Err(Error::Format);
                }
                let offset = u32::from_le_bytes(c.data[..4].try_into().unwrap()) as usize;
                let chunk = &c.data[4..];
                let end = offset.checked_add(chunk.len()).ok_or(Error::Quota)?;
                if offset < self.staging.len() {
                    if end > self.staging.len() || !self.staging.matches(offset, chunk)? {
                        return Err(Error::Format);
                    }
                    return Ok(Vec::new());
                }
                if offset != self.staging.len() || end > MAX_PACKAGE_BYTES {
                    return Err(Error::Quota);
                }
                self.staging.append(chunk)?;
                Ok(Vec::new())
            }
            0xea => {
                if !c.data.is_empty() {
                    return Err(Error::Format);
                }
                let declared_load_aid = self.globalplatform_load.as_ref().map(|load| load.load_aid);
                let expected = self
                    .globalplatform_load
                    .as_ref()
                    .map(|load| {
                        self.state
                            .domain_identifier_by_registry_aid(load.domain_aid)
                            .map(|domain| (load.hash, domain))
                            .ok_or(Error::Missing)
                    })
                    .transpose()?;
                let materialized = if self.staging.as_slice().is_none() {
                    Some(self.staging.read_all()?)
                } else {
                    None
                };
                let staged = self
                    .staging
                    .as_slice()
                    .unwrap_or_else(|| materialized.as_deref().unwrap());
                let p = PackageView::verify_with_expected_digest(
                    staged,
                    &mut self.platform,
                    expected.as_ref().and_then(|(hash, _)| hash.as_ref()),
                )?;
                if expected
                    .as_ref()
                    .is_some_and(|(_, domain)| p.manifest.domain != *domain)
                {
                    return Err(Error::Domain);
                }
                let registry_aid = RegistryAid::synthetic(0x4c, &p.digest);
                // An MP05 load file declares no AID of its own, so MicroCard derives one
                // from the digest and the host has to have declared that same one. Moving
                // the check here from INSTALL is what lets a host leave the hash out, since
                // the digest is only known once the whole load file has arrived.
                //
                // This constrains the load file AID alone. Instance AIDs are chosen at
                // INSTALL [for install] and are free to differ from it and from each other,
                // because one load file can back several instances. A Java Card load file
                // declares its own package AID in the CAP Header, so it will be bound to
                // that rather than to a digest.
                if declared_load_aid.is_some_and(|declared| declared != registry_aid) {
                    return Err(Error::Format);
                }
                let same_existing = self
                    .state
                    .domain(&p.manifest.domain)
                    .and_then(|domain| domain.versions.get(p.manifest.assembly.as_str()))
                    .is_some_and(|(_, digest)| {
                        RegistryAid::synthetic(0x4c, digest) == registry_aid
                    });
                if self.state.registry_aid_in_use(registry_aid) && !same_existing {
                    return Err(Error::Busy);
                }
                let existing: usize = core::iter::once(&self.state.isd)
                    .chain(self.state.domains.values())
                    .flat_map(|d| d.assemblies.values())
                    .map(|raw| raw.len())
                    .sum();
                let replaced = self
                    .state
                    .domain(&p.manifest.domain)
                    .and_then(|d| d.assemblies.get(p.manifest.assembly.as_str()))
                    .map_or(0, |raw| raw.len());
                if existing - replaced + p.raw.len() > MAX_TOTAL_PACKAGE_BYTES {
                    return Err(Error::Quota);
                }
                if p.manifest.domain != "ISD" && !self.state.is_owned() {
                    return Err(Error::Unauthorized);
                }
                if p.manifest.domain == "ISD"
                    && self.state.isd.key.is_none()
                    && (p.manifest.assembly != "mscorlib"
                        || !p.manifest.entry_points.is_empty()
                        || !p.manifest.dependencies.is_empty())
                {
                    return Err(Error::Unauthorized);
                }
                let mut bindings = Vec::new();
                bindings
                    .try_reserve_exact(p.manifest.dependencies.len())
                    .map_err(|_| Error::Quota)?;
                for dependency in &p.manifest.dependencies {
                    bindings.push(
                        resolve_dependency(&self.state, &p.manifest.domain, dependency, &p)
                            .ok_or(Error::Missing)?,
                    );
                }
                let imports = resolve_calls(&self.state, &p, &bindings)?;
                if self.state
                    .domain(&p.manifest.domain)
                    .is_some_and(|domain| {
                        domain
                            .assemblies
                            .contains_key(p.manifest.assembly.as_str())
                    })
                    && self.state.provider_in_use(&p.manifest.domain, &p.manifest.assembly)
                {
                    return Err(Error::Busy);
                }
                let d = self.state.domain(&p.manifest.domain).ok_or(Error::Domain)?;
                if p.manifest
                    .capabilities
                    .iter()
                    .any(|capability| !d.policy.capabilities.contains(capability))
                {
                    return Err(Error::Unauthorized);
                }
                if d.incarnation != p.manifest.incarnation {
                    return Err(Error::Domain);
                }
                if d.key.is_some_and(|key| key != p.signer) {
                    return Err(Error::KeyMismatch);
                }
                let schema = d.merged_storage_schema(&p.manifest.storage)?;
                if let Some((v, h)) = d.versions.get(p.manifest.assembly.as_str()) {
                    if p.manifest.version < *v || (p.manifest.version == *v && p.digest != *h) {
                        return Err(Error::Rollback);
                    }
                    if p.manifest.version == *v
                        && d.assemblies.contains_key(p.manifest.assembly.as_str())
                    {
                        drop(p);
                        self.staging.reset();
                        return Ok(Vec::new());
                    }
                }
                if d
                    .instances
                    .values()
                    .any(|a| a.as_ref() == p.manifest.assembly)
                {
                    return Err(Error::Busy);
                }
                let domain_bytes: usize = d.assemblies.values().map(|raw| raw.len()).sum();
                let domain_replaced = d
                    .assemblies
                    .get(p.manifest.assembly.as_str())
                    .map_or(0, |raw| raw.len());
                if domain_bytes - domain_replaced + p.raw.len()
                    > d.policy.max_package_bytes as usize
                {
                    return Err(Error::Quota);
                }
                if !d.assemblies.contains_key(p.manifest.assembly.as_str())
                    && d.assemblies.len() >= d.policy.max_assemblies as usize
                {
                    return Err(Error::Quota);
                }
                if !d.versions.contains_key(p.manifest.assembly.as_str())
                    && d.versions.len() >= d.policy.max_assemblies as usize
                {
                    return Err(Error::Quota);
                }
                let activated_assembly: Rc<str> = Rc::from(p.manifest.assembly.as_str());
                let metadata = Rc::new(StoredPackage::from_verified(p));
                let raw = Rc::new(match materialized {
                    Some(raw) => raw,
                    None => self.staging.take()?,
                });
                let candidate = lifecycle::PackageActivation {
                    name: activated_assembly, metadata, raw: Rc::clone(&raw),
                    bindings, imports, schema,
                };
                if let Err(error) = self.activate_package(candidate, should_cancel) {
                    self.staging
                        .restore(Rc::try_unwrap(raw).map_err(|_| Error::Storage)?)?;
                    return Err(error);
                }
                self.staging.reset();
                Ok(Vec::new())
            }
            0xec | 0xee | 0xf0 => {
                let (domain_id, name) = management_names(&c.data)?;
                if c.ins == 0xec {
                    let domain = self.state.domain(domain_id).ok_or(Error::Domain)?;
                    let package = domain.packages.values().find(|package| {
                        package.manifest.entry_points.iter().any(|entry| entry.aid == name)
                    }).ok_or(Error::Missing)?;
                    let load = RegistryAid::synthetic(0x4c, &package.digest);
                    self.install_instance_exact(load, name, should_cancel)?;
                } else if c.ins == 0xee {
                    self.uninstall_instance(domain_id, name, should_cancel)?;
                } else {
                    self.remove_package(domain_id, name)?;
                }
                Ok(Vec::new())
            }
            _ => Err(Error::Unsupported),
        }
    }
}

