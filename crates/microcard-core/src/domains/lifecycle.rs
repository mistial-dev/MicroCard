//! Package and instance mutations with bounded rollback before metadata commits.
use super::*;

#[derive(Default)]
pub(super) struct LifecycleRetries([Option<(RegistryAid, CredentialRetryFloors)>; 2]);

pub(super) struct LifecycleControl<'a> {
    pub retry_floor: &'a mut CredentialRetryFloors,
    pub should_cancel: &'a mut dyn FnMut() -> bool,
}

impl LifecycleRetries {
    pub(super) fn control<'a>(
        &'a mut self,
        aid: RegistryAid,
        should_cancel: &'a mut dyn FnMut() -> bool,
    ) -> Result<LifecycleControl<'a>> {
        let index = self
            .0
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|(owner, _)| *owner == aid))
            .or_else(|| self.0.iter().position(Option::is_none))
            .ok_or(Error::Quota)?;
        let (_, retry_floor) =
            self.0[index].get_or_insert_with(|| (aid, CredentialRetryFloors::default()));
        Ok(LifecycleControl {
            retry_floor,
            should_cancel,
        })
    }
}

pub(super) struct PackageActivation {
    pub name: Rc<str>,
    pub metadata: Rc<StoredPackage>,
    pub raw: Rc<Vec<u8>>,
    pub bindings: Vec<ResolvedDependency>,
    pub imports: Vec<ResolvedCall>,
    pub schema: Rc<Vec<StorageDeclaration>>,
}

struct MapUndo<V> {
    index: usize,
    previous: Option<(Rc<str>, V)>,
}
impl<V> MapUndo<V> {
    // The caller reserves every affected map before the first publication.
    fn publish(map: &mut NameMap<V>, name: Rc<str>, value: V) -> Self {
        match map.position(&name) {
            Ok(index) => Self {
                index,
                previous: Some(core::mem::replace(&mut map.0[index], (name, value))),
            },
            Err(index) => {
                debug_assert!(map.0.len() < map.0.capacity());
                map.0.insert(index, (name, value));
                Self {
                    index,
                    previous: None,
                }
            }
        }
    }

    fn restore(self, map: &mut NameMap<V>) {
        if let Some(previous) = self.previous {
            map.0[self.index] = previous;
        } else {
            map.0.remove(self.index);
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Owner {
    Isd,
    Ssd(usize),
}
impl Owner {
    pub(super) fn resolve(state: &State, aid: RegistryAid) -> Result<Self> {
        if state.isd.registry_aid == aid {
            return Ok(Self::Isd);
        }
        state
            .domains
            .iter()
            .position(|(_, domain)| domain.registry_aid == aid)
            .map(Self::Ssd)
            .ok_or(Error::Domain)
    }
    pub(super) fn domain(self, state: &mut State) -> &mut Domain {
        match self {
            Self::Isd => &mut state.isd,
            Self::Ssd(index) => &mut state.domains.0[index].1,
        }
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
    pub(super) fn with_lifecycle_retry_floors<T>(
        &mut self,
        callback: impl FnOnce(&mut Self, &mut LifecycleRetries) -> Result<T>,
    ) -> Result<T> {
        let mut retries = LifecycleRetries::default();
        let result = callback(self, &mut retries);
        if result.is_err() {
            for (owner, floor) in retries.0.iter().flatten() {
                if !floor.is_empty() {
                    self.commit_credential_retry_floor(*owner, floor)?;
                }
            }
        }
        result
    }

    pub(super) fn activate_package(
        &mut self,
        candidate: PackageActivation,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        let PackageActivation {
            name,
            metadata,
            raw,
            bindings,
            imports,
            schema,
        } = candidate;
        let id = metadata.manifest.domain.as_str();
        let domain = self.state.domain(id).ok_or(Error::Domain)?;
        let owner = Owner::resolve(&self.state, domain.registry_aid)?;
        let current_count: usize = core::iter::once(&self.state.isd)
            .chain(self.state.domains.values())
            .map(|domain| domain.image_refs.len())
            .sum();
        let mut protected = Vec::new();
        protected
            .try_reserve_exact((self.uncommitted_images.len() + current_count + 1).min(64))
            .map_err(|_| Error::Quota)?;
        protected.extend_from_slice(&self.uncommitted_images);
        for domain in core::iter::once(&self.state.isd).chain(self.state.domains.values()) {
            for (_, descriptor) in domain.image_refs.iter() {
                if !protected.contains(descriptor) {
                    if protected.len() == 64 {
                        return Err(Error::Quota);
                    }
                    protected.push(*descriptor);
                }
            }
        }
        let domain = owner.domain(&mut self.state);
        domain.versions.reserve_for(&name)?;
        domain.bindings.reserve_for(&name)?;
        domain.imports.reserve_for(&name)?;
        domain.assemblies.reserve_for(&name)?;
        domain.packages.reserve_for(&name)?;
        domain.image_refs.reserve_for(&name)?;
        let assemblies =
            MapUndo::publish(&mut domain.assemblies, Rc::clone(&name), Rc::clone(&raw));
        let packages =
            MapUndo::publish(&mut domain.packages, Rc::clone(&name), Rc::clone(&metadata));
        let versions = MapUndo::publish(
            &mut domain.versions,
            Rc::clone(&name),
            (metadata.manifest.version, metadata.digest),
        );
        let bindings = MapUndo::publish(&mut domain.bindings, Rc::clone(&name), bindings);
        let imports = MapUndo::publish(&mut domain.imports, Rc::clone(&name), imports);
        let key = domain.key.replace(metadata.signer);
        let schema = core::mem::replace(&mut domain.storage_schema, schema);
        let result = (|| {
            {
                let images = linking::BorrowedExecution::with_candidate(&self.state,
                    self.journal.flash(), &mut self.platform, id, &name, &raw)?;
                images.units()?;
            }
            if cancel() {
                return Err(Error::Cancelled);
            }
            let descriptor = crate::image_store::Images::new(self.journal.flash_mut())?.stage(
                &raw,
                &protected,
                &mut self.platform,
            )?;
            if !protected.contains(&descriptor) {
                if protected.len() == 64 {
                    return Err(Error::Quota);
                }
                protected.push(descriptor);
            }
            let images = MapUndo::publish(
                &mut owner.domain(&mut self.state).image_refs,
                Rc::clone(&name),
                descriptor,
            );
            // Keep both generations' images until a later successful commit or reboot.
            self.uncommitted_images = protected;
            let result = self.commit_metadata_snapshot();
            if result.is_err() {
                images.restore(&mut owner.domain(&mut self.state).image_refs);
            }
            result
        })();
        if result.is_err() {
            let domain = owner.domain(&mut self.state);
            assemblies.restore(&mut domain.assemblies);
            packages.restore(&mut domain.packages);
            versions.restore(&mut domain.versions);
            bindings.restore(&mut domain.bindings);
            imports.restore(&mut domain.imports);
            domain.key = key;
            domain.storage_schema = schema;
        }
        result
    }

    pub(super) fn remove_package(&mut self, id: &str, name: &str) -> Result<()> {
        if id == "ISD" && name == "mscorlib" {
            return Err(Error::Unauthorized);
        }
        if self.state.provider_in_use(id, name) {
            return Err(Error::Busy);
        }
        let domain = self.state.domain(id).ok_or(Error::Domain)?;
        if domain
            .instances
            .values()
            .any(|assembly| assembly.as_ref() == name)
        {
            return Err(Error::Busy);
        }
        let owner = Owner::resolve(&self.state, domain.registry_aid)?;
        // Resolve every slot before changing anything. Removing retains capacity,
        // so restoring these exact entries cannot fail or allocate.
        let assembly = domain
            .assemblies
            .position(name)
            .map_err(|_| Error::Missing)?;
        let package = domain.packages.position(name).map_err(|_| Error::Storage)?;
        let image = domain
            .image_refs
            .position(name)
            .map_err(|_| Error::Storage)?;
        let binding = domain.bindings.position(name).map_err(|_| Error::Storage)?;
        let import = domain.imports.position(name).map_err(|_| Error::Storage)?;
        let domain = owner.domain(&mut self.state);
        let previous = (
            domain.assemblies.0.remove(assembly),
            domain.packages.0.remove(package),
            domain.image_refs.0.remove(image),
            domain.bindings.0.remove(binding),
            domain.imports.0.remove(import),
        );
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            let domain = owner.domain(&mut self.state);
            domain.assemblies.0.insert(assembly, previous.0);
            domain.packages.0.insert(package, previous.1);
            domain.image_refs.0.insert(image, previous.2);
            domain.bindings.0.insert(binding, previous.3);
            domain.imports.0.insert(import, previous.4);
        }
        result
    }

    pub(super) fn commit_instance_lifecycle(
        &mut self,
        owner: RegistryAid,
        mut instances: Instances,
        mut application: Option<StagedApplication>,
    ) -> Result<()> {
        let owner = Owner::resolve(&self.state, owner)?;
        let domain = owner.domain(&mut self.state);
        core::mem::swap(&mut domain.instances, &mut instances);
        if let Some(application) = application.as_mut() {
            application.swap(domain);
        }
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            let domain = owner.domain(&mut self.state);
            core::mem::swap(&mut domain.instances, &mut instances);
            if let Some(application) = application.as_mut() {
                application.swap(domain);
            }
        }
        result
    }

    pub(super) fn uninstall_instance(
        &mut self,
        id: &str,
        aid: &str,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.with_lifecycle_retry_floors(|card, retries| {
            card.uninstall_instance_with_retries(id, aid, cancel, retries)
        })
    }

    fn uninstall_instance_with_retries(
        &mut self,
        id: &str,
        aid: &str,
        cancel: &mut dyn FnMut() -> bool,
        retries: &mut LifecycleRetries,
    ) -> Result<()> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        let source = self.state.domain(id).ok_or(Error::Domain)?;
        let owner = source.registry_aid;
        let assembly = source.instances.get(aid).ok_or(Error::Missing)?;
        let images = linking::BorrowedExecution::new(&self.state, self.journal.flash(),
            &mut self.platform, id, assembly)?;
        let units = images.units()?;
        let package = &units[0].package;
        let entry = package
            .manifest
            .entry_points
            .iter()
            .find(|entry| entry.aid == aid)
            .ok_or(Error::Missing)?;
        let mut instances = source
            .instances
            .try_clone_with(&mut crate::fallible_clone::CloneContext::new())?;
        instances.remove(aid).ok_or(Error::Missing)?;
        let mut application = None;
        if let Some(method) = entry.uninstall {
            let mut staged = StagedApplication::new(source)?;
            run_lifecycle(
                staged.view(source),
                package,
                Some(&units),
                method,
                InvocationInput {
                    data: &[],
                    level: 0,
                },
                &mut self.platform,
                &mut retries.control(owner, cancel)?,
            )?;
            application = Some(staged);
        }
        if cancel() {
            return Err(Error::Cancelled);
        }
        drop(units);
        drop(images);
        self.commit_instance_lifecycle(owner, instances, application)
    }
}
