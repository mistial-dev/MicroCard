//! Instance registry and callback data publish in one metadata commit.
use super::*;

#[derive(Clone, Copy)]
enum Owner {
    Isd,
    Ssd(usize),
}
impl Owner {
    fn resolve(state: &State, aid: RegistryAid) -> Result<Self> {
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
    fn domain(self, state: &mut State) -> &mut Domain {
        match self {
            Self::Isd => &mut state.isd,
            Self::Ssd(index) => &mut state.domains.0[index].1,
        }
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
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
        if cancel() {
            return Err(Error::Cancelled);
        }
        let source = self.state.domain(id).ok_or(Error::Domain)?;
        let owner = source.registry_aid;
        let assembly = source.instances.get(aid).ok_or(Error::Missing)?;
        let units = execution_units(&self.state, id, assembly)?;
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
            run_application_with_metrics_and_cancel(
                staged.view(source),
                package,
                Some(&units),
                method,
                InvocationInput {
                    data: &[],
                    level: 0,
                },
                &mut self.platform,
                cancel,
            )?;
            application = Some(staged);
        }
        if cancel() {
            return Err(Error::Cancelled);
        }
        self.commit_instance_lifecycle(owner, instances, application)
    }
}
