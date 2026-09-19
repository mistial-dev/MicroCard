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
