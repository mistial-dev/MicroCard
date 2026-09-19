//! Mutable application data staged independently of package and domain metadata.
use super::*;

pub(super) struct ApplicationView<'a> {
    pub(super) store: &'a mut IntStore,
    pub(super) blobs: &'a mut BlobStore,
    pub(super) keys: &'a mut crate::key_store::KeyStore,
    pub(super) credentials: &'a mut crate::credential_store::CredentialStore,
    pub(super) incarnation: [u8; 16],
    pub(super) storage_schema: &'a [StorageDeclaration],
    pub(super) policy: &'a DomainPolicy,
}

impl Domain {
    pub(super) fn application_view(&mut self) -> ApplicationView<'_> {
        ApplicationView {
            store: &mut self.store,
            blobs: &mut self.blobs,
            keys: &mut self.keys,
            credentials: &mut self.credentials,
            incarnation: self.incarnation,
            storage_schema: &self.storage_schema,
            policy: &self.policy,
        }
    }
}

pub(super) struct StagedApplication {
    store: IntStore,
    blobs: BlobStore,
    keys: crate::key_store::KeyStore,
    credentials: crate::credential_store::CredentialStore,
}

/// A selection can run callbacks in at most the old and new domains.
pub(super) struct ApplicationChanges([Option<(RegistryAid, StagedApplication)>; 2]);

impl ApplicationChanges {
    pub(super) fn new() -> Self {
        Self([None, None])
    }

    pub(super) fn view<'a>(&'a mut self, domain: &'a Domain) -> Result<ApplicationView<'a>> {
        let index = self
            .0
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|(aid, _)| *aid == domain.registry_aid)
            })
            .or_else(|| self.0.iter().position(Option::is_none))
            .ok_or(Error::Quota)?;
        if self.0[index].is_none() {
            self.0[index] = Some((domain.registry_aid, StagedApplication::new(domain)?));
        }
        Ok(self.0[index].as_mut().ok_or(Error::Storage)?.1.view(domain))
    }
}

impl StagedApplication {
    pub(super) fn new(domain: &Domain) -> Result<Self> {
        let context = &mut crate::fallible_clone::CloneContext::new();
        Ok(Self {
            store: domain.store.try_clone_with(context)?,
            blobs: domain.blobs.try_clone_with(context)?,
            keys: domain.keys.try_clone_with(context)?,
            credentials: domain.credentials.try_clone_with(context)?,
        })
    }

    pub(super) fn view<'a>(&'a mut self, domain: &'a Domain) -> ApplicationView<'a> {
        ApplicationView {
            store: &mut self.store,
            blobs: &mut self.blobs,
            keys: &mut self.keys,
            credentials: &mut self.credentials,
            incarnation: domain.incarnation,
            storage_schema: &domain.storage_schema,
            policy: &domain.policy,
        }
    }

    fn unchanged(&self, domain: &Domain) -> bool {
        self.store == domain.store
            && self.blobs == domain.blobs
            && self.keys == domain.keys
            && self.credentials == domain.credentials
    }

    fn swap(&mut self, domain: &mut Domain) {
        core::mem::swap(&mut self.store, &mut domain.store);
        core::mem::swap(&mut self.blobs, &mut domain.blobs);
        core::mem::swap(&mut self.keys, &mut domain.keys);
        core::mem::swap(&mut self.credentials, &mut domain.credentials);
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
    fn application_domain_index(&self, aid: RegistryAid) -> Result<usize> {
        self.state
            .domains
            .0
            .iter()
            .position(|(_, domain)| domain.registry_aid == aid)
            .ok_or(Error::Domain)
    }

    /// Only mutable application fields changed; image descriptors remain valid.
    fn commit_application_snapshot(&mut self) -> Result<()> {
        let data = self.state.encode_snapshot()?;
        if data.len() > 49152 {
            return Err(Error::Quota);
        }
        self.journal
            .commit_with(data.as_slice(), &mut self.platform)?;
        self.uncommitted_images.clear();
        Ok(())
    }

    pub(super) fn commit_application(
        &mut self,
        aid: RegistryAid,
        next: StagedApplication,
    ) -> Result<()> {
        self.commit_application_changes(ApplicationChanges([Some((aid, next)), None]))
    }

    pub(super) fn commit_application_changes(
        &mut self,
        mut changes: ApplicationChanges,
    ) -> Result<()> {
        let mut indexes = [0; 2];
        let mut changed = false;
        // Resolve every owner before swapping anything, so validation cannot interrupt undo.
        for (index, (aid, next)) in indexes.iter_mut().zip(changes.0.iter().flatten()) {
            *index = self.application_domain_index(*aid)?;
            changed |= !next.unchanged(&self.state.domains.0[*index].1);
        }
        if !changed {
            return Ok(());
        }
        // Keep the previous mutable fields as undo data until the journal succeeds.
        for (index, (_, next)) in indexes.iter().zip(changes.0.iter_mut().flatten()) {
            next.swap(&mut self.state.domains.0[*index].1);
        }
        let result = self.commit_application_snapshot();
        if result.is_err() {
            for (index, (_, next)) in indexes.iter().zip(changes.0.iter_mut().flatten()) {
                next.swap(&mut self.state.domains.0[*index].1);
            }
        }
        result
    }

    pub(super) fn commit_credential_retry_floor(
        &mut self,
        aid: RegistryAid,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()> {
        let index = self.application_domain_index(aid)?;
        let domain = &mut self.state.domains.0[index].1;
        let mut next = domain
            .credentials
            .try_clone_with(&mut crate::fallible_clone::CloneContext::new())?;
        if !next.apply_retry_floor(domain.incarnation, retry_floor.iter())? {
            return Ok(());
        }
        core::mem::swap(&mut domain.credentials, &mut next);
        let result = self.commit_application_snapshot();
        if result.is_err() {
            core::mem::swap(&mut self.state.domains.0[index].1.credentials, &mut next);
        }
        result
    }
}
