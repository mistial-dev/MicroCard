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

pub(super) trait CredentialCheckpoint<P: Platform> {
    fn checkpoint(
        &mut self,
        platform: &mut P,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()>;
}

pub(super) struct JournalCredentialCheckpoint<'a, F: Flash> {
    journal: &'a mut Journal<F>,
    owner: RegistryAid,
}

impl<'a, F: Flash> JournalCredentialCheckpoint<'a, F> {
    pub(super) fn new(journal: &'a mut Journal<F>, owner: RegistryAid) -> Self {
        Self { journal, owner }
    }
}

impl<F: Flash, P: Platform> CredentialCheckpoint<P> for JournalCredentialCheckpoint<'_, F> {
    fn checkpoint(
        &mut self,
        platform: &mut P,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()> {
        let data = self
            .journal
            .recover_with(platform)?
            .ok_or(Error::Storage)?;
        let mut durable = State::decode_snapshot(&data).map_err(|error| match error {
            Error::IncompatibleState => error,
            _ => Error::Storage,
        })?;
        let owner = lifecycle::Owner::resolve(&durable, self.owner)?;
        let domain = owner.domain(&mut durable);
        if !domain
            .credentials
            .apply_retry_floor(domain.incarnation, retry_floor.iter())?
        {
            return Ok(());
        }
        let intended = durable.encode_snapshot()?;
        if let Err(error) = self.journal.commit_owned_with(intended, platform) {
            let intended = durable.encode_snapshot()?;
            let recovered = self
                .journal
                .recover_selected_with(platform)?
                .ok_or(Error::Storage)?;
            if intended.as_slice() == recovered.as_slice() {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
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
        Self::new_with(domain, &mut crate::fallible_clone::CloneContext::new())
    }

    pub(super) fn new_with(
        domain: &Domain,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Self::from_parts(
            &domain.store,
            &domain.blobs,
            &domain.keys,
            &domain.credentials,
            context,
        )
    }

    /// Temporarily moves the live application data out of a domain. This is the ordinary
    /// invocation path: it preserves the existing allocations without cloning them.
    pub(super) fn take(domain: &mut Domain) -> Self {
        Self {
            store: core::mem::replace(&mut domain.store, IntStore::new()),
            blobs: core::mem::replace(&mut domain.blobs, BlobStore::new()),
            keys: core::mem::take(&mut domain.keys),
            credentials: core::mem::take(&mut domain.credentials),
        }
    }

    pub(super) fn from_parts(
        store: &IntStore,
        blobs: &BlobStore,
        keys: &crate::key_store::KeyStore,
        credentials: &crate::credential_store::CredentialStore,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self {
            store: store.try_clone_with(context)?,
            blobs: blobs.try_clone_with(context)?,
            keys: keys.try_clone_with(context)?,
            credentials: credentials.try_clone_with(context)?,
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

    pub(super) fn swap(&mut self, domain: &mut Domain) {
        core::mem::swap(&mut self.store, &mut domain.store);
        core::mem::swap(&mut self.blobs, &mut domain.blobs);
        core::mem::swap(&mut self.keys, &mut domain.keys);
        core::mem::swap(&mut self.credentials, &mut domain.credentials);
    }

    pub(super) fn install(mut self, domain: &mut Domain) {
        self.swap(domain);
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Mc04Engine<F, P, S> {
    fn application_domain_index(&self, aid: RegistryAid) -> Result<usize> {
        self.state
            .domains
            .0
            .iter()
            .position(|(_, domain)| domain.registry_aid == aid)
            .ok_or(Error::Domain)
    }

    pub(super) fn restore_application(
        &mut self,
        aid: RegistryAid,
        application: StagedApplication,
    ) -> Result<()> {
        let index = self.application_domain_index(aid)?;
        application.install(&mut self.state.domains.0[index].1);
        Ok(())
    }

    pub(super) fn commit_ordinary_application(
        &mut self,
        aid: RegistryAid,
        application: StagedApplication,
        dirty: bool,
    ) -> Result<()> {
        self.restore_application(aid, application)?;
        if !dirty {
            return Ok(());
        }
        self.commit_application_snapshot()
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
        // Keep the previous mutable fields alive until publication resolves. On a flash
        // error recovery installs whichever authenticated generation became authoritative.
        for (index, (_, next)) in indexes.iter().zip(changes.0.iter_mut().flatten()) {
            next.swap(&mut self.state.domains.0[*index].1);
        }
        self.commit_application_snapshot()
    }

    pub(super) fn commit_credential_retry_floor(
        &mut self,
        aid: RegistryAid,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()> {
        let owner = lifecycle::Owner::resolve(&self.state, aid)?;
        let domain = owner.domain(&mut self.state);
        let mut next = domain
            .credentials
            .try_clone_with(&mut crate::fallible_clone::CloneContext::new())?;
        if !next.apply_retry_floor(domain.incarnation, retry_floor.iter())? {
            return Ok(());
        }
        core::mem::swap(&mut domain.credentials, &mut next);
        self.commit_application_snapshot()
    }

    pub(super) fn apply_credential_retry_floor(
        &mut self,
        aid: RegistryAid,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()> {
        let owner = lifecycle::Owner::resolve(&self.state, aid)?;
        let domain = owner.domain(&mut self.state);
        domain
            .credentials
            .apply_retry_floor(domain.incarnation, retry_floor.iter())?;
        Ok(())
    }

    /// Resolve a failed publication before reporting its outcome. The commit marker may
    /// already be durable when the flash driver reports an error, so callers must not retry
    /// unless recovery proves that the previous generation remained authoritative.
    fn commit_application_snapshot(&mut self) -> Result<()> {
        if let Err(error) = self.commit_metadata_snapshot() {
            // Keep the intended encoding only on this slow failure path. Recovery returns
            // the exact authenticated bytes selected at reboot.
            let intended = self.state.encode_snapshot();
            let recovered = self.recover_committed_state_allow_unanchored()?;
            if intended
                .as_ref()
                .is_ok_and(|intended| intended.as_slice() == recovered.as_slice())
            {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }

    /// Recover the record that reboot would select after an unsafe invocation or an
    /// uncertain flash result. Package metadata is rebuilt because it is intentionally
    /// omitted from the persistent snapshot.
    pub(super) fn recover_committed_state(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        self.recover_committed_state_mode(false)
    }

    fn recover_committed_state_allow_unanchored(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        self.recover_committed_state_mode(true)
    }

    fn recover_committed_state_mode(
        &mut self,
        allow_unanchored: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let data = if allow_unanchored {
            self.journal.recover_selected_with(&mut self.platform)?
        } else {
            self.journal.recover_with(&mut self.platform)?
        }
        .ok_or(Error::Storage)?;
        let mut recovered = State::decode_snapshot(&data).map_err(|error| match error {
            Error::IncompatibleState => error,
            _ => Error::Storage,
        })?;
        for domain in core::iter::once(&mut recovered.isd).chain(recovered.domains.values_mut()) {
            for (name, descriptor) in domain.image_refs.iter() {
                let raw = descriptor.read_verified(self.journal.flash(), &mut self.platform)?;
                let verified = PackageView::verify_with(&raw, &mut self.platform)?;
                domain.packages.insert(
                    Rc::clone(name),
                    Rc::new(StoredPackage::from_verified(verified)),
                )?;
            }
        }
        self.state = recovered;
        self.transaction = None;
        Ok(data)
    }
}
