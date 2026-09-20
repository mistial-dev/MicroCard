//! Small metadata mutations with allocation-free undo after publication begins.
use super::*;

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
    /// Publishes existing image descriptors; this never stages or erases code.
    pub(super) fn commit_metadata_snapshot(&mut self) -> Result<()> {
        let data = self.state.encode_snapshot()?;
        self.journal
            .commit_owned_with(data, &mut self.platform)?;
        self.uncommitted_images.clear();
        Ok(())
    }

    pub(super) fn insert_domain(&mut self, id: String, domain: Domain) -> Result<()> {
        let index = self
            .state
            .domains
            .position(&id)
            .err()
            .ok_or(Error::Domain)?;
        self.state.domains.insert(id, domain)?;
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            self.state.domains.0.remove(index);
        }
        result
    }

    pub(super) fn remove_domain(&mut self, index: usize) -> Result<()> {
        if index >= self.state.domains.len() {
            return Err(Error::Missing);
        }
        let previous = self.state.domains.0.remove(index);
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            // Vec::remove retains capacity, so restoring this slot cannot allocate.
            self.state.domains.0.insert(index, previous);
        }
        result
    }

    pub(super) fn update_domain_policy(&mut self, id: &str, policy: DomainPolicy) -> Result<()> {
        let index = self.state.domains.position(id).map_err(|_| Error::Domain)?;
        let domain = &mut self.state.domains.0[index].1;
        if domain.key.is_some()
            || !domain.assemblies.is_empty()
            || !domain.instances.is_empty()
            || !domain.store.is_empty()
            || !domain.blobs.is_empty()
            || !domain.keys.is_empty()
        {
            return Err(Error::Busy);
        }
        if domain.policy == policy {
            return Ok(());
        }
        let previous = core::mem::replace(&mut domain.policy, policy);
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            self.state.domains.0[index].1.policy = previous;
        }
        result
    }

    #[cfg(feature = "scp03-pseudo-random")]
    pub(super) fn reserve_sequence_window(&mut self, reserved: u32) -> Result<()> {
        let previous = core::mem::replace(&mut self.state.scp03_sequence, reserved);
        let result = self.commit_metadata_snapshot();
        if result.is_err() {
            self.state.scp03_sequence = previous;
        }
        result
    }
}
