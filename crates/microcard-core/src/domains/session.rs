//! Per-command credential authorization and transaction session state.
use super::*;

pub(super) struct PendingTransaction {
    pub(super) owner: (RegistryAid, [u8; 16], String),
    pub(super) state: StagedApplication,
    pub(super) commands_left: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransactionDisposition {
    Inactive,
    Active,
    Begun,
    Commit,
    Abort,
}

impl TransactionDisposition {
    pub(super) fn begin(&mut self) -> Result<()> {
        if *self != Self::Inactive {
            return Err(Error::Busy);
        }
        *self = Self::Begun;
        Ok(())
    }

    pub(super) fn commit(&mut self) -> Result<()> {
        if !matches!(*self, Self::Active | Self::Begun) {
            return Err(Error::Missing);
        }
        *self = Self::Commit;
        Ok(())
    }

    pub(super) fn abort(&mut self) -> Result<()> {
        if !matches!(*self, Self::Active | Self::Begun) {
            return Err(Error::Missing);
        }
        *self = Self::Abort;
        Ok(())
    }

    pub(super) fn transaction_involved(self) -> bool {
        self != Self::Inactive
    }
}

#[derive(Default)]
pub(super) struct CredentialAuthorizations {
    slots: [Option<i32>; crate::credential_store::MAX_SLOTS],
}

impl CredentialAuthorizations {
    pub(super) fn contains(&self, slot: i32) -> bool {
        self.slots.contains(&Some(slot))
    }

    pub(super) fn insert(&mut self, slot: i32) -> Result<()> {
        if self.contains(slot) {
            return Ok(());
        }
        let available = self
            .slots
            .iter_mut()
            .find(|candidate| candidate.is_none())
            .ok_or(Error::Quota)?;
        *available = Some(slot);
        Ok(())
    }

    pub(super) fn remove(&mut self, slot: i32) {
        if let Some(existing) = self
            .slots
            .iter_mut()
            .find(|candidate| **candidate == Some(slot))
        {
            *existing = None;
        }
    }
}

#[derive(Default)]
pub(super) struct CredentialRetryFloors {
    entries: [Option<(i32, (u8, u8))>; crate::credential_store::MAX_SLOTS],
}

impl CredentialRetryFloors {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    pub(super) fn record(&mut self, slot: i32, remaining: (u8, u8)) -> Result<()> {
        if let Some((_, floor)) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.0 == slot)
        {
            floor.0 = floor.0.min(remaining.0);
            floor.1 = floor.1.min(remaining.1);
            return Ok(());
        }
        let available = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.is_none())
            .ok_or(Error::Quota)?;
        *available = Some((slot, remaining));
        Ok(())
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (i32, (u8, u8))> + '_ {
        self.entries.iter().flatten().copied()
    }
}

pub(super) struct Host<'a, 'checkpoint, P: Platform> {
    pub(super) store: &'a mut IntStore,
    pub(super) blobs: &'a mut BlobStore,
    pub(super) keys: &'a mut crate::key_store::KeyStore,
    pub(super) credentials: &'a mut crate::credential_store::CredentialStore,
    pub(super) authorized_credentials: CredentialAuthorizations,
    pub(super) credential_retry_floor: CredentialRetryFloors,
    pub(super) credential_checkpoint: Option<&'checkpoint mut dyn CredentialCheckpoint<P>>,
    pub(super) owner: [u8; 16],
    pub(super) data: &'a [u8],
    pub(super) out: Vec<u8>,
    pub(super) sw: u16,
    pub(super) platform: &'a mut P,
    pub(super) budget: usize,
    pub(super) capabilities: &'a [u8],
    pub(super) domain_schema: &'a [StorageDeclaration],
    pub(super) max_int_records: usize,
    pub(super) max_blob_records: usize,
    pub(super) max_blob_bytes: usize,
    pub(super) max_key_slots: usize,
    pub(super) level: u8,
    pub(super) units: Option<&'a [ExecutionUnit<'a>]>,
    pub(super) transaction: &'a mut TransactionDisposition,
    pub(super) transaction_snapshot: &'a mut Option<StagedApplication>,
    pub(super) persistent_dirty: &'a mut bool,
    #[cfg(test)]
    pub(super) transaction_snapshots: &'a mut usize,
    #[cfg(test)]
    pub(super) transaction_clone_allocations: &'a mut usize,
    pub(super) irreversible_output: bool,
}
