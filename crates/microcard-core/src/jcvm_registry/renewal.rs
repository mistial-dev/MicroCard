//! Authenticated ownership of the shared staging region during heap renewal.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Renewal {
    pub aid: Aid,
    pub bank: u8,
    pub old_identity: [u8; 16],
    pub new_identity: [u8; 16],
    pub package_digest: [u8; 32],
    pub record_length: u32,
    pub record_digest: [u8; 32],
}
impl Renewal {
    pub(super) fn validate(&self, state: &Registry) -> Result<()> {
        let instance = state.instances().find(|instance| instance.aid == self.aid).ok_or(Error::Format)?;
        if instance.heap_bank != self.bank || instance.identity != self.old_identity
            || state.instances().any(|instance| instance.identity == self.new_identity)
            || self.record_length < crate::journal::SeedRecord::MIN_BYTES as u32
            || self.record_length > crate::journal::SeedRecord::MAX_BYTES as u32
            || !state.loads().any(|load| load.aid == instance.load
                && load.image.is_some_and(|image| image.digest == self.package_digest)) {
            return Err(Error::Format);
        }
        Ok(())
    }
    pub(super) fn encode(self, e: &mut Encoder) -> Result<()> {
        e.array(7)?;
        e.bytes(self.aid.as_slice())?;
        e.unsigned(u64::from(self.bank))?;
        e.bytes(&self.old_identity)?;
        e.bytes(&self.new_identity)?;
        e.bytes(&self.package_digest)?;
        e.unsigned(u64::from(self.record_length))?;
        e.bytes(&self.record_digest)
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        d.record(7)?;
        Ok(Self {
            aid: Aid::new(d.bytes(16)?)?, bank: d.number()?,
            old_identity: d.fixed()?, new_identity: d.fixed()?, package_digest: d.fixed()?,
            record_length: d.number()?, record_digest: d.fixed()?,
        })
    }
}

impl<F: crate::journal::Flash> Store<F> {
    /// Stage a live committed heap under a newly reserved identity. The old bank is
    /// untouched; after publication, only renewal recovery may prepare that bank.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_renewal<I: crate::image_store::ImageFlash, H: crate::jcvm_storage::HeapBanks,
            S: crate::staging::PackageStaging>(
        &mut self, aid: Aid, session: &crate::jcvm_storage::Session<H::Bank, PinnedImage<I>>,
        images: &crate::image_store::Images<I>, heaps: &H, root: &crate::journal::JournalKey,
        staging: &mut S, scratch: &mut [u8], provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<Renewal> {
        use crate::image_store::CodeImage;
        let instance = *self.state()?.instances().find(|instance| instance.aid == aid).ok_or(Error::Missing)?;
        if !staging.is_empty() { return Err(Error::Busy); }
        if staging.persistent_capacity() == 0 { return Err(Error::Unsupported); }
        if self.journal.remaining_commits()? < 3 { return Err(Error::Quota); }
        let size = heaps.slot_size(instance.heap_bank)?;
        if size < crate::journal::OVERHEAD { return Err(Error::Bounds); }
        let prepared = (|| {
            let (image, sizes, digest) = Self::session_image_from(self.state()?, instance.load, images, scratch, provider, |_| Ok(()))?;
            let identity = self.reserve_heap_identity()?;
            let key = crate::jcvm_storage::heap_key(provider, root, instance.heap_bank, &identity, &digest)?;
            let snapshot = session.renewal_snapshot(instance.identity, digest, identity)?;
            let record = crate::journal::SeedRecord::seal_new_epoch(snapshot, key, provider)?;
            if record.len() > size - 3 || record.len() > staging.persistent_capacity() { return Err(Error::Quota); }
            staging.append(&record)?;
            if !staging.matches(0, &record)? { return Err(Error::Authentication); }
            let mut hash = [0; 32]; provider.sha256_into(&record, &mut hash)?;
            let key = crate::jcvm_storage::heap_key(provider, root, instance.heap_bank, &identity, &digest)?;
            image.with_bytes(provider, |bytes, provider| {
                let file = microcard_engine_jcvm::cap::LoadFile::parse(bytes).map_err(|_| Error::Format)?;
                crate::journal::SeedRecord::authenticate(&record, &key, provider, |snapshot| {
                    crate::jcvm_storage::validate_seed_snapshot(snapshot, &file, sizes, digest, identity)
                }).map(|_| ())
            })?;
            let package_digest = self.state()?.loads().find(|load| load.aid == instance.load)
                .and_then(|load| load.image).ok_or(Error::Storage)?.digest;
            let renewal = Renewal { aid, bank: instance.heap_bank, old_identity: instance.identity,
                new_identity: identity, package_digest, record_length: record.len() as u32, record_digest: hash };
            let mut next = *self.state()?; next.renewal = Some(renewal); next.validate()?;
            Ok((renewal, next))
        })();
        let (renewal, next) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => { staging.reset(); return Err(error); }
        };
        if let Err(error) = self.commit(next, provider) {
            // Publication can succeed even when its acknowledgment fails.
            if matches!(self.pending_renewal(), Ok(None)) { staging.reset(); }
            return Err(error);
        }
        Ok(renewal)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handoff_renewed_session<I: crate::image_store::ImageFlash, H: crate::jcvm_storage::HeapBanks>(
        &self, aid: Aid, session: &mut crate::jcvm_storage::Session<H::Bank, PinnedImage<I>>,
        images: &crate::image_store::Images<I>, heaps: &mut H, root: &crate::journal::JournalKey,
        scratch: &mut [u8], provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<()> {
        let instance = *self.state()?.instances().find(|instance| instance.aid == aid).ok_or(Error::Missing)?;
        let (_, _, digest) = self.session_image(instance.load, images, scratch, provider, |_| Ok(()))?;
        let key = crate::jcvm_storage::heap_key(provider, root, instance.heap_bank, &instance.identity, &digest)?;
        session.adopt_renewed_store(heaps.open(instance.heap_bank)?, key, instance.identity, provider)
    }

    /// Resolve authenticated staging ownership before uploads or applet execution.
    /// Failure retains the pending descriptor; no command is replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_renewal<I: crate::image_store::ImageFlash, H: crate::jcvm_storage::HeapBanks,
            S: crate::staging::PackageStaging>(
        &mut self, images: &crate::image_store::Images<I>, heaps: &mut H,
        root: &crate::journal::JournalKey, staging: &S, scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<()> {
        use crate::image_store::CodeImage;
        let Some(renewal) = self.pending_renewal()?.copied() else { return Ok(()); };
        renewal.validate(&self.state)?;
        let size = heaps.slot_size(renewal.bank)?;
        let length = renewal.record_length as usize;
        if size < crate::journal::OVERHEAD || length > size - 3 { return Err(Error::Bounds); }
        if staging.persistent_capacity() == 0 { return Err(Error::Unsupported); }
        if length > staging.persistent_capacity() { return Err(Error::Bounds); }
        if self.journal.remaining_commits()? == 0 { return Err(Error::Quota); }
        let mut record = crate::crypto::zeroizing_buffer(length)?;
        staging.read_persistent(0, &mut record)?;
        let mut hash = [0; 32];
        provider.sha256_into(&record, &mut hash)?;
        if hash != renewal.record_digest { return Err(Error::Authentication); }
        let load = self.state.instances().find(|instance| instance.aid == renewal.aid).ok_or(Error::Storage)?.load;
        let (image, sizes, digest) = Self::session_image_from(&self.state, load, images, scratch, provider, |_| Ok(()))?;
        let key = crate::jcvm_storage::heap_key(provider, root, renewal.bank, &renewal.new_identity, &digest)?;
        let seed = image.with_bytes(provider, |bytes, provider| {
            let file = microcard_engine_jcvm::cap::LoadFile::parse(bytes).map_err(|_| Error::Format)?;
            crate::journal::SeedRecord::authenticate(&record, &key, provider, |snapshot| {
                crate::jcvm_storage::validate_seed_snapshot(snapshot, &file, sizes, digest, renewal.new_identity)
            })
        })?;
        let mut next = self.state;
        next.instances.iter_mut().flatten().find(|instance| instance.aid == renewal.aid)
            .ok_or(Error::Storage)?.identity = renewal.new_identity;
        next.renewal = None;
        next.validate()?;
        // Everything needed for recovery is authenticated before the first erase.
        let mut flash = heaps.prepare(renewal.bank)?;
        seed.install_empty_bank(&mut flash)?;
        drop(record);
        image.with_bytes(provider, |bytes, provider| {
            crate::jcvm_storage::Store::validate_journal(flash, key, bytes, renewal.new_identity, sizes, provider)
        })?;
        // Copying the heap does not authorize execution. Publication does.
        self.commit_snapshot(next, provider)
    }
}
