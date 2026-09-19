//! Bounded management metadata. Images and applet heaps live in separate storage.
use crate::{
    cbor::{Decoder, Encoder},
    globalplatform::Aid,
    image_store::{Descriptor, PinnedImage},
    jcvm_package::Package,
    Error, Result,
};
use alloc::vec::Vec;

pub const MAX_DOMAINS: usize = 4;
pub const MAX_PACKAGES: usize = 8;
pub const MAX_INSTANCES: usize = 8;
pub const MAX_SNAPSHOT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    pub aid: Aid,
    pub incarnation: [u8; 16],
    pub owner: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    pub domain: Aid,
    pub aid: Aid,
    /// Retained after deletion, so removing an image cannot reset rollback policy.
    pub version: u32,
    pub image: Option<Descriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instance {
    pub domain: Aid,
    pub load: Aid,
    pub module: Aid,
    pub aid: Aid,
    pub identity: [u8; 16],
    pub heap_bank: u8,
}

/// Copying this bounded metadata is permitted for an atomic journal update; it
/// contains no code, applet heap, execution frames, credentials, or private keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registry {
    domains: [Option<Domain>; MAX_DOMAINS],
    loads: [Option<Load>; MAX_PACKAGES],
    instances: [Option<Instance>; MAX_INSTANCES],
    sequence: u32,
}

impl Registry {
    pub fn new(incarnation: [u8; 16], owner: Option<[u8; 32]>) -> Self {
        let mut domains = [None; MAX_DOMAINS];
        domains[0] = Some(Domain {
            aid: Aid::isd(),
            incarnation,
            owner,
        });
        Self {
            domains,
            loads: [None; MAX_PACKAGES],
            instances: [None; MAX_INSTANCES],
            sequence: 0,
        }
    }

    pub fn domains(&self) -> impl Iterator<Item = &Domain> {
        self.domains.iter().flatten()
    }
    pub fn loads(&self) -> impl Iterator<Item = &Load> {
        self.loads.iter().flatten()
    }
    pub fn instances(&self) -> impl Iterator<Item = &Instance> {
        self.instances.iter().flatten()
    }
    pub fn protected_images(&self) -> impl Iterator<Item = Descriptor> + '_ {
        self.loads().filter_map(|load| load.image)
    }

    fn in_use(&self, aid: Aid) -> bool {
        self.domains().any(|d| d.aid == aid)
            || self.loads().any(|p| p.aid == aid)
            || self.instances().any(|i| i.aid == aid)
    }

    pub fn add_domain(&mut self, aid: Aid, incarnation: [u8; 16]) -> Result<()> {
        if self.in_use(aid) {
            return Err(Error::Busy);
        }
        let owner = self.domains[0]
            .and_then(|domain| domain.owner)
            .ok_or(Error::Unauthorized)?;
        let slot = self
            .domains
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::Quota)?;
        *slot = Some(Domain {
            aid,
            incarnation,
            owner: Some(owner),
        });
        Ok(())
    }

    pub fn remove_domain(&mut self, aid: Aid) -> Result<()> {
        if aid == Aid::isd() {
            return Err(Error::Unauthorized);
        }
        let slot = self
            .domains
            .iter_mut()
            .find(|slot| slot.is_some_and(|d| d.aid == aid))
            .ok_or(Error::Missing)?;
        *slot = None;
        for slot in &mut self.loads {
            if slot.is_some_and(|p| p.domain == aid) {
                *slot = None;
            }
        }
        for slot in &mut self.instances {
            if slot.is_some_and(|i| i.domain == aid) {
                *slot = None;
            }
        }
        Ok(())
    }

    /// Commit this registry before issuing any reserved SCP03 challenge counter.
    pub fn reserve_sequences(&mut self, count: u32) -> Result<core::ops::RangeInclusive<u32>> {
        let end = self.sequence.checked_add(count).ok_or(Error::Quota)?;
        if count == 0 || end > 0xffffff {
            return Err(Error::Quota);
        }
        let start = self.sequence + 1;
        self.sequence = end;
        Ok(start..=end)
    }

    fn activation_slots(&self, package: &Package<'_>) -> Result<(usize, usize)> {
        let domain = Aid::new(package.manifest.domain)?;
        let aid = Aid::new(package.manifest.package)?;
        let domain_slot = self
            .domains
            .iter()
            .position(|entry| entry.is_some_and(|d| d.aid == domain))
            .ok_or(Error::Missing)?;
        let authority = self.domains[domain_slot].unwrap();
        if authority.incarnation != package.manifest.incarnation {
            return Err(Error::Domain);
        }
        if authority
            .owner
            .is_some_and(|owner| owner != package.envelope.signer)
        {
            return Err(Error::KeyMismatch);
        }
        let existing = self
            .loads
            .iter()
            .position(|entry| entry.is_some_and(|p| p.aid == aid));
        if let Some(index) = existing {
            let previous = self.loads[index].unwrap();
            if previous.domain != domain {
                return Err(Error::Domain);
            }
            if package.manifest.version < previous.version {
                return Err(Error::Rollback);
            }
            if package.manifest.version == previous.version {
                return if previous
                    .image
                    .is_some_and(|image| image.digest == package.envelope.package_digest)
                {
                    Ok((domain_slot, index))
                } else {
                    Err(Error::Rollback)
                };
            }
            if self.instances().any(|instance| instance.load == aid) {
                return Err(Error::Busy);
            }
        } else if self.in_use(aid) {
            return Err(Error::Busy);
        }
        let index = existing
            .or_else(|| self.loads.iter().position(Option::is_none))
            .ok_or(Error::Quota)?;
        Ok((domain_slot, index))
    }

    /// Call only with a verified package and a verified, staged image descriptor.
    /// Persist the resulting metadata before reclaiming any formerly protected slot.
    pub fn activate(&mut self, package: &Package<'_>, image: Descriptor) -> Result<()> {
        let (domain_slot, index) = self.activation_slots(package)?;
        let domain = Aid::new(package.manifest.domain)?;
        let aid = Aid::new(package.manifest.package)?;
        let length = crate::envelope::OVERHEAD_BYTES
            + package.envelope.manifest.len()
            + package.envelope.image.len();
        if image.digest != package.envelope.package_digest
            || image.length as usize != length
            || image.slot >= 64
        {
            return Err(Error::Authentication);
        }
        if self
            .loads()
            .any(|p| p.aid != aid && p.image.is_some_and(|old| old.slot == image.slot))
        {
            return Err(Error::Busy);
        }
        self.loads[index] = Some(Load {
            domain,
            aid,
            version: package.manifest.version,
            image: Some(image),
        });
        self.domains[domain_slot].as_mut().unwrap().owner = Some(package.envelope.signer);
        Ok(())
    }

    pub fn remove_load(&mut self, aid: Aid) -> Result<()> {
        if self.instances().any(|instance| instance.load == aid) {
            return Err(Error::Busy);
        }
        let load = self
            .loads
            .iter_mut()
            .flatten()
            .find(|load| load.aid == aid)
            .ok_or(Error::Missing)?;
        if load.image.take().is_none() {
            return Err(Error::Missing);
        }
        Ok(())
    }

    /// The applet heap must already have a durable snapshot bound to `identity`.
    pub fn register(
        &mut self,
        package: &Package<'_>,
        module: Aid,
        aid: Aid,
        identity: [u8; 16],
        heap_bank: u8,
    ) -> Result<()> {
        let load = Aid::new(package.manifest.package)?;
        let domain = Aid::new(package.manifest.domain)?;
        if !self.loads().any(|p| {
            p.aid == load
                && p.domain == domain
                && p.image
                    .is_some_and(|image| image.digest == package.envelope.package_digest)
        }) {
            return Err(Error::Missing);
        }
        if self.in_use(aid)
            || self
                .instances()
                .any(|i| i.heap_bank == heap_bank || i.identity == identity)
        {
            return Err(Error::Busy);
        }
        if heap_bank >= MAX_INSTANCES as u8 {
            return Err(Error::Quota);
        }
        let file = microcard_engine_jcvm::cap::LoadFile::parse(package.envelope.image)
            .map_err(|_| Error::Format)?;
        if !file
            .applets()
            .map_err(|_| Error::Format)?
            .iter()
            .any(|entry| entry.aid == module.as_slice())
        {
            return Err(Error::Missing);
        }
        let slot = self
            .instances
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::Quota)?;
        *slot = Some(Instance {
            domain,
            load,
            module,
            aid,
            identity,
            heap_bank,
        });
        Ok(())
    }

    pub fn remove_instance(&mut self, aid: Aid) -> Result<()> {
        let slot = self
            .instances
            .iter_mut()
            .find(|slot| slot.is_some_and(|i| i.aid == aid))
            .ok_or(Error::Missing)?;
        *slot = None;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new(MAX_SNAPSHOT_BYTES);
        e.array(6)?;
        e.unsigned(1)?;
        e.unsigned(1)?;
        e.unsigned(u64::from(self.sequence))?;
        e.array(MAX_DOMAINS)?;
        for domain in self.domains {
            let Some(d) = domain else {
                e.null()?;
                continue;
            };
            e.array(3)?;
            e.bytes(d.aid.as_slice())?;
            e.bytes(&d.incarnation)?;
            if let Some(owner) = d.owner {
                e.bytes(&owner)?;
            } else {
                e.null()?;
            }
        }
        e.array(MAX_PACKAGES)?;
        for load in self.loads {
            let Some(p) = load else {
                e.null()?;
                continue;
            };
            e.array(4)?;
            e.bytes(p.domain.as_slice())?;
            e.bytes(p.aid.as_slice())?;
            e.unsigned(u64::from(p.version))?;
            if let Some(image) = p.image {
                e.array(3)?;
                e.unsigned(u64::from(image.slot))?;
                e.unsigned(u64::from(image.length))?;
                e.bytes(&image.digest)?;
            } else {
                e.null()?;
            }
        }
        e.array(MAX_INSTANCES)?;
        for instance in self.instances {
            let Some(i) = instance else {
                e.null()?;
                continue;
            };
            e.array(6)?;
            for aid in [i.domain, i.load, i.module, i.aid] {
                e.bytes(aid.as_slice())?;
            }
            e.bytes(&i.identity)?;
            e.unsigned(u64::from(i.heap_bank))?;
        }
        Ok(e.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Format);
        }
        let mut d = Decoder::new(bytes);
        d.record(6).map_err(|_| Error::IncompatibleState)?;
        if d.unsigned()? != 1 || d.unsigned()? != 1 {
            return Err(Error::IncompatibleState);
        }
        let mut state = Self::new([0; 16], None);
        state.sequence = d.number()?;
        d.record(MAX_DOMAINS)?;
        for slot in &mut state.domains {
            if d.null() {
                *slot = None;
                continue;
            }
            d.record(3)?;
            *slot = Some(Domain {
                aid: Aid::new(d.bytes(16)?)?,
                incarnation: d.fixed()?,
                owner: if d.null() { None } else { Some(d.fixed()?) },
            });
        }
        d.record(MAX_PACKAGES)?;
        for slot in &mut state.loads {
            if d.null() {
                continue;
            }
            d.record(4)?;
            let domain = Aid::new(d.bytes(16)?)?;
            let aid = Aid::new(d.bytes(16)?)?;
            let version = d.number()?;
            let image = if d.null() {
                None
            } else {
                d.record(3)?;
                Some(Descriptor {
                    slot: d.number()?,
                    length: d.number()?,
                    digest: d.fixed()?,
                })
            };
            *slot = Some(Load {
                domain,
                aid,
                version,
                image,
            });
        }
        d.record(MAX_INSTANCES)?;
        for slot in &mut state.instances {
            if d.null() {
                continue;
            }
            d.record(6)?;
            *slot = Some(Instance {
                domain: Aid::new(d.bytes(16)?)?,
                load: Aid::new(d.bytes(16)?)?,
                module: Aid::new(d.bytes(16)?)?,
                aid: Aid::new(d.bytes(16)?)?,
                identity: d.fixed()?,
                heap_bank: d.number()?,
            });
        }
        d.finish()?;
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        if self.domains[0].is_none_or(|d| d.aid != Aid::isd()) || self.sequence > 0xffffff {
            return Err(Error::Format);
        }
        for (index, domain) in self
            .domains
            .iter()
            .enumerate()
            .filter_map(|(i, d)| d.map(|d| (i, d)))
        {
            if self.domains[..index]
                .iter()
                .flatten()
                .any(|d| d.aid == domain.aid)
            {
                return Err(Error::Format);
            }
        }
        for (index, load) in self
            .loads
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.map(|p| (i, p)))
        {
            if load.version == 0
                || !self
                    .domains()
                    .any(|d| d.aid == load.domain && d.owner.is_some())
                || self.domains().any(|d| d.aid == load.aid)
                || self.loads[..index].iter().flatten().any(|p| {
                    p.aid == load.aid
                        || p.image
                            .zip(load.image)
                            .is_some_and(|(a, b)| a.slot == b.slot)
                })
                || load.image.is_some_and(|image| {
                    image.slot >= 64
                        || image.length as usize <= crate::envelope::OVERHEAD_BYTES
                        || image.length as usize > crate::jcvm_package::MAX_PACKAGE_BYTES
                })
            {
                return Err(Error::Format);
            }
        }
        for (index, instance) in self
            .instances
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.map(|p| (i, p)))
        {
            if instance.heap_bank >= MAX_INSTANCES as u8
                || !self.loads().any(|p| {
                    p.aid == instance.load && p.domain == instance.domain && p.image.is_some()
                })
                || self.domains().any(|d| d.aid == instance.aid)
                || self.loads().any(|p| p.aid == instance.aid)
                || self.instances[..index].iter().flatten().any(|i| {
                    i.aid == instance.aid
                        || i.heap_bank == instance.heap_bank
                        || i.identity == instance.identity
                })
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
}

/// The small metadata journal owns activation. A failed write may have committed;
/// recovery resolves it before the caller can query state or stage another image.
pub struct Store<F: crate::journal::Flash> {
    journal: crate::journal::Journal<F>,
    state: Registry,
    recovery_required: bool,
}

impl<F: crate::journal::Flash> Store<F> {
    pub fn open(
        flash: F,
        key: impl Into<crate::journal::JournalKey>,
        initial: Registry,
        provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<Self> {
        let (mut journal, snapshot) = crate::journal::Journal::open_with(flash, key, provider)?;
        let state = if let Some(snapshot) = snapshot {
            Registry::decode(&snapshot)?
        } else {
            journal.commit_with(&initial.encode()?, provider)?;
            initial
        };
        Ok(Self {
            journal,
            state,
            recovery_required: false,
        })
    }

    pub fn state(&self) -> Result<&Registry> {
        if self.recovery_required {
            return Err(Error::Storage);
        }
        Ok(&self.state)
    }

    /// Authenticate and authorize before erasing, then activate only verified writes.
    /// On error, query recovered state before reusing any image slot.
    pub fn load<I: crate::image_store::ImageFlash>(
        &mut self,
        images: &mut crate::image_store::Images<I>,
        raw: &[u8],
        scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Descriptor> {
        self.load_inner(images, raw, None, scratch, provider, cancel)
    }

    /// Bind authenticated C4 reception to the requested load and security domain.
    #[allow(clippy::too_many_arguments)]
    pub fn load_requested<I: crate::image_store::ImageFlash>(
        &mut self,
        images: &mut crate::image_store::Images<I>,
        raw: &[u8],
        request: &crate::globalplatform::LoadRequest<'_>,
        scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Descriptor> {
        self.load_inner(images, raw, Some(request), scratch, provider, cancel)
    }

    #[allow(clippy::too_many_arguments)]
    fn load_inner<I: crate::image_store::ImageFlash>(
        &mut self,
        images: &mut crate::image_store::Images<I>,
        raw: &[u8],
        request: Option<&crate::globalplatform::LoadRequest<'_>>,
        scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Descriptor> {
        self.state()?;
        if cancel() {
            return Err(Error::Cancelled);
        }
        let package = Package::verify(raw, provider, scratch)?;
        if request.is_some_and(|request| {
            request.load_aid != package.manifest.package
                || request.domain_aid != package.manifest.domain
                || request.hash.is_some_and(|hash| hash != package.envelope.package_digest)
        }) {
            return Err(Error::Signature);
        }
        self.state.activation_slots(&package)?;
        let mut protected = [Descriptor {
            slot: 0,
            length: 0,
            digest: [0; 32],
        }; MAX_PACKAGES];
        let mut count = 0;
        for image in self.state.protected_images() {
            protected[count] = image;
            count += 1;
        }
        let image = images.stage_with_cancel(raw, &protected[..count], provider, cancel)?;
        let mut next = self.state;
        next.activate(&package, image)?;
        if cancel() {
            return Err(Error::Cancelled);
        }
        if next != self.state {
            self.commit(next, provider)?;
        }
        Ok(image)
    }

    pub fn recover(&mut self, provider: &mut impl crate::crypto::CryptoProvider) -> Result<()> {
        self.recovery_required = true;
        let snapshot = self.journal.recover_with(provider)?.ok_or(Error::Storage)?;
        self.state = Registry::decode(&snapshot)?;
        self.recovery_required = false;
        Ok(())
    }

    /// Prepare and commit an unreferenced heap before publishing the instance.
    #[allow(clippy::too_many_arguments)]
    pub fn install<I: crate::image_store::ImageFlash, H: crate::jcvm_storage::HeapBanks>(
        &mut self,
        request: &crate::globalplatform::ApplicationInstall<'_>,
        images: &crate::image_store::Images<I>,
        heaps: &mut H,
        root: &crate::journal::JournalKey,
        scratch: &mut [u8],
        provider: &mut (impl crate::crypto::CryptoProvider + crate::hal::Entropy),
        cancel: &mut dyn FnMut() -> bool,
        volatile_limit: usize,
    ) -> Result<(Instance, microcard_engine_jcvm::applet::VolatileState)> {
        let mut next = *self.state()?;
        if cancel() { return Err(Error::Cancelled); }
        let load = Aid::new(request.load_aid)?;
        let module = Aid::new(request.module_aid)?;
        let aid = Aid::new(request.instance_aid)?;
        if next.in_use(aid) { return Err(Error::Busy); }
        if !(1..=MAX_INSTANCES).contains(&heaps.bank_count()) { return Err(Error::Storage); }
        let bank = (0..heaps.bank_count() as u8).find(|bank| !next.instances().any(|i| i.heap_bank == *bank)).ok_or(Error::Quota)?;
        let nonce = self.journal.reserve_identity_nonce()?;
        let mut identity = *b"\0\0\0\0\0\0\0\0JCVMv1\0\0";
        identity[..8].copy_from_slice(&nonce.to_le_bytes());
        let (image, sizes, digest) = self.session_image(load, images, scratch, provider, |package| {
            next.register(package, module, aid, identity, bank).map(|_| ())
        })?;
        let key = crate::jcvm_storage::heap_key(provider, root, bank, &identity, &digest)?;
        if cancel() { return Err(Error::Cancelled); }
        let flash = heaps.prepare(bank)?;
        let mut session = crate::jcvm_storage::Session::open(flash, key, image, identity, sizes, provider)?;
        session.install_globalplatform(request, provider, cancel)?;
        let volatile = session.retain_volatile(volatile_limit)?;
        // Release the execution heap before serializing metadata. On any failure,
        // this heap remains an orphan until a later authorized installation reclaims it.
        drop(session);
        if cancel() { return Err(Error::Cancelled); }
        self.commit(next, provider)?;
        Ok((*self.state()?.instances().find(|instance| instance.aid == aid).ok_or(Error::Storage)?, volatile))
    }

    /// Reopen exactly the heap named by committed metadata. Missing or incompatible
    /// state is an error, never permission to reinstall or erase it.
    #[allow(clippy::too_many_arguments)]
    pub fn open_session<I: crate::image_store::ImageFlash, H: crate::jcvm_storage::HeapBanks>(
        &self,
        aid: Aid,
        images: &crate::image_store::Images<I>,
        heaps: &mut H,
        root: &crate::journal::JournalKey,
        scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<crate::jcvm_storage::Session<H::Bank, PinnedImage<I>>> {
        let instance = *self.state()?.instances().find(|i| i.aid == aid).ok_or(Error::Missing)?;
        if usize::from(instance.heap_bank) >= heaps.bank_count() { return Err(Error::Storage); }
        let (image, sizes, digest) = self.session_image(instance.load, images, scratch, provider, |_| Ok(()))?;
        let key = crate::jcvm_storage::heap_key(provider, root, instance.heap_bank, &instance.identity, &digest)?;
        let session = crate::jcvm_storage::Session::open(heaps.open(instance.heap_bank)?, key, image, instance.identity, sizes, provider)?;
        if !session.installed()? { return Err(Error::Storage); }
        Ok(session)
    }

    fn session_image<I: crate::image_store::ImageFlash>(
        &self, load: Aid, images: &crate::image_store::Images<I>, scratch: &mut [u8],
        provider: &mut impl crate::crypto::CryptoProvider,
        validate: impl FnOnce(&Package<'_>) -> Result<()>,
    ) -> Result<(PinnedImage<I>, microcard_engine_jcvm::applet::Sizes, [u8; 32])> {
        let (length, sizes, digest) = self.with_package(load, images, scratch, provider, |package| {
            validate(package)?;
            Ok((package.envelope.image.len(), package.manifest.sizes, package.envelope.image_digest))
        })?;
        let descriptor = self.state()?.loads().find(|item| item.aid == load)
            .and_then(|item| item.image).ok_or(Error::Storage)?;
        let end = usize::try_from(descriptor.length).map_err(|_| Error::Bounds)?;
        let start = end.checked_sub(length).ok_or(Error::Bounds)?;
        let image = images.pin(&descriptor, start..end, provider)?;
        Ok((image, sizes, digest))
    }

    /// Verify the persisted image and its current registry binding before using it.
    pub fn with_package<I: crate::image_store::ImageFlash, P: crate::crypto::CryptoProvider, T>(
        &self,
        aid: Aid,
        images: &crate::image_store::Images<I>,
        scratch: &mut [u8],
        provider: &mut P,
        read: impl FnOnce(&Package<'_>) -> Result<T>,
    ) -> Result<T> {
        let state = self.state()?;
        let load = state.loads().find(|p| p.aid == aid).ok_or(Error::Missing)?;
        let image = load.image.ok_or(Error::Missing)?;
        images.with_verified_image(&image, provider, |raw, provider| {
            let package = Package::verify(raw, provider, scratch)?;
            if package.manifest.package != aid.as_slice()
                || package.manifest.version != load.version
            {
                return Err(Error::Authentication);
            }
            state.activation_slots(&package)?;
            read(&package)
        })
    }

    pub fn commit(
        &mut self,
        next: Registry,
        provider: &mut impl crate::crypto::CryptoProvider,
    ) -> Result<()> {
        self.state()?;
        let result = self.journal.commit_with(&next.encode()?, provider);
        match result {
            Ok(()) => {
                self.state = next;
                Ok(())
            }
            Err(error) => {
                self.recover(provider)?;
                Err(error)
            }
        }
    }

    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests;
