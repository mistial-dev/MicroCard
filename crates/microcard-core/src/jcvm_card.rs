//! JCVM management and execution behind the shared authenticated transport.
use crate::{
    apdu::Command,
    crypto::CryptoProvider,
    engine::CardEngine,
    globalplatform::{self as gp, Aid, LoadReceiver, Payload},
    hal::Entropy,
    image_store::{ImageFlash, Images, PinnedImage},
    jcvm_package::MAX_PACKAGE_BYTES,
    jcvm_registry::{Registry, Store},
    jcvm_storage::{HeapBanks, Session},
    journal::{Flash, JournalKey},
    scp03::Verified,
    staging::PackageStaging,
    Error, Result,
};
use alloc::vec::Vec;

pub struct Storage<F: Flash, I: ImageFlash, H: HeapBanks> {
    pub registry: Store<F>,
    pub images: Images<I>,
    pub heaps: H,
    pub heap_key: JournalKey,
}

struct Upload {
    load: Aid,
    domain: Aid,
    hash: Option<[u8; 32]>,
    receiver: LoadReceiver,
}

type StoredSession<F, I> = Session<F, PinnedImage<I>>;

// A card-wide RAM quota, independent of the persistent heap journals.
const MAX_RETAINED_VOLATILE: usize = 65536;
struct Retained {
    aid: Aid,
    identity: [u8; 16],
    state: microcard_engine_jcvm::applet::VolatileState,
}

pub struct Card<F: Flash, I: ImageFlash, H: HeapBanks, P, S> {
    storage: Storage<F, I, H>,
    provider: P,
    staging: S,
    scratch: Vec<u8>,
    upload: Option<Upload>,
    selected: Option<(Aid, StoredSession<H::Bank, I>)>,
    retained: Vec<Retained>,
    reset_requested: bool,
    #[cfg(feature = "scp03-pseudo-random")]
    sequences: Option<core::ops::RangeInclusive<u32>>,
}

impl<F: Flash, I: ImageFlash, H: HeapBanks, P: CryptoProvider + Entropy, S: PackageStaging>
    Card<F, I, H, P, S>
{
    /// Verify all committed references on boot. Recovery never repairs missing heaps
    /// by running install, and each temporary session is dropped before opening another.
    pub fn open(
        mut storage: Storage<F, I, H>,
        mut provider: P,
        mut staging: S,
        mut scratch: Vec<u8>,
    ) -> Result<Self> {
        storage.registry.recover_renewal(&storage.images, &mut storage.heaps,
            &storage.heap_key, &staging, &mut scratch, &mut provider)?;
        staging.reset();
        for load in storage
            .registry
            .state()?
            .loads()
            .filter(|load| load.image.is_some())
        {
            storage.registry.with_package(
                load.aid,
                &storage.images,
                &mut scratch,
                &mut provider,
                |_| Ok(()),
            )?;
        }
        for instance in storage.registry.state()?.instances() {
            storage.registry.open_session(
                instance.aid,
                &storage.images,
                &mut storage.heaps,
                &storage.heap_key,
                &mut scratch,
                &mut provider,
            )?;
        }
        Ok(Self {
            storage,
            provider,
            staging,
            scratch,
            upload: None,
            selected: None,
            retained: Vec::new(),
            reset_requested: false,
            #[cfg(feature = "scp03-pseudo-random")]
            sequences: None,
        })
    }

    fn maintain_session(&mut self, aid: Aid, session: &mut StoredSession<H::Bank, I>,
            cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        if cancel() { return Err(Error::Cancelled); }
        // Renew between callbacks. This reserve is a maintenance threshold, not a
        // promise that an arbitrary applet command fits the remaining counter space.
        if session.remaining_commits()? > 1024 { return Ok(()); }
        if self.upload.is_some() { return Err(Error::Busy); }
        session.release_execution_frames()?;
        self.storage.registry.begin_renewal(aid, session, &self.storage.images,
            &self.storage.heaps, &self.storage.heap_key, &mut self.staging,
            &mut self.scratch, &mut self.provider)?;
        // Once ownership is published, finish or retain the protected recovery copy.
        // Cancellation must not expose the old session against a replaced bank.
        self.storage.registry.recover_renewal(&self.storage.images, &mut self.storage.heaps,
            &self.storage.heap_key, &self.staging, &mut self.scratch, &mut self.provider)?;
        self.storage.registry.handoff_renewed_session(aid, session, &self.storage.images,
            &mut self.storage.heaps, &self.storage.heap_key, &mut self.scratch, &mut self.provider)?;
        self.staging.reset();
        session.restore_execution_frames()?;
        if cancel() { return Err(Error::Cancelled); }
        Ok(())
    }

    fn maintain_selected(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        let Some((aid, mut session)) = self.selected.take() else { return Ok(()); };
        // Any maintenance error drops the old journal handle before returning.
        self.maintain_session(aid, &mut session, cancel)?;
        self.selected = Some((aid, session));
        Ok(())
    }

    fn park_selected(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        self.maintain_selected(cancel)?;
        let Some((aid, session)) = self.selected.as_mut() else { return Ok(()); };
        let instance = *self.storage.registry.state()?.instances()
            .find(|instance| instance.aid == *aid).ok_or(Error::Storage)?;
        let identity = instance.identity;
        let used: usize = self.retained.iter().map(|entry| entry.state.bytes()).sum();
        let available = MAX_RETAINED_VOLATILE.checked_sub(used).ok_or(Error::Quota)?;
        self.retained.try_reserve_exact(1).map_err(|_| Error::Quota)?;
        session.deselect(&mut self.provider, cancel)?;
        if session.take_security_reset() && instance.domain == Aid::isd() { self.reset_requested = true; }
        let state = session.retain_volatile(available)?;
        if state.bytes() != 0 { self.retained.push(Retained { aid: *aid, identity, state }); }
        self.selected = None;
        Ok(())
    }

    fn select_application(
        &mut self,
        request: &Command<'_>,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        let result = self.select_application_inner(request, cancel);
        if result.as_ref().is_err_and(|error| !matches!(error, Error::Missing | Error::Format)) {
            self.selected = None;
        }
        result
    }

    fn select_application_inner(
        &mut self,
        request: &Command<'_>,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        if !matches!(request.p1, 0 | 4) || !matches!(request.p2, 0 | 0x0c) {
            return Err(Error::Format);
        }
        let requested = Aid::new(&request.data)?;
        // First occurrence uses bytewise AID order, so an exact match precedes its
        // extensions. A missing prefix must not deselect the current applet.
        let aid = self.storage.registry.state()?.instances()
            .filter(|instance| instance.aid.as_slice().starts_with(requested.as_slice()))
            .min_by(|left, right| left.aid.as_slice().cmp(right.aid.as_slice()))
            .map(|instance| instance.aid).ok_or(Error::Missing)?;
        let command = Command {
            cla: 0,
            ins: 0xa4,
            p1: 4,
            p2: request.p2,
            data: requested.as_slice().into(),
            le: request.le.or(Some(256)),
        }
        .encode()?;
        self.maintain_selected(cancel)?;
        if self.selected.as_ref().is_some_and(|(selected, _)| *selected == aid) {
            let (_, session) = self.selected.as_mut().unwrap();
            let response = session.process(&command, true, &mut self.provider, cancel)?;
            if session.take_security_reset() && self.storage.registry.state()?.instances()
                .any(|instance| instance.aid == aid && instance.domain == Aid::isd()) {
                self.reset_requested = true;
            }
            if !session.selected()? { self.park_selected(cancel)?; }
            return response_wire(response);
        }
        self.park_selected(cancel)?;
        let identity = self.storage.registry.state()?.instances()
            .find(|instance| instance.aid == aid).ok_or(Error::Missing)?.identity;
        let mut session = self.storage.registry.open_session(
            aid, &self.storage.images, &mut self.storage.heaps,
            &self.storage.heap_key, &mut self.scratch, &mut self.provider,
        )?;
        if let Some(index) = self.retained.iter().position(|entry| entry.aid == aid) {
            let cached = &self.retained[index];
            if cached.identity != identity { return Err(Error::Storage); }
            session.restore_volatile(&cached.state)?;
            self.retained.remove(index);
        }
        self.maintain_session(aid, &mut session, cancel)?;
        let response = session.process(&command, true, &mut self.provider, cancel)?;
        let selected = session.selected()?;
        self.selected = Some((aid, session));
        if !selected { self.park_selected(cancel)?; }
        response_wire(response)
    }

    pub fn into_storage(self) -> Storage<F, I, H> {
        self.storage
    }

    fn commit(&mut self, next: Registry, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        self.storage.registry.commit(next, &mut self.provider)
    }

    fn receive(&mut self, command: &Command, cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        let upload = self.upload.as_mut().ok_or(Error::Format)?;
        if !upload.receiver.receive(command, &mut self.staging)? {
            return receipt();
        }
        let upload = self.upload.take().ok_or(Error::Format)?;
        let raw = self.staging.take()?;
        self.staging.reset();
        self.storage.registry.load_requested(
            &mut self.storage.images,
            &raw,
            &gp::LoadRequest {
                load_aid: upload.load.as_slice(),
                domain_aid: upload.domain.as_slice(),
                hash: upload.hash,
            },
            &mut self.scratch,
            &mut self.provider,
            cancel,
        )?;
        receipt()
    }

    fn manage_gp(
        &mut self,
        command: &Command,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        if command.ins == 0xe8 {
            return self.receive(command, cancel);
        }
        self.abort_staging();
        if command.ins == 0xe6 && command.p1 == 2 {
            let request = gp::load_request(command)?;
            let domain = Aid::new(request.domain_aid)?;
            let load = Aid::new(request.load_aid)?;
            let registry = self.storage.registry.state()?;
            if !registry.domains().any(|d| d.aid == domain) {
                return Err(Error::Missing);
            }
            if registry.domains().any(|d| d.aid == load)
                || registry.instances().any(|i| i.aid == load)
            {
                return Err(Error::Busy);
            }
            self.upload = Some(Upload {
                load,
                domain,
                hash: request.hash,
                receiver: LoadReceiver::new(Payload::SignedPackage, MAX_PACKAGE_BYTES),
            });
            return receipt();
        }
        if command.ins == 0xe6 && command.p1 == 0x0c {
            if let Ok(aid) = gp::ssd_install_aid(command) {
                let mut next = *self.storage.registry.state()?;
                let mut incarnation = [0; 16];
                self.provider.fill_entropy(&mut incarnation)?;
                next.add_domain(Aid::new(aid)?, incarnation)?;
                self.commit(next, cancel)?;
                return Ok(Vec::new());
            }
            let request = gp::application_install(command)?;
            let used: usize = self.retained.iter().map(|entry| entry.state.bytes()).sum();
            let available = MAX_RETAINED_VOLATILE.checked_sub(used).ok_or(Error::Quota)?;
            self.retained.try_reserve_exact(1).map_err(|_| Error::Quota)?;
            let (instance, state) = self.storage.registry.install(
                &request,
                &self.storage.images,
                &mut self.storage.heaps,
                &self.storage.heap_key,
                &mut self.scratch,
                &mut self.provider,
                cancel,
                available,
            )?;
            if state.bytes() != 0 {
                self.retained.push(Retained { aid: instance.aid, identity: instance.identity, state });
            }
            return receipt();
        }
        let aid = Aid::new(gp::delete_aid(command)?)?;
        let mut next = *self.storage.registry.state()?;
        if next.domains().any(|d| d.aid == aid) {
            next.remove_domain(aid)?;
        } else if next.instances().any(|i| i.aid == aid) {
            next.remove_instance(aid)?;
        } else {
            next.remove_load(aid)?;
        }
        self.commit(next, cancel)?;
        self.retained.retain(|entry| next.instances().any(|instance|
            instance.aid == entry.aid && instance.identity == entry.identity));
        Ok(Vec::new())
    }
}

impl<F: Flash, I: ImageFlash, H: HeapBanks, P: CryptoProvider + Entropy, S: PackageStaging>
    CardEngine for Card<F, I, H, P, S>
{
    type Provider = P;
    const DIRECT_APDUS: bool = true;
    fn is_application_command(&self, command: &Command<'_>) -> bool {
        command.cla == 0 || command.ins == 0xa4 || self.selected.is_some() && command.ins != 0xe2
    }
    fn crypto_provider(&mut self) -> &mut P {
        &mut self.provider
    }
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        self.provider.fill_entropy(output)
    }
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32> {
        if let Some(value) = self.sequences.as_mut().and_then(Iterator::next) {
            return Ok(value);
        }
        let mut next = *self.storage.registry.state()?;
        let range = next.reserve_sequences(32)?;
        self.storage.registry.commit(next, &mut self.provider)?;
        self.sequences = Some(range);
        self.sequences
            .as_mut()
            .and_then(Iterator::next)
            .ok_or(Error::Storage)
    }
    fn abort_staging(&mut self) {
        if matches!(self.storage.registry.pending_renewal(), Ok(None)) { self.staging.reset(); }
        self.upload = None;
    }
    fn abort_transaction(&mut self) {
        self.selected = None;
        self.retained.clear();
        self.reset_requested = false;
    }
    fn restart_secure_channel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        let aid = self.selected.as_ref().map(|(aid, _)| *aid);
        self.abort_staging();
        self.abort_transaction();
        if let Some(aid) = aid {
            // Reloading clears PIN validation and reset-scoped secrets. The host
            // may then authenticate SCP03 to the applet it selected beforehand.
            let command = Command { cla: 0, ins: 0xa4, p1: 4, p2: 0,
                data: aid.as_slice().into(), le: Some(256) };
            let response = self.select_application(&command, cancel)?;
            if !response.ends_with(&[0x90, 0]) { return Err(Error::Unauthorized); }
            self.reset_requested = false;
        }
        Ok(())
    }
    fn globalplatform_load_active(&self) -> bool {
        self.upload.is_some()
    }

    fn get_status_record(
        &mut self,
        kind: u8,
        index: usize,
        filter: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        use gp::{push_tlv, template};
        let registry = self.storage.registry.state()?;
        let mut count = 0;
        let mut chosen = None;
        let mut visit = |aid: Aid| {
            if kind == 0x80 || gp::aid_matches(aid.as_slice(), filter) {
                if count == index {
                    chosen = Some(aid);
                }
                count += 1;
            }
        };
        match kind {
            0x80 => visit(Aid::isd()),
            0x40 => {
                for domain in registry.domains().filter(|d| d.aid != Aid::isd()) {
                    visit(domain.aid);
                }
                for instance in registry.instances() {
                    visit(instance.aid);
                }
            }
            0x20 | 0x10 => {
                for load in registry.loads().filter(|l| l.image.is_some()) {
                    visit(load.aid);
                }
            }
            _ => return Err(Error::Format),
        }
        let aid = chosen.ok_or(Error::Missing)?;
        let mut body = Vec::new();
        push_tlv(&mut body, &[0x4f], aid.as_slice())?;
        if let Some(domain) = registry.domains().find(|d| d.aid == aid) {
            push_tlv(
                &mut body,
                &[0x9f, 0x70],
                &[if domain.owner.is_some() { 0x0f } else { 1 }],
            )?;
            push_tlv(&mut body, &[0xc5], &[0x80, 0, 0])?;
            if aid != Aid::isd() {
                push_tlv(&mut body, &[0xcc], &gp::ISD_AID)?;
            }
        } else if let Some(instance) = registry.instances().find(|i| i.aid == aid) {
            push_tlv(&mut body, &[0x9f, 0x70], &[7])?;
            push_tlv(&mut body, &[0xc5], &[0, 0, 0])?;
            push_tlv(&mut body, &[0xc4], instance.load.as_slice())?;
            push_tlv(&mut body, &[0xcc], instance.domain.as_slice())?;
        } else {
            self.storage.registry.with_package(
                aid,
                &self.storage.images,
                &mut self.scratch,
                &mut self.provider,
                |package| {
                    push_tlv(&mut body, &[0x9f, 0x70], &[1])?;
                    push_tlv(&mut body, &[0xce], &package.manifest.package_version)?;
                    if kind == 0x10 {
                        let file =
                            microcard_engine_jcvm::cap::LoadFile::parse(package.envelope.image)
                                .map_err(|_| Error::Storage)?;
                        for module in file.applets().map_err(|_| Error::Storage)?.iter() {
                            push_tlv(&mut body, &[0x84], module.aid)?;
                        }
                    }
                    push_tlv(&mut body, &[0xcc], package.manifest.domain)
                },
            )?;
        }
        Ok((template(body)?, count > index + 1))
    }

    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        self.park_selected(cancel)?;
        if cancel() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    fn select_verified_with_cancel(&mut self, verified: Verified, cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        self.select_application(verified.command(), cancel)
    }

    fn select_plain_with_cancel(&mut self, command: &Command<'_>, cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        self.select_application(command, cancel)
    }

    fn process_plain_with_cancel(&mut self, command: &Command<'_>, cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        self.maintain_selected(cancel)?;
        let (aid, session) = self.selected.as_mut().ok_or(Error::Missing)?;
        let result = session.process(&command.encode()?, false, &mut self.provider, cancel);
        if session.take_security_reset() && self.storage.registry.state()?.instances()
            .any(|instance| instance.aid == *aid && instance.domain == Aid::isd()) {
            self.reset_requested = true;
        }
        match result {
            Ok(response) => response_wire(response),
            Err(error) => { self.selected = None; Err(error) }
        }
    }

    fn take_security_reset(&mut self) -> bool { core::mem::take(&mut self.reset_requested) }

    fn manage_globalplatform_with_cancel(
        &mut self,
        verified: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        if verified.level() & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        self.select_isd_with_cancel(cancel)?;
        let result = self.manage_gp(verified.command(), cancel);
        if result.is_err() {
            self.abort_staging();
        }
        result
    }

    fn manage_with_cancel(
        &mut self,
        verified: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        if verified.level() & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        if cancel() {
            return Err(Error::Cancelled);
        }
        let command = verified.command();
        // Domain discovery is bounded and identifies this engine and schema explicitly.
        if command.ins != 0xe2 || command.p1 != 0 || command.p2 != 0 || command.data.len() != 1 {
            return Err(Error::Unsupported);
        }
        let registry = self.storage.registry.state()?;
        let index = usize::from(command.data[0]);
        let domain = registry.domains().nth(index).ok_or(Error::Missing)?;
        let mut wire = crate::cbor::Encoder::new(128);
        wire.array(9)?;
        for value in [2, 1, registry.domains().count() as u64, index as u64] {
            wire.unsigned(value)?;
        }
        wire.bytes(domain.aid.as_slice())?;
        wire.bytes(&domain.incarnation)?;
        match domain.owner {
            Some(owner) => wire.bytes(&owner)?,
            None => wire.null()?,
        }
        wire.unsigned(
            registry
                .loads()
                .filter(|l| l.domain == domain.aid && l.image.is_some())
                .count() as u64,
        )?;
        wire.unsigned(
            registry
                .instances()
                .filter(|i| i.domain == domain.aid)
                .count() as u64,
        )?;
        Ok(wire.finish())
    }

    fn process_verified_with_cancel(
        &mut self,
        verified: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.maintain_selected(cancel)?;
        let (aid, session) = self.selected.as_mut().ok_or(Error::Missing)?;
        let instance = self.storage.registry.state()?.instances()
            .find(|instance| instance.aid == *aid).ok_or(Error::Storage)?;
        // The transport authenticates the ISD; it does not authenticate an SSD session.
        let result = if instance.domain == Aid::isd() {
            session.process_verified(verified, &mut self.provider, cancel)
        } else {
            session.process(&verified.command().encode()?, false, &mut self.provider, cancel)
        };
        if session.take_security_reset() && instance.domain == Aid::isd() { self.reset_requested = true; }
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                self.selected = None;
                return Err(error);
            }
        };
        response_wire(response)
    }
}

fn response_wire(response: microcard_engine_jcvm::applet::Response) -> Result<Vec<u8>> {
    let mut data = response.data;
    data.try_reserve_exact(2).map_err(|_| Error::Quota)?;
    data.extend_from_slice(&response.sw.to_be_bytes());
    Ok(data)
}

fn receipt() -> Result<Vec<u8>> {
    let mut value = Vec::new();
    value.try_reserve_exact(1).map_err(|_| Error::Quota)?;
    value.push(0);
    Ok(value)
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests;
