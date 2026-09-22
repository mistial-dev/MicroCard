//! Persistent MC04 domain management and application lifecycle.
use crate::{
    journal::{Flash, Journal, JournalKey},
    package::{
        Manifest, Package, PackageView, StorageDeclaration, MAX_DECLARED_BLOB_BYTES,
        MAX_PACKAGE_BYTES, MAX_STORAGE_DECLARATIONS,
    },
    scp03::Verified,
    staging::{PackageStaging, RamStaging},
    Error, Result,
};
use alloc::{rc::Rc, string::String, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub use crate::hal::RuntimePlatform as Platform;
mod application;
mod collections;
mod engine;
mod execution;
mod lifecycle;
mod linking;
mod management;
mod metadata;
mod model;
mod native;
mod registry;
mod session;
mod snapshot;
use application::{
    ApplicationChanges, ApplicationView, CredentialCheckpoint, JournalCredentialCheckpoint,
    StagedApplication,
};
use collections::{BlobStore, Domains, Instances, IntStore, NameMap};
#[cfg(test)]
use execution::run_context;
use execution::{run_lifecycle, InvocationInput};
#[cfg(test)]
use linking::{
    push_execution_source, push_link_edge, validate_linked_program, validate_program_graph,
};
use linking::{
    resolve_calls, resolve_dependency, CallTarget, ExecutionUnit, PackageData, ResolvedCall,
    ResolvedDependency,
};
use model::{Domain, State, StoredPackage, StoredPackageView};
#[cfg(test)]
use native::{BufferResult, NativeArgument};
use registry::{
    decode_aid, encode_aid, insert_unique_registry_aid, management_names, management_names_wire,
    registry_record, visit_registry, DomainPolicy,
};
use session::{
    CredentialAuthorizations, CredentialRetryFloors, Host, PendingTransaction,
    TransactionDisposition,
};

const MAX_TOTAL_PACKAGE_BYTES: usize = 24 * 1024;
const MAX_SSDS: usize = 8;
const MAX_ASSEMBLIES_PER_DOMAIN: u8 = 8;
const MAX_INSTANCES_PER_DOMAIN: u8 = 8;
const MAX_TOTAL_INSTANCES: usize = 16;
const MAX_INT_RECORDS: usize = 512;
const INT_STORE_GROWTH: usize = 16;
const MAX_BLOB_RECORDS: usize = 64;
const BLOB_STORE_GROWTH: usize = 8;
const MAX_DOMAIN_STORAGE_DECLARATIONS: usize =
    MAX_ASSEMBLIES_PER_DOMAIN as usize * MAX_STORAGE_DECLARATIONS;
const MAX_EXECUTION_UNITS: usize = 17;
const MAX_TOTAL_ASSEMBLIES: usize = (MAX_SSDS + 1) * MAX_ASSEMBLIES_PER_DOMAIN as usize;
const MAX_REGISTRY_AIDS: usize = 1 + MAX_SSDS + MAX_TOTAL_ASSEMBLIES + MAX_TOTAL_INSTANCES;
const MAX_LINKED_METHODS: usize =
    MAX_EXECUTION_UNITS * crate::mc04_schema::MAX_METHODDEF_ROWS as usize;
const MAX_LINKED_CALL_EDGES: usize = 2048;
const MAX_KEY_SERVICE_ARGUMENT_BYTES: usize = 1024;
const MAX_KEY_SERVICE_TOTAL_BYTES: usize = 2048;
const MAX_TRANSACTION_COMMANDS: u8 = 16;
const MAX_MANAGED_RESPONSE_BYTES: usize = 248;
const MAX_MANAGED_RESPONSE_WITH_STATUS: usize = MAX_MANAGED_RESPONSE_BYTES + 2;

/// Values reserved by one durable write, so a secure channel does not cost a flash write.
#[cfg(feature = "scp03-pseudo-random")]
const SEQUENCE_WINDOW: u32 = 64;

/// The counter travels in three bytes, so this is the last value it can express.
#[cfg(feature = "scp03-pseudo-random")]
const SEQUENCE_CEILING: u32 = 0x00ff_ffff;
fn fallible_filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| Error::Quota)?;
    values.resize(length, value);
    Ok(values)
}

fn fallible_copy(value: &[u8]) -> Result<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| Error::Quota)?;
    copy.extend_from_slice(value);
    Ok(copy)
}

fn fallible_string(value: &str) -> Result<String> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| Error::Quota)?;
    copy.push_str(value);
    Ok(copy)
}

use crate::globalplatform::Aid as RegistryAid;

struct GlobalPlatformLoad {
    domain_aid: RegistryAid,
    /// The load file AID the host declared. It is checked against the digest of what
    /// actually arrived, at the end of the load rather than when it was declared, because
    /// only the received bytes can settle it.
    load_aid: RegistryAid,
    hash: Option<[u8; 32]>,
    receiver: crate::globalplatform::LoadReceiver,
}

pub struct Mc04Engine<
    F: Flash + crate::image_store::ImageFlash,
    P: Platform,
    S: PackageStaging = RamStaging,
> {
    journal: Journal<F>,
    state: State,
    platform: P,
    staging: S,
    // A failed metadata write may already have committed its marker. Keep candidate
    // images protected until a later successful commit or reboot resolves ownership.
    uncommitted_images: Vec<crate::image_store::Descriptor>,
    globalplatform_load: Option<GlobalPlatformLoad>,
    selected: Option<(String, [u8; 16], String)>,
    transaction: Option<PendingTransaction>,
    /// Next sequence counter value to issue, and the reserved value it stops at.
    #[cfg(feature = "scp03-pseudo-random")]
    sequence: (u32, u32),
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform> Mc04Engine<F, P, RamStaging> {
    pub fn open(flash: F, platform: P, storage_key: impl Into<JournalKey>) -> Result<Self> {
        Self::open_with_staging(flash, platform, storage_key, RamStaging::default())
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging>
    Mc04Engine<F, P, S>
{
    pub fn open_with_staging(
        flash: F,
        mut platform: P,
        storage_key: impl Into<JournalKey>,
        staging: S,
    ) -> Result<Self> {
        let (mut journal, data) = Journal::open_with(flash, storage_key, &mut platform)?;
        let mut state: State = match data {
            Some(d) => State::decode_snapshot(&d).map_err(|error| match error {
                Error::IncompatibleState => error,
                _ => Error::Storage,
            })?,
            None => {
                let mut incarnation = [0; 16];
                platform.random(&mut incarnation)?;
                let state = State {
                    isd: Domain::new(incarnation, RegistryAid::isd(), DomainPolicy::standard()?),
                    domains: Domains::new(),
                    scp03_sequence: 0,
                };
                let encoded = state.encode_snapshot()?;
                journal.commit_owned_with(encoded, &mut platform)?;
                state
            }
        };
        // Check backend geometry even when no packages have been installed.
        crate::image_store::Images::new(journal.flash_mut())?;
        if state.domains.len() > MAX_SSDS {
            return Err(Error::Storage);
        }
        let mut registry_aids = Vec::new();
        registry_aids
            .try_reserve_exact(MAX_REGISTRY_AIDS)
            .map_err(|_| Error::Quota)?;
        for (id, domain) in core::iter::once(("ISD", &state.isd)).chain(
            state
                .domains
                .iter()
                .map(|(id, domain)| (id.as_str(), domain)),
        ) {
            if !domain.registry_aid.valid()
                || id == "ISD" && domain.registry_aid != RegistryAid::isd()
                || !insert_unique_registry_aid(&mut registry_aids, domain.registry_aid)
            {
                return Err(Error::Storage);
            }
        }
        let mut linked_roots = Vec::new();
        linked_roots
            .try_reserve_exact(MAX_TOTAL_ASSEMBLIES)
            .map_err(|_| Error::Quota)?;
        for domain in core::iter::once(&mut state.isd).chain(state.domains.values_mut()) {
            for (name, descriptor) in domain.image_refs.iter() {
                let raw = descriptor.read_verified(journal.flash(), &mut platform)?;
                let verified = PackageView::verify_with(&raw, &mut platform)?;
                domain.packages.insert(
                    Rc::clone(name),
                    Rc::new(StoredPackage::from_verified(verified)),
                )?;
            }
        }
        let mut total_bytes = 0usize;
        let mut instance_count = 0usize;
        for (id, d) in core::iter::once(("ISD", &state.isd))
            .chain(state.domains.iter().map(|(id, d)| (id.as_str(), d)))
        {
            if !crate::package::valid_identifier(id)
                || !d.policy.valid()
                || d.image_refs.len() > d.policy.max_assemblies as usize
                || d.bindings.len() != d.image_refs.len()
                || d.imports.len() != d.image_refs.len()
                || d.bindings
                    .keys()
                    .any(|name| !d.image_refs.contains_key(name))
                || d.imports
                    .keys()
                    .any(|name| !d.image_refs.contains_key(name))
                || d.versions.len() > d.policy.max_assemblies as usize
                || d.storage_schema.len() > MAX_DOMAIN_STORAGE_DECLARATIONS
                || !d.storage_schema.iter().all(StorageDeclaration::valid)
                || !d
                    .storage_schema
                    .windows(2)
                    .all(|pair| pair[0].key < pair[1].key)
                || d.instances.len() > d.policy.max_instances as usize
                || d.store.len() > d.policy.max_int_records as usize
                || d.store.iter().any(|(key, _)| {
                    d.storage_declaration(*key)
                        .is_none_or(|declaration| declaration.kind != 1)
                })
                || d.blobs.len() > d.policy.max_blob_records as usize
                || d.blobs.iter().any(|(key, value)| {
                    d.storage_declaration(*key).is_none_or(|declaration| {
                        declaration.kind != 2 || value.len() > usize::from(declaration.max_bytes)
                    })
                })
                || d.blobs.values().map(Vec::len).sum::<usize>() > d.policy.max_blob_bytes as usize
                || d.keys.len() > d.policy.max_key_slots as usize
                || (d.key.is_none()
                    && (!d.image_refs.is_empty()
                        || !d.versions.is_empty()
                        || !d.storage_schema.is_empty()
                        || !d.instances.is_empty()
                        || !d.store.is_empty()
                        || !d.blobs.is_empty()
                        || !d.keys.is_empty()
                        || !d.credentials.is_empty()))
                || d.versions
                    .iter()
                    .any(|(name, (v, _))| name.is_empty() || name.len() > 64 || *v == 0)
            {
                return Err(Error::Storage);
            }
            d.keys.validate()?;
            d.credentials.validate(d.incarnation)?;
            let mut domain_package_bytes = 0usize;
            for (name, descriptor) in d.image_refs.iter() {
                total_bytes += descriptor.length as usize;
                domain_package_bytes += descriptor.length as usize;
                let raw = descriptor.read_verified(journal.flash(), &mut platform)?;
                let p = d.package_metadata(name)?.view(&raw)?;
                if p.image.starts_with(b"MC04") {
                    linked_roots.push((id, name.as_ref()));
                }
                let bindings = d.bindings.get(name).ok_or(Error::Storage)?;
                let imports = d.imports.get(name).ok_or(Error::Storage)?;
                if bindings.len() != p.manifest.dependencies.len()
                    || bindings
                        .iter()
                        .zip(&p.manifest.dependencies)
                        .any(|(binding, dependency)| {
                            resolve_dependency(&state, id, dependency, &p).as_ref() != Some(binding)
                        })
                    || imports
                        != &resolve_calls(&state, &p, bindings, journal.flash(), &mut platform)?
                    || p.manifest.domain != id
                    || p.manifest.assembly.as_str() != name.as_ref()
                    || p.manifest.incarnation != d.incarnation
                    || Some(p.signer) != d.key
                    || d.versions.get(name) != Some(&(p.manifest.version, p.digest))
                    || p.manifest.storage.iter().any(|declaration| {
                        d.storage_declaration(declaration.key) != Some(declaration)
                    })
                    || p.manifest
                        .capabilities
                        .iter()
                        .any(|capability| !d.policy.capabilities.contains(capability))
                {
                    return Err(Error::Storage);
                }
                if !insert_unique_registry_aid(
                    &mut registry_aids,
                    RegistryAid::synthetic(0x4c, &p.digest),
                ) {
                    return Err(Error::Storage);
                }
            }
            if domain_package_bytes > d.policy.max_package_bytes as usize {
                return Err(Error::Storage);
            }
            for (aid, assembly) in d.instances.iter() {
                if instance_count >= MAX_TOTAL_INSTANCES {
                    return Err(Error::Storage);
                }
                instance_count += 1;
                let (decoded, decoded_len) = decode_aid(aid).map_err(|_| Error::Storage)?;
                if !insert_unique_registry_aid(
                    &mut registry_aids,
                    RegistryAid::new(&decoded[..decoded_len]).map_err(|_| Error::Storage)?,
                ) {
                    return Err(Error::Storage);
                }
                let p = d.package_metadata(assembly.as_ref())?;
                if !p.manifest.entry_points.iter().any(|a| &a.aid == aid) {
                    return Err(Error::Storage);
                }
            }
        }
        if state.isd.key.is_some() != state.isd.image_refs.contains_key("mscorlib")
            || (state.isd.key.is_none() && !state.isd.is_unbound_and_empty())
        {
            return Err(Error::Storage);
        }
        if total_bytes > MAX_TOTAL_PACKAGE_BYTES {
            return Err(Error::Storage);
        }
        for (id, assembly) in linked_roots {
            linking::BorrowedExecution::new(&state, journal.flash(), &mut platform, id, assembly)?
                .units()?;
        }
        #[cfg(feature = "scp03-pseudo-random")]
        let sequence = (state.scp03_sequence, state.scp03_sequence);
        Ok(Self {
            journal,
            state,
            platform,
            staging,
            uncommitted_images: Vec::new(),
            globalplatform_load: None,
            selected: None,
            transaction: None,
            #[cfg(feature = "scp03-pseudo-random")]
            sequence,
        })
    }

    /// Hand out the next SCP03 sequence counter value, SCP03 1.1.2.6 §6.2.2.1.
    ///
    /// A block of values is made durable before any of them is used, so a power cut loses
    /// the unused remainder rather than replaying a value that already seeded a challenge.
    #[cfg(feature = "scp03-pseudo-random")]
    pub(crate) fn next_secure_channel_sequence(&mut self) -> Result<u32> {
        if self.sequence.0 >= self.sequence.1 {
            if self.state.scp03_sequence > SEQUENCE_CEILING {
                return Err(Error::Unauthorized);
            }
            let reserved = self
                .state
                .scp03_sequence
                .saturating_add(SEQUENCE_WINDOW)
                .min(SEQUENCE_CEILING + 1);
            self.reserve_sequence_window(reserved)?;
            self.sequence.1 = reserved;
        }
        let issued = self.sequence.0;
        if issued > SEQUENCE_CEILING {
            return Err(Error::Unauthorized);
        }
        self.sequence.0 = issued + 1;
        Ok(issued)
    }
    #[cfg_attr(feature = "scp03-pseudo-random", allow(dead_code))]
    pub(crate) fn random(&mut self, b: &mut [u8]) -> Result<()> {
        self.platform.random(b)
    }
    pub(crate) fn crypto_provider(&mut self) -> &mut P {
        &mut self.platform
    }
    pub(crate) fn abort_staging(&mut self) {
        self.staging.reset();
        self.globalplatform_load = None;
    }
    pub(crate) fn abort_transaction(&mut self) {
        self.transaction = None;
    }
    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
}

#[cfg(test)]
mod tests;
