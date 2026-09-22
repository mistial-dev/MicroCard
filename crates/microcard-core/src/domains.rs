//! Persistent MC04 domain management and application lifecycle.
use crate::{
    Error, Result,
    journal::{Flash, Journal, JournalKey},
    package::{
        MAX_DECLARED_BLOB_BYTES, MAX_PACKAGE_BYTES, MAX_STORAGE_DECLARATIONS, Manifest, Package,
        PackageView, StorageDeclaration,
    },
    scp03::Verified,
    staging::{PackageStaging, RamStaging},
};
use alloc::{rc::Rc, string::String, vec::Vec};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub use crate::hal::RuntimePlatform as Platform;
mod snapshot;
mod engine;
mod application;
mod metadata;
mod lifecycle;
mod linking;
mod native;
mod execution;
mod management;
use execution::{InvocationInput, run_lifecycle};
#[cfg(test)]
use execution::run_context;
#[cfg(test)]
use native::{BufferResult, NativeArgument};
use linking::{CallTarget, ExecutionUnit, PackageData, ResolvedCall, ResolvedDependency,
    resolve_calls, resolve_dependency};
#[cfg(test)]
use linking::{validate_program_graph, push_execution_source, validate_linked_program, push_link_edge};
use application::{
    ApplicationChanges, ApplicationView, CredentialCheckpoint, JournalCredentialCheckpoint,
    StagedApplication,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct NameMap<V>(Vec<(Rc<str>, V)>);

impl<V> Default for NameMap<V> {
    fn default() -> Self { Self::new() }
}

impl<V> NameMap<V> {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn position(&self, name: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_ref().cmp(name))
    }

    fn reserve_entry(&mut self) -> Result<()> {
        if self.0.len() >= MAX_ASSEMBLIES_PER_DOMAIN as usize {
            return Err(Error::Quota);
        }
        if self.0.len() == self.0.capacity() {
            self.0
                .try_reserve_exact(1)
                .map_err(|_| Error::Quota)?;
        }
        Ok(())
    }

    fn reserve_for(&mut self, name: &str) -> Result<()> {
        if self.contains_key(name) {
            Ok(())
        } else {
            self.reserve_entry()
        }
    }

    fn insert(&mut self, name: Rc<str>, value: V) -> Result<()> {
        match self.position(name.as_ref()) {
            Ok(index) => {
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_ASSEMBLIES_PER_DOMAIN as usize {
                    return Err(Error::Quota);
                }
                self.reserve_entry()?;
                self.0.insert(index, (name, value));
                Ok(())
            }
        }
    }

    fn get(&self, name: &str) -> Option<&V> {
        self.position(name).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    fn get_mut(&mut self, name: &str) -> Option<&mut V> {
        self.position(name)
            .ok()
            .map(|index| &mut self.0[index].1)
    }

    fn get_key_value(&self, name: &str) -> Option<(&Rc<str>, &V)> {
        self.position(name)
            .ok()
            .map(|index| (&self.0[index].0, &self.0[index].1))
    }

    fn contains_key(&self, name: &str) -> bool {
        self.position(name).is_ok()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (Rc<str>, V)> {
        self.0.iter()
    }

    fn iter_mut(&mut self) -> core::slice::IterMut<'_, (Rc<str>, V)> {
        self.0.iter_mut()
    }

    fn keys(&self) -> impl Iterator<Item = &Rc<str>> {
        self.0.iter().map(|(name, _)| name)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl<V> core::ops::Index<&str> for NameMap<V> {
    type Output = V;

    fn index(&self, name: &str) -> &Self::Output {
        self.get(name).expect("missing assembly identity")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Domains(Vec<(String, Domain)>);

impl Domains {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn position(&self, id: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(id))
    }

    fn get(&self, id: &str) -> Option<&Domain> {
        self.position(id).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    fn get_mut(&mut self, id: &str) -> Option<&mut Domain> {
        self.position(id)
            .ok()
            .map(|index| &mut self.0[index].1)
    }

    fn get_key_value(&self, id: &str) -> Option<(&String, &Domain)> {
        self.position(id)
            .ok()
            .map(|index| (&self.0[index].0, &self.0[index].1))
    }

    fn contains_key(&self, id: &str) -> bool {
        self.position(id).is_ok()
    }

    fn insert(&mut self, id: String, domain: Domain) -> Result<Option<Domain>> {
        match self.position(&id) {
            Ok(index) => Ok(Some(core::mem::replace(&mut self.0[index].1, domain))),
            Err(index) => {
                if self.0.len() >= MAX_SSDS {
                    return Err(Error::Quota);
                }
                self.0.try_reserve_exact(1).map_err(|_| Error::Quota)?;
                self.0.insert(index, (id, domain));
                Ok(None)
            }
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (String, Domain)> {
        self.0.iter()
    }

    fn values(&self) -> impl Iterator<Item = &Domain> {
        self.0.iter().map(|(_, domain)| domain)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Domain> {
        self.0.iter_mut().map(|(_, domain)| domain)
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Domains {
    type Output = Domain;

    fn index(&self, id: &str) -> &Self::Output {
        self.get(id).expect("missing domain")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct IntStore(Vec<(i32, i32)>);

impl Drop for IntStore {
    fn drop(&mut self) {
        for value in self.values_mut() {
            value.zeroize();
        }
    }
}

impl IntStore {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self(context.clone_vec(&self.0)?))
    }

    fn position(&self, key: i32) -> core::result::Result<usize, usize> {
        self.0.binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    fn get(&self, key: &i32) -> Option<&i32> {
        self.position(*key).ok().map(|index| &self.0[index].1)
    }

    fn contains_key(&self, key: &i32) -> bool {
        self.position(*key).is_ok()
    }

    fn insert(&mut self, key: i32, value: i32) -> Result<()> {
        match self.position(key) {
            Ok(index) => {
                self.0[index].1.zeroize();
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_INT_RECORDS {
                    return Err(Error::Quota);
                }
                if self.0.len() == self.0.capacity() {
                    let additional = INT_STORE_GROWTH.min(MAX_INT_RECORDS - self.0.len());
                    self.0
                        .try_reserve_exact(additional)
                        .map_err(|_| Error::Quota)?;
                }
                self.0.insert(index, (key, value));
                Ok(())
            }
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (i32, i32)> {
        self.0.iter()
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut i32> {
        self.0.iter_mut().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl core::ops::Index<&i32> for IntStore {
    type Output = i32;

    fn index(&self, key: &i32) -> &Self::Output {
        self.get(key).expect("missing integer record")
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct BlobStore(Vec<(i32, Vec<u8>)>);

impl Drop for BlobStore {
    fn drop(&mut self) {
        for value in self.values_mut() {
            value.zeroize();
        }
    }
}

impl BlobStore {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut values = Self::new();
        context.reserve_exact(&mut values.0, self.0.len())?;
        for (key, value) in &self.0 {
            values.0.push((*key, context.clone_vec(value)?));
        }
        Ok(values)
    }

    fn position(&self, key: i32) -> core::result::Result<usize, usize> {
        self.0.binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    fn get(&self, key: &i32) -> Option<&Vec<u8>> {
        self.position(*key).ok().map(|index| &self.0[index].1)
    }

    fn contains_key(&self, key: &i32) -> bool {
        self.position(*key).is_ok()
    }

    fn insert(&mut self, key: i32, mut value: Vec<u8>) -> Result<()> {
        match self.position(key) {
            Ok(index) => {
                self.0[index].1.zeroize();
                self.0[index].1 = value;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_BLOB_RECORDS {
                    value.zeroize();
                    return Err(Error::Quota);
                }
                if self.0.len() == self.0.capacity() {
                    let additional = BLOB_STORE_GROWTH.min(MAX_BLOB_RECORDS - self.0.len());
                    if self.0.try_reserve_exact(additional).is_err() {
                        value.zeroize();
                        return Err(Error::Quota);
                    }
                }
                self.0.insert(index, (key, value));
                Ok(())
            }
        }
    }

    fn remove(&mut self, key: &i32) -> Option<Vec<u8>> {
        self.position(*key)
            .ok()
            .map(|index| self.0.remove(index).1)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (i32, Vec<u8>)> {
        self.0.iter()
    }

    fn values(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.iter().map(|(_, value)| value)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Vec<u8>> {
        self.0.iter_mut().map(|(_, value)| value)
    }
}

#[cfg(test)]
impl core::ops::Index<&i32> for BlobStore {
    type Output = Vec<u8>;

    fn index(&self, key: &i32) -> &Self::Output {
        self.get(key).expect("missing byte record")
    }
}

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
struct State {
    isd: Domain,
    domains: Domains,
    /// First SCP03 sequence counter value never yet handed out, SCP03 1.1.2.6 §6.2.2.1.
    ///
    /// Reserved ahead of use so a power cut can only skip values, never repeat one.

    scp03_sequence: u32,
}

/// Values reserved by one durable write, so a secure channel does not cost a flash write.
#[cfg(feature = "scp03-pseudo-random")]
const SEQUENCE_WINDOW: u32 = 64;

/// The counter travels in three bytes, so this is the last value it can express.
#[cfg(feature = "scp03-pseudo-random")]
const SEQUENCE_CEILING: u32 = 0x00ff_ffff;
impl State {
    fn domain(&self, id: &str) -> Option<&Domain> {
        if id == "ISD" {
            Some(&self.isd)
        } else {
            self.domains.get(id)
        }
    }
    #[cfg(test)]
    fn domain_mut(&mut self, id: &str) -> Option<&mut Domain> {
        if id == "ISD" {
            Some(&mut self.isd)
        } else {
            self.domains.get_mut(id)
        }
    }
    fn domain_entry(&self, id: &str) -> Option<(&str, &Domain)> {
        if id == "ISD" {
            Some(("ISD", &self.isd))
        } else {
            self.domains
                .get_key_value(id)
                .map(|(identifier, domain)| (identifier.as_str(), domain))
        }
    }
    fn is_owned(&self) -> bool {
        self.isd.key.is_some() && self.isd.image_refs.contains_key("mscorlib")
    }
    fn assembly_by_digest(&self, digest: &[u8; 32]) -> Result<(&str, &str, &Domain)> {
        let mut found = None;
        for (domain_id, domain) in core::iter::once(("ISD", &self.isd)).chain(
            self.domains
                .iter()
                .map(|(identifier, domain)| (identifier.as_str(), domain)),
        ) {
            for (assembly, (_, candidate)) in domain.versions.iter() {
                if candidate == digest && domain.packages.contains_key(assembly) {
                    if found.is_some() {
                        return Err(Error::Storage);
                    }
                    found = Some((domain_id, assembly.as_ref(), domain));
                }
            }
        }
        found.ok_or(Error::Missing)
    }
    fn provider_in_use(&self, provider_domain: &str, provider_assembly: &str) -> bool {
        let Some((_, digest)) = self
            .domain(provider_domain)
            .and_then(|domain| domain.versions.get(provider_assembly))
        else {
            return false;
        };
        core::iter::once(&self.isd)
            .chain(self.domains.values())
            .flat_map(|domain| domain.bindings.values())
            .flatten()
            .any(|binding| binding.digest == *digest)
    }

    fn registry_aid_in_use(&self, aid: RegistryAid) -> bool {
        self.registry_aid_reserved_by_non_assembly(aid)
            || core::iter::once(&self.isd)
                .chain(self.domains.values())
                .any(|domain| {
                    domain
                        .image_refs
                        .keys()
                        .filter_map(|assembly| domain.versions.get(assembly))
                        .any(|(_, digest)| RegistryAid::synthetic(0x4c, digest) == aid)
                })
    }

    fn registry_aid_reserved_by_non_assembly(&self, aid: RegistryAid) -> bool {
        self.isd.registry_aid == aid
            || self
                .domains
                .values()
                .any(|domain| domain.registry_aid == aid)
            || core::iter::once(&self.isd)
                .chain(self.domains.values())
                .any(|domain| {
                    domain.instances.keys().any(|text| {
                        decode_aid(text)
                            .ok()
                            .and_then(|(bytes, len)| RegistryAid::new(&bytes[..len]).ok())
                            == Some(aid)
                    })
                })
    }

    fn domain_identifier_by_registry_aid(&self, aid: RegistryAid) -> Option<&str> {
        if aid == RegistryAid::isd() {
            return Some("ISD");
        }
        self.domains
            .iter()
            .find(|(_, domain)| domain.registry_aid == aid)
            .map(|(identifier, _)| identifier.as_str())
    }
}

fn fallible_filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::Quota)?;
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

fn insert_unique_registry_aid(values: &mut Vec<RegistryAid>, value: RegistryAid) -> bool {
    if values.contains(&value) {
        return false;
    }
    values.push(value);
    true
}

#[derive(Clone, PartialEq, Eq)]

struct DomainPolicy {
    capabilities: Vec<u8>,
    max_assemblies: u8,
    max_instances: u8,
    max_int_records: u16,
    max_blob_records: u8,
    max_blob_bytes: u16,
    max_key_slots: u8,
    max_package_bytes: u16,
}
impl DomainPolicy {
    fn standard() -> Result<Self> {
        let mut capabilities = Vec::new();
        capabilities.try_reserve_exact(46).map_err(|_| Error::Quota)?;
        // 21 was the Ed25519 verification primitive, which the card no longer carries.
        capabilities.extend((2..=13).chain(core::iter::once(20)).chain(22..=54));
        Ok(Self {
            capabilities,
            max_assemblies: MAX_ASSEMBLIES_PER_DOMAIN,
            max_instances: MAX_INSTANCES_PER_DOMAIN,
            max_int_records: MAX_INT_RECORDS as u16,
            max_blob_records: MAX_BLOB_RECORDS as u8,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            max_package_bytes: 16384,
        })
    }
    fn valid(&self) -> bool {
        self.capabilities.windows(2).all(|pair| pair[0] < pair[1])
            && self
                .capabilities
                .iter()
                .all(|id| crate::native_abi::signature(*id).is_ok())
            && (1..=MAX_ASSEMBLIES_PER_DOMAIN).contains(&self.max_assemblies)
            && (1..=MAX_INSTANCES_PER_DOMAIN).contains(&self.max_instances)
            && (1..=MAX_INT_RECORDS as u16).contains(&self.max_int_records)
            && (1..=MAX_BLOB_RECORDS as u8).contains(&self.max_blob_records)
            && (1..=8192).contains(&self.max_blob_bytes)
            && (1..=8).contains(&self.max_key_slots)
            && (108..=16384).contains(&self.max_package_bytes)
    }
    fn wire(&self) -> Result<Vec<u8>> {
        let capabilities = self
            .capabilities
            .iter()
            .fold(0u64, |bits, id| bits | (1u64 << id));
        let mut out = Vec::new();
        out.try_reserve_exact(19).map_err(|_| Error::Quota)?;
        out.push(1);
        out.extend(capabilities.to_le_bytes());
        out.extend([self.max_assemblies, self.max_instances]);
        out.extend(self.max_int_records.to_le_bytes());
        out.push(self.max_blob_records);
        out.extend(self.max_blob_bytes.to_le_bytes());
        out.push(self.max_key_slots);
        out.extend(self.max_package_bytes.to_le_bytes());
        Ok(out)
    }
    fn request(data: &[u8]) -> Result<(String, Self)> {
        if data.len() < 20 || data[0] != 1 {
            return Err(Error::Format);
        }
        let name_len = data[1] as usize;
        if name_len == 0 || name_len > 64 || data.len() != 20 + name_len {
            return Err(Error::Format);
        }
        let identifier = core::str::from_utf8(&data[2..2 + name_len])
            .map_err(|_| Error::Format)?;
        if !crate::package::valid_identifier(identifier) {
            return Err(Error::Format);
        }
        let p = &data[2 + name_len..];
        let bits = u64::from_le_bytes(p[..8].try_into().unwrap());
        let identifier = fallible_string(identifier)?;
        let mut capabilities = Vec::new();
        capabilities
            .try_reserve_exact(bits.count_ones() as usize)
            .map_err(|_| Error::Quota)?;
        capabilities.extend(
            (0..64)
                .filter(|id| bits & (1u64 << id) != 0)
                .map(|id| id as u8),
        );
        let policy = Self {
            capabilities,
            max_assemblies: p[8],
            max_instances: p[9],
            max_int_records: u16::from_le_bytes(p[10..12].try_into().unwrap()),
            max_blob_records: p[12],
            max_blob_bytes: u16::from_le_bytes(p[13..15].try_into().unwrap()),
            max_key_slots: p[15],
            max_package_bytes: u16::from_le_bytes(p[16..18].try_into().unwrap()),
        };
        if !policy.valid() {
            return Err(Error::Format);
        }
        Ok((identifier, policy))
    }
}
use crate::globalplatform::Aid as RegistryAid;

#[derive(Clone, PartialEq, Eq)]
struct Instances(Vec<(String, Rc<str>)>);

impl Instances {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut instances = Vec::new();
        context.reserve_exact(&mut instances, self.0.len())?;
        for (aid, assembly) in &self.0 {
            instances.push((context.clone_string(aid)?, Rc::clone(assembly)));
        }
        Ok(Self(instances))
    }

    fn position(&self, aid: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(aid))
    }

    fn reserve_entry(&mut self) -> Result<()> {
        if self.0.len() >= MAX_INSTANCES_PER_DOMAIN as usize {
            return Err(Error::Quota);
        }
        if self.0.len() == self.0.capacity() {
            self.0
                .try_reserve_exact(1)
                .map_err(|_| Error::Quota)?;
        }
        Ok(())
    }

    fn insert(&mut self, aid: String, assembly: Rc<str>) -> Result<()> {
        match self.position(&aid) {
            Ok(_) => Err(Error::Busy),
            Err(index) => {
                if self.0.len() >= MAX_INSTANCES_PER_DOMAIN as usize {
                    return Err(Error::Quota);
                }
                self.reserve_entry()?;
                self.0.insert(index, (aid, assembly));
                Ok(())
            }
        }
    }

    fn get(&self, aid: &str) -> Option<&Rc<str>> {
        self.position(aid).ok().map(|index| &self.0[index].1)
    }

    #[cfg(test)]
    fn get_mut(&mut self, aid: &str) -> Option<&mut Rc<str>> {
        self.position(aid)
            .ok()
            .map(|index| &mut self.0[index].1)
    }

    fn contains_key(&self, aid: &str) -> bool {
        self.position(aid).is_ok()
    }

    fn remove(&mut self, aid: &str) -> Option<Rc<str>> {
        self.position(aid)
            .ok()
            .map(|index| self.0.remove(index).1)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (String, Rc<str>)> {
        self.0.iter()
    }

    fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(aid, _)| aid)
    }

    fn values(&self) -> impl Iterator<Item = &Rc<str>> {
        self.0.iter().map(|(_, assembly)| assembly)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut Rc<str>> {
        self.0.iter_mut().map(|(_, assembly)| assembly)
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Instances {
    type Output = Rc<str>;

    fn index(&self, aid: &str) -> &Self::Output {
        self.get(aid).expect("missing installed instance")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct StoredPackage {
    manifest: Manifest,
    image: core::ops::Range<usize>,
    signer: [u8; 32],
    digest: [u8; 32],
}

impl StoredPackage {
    fn view<'a>(&'a self, raw: &'a [u8]) -> Result<StoredPackageView<'a>> {
        Ok(StoredPackageView {
            #[cfg(test)]
            raw,
            manifest: &self.manifest,
            image: raw.get(self.image.clone()).ok_or(Error::Storage)?,
            signer: self.signer,
            digest: self.digest,
        })
    }

    fn from_verified(package: PackageView<'_>) -> Self {
        let start = package.image.as_ptr() as usize - package.raw.as_ptr() as usize;
        Self {
            image: start..start + package.image.len(),
            manifest: package.manifest,
            signer: package.signer,
            digest: package.digest,
        }
    }
}

struct StoredPackageView<'a> {
    #[cfg(test)]
    raw: &'a [u8],
    manifest: &'a Manifest,
    image: &'a [u8],
    signer: [u8; 32],
    digest: [u8; 32],
}

#[cfg(test)]
impl<'a> From<&'a PackageView<'a>> for StoredPackageView<'a> {
    fn from(package: &'a PackageView<'a>) -> Self {
        Self { raw: package.raw, manifest: &package.manifest, image: package.image,
            signer: package.signer, digest: package.digest }
    }
}

impl PackageData for StoredPackageView<'_> {
    fn manifest(&self) -> &Manifest { self.manifest }
    fn image(&self) -> &[u8] { self.image }
    fn digest(&self) -> [u8; 32] { self.digest }
    fn key(&self) -> [u8; 32] { self.signer }
}

#[derive(Clone, PartialEq, Eq)]

struct Domain {
    incarnation: [u8; 16],
    registry_aid: RegistryAid,
    key: Option<[u8; 32]>,

    packages: NameMap<Rc<StoredPackage>>,
    image_refs: NameMap<crate::image_store::Descriptor>,
    bindings: NameMap<Vec<ResolvedDependency>>,
    imports: NameMap<Vec<ResolvedCall>>,
    versions: NameMap<(u32, [u8; 32])>,

    storage_schema: Rc<Vec<StorageDeclaration>>,
    instances: Instances,
    store: IntStore,

    blobs: BlobStore,

    keys: crate::key_store::KeyStore,

    credentials: crate::credential_store::CredentialStore,
    policy: DomainPolicy,
}
impl Drop for Domain {
    fn drop(&mut self) {
        self.zeroize_application_state();
    }
}
impl Domain {
    fn package_metadata(&self, name: &str) -> Result<&StoredPackage> {
        self.packages.get(name).map(Rc::as_ref).ok_or(Error::Missing)
    }

    fn new(incarnation: [u8; 16], registry_aid: RegistryAid, policy: DomainPolicy) -> Self {
        Self {
            incarnation,
            registry_aid,
            key: None,
            packages: NameMap::new(),
            image_refs: NameMap::new(),
            bindings: NameMap::new(),
            imports: NameMap::new(),
            versions: NameMap::new(),
            storage_schema: Rc::new(Vec::new()),
            instances: Instances::new(),
            store: IntStore::new(),
            blobs: BlobStore::new(),
            keys: crate::key_store::KeyStore::default(),
            credentials: crate::credential_store::CredentialStore::default(),
            policy,
        }
    }

    fn zeroize_application_state(&mut self) {
        for value in self.store.values_mut() {
            value.zeroize();
        }
        for value in self.blobs.values_mut() {
            value.zeroize();
        }
    }

    fn intern_assembly_names(&mut self) -> Result<()> {
        fn rekey<T>(
            assemblies: &NameMap<crate::image_store::Descriptor>,
            values: &mut NameMap<T>,
            require_active: bool,
        ) -> Result<()> {
            for (name, _) in values.iter_mut() {
                if let Some((canonical, _)) = assemblies.get_key_value(name.as_ref()) {
                    *name = Rc::clone(canonical);
                } else if require_active {
                    return Err(Error::Storage);
                }
            }
            Ok(())
        }

        rekey(&self.image_refs, &mut self.versions, false)?;
        rekey(&self.image_refs, &mut self.bindings, true)?;
        rekey(&self.image_refs, &mut self.imports, true)?;
        for assembly in self.instances.values_mut() {
            let (canonical, _) = self
                .image_refs
                .get_key_value(assembly.as_ref())
                .ok_or(Error::Storage)?;
            *assembly = Rc::clone(canonical);
        }
        Ok(())
    }
    fn storage_declaration(&self, key: i32) -> Option<&StorageDeclaration> {
        self.storage_schema
            .binary_search_by_key(&key, |declaration| declaration.key)
            .ok()
            .map(|index| &self.storage_schema[index])
    }

    fn merged_storage_schema(&self, declarations: &[StorageDeclaration]) -> Result<Rc<Vec<StorageDeclaration>>> {
        for declaration in declarations {
            if self
                .storage_declaration(declaration.key)
                .is_some_and(|existing| existing != declaration)
            {
                return Err(Error::KeyMismatch);
            }
        }
        let additional = declarations
            .iter()
            .filter(|declaration| self.storage_declaration(declaration.key).is_none())
            .count();
        if self.storage_schema.len() + additional > MAX_DOMAIN_STORAGE_DECLARATIONS {
            return Err(Error::Quota);
        }
        if additional == 0 {
            return Ok(Rc::clone(&self.storage_schema));
        }
        let mut merged = Vec::new();
        merged
            .try_reserve_exact(self.storage_schema.len() + additional)
            .map_err(|_| Error::Quota)?;
        merged.extend_from_slice(&self.storage_schema);
        for declaration in declarations {
            if let Err(index) = merged.binary_search_by_key(&declaration.key, |existing| existing.key)
            {
                merged.insert(index, *declaration);
            }
        }
        Ok(Rc::new(merged))
    }

    fn is_unbound_and_empty(&self) -> bool {
        self.key.is_none()
            && self.image_refs.is_empty()
            && self.bindings.is_empty()
            && self.imports.is_empty()
            && self.versions.is_empty()
            && self.storage_schema.is_empty()
            && self.instances.is_empty()
            && self.store.is_empty()
            && self.blobs.is_empty()
            && self.keys.is_empty()
            && self.credentials.is_empty()
    }
}

enum RegistryEntry<'a> {
    Isd {
        owned: bool,
    },
    Ssd {
        domain: &'a Domain,
    },
    Instance {
        domain_id: &'a str,
        domain: &'a Domain,
        assembly: &'a str,
    },
    Load {
        domain_id: &'a str,
        domain: &'a Domain,
        assembly: &'a str,
    },
}

fn visit_registry<'a>(
    state: &'a State,
    p1: u8,
    mut visit: impl FnMut(&[u8], RegistryEntry<'a>) -> Result<()>,
) -> Result<()> {
    match p1 {
        0x80 => visit(
            &crate::globalplatform::ISD_AID,
            RegistryEntry::Isd {
                owned: state.is_owned(),
            },
        ),
        0x40 => {
            for domain in state.domains.values() {
                visit(
                    domain.registry_aid.as_slice(),
                    RegistryEntry::Ssd { domain },
                )?;
            }
            for (domain_id, domain) in core::iter::once(("ISD", &state.isd)).chain(
                state
                    .domains
                    .iter()
                    .map(|(id, domain)| (id.as_str(), domain)),
            ) {
                for (aid_text, assembly) in domain.instances.iter() {
                    let (aid, aid_len) = decode_aid(aid_text)?;
                    visit(
                        &aid[..aid_len],
                        RegistryEntry::Instance {
                            domain_id,
                            domain,
                            assembly,
                        },
                    )?;
                }
            }
            Ok(())
        }
        0x20 | 0x10 => {
            for (domain_id, domain) in core::iter::once(("ISD", &state.isd)).chain(
                state
                    .domains
                    .iter()
                    .map(|(id, domain)| (id.as_str(), domain)),
            ) {
                for assembly in domain.image_refs.keys() {
                    let digest = domain.versions.get(assembly).ok_or(Error::Storage)?.1;
                    let aid = crate::globalplatform::synthetic_aid(0x4c, &digest);
                    visit(
                        &aid,
                        RegistryEntry::Load {
                            domain_id,
                            domain,
                            assembly,
                        },
                    )?;
                }
            }
            Ok(())
        }
        _ => Err(Error::Format),
    }
}

fn registry_record(p1: u8, aid: &[u8], entry: RegistryEntry<'_>) -> Result<Vec<u8>> {
    use crate::globalplatform::{ISD_AID, push_tlv, synthetic_aid, template};
    let mut body = Vec::new();
    push_tlv(&mut body, &[0x4f], aid)?;
    match entry {
        RegistryEntry::Isd { owned } => {
            // GP 2.3.1 Tables 11-6 and 11-7: OP_READY/SECURED and SD privilege.
            push_tlv(&mut body, &[0x9f, 0x70], &[if owned { 0x0f } else { 0x01 }])?;
            push_tlv(&mut body, &[0xc5], &[0x80, 0x00, 0x00])?;
        }
        RegistryEntry::Ssd { domain } => {
            // A pinned SSD is represented as PERSONALIZED; an empty SSD is SELECTABLE.
            push_tlv(
                &mut body,
                &[0x9f, 0x70],
                &[if domain.key.is_some() { 0x0f } else { 0x07 }],
            )?;
            push_tlv(&mut body, &[0xc5], &[0x80, 0x00, 0x00])?;
            push_tlv(&mut body, &[0xcc], &ISD_AID)?;
        }
        RegistryEntry::Instance {
            domain_id,
            domain,
            assembly,
        } => {
            let digest = domain.versions.get(assembly).ok_or(Error::Storage)?.1;
            let load_aid = synthetic_aid(0x4c, &digest);
            let (domain_aid, domain_aid_len) = registry_domain_aid(domain_id, domain);
            push_tlv(&mut body, &[0x9f, 0x70], &[0x07])?;
            push_tlv(&mut body, &[0xc5], &[0x00, 0x00, 0x00])?;
            push_tlv(&mut body, &[0xc4], &load_aid)?;
            push_tlv(&mut body, &[0xcc], &domain_aid[..domain_aid_len])?;
        }
        RegistryEntry::Load {
            domain_id,
            domain,
            assembly,
        } => {
            let package = domain.package_metadata(assembly)?;
            if package.manifest.assembly != assembly {
                return Err(Error::Storage);
            }
            push_tlv(&mut body, &[0x9f, 0x70], &[0x01])?;
            let mut version = [0; 8];
            for (index, component) in package.manifest.assembly_version.iter().enumerate() {
                version[index * 2..index * 2 + 2].copy_from_slice(&component.to_be_bytes());
            }
            push_tlv(&mut body, &[0xce], &version)?;
            if p1 == 0x10 {
                for module in &package.manifest.entry_points {
                    let (module_aid, module_len) = decode_aid(&module.aid)?;
                    push_tlv(&mut body, &[0x84], &module_aid[..module_len])?;
                }
            }
            let (domain_aid, domain_aid_len) = registry_domain_aid(domain_id, domain);
            push_tlv(&mut body, &[0xcc], &domain_aid[..domain_aid_len])?;
        }
    }
    template(body)
}

fn registry_domain_aid(domain_id: &str, domain: &Domain) -> ([u8; 16], usize) {
    if domain_id == "ISD" {
        let mut aid = [0; 16];
        aid[..crate::globalplatform::ISD_AID.len()]
            .copy_from_slice(&crate::globalplatform::ISD_AID);
        (aid, crate::globalplatform::ISD_AID.len())
    } else {
        (
            domain.registry_aid.padded(),
            domain.registry_aid.as_slice().len(),
        )
    }
}

fn decode_aid(text: &str) -> Result<([u8; 16], usize)> {
    if !(10..=32).contains(&text.len()) || !text.len().is_multiple_of(2) {
        return Err(Error::Format);
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut aid = [0; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        aid[index] = nibble(pair[0])
            .zip(nibble(pair[1]))
            .map(|(high, low)| high << 4 | low)
            .ok_or(Error::Format)?;
    }
    Ok((aid, text.len() / 2))
}

fn management_names(data: &[u8]) -> Result<(&str, &str)> {
    let mut decoder = crate::cbor::Decoder::new(data);
    decoder.record(3)?;
    if decoder.unsigned()? != 1 { return Err(Error::Format); }
    let first = decoder.text(64)?;
    let second = decoder.text(64)?;
    if !crate::package::valid_identifier(first) || !crate::package::valid_identifier(second) {
        return Err(Error::Format);
    }
    decoder.finish()?;
    Ok((first, second))
}

fn management_names_wire(first: &str, second: &str) -> Result<Vec<u8>> {
    if !crate::package::valid_identifier(first) || !crate::package::valid_identifier(second) {
        return Err(Error::Format);
    }
    let mut encoder = crate::cbor::Encoder::new(134);
    encoder.array(3)?;
    encoder.unsigned(1)?;
    encoder.text(first)?;
    encoder.text(second)?;
    Ok(encoder.finish())
}

pub(crate) fn encode_aid(value: &[u8]) -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let capacity = value.len().checked_mul(2).ok_or(Error::Quota)?;
    let mut text = String::new();
    text.try_reserve_exact(capacity)
        .map_err(|_| Error::Quota)?;
    for byte in value {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(text)
}

struct GlobalPlatformLoad {
    domain_aid: RegistryAid,
    /// The load file AID the host declared. It is checked against the digest of what
    /// actually arrived, at the end of the load rather than when it was declared, because
    /// only the received bytes can settle it.
    load_aid: RegistryAid,
    hash: Option<[u8; 32]>,
    receiver: crate::globalplatform::LoadReceiver,
}

pub struct Mc04Engine<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging = RamStaging> {
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

struct PendingTransaction {
    owner: (RegistryAid, [u8; 16], String),
    state: StagedApplication,
    commands_left: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionDisposition {
    Inactive,
    Active,
    Begun,
    Commit,
    Abort,
}

impl TransactionDisposition {
    fn begin(&mut self) -> Result<()> {
        if *self != Self::Inactive {
            return Err(Error::Busy);
        }
        *self = Self::Begun;
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        if !matches!(*self, Self::Active | Self::Begun) {
            return Err(Error::Missing);
        }
        *self = Self::Commit;
        Ok(())
    }

    fn abort(&mut self) -> Result<()> {
        if !matches!(*self, Self::Active | Self::Begun) {
            return Err(Error::Missing);
        }
        *self = Self::Abort;
        Ok(())
    }

    fn transaction_involved(self) -> bool {
        self != Self::Inactive
    }
}
impl<F: Flash + crate::image_store::ImageFlash, P: Platform> Mc04Engine<F, P, RamStaging> {
    pub fn open(flash: F, platform: P, storage_key: impl Into<JournalKey>) -> Result<Self> {
        Self::open_with_staging(flash, platform, storage_key, RamStaging::default())
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Mc04Engine<F, P, S> {
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
                let encoded =
                    state.encode_snapshot()?;
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
                domain.packages.insert(Rc::clone(name), Rc::new(StoredPackage::from_verified(verified)))?;
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
                    || imports != &resolve_calls(&state, &p, bindings, journal.flash(), &mut platform)?
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
                )
                {
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
            linking::BorrowedExecution::new(&state, journal.flash(), &mut platform, id, assembly)?.units()?;
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

#[derive(Default)]
struct CredentialAuthorizations {
    slots: [Option<i32>; crate::credential_store::MAX_SLOTS],
}

impl CredentialAuthorizations {
    fn contains(&self, slot: i32) -> bool {
        self.slots.contains(&Some(slot))
    }

    fn insert(&mut self, slot: i32) -> Result<()> {
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

    fn remove(&mut self, slot: i32) {
        if let Some(existing) = self.slots.iter_mut().find(|candidate| **candidate == Some(slot)) {
            *existing = None;
        }
    }
}

#[derive(Default)]
struct CredentialRetryFloors {
    entries: [Option<(i32, (u8, u8))>; crate::credential_store::MAX_SLOTS],
}

impl CredentialRetryFloors {
    fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    fn record(&mut self, slot: i32, remaining: (u8, u8)) -> Result<()> {
        if let Some((_, floor)) = self.entries.iter_mut().flatten().find(|entry| entry.0 == slot) {
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

    fn iter(&self) -> impl Iterator<Item = (i32, (u8, u8))> + '_ {
        self.entries.iter().flatten().copied()
    }
}

struct Host<'a, 'checkpoint, P: Platform> {
    store: &'a mut IntStore,
    blobs: &'a mut BlobStore,
    keys: &'a mut crate::key_store::KeyStore,
    credentials: &'a mut crate::credential_store::CredentialStore,
    authorized_credentials: CredentialAuthorizations,
    credential_retry_floor: CredentialRetryFloors,
    credential_checkpoint: Option<&'checkpoint mut dyn CredentialCheckpoint<P>>,
    owner: [u8; 16],
    data: &'a [u8],
    out: Vec<u8>,
    sw: u16,
    platform: &'a mut P,
    budget: usize,
    capabilities: &'a [u8],
    domain_schema: &'a [StorageDeclaration],
    max_int_records: usize,
    max_blob_records: usize,
    max_blob_bytes: usize,
    max_key_slots: usize,
    level: u8,
    units: Option<&'a [ExecutionUnit<'a>]>,
    transaction: &'a mut TransactionDisposition,
    transaction_snapshot: &'a mut Option<StagedApplication>,
    persistent_dirty: &'a mut bool,
    #[cfg(test)]
    transaction_snapshots: &'a mut usize,
    #[cfg(test)]
    transaction_clone_allocations: &'a mut usize,
    irreversible_output: bool,
}

#[cfg(test)]
mod tests;
