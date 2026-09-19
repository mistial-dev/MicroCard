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

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
        mut clone_value: impl FnMut(
            &mut crate::fallible_clone::CloneContext,
            &V,
        ) -> Result<V>,
    ) -> Result<Self> {
        let mut values = Vec::new();
        context.reserve_exact(&mut values, self.0.len())?;
        for (name, value) in &self.0 {
            values.push((Rc::clone(name), clone_value(context, value)?));
        }
        Ok(Self(values))
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

    fn remove(&mut self, name: &str) -> Option<V> {
        self.position(name)
            .ok()
            .map(|index| self.0.remove(index).1)
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

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut domains = Vec::new();
        context.reserve_exact(&mut domains, self.0.len())?;
        for (identifier, domain) in &self.0 {
            domains.push((
                context.clone_string(identifier)?,
                domain.try_clone_with(context)?,
            ));
        }
        Ok(Self(domains))
    }

    fn position(&self, id: &str) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(id))
    }

    fn get(&self, id: &str) -> Option<&Domain> {
        self.position(id).ok().map(|index| &self.0[index].1)
    }

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

    fn remove(&mut self, id: &str) -> Option<Domain> {
        self.position(id)
            .ok()
            .map(|index| self.0.remove(index).1)
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
        let mut values = Vec::new();
        context.reserve_exact(&mut values, self.0.len())?;
        for (key, value) in &self.0 {
            values.push((*key, context.clone_vec(value)?));
        }
        Ok(Self(values))
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
    fn try_clone(&self) -> Result<Self> {
        self.try_clone_with(&mut crate::fallible_clone::CloneContext::new())
    }

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self {
            isd: self.isd.try_clone_with(context)?,
            domains: self.domains.try_clone_with(context)?,
            scp03_sequence: self.scp03_sequence,
        })
    }

    fn domain(&self, id: &str) -> Option<&Domain> {
        if id == "ISD" {
            Some(&self.isd)
        } else {
            self.domains.get(id)
        }
    }
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
        self.isd.key.is_some() && self.isd.assemblies.contains_key("mscorlib")
    }
    fn assembly_by_digest(&self, digest: &[u8; 32]) -> Result<(&str, &str, &Domain)> {
        let mut found = None;
        for (domain_id, domain) in core::iter::once(("ISD", &self.isd)).chain(
            self.domains
                .iter()
                .map(|(identifier, domain)| (identifier.as_str(), domain)),
        ) {
            for (assembly, (_, candidate)) in domain.versions.iter() {
                if candidate == digest && domain.assemblies.contains_key(assembly) {
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
                        .assemblies
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

#[derive(Clone, Debug, PartialEq, Eq)]

struct ResolvedDependency {

    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]

struct ResolvedCall {
    member: u16,
    target: CallTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]

enum CallTarget {
    ObjectConstructor,
    CurrentDomain,
    DomainStorage,
    DomainKeys,
    Native(u8),
    Managed {
        dependency: u8,
        method: u16,
    },
}

fn resolve_calls(
    state: &State,
    package: &impl PackageData,
    bindings: &[ResolvedDependency],
) -> Result<Vec<ResolvedCall>> {
    if !package.image().starts_with(b"MC04") {
        return Ok(Vec::new());
    }
    let consumer = crate::assembly::Assembly::parse(package.image())?;
    let uses = consumer.member_ref_uses()?;
    let mut calls = Vec::new();
    calls
        .try_reserve_exact(uses.len())
        .map_err(|_| Error::Quota)?;
    for (member_index, opcode) in uses {
        let target = if let Some(import) = crate::mc04_imports::resolve(&consumer, member_index)? {
            match import {
                crate::mc04_imports::Import::ObjectConstructor => CallTarget::ObjectConstructor,
                crate::mc04_imports::Import::CurrentDomain => CallTarget::CurrentDomain,
                crate::mc04_imports::Import::DomainStorage => CallTarget::DomainStorage,
                crate::mc04_imports::Import::DomainKeys => CallTarget::DomainKeys,
                crate::mc04_imports::Import::Native(id) => CallTarget::Native(id),
            }
        } else {
            if opcode == 0x0073 {
                return Err(Error::Unsupported);
            }
            let member = consumer.member_ref(member_index)?;
            if member.parent.table != 1 {
                return Err(Error::Unsupported);
            }
            let owner = consumer.type_ref(member.parent.row)?;
            if owner.scope.table != 35 {
                return Err(Error::Unsupported);
            }
            let reference = consumer.assembly_ref(owner.scope.row)?;
            let mut binding = None;
            for (index, candidate) in bindings.iter().enumerate() {
                let (_, assembly, _) = state.assembly_by_digest(&candidate.digest)?;
                if assembly == reference.name && binding.replace((index, candidate)).is_some() {
                    return Err(Error::Format);
                }
            }
            let (dependency, binding) = binding.ok_or(Error::Missing)?;
            let (_, provider_name, provider) =
                state.assembly_by_digest(&binding.digest)?;
            let provider = provider.package(provider_name)?;
            if provider.digest != binding.digest
                || reference.name != provider.manifest.assembly
                || reference.version != provider.manifest.assembly_version
                || reference.flags != 0
                || !reference.public_key_or_token.is_empty()
                || !reference.culture.is_empty()
                || !reference.hash_value.is_empty()
                || !provider.image.starts_with(b"MC04")
            {
                return Err(Error::Unauthorized);
            }
            let provider_assembly = crate::assembly::Assembly::parse(provider.image)?;
            let method = provider_assembly.find_method_for(
                owner.namespace,
                owner.name,
                member.name,
                &consumer,
                member_index,
            )?;
            CallTarget::Managed {
                dependency: u8::try_from(dependency).map_err(|_| Error::Quota)?,
                method,
            }
        };
        calls.push(ResolvedCall {
            member: member_index,
            target,
        });
    }
    Ok(calls)
}

struct ExecutionUnit<'a> {
    package: StoredPackageView<'a>,
    bindings: &'a [ResolvedDependency],
    calls: &'a [ResolvedCall],
}

fn push_execution_unit<'a>(
    state: &'a State,
    units: &mut Vec<ExecutionUnit<'a>>,
    domain: &'a str,
    assembly: &'a str,
    expected_digest: Option<[u8; 32]>,
) -> Result<()> {
    if let Some(existing) = units
        .iter()
        .find(|unit| {
            unit.package.manifest.domain == domain && unit.package.manifest.assembly == assembly
        })
    {
        if expected_digest.is_some_and(|expected| expected != existing.package.digest) {
            return Err(Error::Storage);
        }
        return Ok(());
    }
    if units.len() >= MAX_EXECUTION_UNITS {
        return Err(Error::Quota);
    }
    let source = state.domain(domain).ok_or(Error::Domain)?;
    let package = source.package(assembly)?;
    if expected_digest.is_some_and(|digest| digest != package.digest) {
        return Err(Error::Unauthorized);
    }
    units.push(ExecutionUnit {
        package,
        bindings: source.bindings.get(assembly).ok_or(Error::Storage)?,
        calls: source.imports.get(assembly).ok_or(Error::Storage)?,
    });
    Ok(())
}

fn execution_units<'a>(
    state: &'a State,
    domain: &str,
    assembly: &str,
) -> Result<Vec<ExecutionUnit<'a>>> {
    let (domain, source) = state.domain_entry(domain).ok_or(Error::Domain)?;
    let (assembly, _) = source
        .assemblies
        .get_key_value(assembly)
        .ok_or(Error::Missing)?;
    let mut units = Vec::<ExecutionUnit>::new();
    units
        .try_reserve_exact(MAX_EXECUTION_UNITS)
        .map_err(|_| Error::Quota)?;
    push_execution_unit(state, &mut units, domain, assembly.as_ref(), None)?;
    let mut cursor = 0usize;
    while cursor < units.len() {
        for call_index in 0..units[cursor].calls.len() {
            let call = &units[cursor].calls[call_index];
            if let CallTarget::Managed { dependency, .. } = &call.target {
                let digest = units[cursor]
                    .bindings
                    .get(usize::from(*dependency))
                    .ok_or(Error::Storage)?
                    .digest;
                let (domain, assembly, _) = state.assembly_by_digest(&digest)?;
                push_execution_unit(state, &mut units, domain, assembly, Some(digest))?;
            }
        }
        cursor += 1;
    }
    validate_linked_program(&units)?;
    Ok(units)
}

fn validate_program_graph(
    node_count: usize,
    edges: &[(usize, usize)],
    irreversible: &[bool],
    transactional: &[bool],
) -> Result<()> {
    if irreversible.len() != node_count || transactional.len() != node_count {
        return Err(Error::Bounds);
    }
    fn visit(
        node: usize,
        node_count: usize,
        edges: &[(usize, usize)],
        irreversible: &[bool],
        states: &mut [u8],
        depths: &mut [u8],
        effects: &mut [bool],
    ) -> Result<(u8, bool)> {
        match *states.get(node).ok_or(Error::Bounds)? {
            1 => return Err(Error::Quota),
            2 => {
                return Ok((
                    depths.get(node).copied().ok_or(Error::Bounds)?,
                    effects.get(node).copied().ok_or(Error::Bounds)?,
                ));
            }
            _ => {}
        }
        states[node] = 1;
        let mut depth = 1u8;
        let mut effect = *irreversible.get(node).ok_or(Error::Bounds)?;
        for target in edges
            .iter()
            .filter_map(|&(source, target)| (source == node).then_some(target))
        {
            if target >= node_count {
                return Err(Error::Bounds);
            }
            let (target_depth, target_effect) = visit(
                target,
                node_count,
                edges,
                irreversible,
                states,
                depths,
                effects,
            )?;
            depth = depth.max(target_depth.checked_add(1).ok_or(Error::Quota)?);
            effect |= target_effect;
            if depth > 32 {
                return Err(Error::Quota);
            }
        }
        states[node] = 2;
        depths[node] = depth;
        effects[node] = effect;
        Ok((depth, effect))
    }

    let mut states = fallible_filled(node_count, 0u8)?;
    let mut depths = fallible_filled(node_count, 0u8)?;
    let mut effects = fallible_filled(node_count, false)?;
    for node in 0..node_count {
        visit(
            node,
            node_count,
            edges,
            irreversible,
            &mut states,
            &mut depths,
            &mut effects,
        )?;
    }
    if transactional
        .iter()
        .zip(effects)
        .any(|(&root, effect)| root && effect)
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

fn push_link_edge(edges: &mut Vec<(usize, usize)>, edge: (usize, usize)) -> Result<()> {
    if edges.len() >= MAX_LINKED_CALL_EDGES {
        return Err(Error::Quota);
    }
    edges.try_reserve(1).map_err(|_| Error::Quota)?;
    edges.push(edge);
    Ok(())
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

fn validate_linked_program(units: &[ExecutionUnit<'_>]) -> Result<()> {
    if units.len() > MAX_EXECUTION_UNITS {
        return Err(Error::Quota);
    }
    let mut assemblies = Vec::new();
    assemblies
        .try_reserve_exact(units.len())
        .map_err(|_| Error::Quota)?;
    for unit in units {
        assemblies.push(crate::assembly::Assembly::parse(unit.package.image)?);
    }
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(assemblies.len() + 1)
        .map_err(|_| Error::Quota)?;
    offsets.push(0usize);
    for assembly in &assemblies {
        let next = offsets
            .last()
            .copied()
            .unwrap()
            .checked_add(usize::from(
                assembly.row_count(crate::mc04_schema::TABLE_METHODDEF)?,
            ))
            .ok_or(Error::Quota)?;
        if next > MAX_LINKED_METHODS {
            return Err(Error::Quota);
        }
        offsets.push(next);
    }
    let node_count = *offsets.last().unwrap_or(&0);
    let mut edges = Vec::new();
    let mut irreversible = fallible_filled(node_count, false)?;
    let mut transactional = fallible_filled(node_count, false)?;
    for (unit_index, (unit, assembly)) in units.iter().zip(&assemblies).enumerate() {
        let method_count = assembly.row_count(crate::mc04_schema::TABLE_METHODDEF)?;
        for method in 0..method_count {
            let source = offsets[unit_index] + usize::from(method);
            transactional[source] = assembly.method(method)?.body_flags & 1 != 0;
            for token in assembly.method_calls(method)? {
                let (target_unit, target_method) =
                    if token.table == crate::mc04_schema::TABLE_METHODDEF {
                        (unit_index, token.row.checked_sub(1).ok_or(Error::Bounds)?)
                    } else if token.table == crate::mc04_schema::TABLE_MEMBERREF {
                        let binding = unit
                            .calls
                            .iter()
                            .find(|binding| binding.member == token.row)
                            .ok_or(Error::Storage)?;
                        let (dependency, method) = match &binding.target {
                            CallTarget::Native(6) => {
                                irreversible[source] = true;
                                continue;
                            }
                            CallTarget::Managed { dependency, method } => (dependency, method),
                            _ => continue,
                        };
                        let digest = unit
                            .bindings
                            .get(usize::from(*dependency))
                            .ok_or(Error::Storage)?
                            .digest;
                        let mut matching = units.iter().enumerate().filter(|(_, candidate)| {
                            candidate.package.digest == digest
                        });
                        let (index, _) = matching.next().ok_or(Error::Missing)?;
                        if matching.next().is_some() {
                            return Err(Error::Storage);
                        }
                        (index, *method)
                    } else {
                        return Err(Error::Format);
                    };
                let target = offsets
                    .get(target_unit)
                    .copied()
                    .ok_or(Error::Bounds)?
                    .checked_add(usize::from(target_method))
                    .ok_or(Error::Quota)?;
                if target >= offsets[target_unit + 1] {
                    return Err(Error::Bounds);
                }
                push_link_edge(&mut edges, (source, target))?;
            }
        }
    }
    validate_program_graph(node_count, &edges, &irreversible, &transactional)
}

trait PackageData {
    fn manifest(&self) -> &Manifest;
    fn image(&self) -> &[u8];
    fn digest(&self) -> [u8; 32];
    fn key(&self) -> [u8; 32];
}

impl PackageData for Package {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn image(&self) -> &[u8] {
        self.image()
    }
    fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn key(&self) -> [u8; 32] {
        self.signer
    }
}

impl PackageData for PackageView<'_> {
    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    fn image(&self) -> &[u8] {
        self.image
    }
    fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn key(&self) -> [u8; 32] {
        self.signer
    }
}

fn resolve_dependency(
    state: &State,
    consumer_domain: &str,
    dependency: &crate::package::Dependency,
    consumer: &impl PackageData,
) -> Option<ResolvedDependency> {
    let local = if consumer_domain == "ISD" {
        Some(&state.isd)
    } else {
        state.domains.get(consumer_domain)
    };
    let mut resolved = None;
    let mut ambiguous = false;
    let mut consider = |domain: Option<&Domain>| {
        if let Some(provider) = domain
            .and_then(|d| d.package(dependency.assembly.as_str()).ok())
            .filter(|provider| {
                dependency.matches_parts(provider.manifest, provider.signer, provider.digest)
                    && provider
                        .manifest
                        .export
                        .allows(provider.signer, consumer.key())
            })
        {
            let candidate = ResolvedDependency {
                digest: provider.digest,
            };
            if resolved.replace(candidate).is_some() {
                ambiguous = true;
            }
        }
    };
    match dependency.scope {
        0 => consider(local),
        1 => consider(Some(&state.isd)),
        2 => {
            consider(local);
            if consumer_domain != "ISD" {
                consider(Some(&state.isd));
            }
        }
        _ => return None,
    }
    if ambiguous { None } else { resolved }
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
    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self {
            capabilities: context.clone_vec(&self.capabilities)?,
            max_assemblies: self.max_assemblies,
            max_instances: self.max_instances,
            max_int_records: self.max_int_records,
            max_blob_records: self.max_blob_records,
            max_blob_bytes: self.max_blob_bytes,
            max_key_slots: self.max_key_slots,
            max_package_bytes: self.max_package_bytes,
        })
    }

    fn standard() -> Result<Self> {
        let mut capabilities = Vec::new();
        capabilities.try_reserve_exact(44).map_err(|_| Error::Quota)?;
        // 21 was the Ed25519 verification primitive, which the card no longer carries.
        capabilities.extend((2..=13).chain(core::iter::once(20)).chain(22..=52));
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

    assemblies: NameMap<Rc<Vec<u8>>>,

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
    fn package(&self, name: &str) -> Result<StoredPackageView<'_>> {
        let metadata = self.packages.get(name).ok_or(Error::Missing)?;
        let raw = self.assemblies.get(name).ok_or(Error::Storage)?;
        Ok(StoredPackageView {
            #[cfg(test)]
            raw,
            manifest: &metadata.manifest,
            image: raw.get(metadata.image.clone()).ok_or(Error::Storage)?,
            signer: metadata.signer,
            digest: metadata.digest,
        })
    }

    fn new(incarnation: [u8; 16], registry_aid: RegistryAid, policy: DomainPolicy) -> Self {
        Self {
            incarnation,
            registry_aid,
            key: None,
            assemblies: NameMap::new(),
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

    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self {
            incarnation: self.incarnation,
            registry_aid: self.registry_aid,
            key: self.key,
            assemblies: self
                .assemblies
                .try_clone_with(context, |_, package| Ok(Rc::clone(package)))?,
            image_refs: self.image_refs.try_clone_with(context, |_, value| Ok(*value))?,
            packages: self.packages.try_clone_with(context, |_, metadata| Ok(Rc::clone(metadata)))?,
            bindings: self.bindings.try_clone_with(context, |context, bindings| {
                context.clone_vec(bindings)
            })?,
            imports: self.imports.try_clone_with(context, |context, imports| {
                context.clone_vec(imports)
            })?,
            versions: self
                .versions
                .try_clone_with(context, |_, version| Ok(*version))?,
            storage_schema: Rc::clone(&self.storage_schema),
            instances: self.instances.try_clone_with(context)?,
            store: self.store.try_clone_with(context)?,
            blobs: self.blobs.try_clone_with(context)?,
            keys: self.keys.try_clone_with(context)?,
            credentials: self.credentials.try_clone_with(context)?,
            policy: self.policy.try_clone_with(context)?,
        })
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
            assemblies: &NameMap<Rc<Vec<u8>>>,
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

        rekey(&self.assemblies, &mut self.versions, false)?;
        rekey(&self.assemblies, &mut self.bindings, true)?;
        rekey(&self.assemblies, &mut self.imports, true)?;
        for assembly in self.instances.values_mut() {
            let (canonical, _) = self
                .assemblies
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

    fn merge_storage_schema(&mut self, declarations: &[StorageDeclaration]) -> Result<()> {
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
            return Ok(());
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
        self.storage_schema = Rc::new(merged);
        Ok(())
    }

    fn is_unbound_and_empty(&self) -> bool {
        self.key.is_none()
            && self.assemblies.is_empty()
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
                for assembly in domain.assemblies.keys() {
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
            let package = domain.package(assembly)?;
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

pub struct Card<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging = RamStaging> {
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
    state: State,
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
impl<F: Flash + crate::image_store::ImageFlash, P: Platform> Card<F, P, RamStaging> {
    pub fn open(flash: F, platform: P, storage_key: impl Into<JournalKey>) -> Result<Self> {
        Self::open_with_staging(flash, platform, storage_key, RamStaging::default())
    }
}

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> Card<F, P, S> {
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
                journal.commit_with(encoded.as_slice(), &mut platform)?;
                state
            }
        };
        let images = crate::image_store::Images::new(journal.flash_mut())?;
        for domain in core::iter::once(&mut state.isd).chain(state.domains.0.iter_mut().map(|(_, domain)| domain)) {
            for (name, raw) in domain.assemblies.iter_mut() {
                let descriptor = domain.image_refs.get(name).ok_or(Error::Storage)?;
                *raw = images.with_image(descriptor, &mut platform, |bytes| {
                    let mut raw = Vec::new();
                    raw.try_reserve_exact(bytes.len()).map_err(|_| Error::Quota)?;
                    raw.extend_from_slice(bytes);
                    Ok(Rc::new(raw))
                })?;
            }
        }
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
            for (name, raw) in domain.assemblies.iter() {
                let verified = PackageView::verify_with(raw, &mut platform)?;
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
                || d.assemblies.len() > d.policy.max_assemblies as usize
                || d.bindings.len() != d.assemblies.len()
                || d.imports.len() != d.assemblies.len()
                || d.bindings
                    .keys()
                    .any(|name| !d.assemblies.contains_key(name))
                || d.imports
                    .keys()
                    .any(|name| !d.assemblies.contains_key(name))
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
                    && (!d.assemblies.is_empty()
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
            for (name, raw) in d.assemblies.iter() {
                total_bytes += raw.len();
                domain_package_bytes += raw.len();
                let p = d.package(name)?;
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
                    || imports != &resolve_calls(&state, &p, bindings)?
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
                let p = d.package(assembly.as_ref())?;
                if !p.manifest.entry_points.iter().any(|a| &a.aid == aid) {
                    return Err(Error::Storage);
                }
            }
        }
        if state.isd.key.is_some() != state.isd.assemblies.contains_key("mscorlib")
            || (state.isd.key.is_none() && !state.isd.is_unbound_and_empty())
        {
            return Err(Error::Storage);
        }
        if total_bytes > MAX_TOTAL_PACKAGE_BYTES {
            return Err(Error::Storage);
        }
        for (id, assembly) in linked_roots {
            execution_units(&state, id, assembly)?;
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
            let mut next = self.state.try_clone()?;
            next.scp03_sequence = reserved;
            self.commit(next)?;
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
    pub(crate) fn globalplatform_load_active(&self) -> bool {
        self.globalplatform_load.is_some()
    }
    /// Returns one bounded GlobalPlatform Registry record. The caller owns
    /// session-scoped continuation state; no cursor is persisted in flash.
    pub(crate) fn get_status_record(
        &self,
        p1: u8,
        index: usize,
        filter: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        let mut matching = 0usize;
        let mut selected = None;
        visit_registry(&self.state, p1, |aid, entry| {
            // GP 2.3.1 §11.4.2.1 requires the ISD search criterion to be ignored.
            if p1 == 0x80 || crate::globalplatform::aid_matches(aid, filter) {
                if matching == index {
                    selected = Some(registry_record(p1, aid, entry)?);
                }
                matching += 1;
            }
            Ok(())
        })?;
        let record = selected.ok_or(Error::Missing)?;
        Ok((record, matching > index + 1))
    }

    pub(crate) fn select_isd_with_cancel(
        &mut self,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.abort_transaction();
        let Some(selected) = self.selected.take() else {
            return Ok(());
        };
        let (id, incarnation, aid) = &selected;
        let result = (|| {
            let Some(domain) = self.state.domains.get(id) else {
                return Ok(());
            };
            if domain.incarnation != *incarnation {
                return Ok(());
            }
            let assembly = domain.instances.get(aid).ok_or(Error::Missing)?;
            let units = execution_units(&self.state, id, assembly)?;
            let deselect = units[0]
                .package
                .manifest
                .entry_points
                .iter()
                .find(|entry| entry.aid.as_str() == aid.as_str())
                .ok_or(Error::Missing)?
                .deselect;
            if let Some(entry) = deselect {
                let mut next = self.state.try_clone()?;
                let next_domain = next.domains.get_mut(id).ok_or(Error::Domain)?;
                run_context_with_cancel(
                    next_domain,
                    &units[0].package,
                    Some(&units),
                    entry,
                    InvocationInput {
                        data: &[],
                        level: 0,
                    },
                    &mut self.platform,
                    should_cancel,
                )?;
                self.commit(next)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.selected = Some(selected);
        }
        result
    }

    /// GlobalPlatform-shaped management commands retain the same level-13
    /// authorization and transactional state changes as native management.
    #[cfg(test)]
    pub(crate) fn manage_globalplatform(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.manage_globalplatform_with_cancel(verified, &mut || false)
    }
    pub(crate) fn manage_globalplatform_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.abort_transaction();
        if verified.level & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        let command = verified.command;
        if command.ins == 0xe6 && command.p1 == 0x02 {
            let request = crate::globalplatform::load_request(&command)?;
            let load_aid = RegistryAid::new(request.load_aid)?;
            if self.state.registry_aid_reserved_by_non_assembly(load_aid) {
                return Err(Error::Busy);
            }
            let domain_aid = RegistryAid::new(request.domain_aid)?;
            self.state
                .domain_identifier_by_registry_aid(domain_aid)
                .ok_or(Error::Missing)?;
            self.abort_staging();
            self.globalplatform_load = Some(GlobalPlatformLoad {
                domain_aid,
                load_aid,
                hash: request.hash,
                receiver: crate::globalplatform::LoadReceiver::new(
                    crate::globalplatform::Payload::SignedPackage, MAX_PACKAGE_BYTES,
                ),
            });
            return fallible_filled(1, 0);
        }
        if command.ins == 0xe8 && self.globalplatform_load.is_some() {
            let result = self.continue_globalplatform_load(&command, should_cancel);
            if result.is_err() {
                self.abort_staging();
            }
            return result;
        }
        if command.ins == 0xe6 && command.p1 == 0x0c {
            if !self.state.is_owned() {
                return Err(Error::Unauthorized);
            }
            if let Ok(requested) = crate::globalplatform::ssd_install_aid(&command) {
                let requested = RegistryAid::new(requested)?;
                let in_use = self.state.registry_aid_in_use(requested);
                if in_use || self.state.domains.len() >= MAX_SSDS {
                    return Err(if in_use { Error::Busy } else { Error::Quota });
                }
                let identifier = encode_aid(requested.as_slice())?;
                let mut incarnation = [0; 16];
                self.platform.random(&mut incarnation)?;
                let mut next = self.state.try_clone()?;
                next.domains.insert(
                    identifier,
                    Domain::new(incarnation, requested, DomainPolicy::standard()?),
                )?;
                self.commit(next)?;
                return Ok(Vec::new());
            }
            let install = crate::globalplatform::application_install(&command)?;
            let load_aid = RegistryAid::new(install.load_aid)?;
            // The instance answers to its own AID, which GlobalPlatform lets differ from
            // the module AID so one module can back several instances.
            let aid = encode_aid(install.instance_aid)?;
            self.install_instance_exact(load_aid, &aid, should_cancel)?;
            return fallible_filled(1, 0);
        }

        let target = RegistryAid::new(crate::globalplatform::delete_aid(&command)?)?;
        if target == RegistryAid::isd() {
            return Err(Error::Unauthorized);
        }
        if let Some(identifier) = self
            .state
            .domains
            .iter()
            .find(|(_, domain)| domain.registry_aid == target)
            .map(|(identifier, _)| identifier.as_str())
        {
            let mut next = self.state.try_clone()?;
            next.domains.remove(identifier).ok_or(Error::Missing)?;
            self.commit(next)?;
            self.abort_staging();
            return Ok(Vec::new());
        }

        let target_text = encode_aid(target.as_slice())?;
        let instance_delete = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .find(|(_, domain)| domain.instances.contains_key(&target_text))
            .map(|(identifier, _)| management_names_wire(identifier, target_text.as_str()))
            .transpose()?;
        if let Some(data) = instance_delete {
            return self.manage_with_cancel(
                Verified {
                    level: 0x13,
                    command: crate::apdu::Command {
                        cla: 0x80,
                        ins: 0xee,
                        p1: 0,
                        p2: 0,
                        data: data.into(),
                        le: None,
                    },
                },
                should_cancel,
            );
        }

        let assembly_delete = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .flat_map(|(identifier, domain)| {
                domain.assemblies.keys().filter_map(move |assembly| {
                    domain
                        .versions
                        .get(assembly)
                        .map(|(_, digest)| (identifier, assembly, digest))
                })
            })
            .find(|(_, _, digest)| RegistryAid::synthetic(0x4c, *digest) == target)
            .map(|(identifier, assembly, _)| management_names_wire(identifier, assembly.as_ref()))
            .transpose()?;
        if let Some(data) = assembly_delete {
            return self.manage_with_cancel(
                Verified {
                    level: 0x13,
                    command: crate::apdu::Command {
                        cla: 0x80,
                        ins: 0xf0,
                        p1: 0,
                        p2: 0,
                        data: data.into(),
                        le: None,
                    },
                },
                should_cancel,
            );
        }
        Err(Error::Missing)
    }

    fn continue_globalplatform_load(
        &mut self,
        command: &crate::apdu::Command,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        let load = self.globalplatform_load.as_mut().ok_or(Error::Format)?;
        if !load.receiver.receive(command, &mut self.staging)? {
            return fallible_filled(1, 0);
        }
        let result = self.manage_with_cancel(
            Verified {
                level: 0x13,
                command: crate::apdu::Command {
                    cla: 0x80,
                    ins: 0xea,
                    p1: 0,
                    p2: 0,
                    data: Vec::new().into(),
                    le: None,
                },
            },
            should_cancel,
        );
        self.globalplatform_load = None;
        result?;
        fallible_filled(1, 0)
    }

    fn install_instance_exact(
        &mut self,
        load_aid: RegistryAid,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        let (aid_bytes, aid_len) = decode_aid(aid)?;
        if self
            .state
            .registry_aid_in_use(RegistryAid::new(&aid_bytes[..aid_len])?)
        {
            return Err(Error::Busy);
        }
        let (domain_id, assembly, source) = core::iter::once(("ISD", &self.state.isd))
            .chain(
                self.state
                    .domains
                    .iter()
                    .map(|(identifier, domain)| (identifier.as_str(), domain)),
            )
            .flat_map(|(identifier, domain)| {
                domain.versions.iter().map(move |(assembly, (_, digest))| {
                    (
                        identifier,
                        assembly.as_ref(),
                        domain,
                        RegistryAid::synthetic(0x4c, digest),
                    )
                })
            })
            .find(|(_, _, _, candidate)| *candidate == load_aid)
            .map(|(identifier, assembly, domain, _)| (identifier, assembly, domain))
            .ok_or(Error::Missing)?;
        if source.instances.len() >= source.policy.max_instances as usize {
            return Err(Error::Quota);
        }
        let count = core::iter::once(&self.state.isd)
            .chain(self.state.domains.values())
            .map(|domain| domain.instances.len())
            .sum::<usize>();
        if count >= MAX_TOTAL_INSTANCES {
            return Err(Error::Quota);
        }
        let units = execution_units(&self.state, domain_id, assembly)?;
        let package = &units[0].package;
        let entry = package
            .manifest
            .entry_points
            .iter()
            .find(|entry| entry.aid == aid)
            .ok_or(Error::Missing)?;
        let mut next = self.state.try_clone()?;
        let domain = next.domain_mut(domain_id).ok_or(Error::Domain)?;
        let instance_aid = fallible_string(aid)?;
        domain.instances.reserve_entry()?;
        if let Some(method) = entry.install {
            run_context_with_cancel(
                domain,
                package,
                Some(&units),
                method,
                InvocationInput {
                    data: &[],
                    level: 0,
                },
                &mut self.platform,
                should_cancel,
            )?;
        }
        let canonical = domain
            .assemblies
            .get_key_value(assembly)
            .map(|(name, _)| Rc::clone(name))
            .ok_or(Error::Storage)?;
        domain.instances.insert(instance_aid, canonical)?;
        self.commit(next)
    }

    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
    /// Bypasses SCP03 only in dedicated fuzz builds so stateful management paths remain reachable.
    #[cfg(feature = "fuzzing")]
    pub fn manage_fuzz_authenticated(&mut self, command: crate::apdu::Command) -> Result<Vec<u8>> {
        self.manage(Verified {
            command,
            level: 0x13,
        })
    }
    fn commit(&mut self, mut next: State) -> Result<()> {
        if self.state == next {
            return Ok(());
        }
        let mut protected = Vec::new();
        let current_count: usize = core::iter::once(&self.state.isd)
            .chain(self.state.domains.0.iter().map(|(_, domain)| domain))
            .map(|domain| domain.image_refs.len()).sum();
        let next_count: usize = core::iter::once(&next.isd)
            .chain(next.domains.0.iter().map(|(_, domain)| domain))
            .map(|domain| domain.assemblies.len()).sum();
        protected.try_reserve_exact((self.uncommitted_images.len() + current_count + next_count).min(64))
            .map_err(|_| Error::Quota)?;
        protected.extend_from_slice(&self.uncommitted_images);
        for domain in core::iter::once(&self.state.isd).chain(self.state.domains.0.iter().map(|(_, domain)| domain)) {
            for (_, descriptor) in domain.image_refs.iter() {
                if !protected.contains(descriptor) { protected.push(*descriptor); }
            }
        }
        let mut images = crate::image_store::Images::new(self.journal.flash_mut())?;
        for domain in core::iter::once(&mut next.isd).chain(next.domains.0.iter_mut().map(|(_, domain)| domain)) {
            let mut references = NameMap::new();
            for (name, raw) in domain.assemblies.iter() {
                let digest = domain.packages.get(name).ok_or(Error::Storage)?.digest;
                let descriptor = match domain.image_refs.get(name) {
                    Some(descriptor) if descriptor.digest == digest && descriptor.length as usize == raw.len() => *descriptor,
                    _ => images.stage(raw, &protected, &mut self.platform)?,
                };
                if !protected.contains(&descriptor) {
                    if protected.len() == 64 { return Err(Error::Quota); }
                    protected.push(descriptor);
                }
                references.insert(Rc::clone(name), descriptor)?;
            }
            domain.image_refs = references;
        }
        let data = next.encode_snapshot()?;
        if data.len() > 49152 {
            return Err(Error::Quota);
        }
        self.uncommitted_images = protected;
        self.journal
            .commit_with(data.as_slice(), &mut self.platform)?;
        self.uncommitted_images.clear();
        self.state = next;
        Ok(())
    }
    /// The verified APDU supplies both authority and parameters. No caller-provided domain override.
    pub fn manage(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.manage_with_cancel(verified, &mut || false)
    }
    pub(crate) fn manage_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.abort_transaction();
        if verified.level & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        let c = verified.command;
        if c.p1 != 0 || c.p2 != 0 {
            return Err(Error::Format);
        }
        match c.ins {
            0xe0 => {
                if !self.state.is_owned() {
                    return Err(Error::Unauthorized);
                }
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                if !crate::package::valid_identifier(id)
                    || id == "ISD"
                    || self.state.domains.contains_key(id)
                {
                    return Err(Error::Domain);
                }
                if self.state.domains.len() >= MAX_SSDS {
                    return Err(Error::Quota);
                }
                let mut incarnation = [0; 16];
                self.platform.random(&mut incarnation)?;
                let registry_aid = RegistryAid::synthetic(0x53, &incarnation);
                if self.state.registry_aid_in_use(registry_aid) {
                    return Err(Error::Busy);
                }
                let mut next = self.state.try_clone()?;
                next.domains.insert(
                    fallible_string(id)?,
                    Domain::new(incarnation, registry_aid, DomainPolicy::standard()?),
                )?;
                self.commit(next)?;
                fallible_copy(&incarnation)
            }
            0xe1 => {
                let (identifier, policy) = DomainPolicy::request(&c.data)?;
                let mut next = self.state.try_clone()?;
                let domain = next.domains.get_mut(&identifier).ok_or(Error::Domain)?;
                if domain.key.is_some()
                    || !domain.assemblies.is_empty()
                    || !domain.instances.is_empty()
                    || !domain.store.is_empty()
                    || !domain.blobs.is_empty()
                    || !domain.keys.is_empty()
                {
                    return Err(Error::Busy);
                }
                domain.policy = policy;
                self.commit(next)?;
                Ok(Vec::new())
            }
            0xe2 => {
                if c.data.len() != 1 {
                    return Err(Error::Format);
                }
                let index = c.data[0] as usize;
                let total = self.state.domains.len() + 1;
                let (id, d) = if index == 0 {
                    ("ISD", &self.state.isd)
                } else {
                    let Some((id, d)) = self.state.domains.iter().nth(index - 1) else {
                        return Err(Error::Missing);
                    };
                    (id.as_str(), d)
                };
                // One bounded record per command, ordered by domain identifier.
                let capacity = 55usize.checked_add(id.len()).ok_or(Error::Quota)?;
                let mut out = Vec::new();
                out.try_reserve_exact(capacity)
                    .map_err(|_| Error::Quota)?;
                out.extend([1, total as u8, index as u8, id.len() as u8]);
                out.extend(id.as_bytes());
                out.extend(d.incarnation);
                out.push(u8::from(d.key.is_some()));
                out.extend(d.key.unwrap_or([0; 32]));
                out.extend([d.assemblies.len() as u8, d.instances.len() as u8]);
                out.extend(((d.store.len() + d.blobs.len()) as u16).to_le_bytes());
                Ok(out)
            }
            0xe3 => {
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                let policy = &self.state.domain(id).ok_or(Error::Domain)?.policy;
                policy.wire()
            }
            0xe4 => {
                let id = core::str::from_utf8(&c.data).map_err(|_| Error::Format)?;
                if id == "ISD" {
                    return Err(Error::Unauthorized);
                }
                let mut next = self.state.try_clone()?;
                next.domains.remove(id).ok_or(Error::Missing)?;
                self.commit(next)?;
                self.staging.reset();
                Ok(Vec::new())
            }
            0xe6 => {
                if !c.data.is_empty() {
                    return Err(Error::Format);
                }
                self.staging.reset();
                Ok(Vec::new())
            }
            0xe8 => {
                if c.data.len() < 4 {
                    return Err(Error::Format);
                }
                let offset = u32::from_le_bytes(c.data[..4].try_into().unwrap()) as usize;
                let chunk = &c.data[4..];
                let end = offset.checked_add(chunk.len()).ok_or(Error::Quota)?;
                if offset < self.staging.len() {
                    if end > self.staging.len() || !self.staging.matches(offset, chunk)? {
                        return Err(Error::Format);
                    }
                    return Ok(Vec::new());
                }
                if offset != self.staging.len() || end > MAX_PACKAGE_BYTES {
                    return Err(Error::Quota);
                }
                self.staging.append(chunk)?;
                Ok(Vec::new())
            }
            0xea => {
                if !c.data.is_empty() {
                    return Err(Error::Format);
                }
                let declared_load_aid = self.globalplatform_load.as_ref().map(|load| load.load_aid);
                let expected = self
                    .globalplatform_load
                    .as_ref()
                    .map(|load| {
                        self.state
                            .domain_identifier_by_registry_aid(load.domain_aid)
                            .map(|domain| (load.hash, domain))
                            .ok_or(Error::Missing)
                    })
                    .transpose()?;
                let materialized = if self.staging.as_slice().is_none() {
                    Some(self.staging.read_all()?)
                } else {
                    None
                };
                let staged = self
                    .staging
                    .as_slice()
                    .unwrap_or_else(|| materialized.as_deref().unwrap());
                let p = PackageView::verify_with_expected_digest(
                    staged,
                    &mut self.platform,
                    expected.as_ref().and_then(|(hash, _)| hash.as_ref()),
                )?;
                if expected
                    .as_ref()
                    .is_some_and(|(_, domain)| p.manifest.domain != *domain)
                {
                    return Err(Error::Domain);
                }
                let registry_aid = RegistryAid::synthetic(0x4c, &p.digest);
                // An MP03 load file declares no AID of its own, so MicroCard derives one
                // from the digest and the host has to have declared that same one. Moving
                // the check here from INSTALL is what lets a host leave the hash out, since
                // the digest is only known once the whole load file has arrived.
                //
                // This constrains the load file AID alone. Instance AIDs are chosen at
                // INSTALL [for install] and are free to differ from it and from each other,
                // because one load file can back several instances. A Java Card load file
                // declares its own package AID in the CAP Header, so it will be bound to
                // that rather than to a digest.
                if declared_load_aid.is_some_and(|declared| declared != registry_aid) {
                    return Err(Error::Format);
                }
                let same_existing = self
                    .state
                    .domain(&p.manifest.domain)
                    .and_then(|domain| domain.versions.get(p.manifest.assembly.as_str()))
                    .is_some_and(|(_, digest)| {
                        RegistryAid::synthetic(0x4c, digest) == registry_aid
                    });
                if self.state.registry_aid_in_use(registry_aid) && !same_existing {
                    return Err(Error::Busy);
                }
                let existing: usize = core::iter::once(&self.state.isd)
                    .chain(self.state.domains.values())
                    .flat_map(|d| d.assemblies.values())
                    .map(|raw| raw.len())
                    .sum();
                let replaced = self
                    .state
                    .domain(&p.manifest.domain)
                    .and_then(|d| d.assemblies.get(p.manifest.assembly.as_str()))
                    .map_or(0, |raw| raw.len());
                if existing - replaced + p.raw.len() > MAX_TOTAL_PACKAGE_BYTES {
                    return Err(Error::Quota);
                }
                let mut next = self.state.try_clone()?;
                if p.manifest.domain != "ISD" && !next.is_owned() {
                    return Err(Error::Unauthorized);
                }
                if p.manifest.domain == "ISD"
                    && next.isd.key.is_none()
                    && (p.manifest.assembly != "mscorlib"
                        || !p.manifest.entry_points.is_empty()
                        || !p.manifest.dependencies.is_empty())
                {
                    return Err(Error::Unauthorized);
                }
                let mut bindings = Vec::new();
                bindings
                    .try_reserve_exact(p.manifest.dependencies.len())
                    .map_err(|_| Error::Quota)?;
                for dependency in &p.manifest.dependencies {
                    bindings.push(
                        resolve_dependency(&next, &p.manifest.domain, dependency, &p)
                            .ok_or(Error::Missing)?,
                    );
                }
                let imports = resolve_calls(&next, &p, &bindings)?;
                if next
                    .domain(&p.manifest.domain)
                    .is_some_and(|domain| {
                        domain
                            .assemblies
                            .contains_key(p.manifest.assembly.as_str())
                    })
                    && next.provider_in_use(&p.manifest.domain, &p.manifest.assembly)
                {
                    return Err(Error::Busy);
                }
                let d = next.domain_mut(&p.manifest.domain).ok_or(Error::Domain)?;
                if p.manifest
                    .capabilities
                    .iter()
                    .any(|capability| !d.policy.capabilities.contains(capability))
                {
                    return Err(Error::Unauthorized);
                }
                if d.incarnation != p.manifest.incarnation {
                    return Err(Error::Domain);
                }
                if d.key.is_some_and(|key| key != p.signer) {
                    return Err(Error::KeyMismatch);
                }
                d.merge_storage_schema(&p.manifest.storage)?;
                if let Some((v, h)) = d.versions.get(p.manifest.assembly.as_str()) {
                    if p.manifest.version < *v || (p.manifest.version == *v && p.digest != *h) {
                        return Err(Error::Rollback);
                    }
                    if p.manifest.version == *v
                        && d.assemblies.contains_key(p.manifest.assembly.as_str())
                    {
                        drop(p);
                        self.staging.reset();
                        return Ok(Vec::new());
                    }
                }
                if d
                    .instances
                    .values()
                    .any(|a| a.as_ref() == p.manifest.assembly)
                {
                    return Err(Error::Busy);
                }
                let domain_bytes: usize = d.assemblies.values().map(|raw| raw.len()).sum();
                let domain_replaced = d
                    .assemblies
                    .get(p.manifest.assembly.as_str())
                    .map_or(0, |raw| raw.len());
                if domain_bytes - domain_replaced + p.raw.len()
                    > d.policy.max_package_bytes as usize
                {
                    return Err(Error::Quota);
                }
                if !d.assemblies.contains_key(p.manifest.assembly.as_str())
                    && d.assemblies.len() >= d.policy.max_assemblies as usize
                {
                    return Err(Error::Quota);
                }
                if !d.versions.contains_key(p.manifest.assembly.as_str())
                    && d.versions.len() >= d.policy.max_assemblies as usize
                {
                    return Err(Error::Quota);
                }
                d.versions.reserve_for(p.manifest.assembly.as_str())?;
                d.bindings.reserve_for(p.manifest.assembly.as_str())?;
                d.imports.reserve_for(p.manifest.assembly.as_str())?;
                d.assemblies.reserve_for(p.manifest.assembly.as_str())?;
                d.packages.reserve_for(p.manifest.assembly.as_str())?;
                let signing_key = p.signer;
                let version = p.manifest.version;
                let digest = p.digest;
                let activated_domain = fallible_string(&p.manifest.domain)?;
                let activated_assembly: Rc<str> = Rc::from(p.manifest.assembly.as_str());
                let metadata = Rc::new(StoredPackage::from_verified(p));

                let raw = Rc::new(match materialized {
                    Some(raw) => raw,
                    None => self.staging.take()?,
                });
                d.packages.insert(Rc::clone(&activated_assembly), metadata)?;
                d.key = Some(signing_key);
                d.versions
                    .insert(Rc::clone(&activated_assembly), (version, digest))?;
                d.bindings
                    .insert(Rc::clone(&activated_assembly), bindings)?;
                d.imports
                    .insert(Rc::clone(&activated_assembly), imports)?;
                d.assemblies
                    .insert(Rc::clone(&activated_assembly), Rc::clone(&raw))?;
                if let Err(error) =
                    execution_units(&next, &activated_domain, activated_assembly.as_ref())
                {
                    drop(next);
                    self.staging
                        .restore(Rc::try_unwrap(raw).map_err(|_| Error::Storage)?)?;
                    return Err(error);
                }
                if let Err(error) = self.commit(next) {
                    self.staging
                        .restore(Rc::try_unwrap(raw).map_err(|_| Error::Storage)?)?;
                    return Err(error);
                }
                self.staging.reset();
                Ok(Vec::new())
            }
            0xec | 0xee | 0xf0 => {
                let args = management_names(&c.data)?;
                if c.ins == 0xf0 && args.0 == "ISD" && args.1 == "mscorlib" {
                    return Err(Error::Unauthorized);
                }
                let mut next = self.state.try_clone()?;
                if c.ins == 0xf0 && next.provider_in_use(args.0, args.1) {
                    return Err(Error::Busy);
                }
                let count = core::iter::once(&next.isd)
                    .chain(next.domains.values())
                    .map(|domain| domain.instances.len())
                    .sum::<usize>();
                if c.ins == 0xec {
                    let (aid, aid_len) = decode_aid(args.1)?;
                    if self
                        .state
                        .registry_aid_in_use(RegistryAid::new(&aid[..aid_len])?)
                    {
                        return Err(Error::Busy);
                    }
                }
                let units = if c.ins == 0xec {
                    let source = self.state.domain(args.0).ok_or(Error::Domain)?;
                    let assembly = source
                        .packages
                        .values()
                        .find(|package| {
                            package
                                .manifest
                                .entry_points
                                .iter()
                                .any(|entry| entry.aid == args.1)
                        })
                        .map(|package| package.manifest.assembly.as_str())
                        .ok_or(Error::Missing)?;
                    Some(execution_units(&self.state, args.0, assembly)?)
                } else if c.ins == 0xee {
                    let source = self.state.domain(args.0).ok_or(Error::Domain)?;
                    let assembly = source.instances.get(args.1).ok_or(Error::Missing)?;
                    Some(execution_units(&self.state, args.0, assembly)?)
                } else {
                    None
                };
                let d = next.domain_mut(args.0).ok_or(Error::Domain)?;
                if c.ins == 0xf0 {
                    if d
                        .instances
                        .values()
                        .any(|assembly| assembly.as_ref() == args.1)
                    {
                        return Err(Error::Busy);
                    }
                    d.assemblies.remove(args.1).ok_or(Error::Missing)?;
                    d.packages.remove(args.1).ok_or(Error::Storage)?;
                    d.bindings.remove(args.1).ok_or(Error::Storage)?;
                    d.imports.remove(args.1).ok_or(Error::Storage)?;
                } else if c.ins == 0xec {
                    if count >= MAX_TOTAL_INSTANCES {
                        return Err(Error::Quota);
                    }
                    if d.instances.len() >= d.policy.max_instances as usize {
                        return Err(Error::Quota);
                    }
                    if d.instances.contains_key(args.1) {
                        return Err(Error::Busy);
                    }
                    let units = units.as_deref().ok_or(Error::Storage)?;
                    let p = &units[0].package;
                    let a = p
                        .manifest
                        .entry_points
                        .iter()
                        .find(|a| a.aid == args.1)
                        .unwrap();
                    let instance_aid = fallible_string(args.1)?;
                    d.instances.reserve_entry()?;
                    if let Some(entry) = a.install {
                        run_context_with_cancel(
                            d,
                            p,
                            Some(units),
                            entry,
                            InvocationInput {
                                data: &[],
                                level: 0,
                            },
                            &mut self.platform,
                            should_cancel,
                        )?;
                    }
                    let canonical = d
                        .assemblies
                        .get_key_value(p.manifest.assembly.as_str())
                        .map(|(name, _)| Rc::clone(name))
                        .ok_or(Error::Storage)?;
                    d.instances.insert(instance_aid, canonical)?;
                } else {
                    let units = units.as_deref().ok_or(Error::Storage)?;
                    let p = &units[0].package;
                    let a = p
                        .manifest
                        .entry_points
                        .iter()
                        .find(|a| a.aid == args.1)
                        .ok_or(Error::Missing)?;
                    if let Some(entry) = a.uninstall {
                        run_context_with_cancel(
                            d,
                            p,
                            Some(units),
                            entry,
                            InvocationInput {
                                data: &[],
                                level: 0,
                            },
                            &mut self.platform,
                            should_cancel,
                        )?;
                    }
                    d.instances.remove(args.1);
                }
                self.commit(next)?;
                Ok(Vec::new())
            }
            _ => Err(Error::Unsupported),
        }
    }
    pub fn select(&mut self, aid: &str) -> Result<()> {
        self.select_with_cancel(aid, &mut || false)
    }
    pub(crate) fn select_with_cancel(
        &mut self,
        aid: &str,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.abort_transaction();
        let old = self
            .selected
            .as_ref()
            .map(|(id, incarnation, old_aid)| {
                let domain = self.state.domains.get(id).ok_or(Error::Missing)?;
                if domain.incarnation != *incarnation {
                    return Ok(None);
                }
                let assembly = domain.instances.get(old_aid).ok_or(Error::Missing)?;
                let units = execution_units(&self.state, id, assembly)?;
                let entry = units[0]
                    .package
                    .manifest
                    .entry_points
                    .iter()
                    .find(|entry| entry.aid == *old_aid)
                    .ok_or(Error::Missing)?
                    .deselect;
                Ok(Some((fallible_string(id)?, units, entry)))
            })
            .transpose()?
            .flatten();
        let (id, domain) = self
            .state
            .domains
            .iter()
            .find(|(_, domain)| domain.instances.contains_key(aid))
            .ok_or(Error::Missing)?;
        let assembly = domain.instances.get(aid).ok_or(Error::Missing)?;
        let units = execution_units(&self.state, id, assembly)?;
        let entry = units[0]
            .package
            .manifest
            .entry_points
            .iter()
            .find(|entry| entry.aid == aid)
            .ok_or(Error::Missing)?
            .select;
        let selected = (
            fallible_string(id)?,
            domain.incarnation,
            fallible_string(aid)?,
        );
        let mut next = self.state.try_clone()?;
        if let Some((old_id, old_units, Some(old_entry))) = old {
            let old_domain = next.domains.get_mut(&old_id).ok_or(Error::Domain)?;
            run_context_with_cancel(
                old_domain,
                &old_units[0].package,
                Some(&old_units),
                old_entry,
                InvocationInput {
                    data: &[],
                    level: 0,
                },
                &mut self.platform,
                should_cancel,
            )?;
        }
        if let Some(entry) = entry {
            let domain = next.domains.get_mut(id).ok_or(Error::Domain)?;
            run_context_with_cancel(
                domain,
                &units[0].package,
                Some(&units),
                entry,
                InvocationInput {
                    data: &[],
                    level: 0,
                },
                &mut self.platform,
                should_cancel,
            )?;
        }
        self.commit(next)?;
        self.selected = Some(selected);
        Ok(())
    }
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let selected = self.selected.take().ok_or(Error::Missing)?;
        let (id, inc, aid) = &selected;
        if !self
            .state
            .domains
            .get(id)
            .is_some_and(|d| d.incarnation == *inc && d.instances.contains_key(aid))
        {
            return Err(Error::Missing);
        }
        let result = self.invoke(aid, data);
        self.selected = Some(selected);
        result
    }
    pub fn invoke(&mut self, aid: &str, data: &[u8]) -> Result<Vec<u8>> {
        self.invoke_context(aid, data, 0)
    }
    pub fn process_verified(&mut self, verified: Verified) -> Result<Vec<u8>> {
        self.process_verified_with_cancel(verified, &mut || false)
    }
    pub(crate) fn process_verified_with_cancel(
        &mut self,
        verified: Verified,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        let selected = self.selected.take().ok_or(Error::Missing)?;
        let (id, inc, aid) = &selected;
        if !self
            .state
            .domains
            .get(id)
            .is_some_and(|d| d.incarnation == *inc && d.instances.contains_key(aid))
        {
            return Err(Error::Missing);
        }
        let result = self.invoke_context_with_cancel(
            aid,
            &verified.command.data,
            verified.level,
            should_cancel,
        );
        self.selected = Some(selected);
        result
    }
    fn invoke_context(&mut self, aid: &str, data: &[u8], level: u8) -> Result<Vec<u8>> {
        self.invoke_context_with_cancel(aid, data, level, &mut || false)
    }
    fn invoke_context_with_cancel(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.invoke_context_with_metrics_and_cancel(aid, data, level, should_cancel)
            .map(|(output, _)| output)
    }
    #[cfg(test)]
    fn invoke_context_with_metrics(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
    ) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
        self.invoke_context_with_metrics_and_cancel(aid, data, level, &mut || false)
    }
    fn invoke_context_with_metrics_and_cancel(
        &mut self,
        aid: &str,
        data: &[u8],
        level: u8,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
        if data.len() > 255 {
            self.abort_transaction();
            return Err(Error::Bounds);
        }
        let mut found = self
            .state
            .domains
            .iter()
            .filter(|(_, d)| d.instances.contains_key(aid));
        let Some((domain_id, source)) = found.next() else {
            self.abort_transaction();
            return Err(Error::Missing);
        };
        if found.next().is_some() {
            self.abort_transaction();
            return Err(Error::Domain);
        }
        let source_assembly = source.instances.get(aid).ok_or(Error::Missing)?;
        let incarnation = source.incarnation;
        let domain_registry_aid = source.registry_aid;
        let units = match execution_units(&self.state, domain_id, source_assembly) {
            Ok(units) => units,
            Err(error) => {
                self.abort_transaction();
                return Err(error);
            }
        };
        let p = &units[0].package;
        let Some(a) = p
            .manifest
            .entry_points
            .iter()
            .find(|a| a.aid == aid)
        else {
            self.abort_transaction();
            return Err(Error::Missing);
        };
        let process = a.process;
        let (mut next, mut transaction, commands_left, pending_owner) =
            match self.transaction.take() {
            Some(pending)
                if pending.owner.0 == domain_registry_aid
                    && pending.owner.1 == incarnation
                    && pending.owner.2.as_str() == aid =>
            {
                (
                    pending.state,
                    TransactionDisposition::Active,
                    pending.commands_left,
                    Some(pending.owner),
                )
            }
            Some(_) | None => (
                self.state.try_clone()?,
                TransactionDisposition::Inactive,
                MAX_TRANSACTION_COMMANDS,
                None,
            ),
        };
        let d = next.domains.get_mut(domain_id).ok_or(Error::Domain)?;
        let mut retry_floor = CredentialRetryFloors::default();
        let mut control = InvocationControl {
            retry_floor: &mut retry_floor,
            should_cancel,
            transaction: &mut transaction,
        };
        let execution = run_context_with_metrics_and_retry_floor(
            d,
            p,
            Some(&units),
            process,
            InvocationInput { data, level },
            &mut self.platform,
            &mut control,
        );
        let (out, metrics) = match execution {
            Ok(value) => value,
            Err(error) => {
                drop(units);
                if !retry_floor.is_empty() {
                    self.commit_credential_retry_floor(domain_registry_aid, &retry_floor)?;
                }
                return Err(error);
            }
        };
        let retry_commit = !retry_floor.is_empty()
            && matches!(
                transaction,
                TransactionDisposition::Active
                    | TransactionDisposition::Begun
                    | TransactionDisposition::Abort
            );
        drop(units);
        if retry_commit {
            self.commit_credential_retry_floor(domain_registry_aid, &retry_floor)?;
        }
        let begun_aid = (transaction == TransactionDisposition::Begun)
            .then(|| fallible_string(aid))
            .transpose()?;
        let transaction_owner = match transaction {
            TransactionDisposition::Begun => Some((
                domain_registry_aid,
                incarnation,
                begun_aid.ok_or(Error::Storage)?,
            )),
            TransactionDisposition::Active => pending_owner,
            _ => None,
        };
        match transaction {
            TransactionDisposition::Inactive | TransactionDisposition::Commit => {
                self.commit(next)?;
            }
            TransactionDisposition::Begun => {
                self.transaction = Some(PendingTransaction {
                    owner: transaction_owner.ok_or(Error::Storage)?,
                    state: next,
                    commands_left: MAX_TRANSACTION_COMMANDS - 1,
                });
            }
            TransactionDisposition::Active if commands_left > 1 => {
                self.transaction = Some(PendingTransaction {
                    owner: transaction_owner.ok_or(Error::Storage)?,
                    state: next,
                    commands_left: commands_left - 1,
                });
            }
            TransactionDisposition::Active => return Err(Error::Budget),
            TransactionDisposition::Abort => {}
        }
        Ok((out, metrics))
    }

    fn commit_credential_retry_floor(
        &mut self,
        domain_registry_aid: RegistryAid,
        retry_floor: &CredentialRetryFloors,
    ) -> Result<()> {
        let mut failure_state = self.state.try_clone()?;
        let failure_domain = failure_state
            .domains
            .values_mut()
            .find(|domain| domain.registry_aid == domain_registry_aid)
            .ok_or(Error::Domain)?;
        if failure_domain
            .credentials
            .apply_retry_floor(failure_domain.incarnation, retry_floor.iter())?
        {
            self.commit(failure_state)?;
        }
        Ok(())
    }
}
#[cfg(test)]
fn run_context(
    d: &mut Domain,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    data: &[u8],
    platform: &mut impl Platform,
    level: u8,
) -> Result<Vec<u8>> {
    run_context_with_cancel(
        d,
        p,
        units,
        entry,
        InvocationInput { data, level },
        platform,
        &mut || false,
    )
}
fn run_context_with_cancel(
    d: &mut Domain,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    input: InvocationInput<'_>,
    platform: &mut impl Platform,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Result<Vec<u8>> {
    run_context_with_metrics_and_cancel(d, p, units, entry, input, platform, should_cancel)
        .map(|(output, _)| output)
}
fn run_context_with_metrics_and_cancel(
    d: &mut Domain,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    input: InvocationInput<'_>,
    platform: &mut impl Platform,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
    let mut retry_floor = CredentialRetryFloors::default();
    let mut transaction = TransactionDisposition::Inactive;
    let mut control = InvocationControl {
        retry_floor: &mut retry_floor,
        should_cancel,
        transaction: &mut transaction,
    };
    let result =
        run_context_with_metrics_and_retry_floor(d, p, units, entry, input, platform, &mut control);
    if transaction != TransactionDisposition::Inactive {
        return Err(Error::Unauthorized);
    }
    result
}
#[derive(Clone, Copy)]
struct InvocationInput<'a> {
    data: &'a [u8],
    level: u8,
}
struct InvocationControl<'a> {
    retry_floor: &'a mut CredentialRetryFloors,
    should_cancel: &'a mut dyn FnMut() -> bool,
    transaction: &'a mut TransactionDisposition,
}

fn managed_response_buffer() -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response
        .try_reserve_exact(MAX_MANAGED_RESPONSE_WITH_STATUS)
        .map_err(|_| Error::Quota)?;
    Ok(response)
}

fn run_context_with_metrics_and_retry_floor(
    d: &mut Domain,
    p: &impl PackageData,
    units: Option<&[ExecutionUnit]>,
    entry: u16,
    input: InvocationInput<'_>,
    platform: &mut impl Platform,
    control: &mut InvocationControl<'_>,
) -> Result<(Vec<u8>, crate::mc04_vm::ExecutionMetrics)> {
    let mut host = Host {
        store: &mut d.store,
        blobs: &mut d.blobs,
        keys: &mut d.keys,
        credentials: &mut d.credentials,
        authorized_credentials: CredentialAuthorizations::default(),
        credential_retry_floor: CredentialRetryFloors::default(),
        owner: d.incarnation,
        data: input.data,
        out: managed_response_buffer()?,
        sw: 0x9000,
        platform,
        budget: 1024,
        capabilities: &p.manifest().capabilities,
        domain_schema: &d.storage_schema,
        max_int_records: d.policy.max_int_records as usize,
        max_blob_records: d.policy.max_blob_records as usize,
        max_blob_bytes: d.policy.max_blob_bytes as usize,
        max_key_slots: d.policy.max_key_slots as usize,
        level: input.level,
        units,
        transaction: control.transaction,
        irreversible_output: false,
    };
    let units = units.ok_or(Error::Storage)?;
    if units
        .first()
        .is_none_or(|unit| unit.package.digest != p.digest())
    {
        return Err(Error::Storage);
    }
    let mut vm_units = Vec::new();
    vm_units
        .try_reserve_exact(units.len())
        .map_err(|_| Error::Quota)?;
    for unit in units {
        vm_units.push(crate::mc04_vm::Unit {
            name: &unit.package.manifest.assembly,
            assembly: crate::assembly::Assembly::parse(unit.package.image)?,
        });
    }
    let execution = crate::mc04_vm::execute_program_with_metrics_and_cancel(
        &vm_units,
        0,
        entry,
        &[],
        &mut host,
        control.should_cancel,
    );
    *control.retry_floor = core::mem::take(&mut host.credential_retry_floor);
    let (_, metrics) = execution?;
    #[cfg(test)]
    let metrics = {
        let mut metrics = metrics;
        metrics.native_work_units = 1024 - host.budget;
        metrics
    };
    host.out.extend_from_slice(&host.sw.to_be_bytes());
    Ok((host.out, metrics))
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

struct Host<'a, P: Platform> {
    store: &'a mut IntStore,
    blobs: &'a mut BlobStore,
    keys: &'a mut crate::key_store::KeyStore,
    credentials: &'a mut crate::credential_store::CredentialStore,
    authorized_credentials: CredentialAuthorizations,
    credential_retry_floor: CredentialRetryFloors,
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
    irreversible_output: bool,
}

#[derive(Clone, Copy)]
enum NativeArgument<'a> {
    Int(i32),
    Bytes(&'a [u8]),
}

fn native_range(bytes: &[u8], offset: i32, length: i32) -> Result<&[u8]> {
    let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
    let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
    let end = offset.checked_add(length).ok_or(Error::Bounds)?;
    bytes.get(offset..end).ok_or(Error::Bounds)
}

impl NativeArgument<'_> {
    fn int(&self) -> Result<i32> {
        match self {
            Self::Int(value) => Ok(*value),
            Self::Bytes(_) => Err(Error::Format),
        }
    }

    fn bytes(&self) -> Result<&[u8]> {
        match self {
            Self::Bytes(value) => Ok(value),
            Self::Int(_) => Err(Error::Format),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BufferResult {
    Void,
    Bytes(Vec<u8>),
    Scalar(i32),
}

impl<P: Platform> crate::mc04_vm::External for Host<'_, P> {
    fn resolve(&self, unit: usize, member: u16) -> Result<crate::mc04_vm::LinkedTarget> {
        let units = self.units.ok_or(Error::Unauthorized)?;
        let target = &units
            .get(unit)
            .ok_or(Error::Unauthorized)?
            .calls
            .iter()
            .find(|binding| binding.member == member)
            .ok_or(Error::Unauthorized)?
            .target;
        match target {
            CallTarget::ObjectConstructor => Ok(crate::mc04_vm::LinkedTarget::ObjectConstructor),
            CallTarget::CurrentDomain => Ok(crate::mc04_vm::LinkedTarget::CurrentDomain),
            CallTarget::DomainStorage => Ok(crate::mc04_vm::LinkedTarget::DomainStorage),
            CallTarget::DomainKeys => Ok(crate::mc04_vm::LinkedTarget::DomainKeys),
            CallTarget::Native(id) => Ok(crate::mc04_vm::LinkedTarget::Native(*id)),
            CallTarget::Managed { dependency, method } => {
                let digest = units
                    .get(unit)
                    .and_then(|unit| unit.bindings.get(usize::from(*dependency)))
                    .ok_or(Error::Storage)?
                    .digest;
                let mut matches = units.iter().enumerate().filter(|(_, unit)| {
                    unit.package.digest == digest
                });
                let (index, _) = matches.next().ok_or(Error::Missing)?;
                if matches.next().is_some() {
                    return Err(Error::Storage);
                }
                Ok(crate::mc04_vm::LinkedTarget::Managed {
                    unit: index,
                    method: *method,
                })
            }
        }
    }

    fn invoke(
        &mut self,
        unit: usize,
        member: u16,
        id: u8,
        arguments: &[crate::mc04_vm::RuntimeValue],
        heap: &mut crate::mc04_vm::Heap,
    ) -> Result<Option<crate::mc04_vm::RuntimeValue>> {
        use crate::mc04_vm::RuntimeValue::{Int, Opaque};
        fn scalar(value: Option<i32>) -> BufferResult {
            value.map_or(BufferResult::Void, BufferResult::Scalar)
        }
        if !self
            .units
            .and_then(|units| units.get(unit))
            .is_some_and(|unit| {
                unit.calls.iter().any(|binding| {
                    binding.member == member && binding.target == CallTarget::Native(id)
                })
            })
        {
            return Err(Error::Unauthorized);
        }
        if matches!(
            *self.transaction,
            TransactionDisposition::Commit | TransactionDisposition::Abort
        ) && !matches!(id, 2 | 13)
        {
            return Err(Error::Unauthorized);
        }
        self.capabilities = &self
            .units
            .and_then(|units| units.get(unit))
            .ok_or(Error::Unauthorized)?
            .package
            .manifest
            .capabilities;
        match (id, arguments) {
            (3, [Int(key)]) | (7, [Opaque(3), Int(key)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (4, [Int(key), Int(_)]) | (8, [Opaque(3), Int(key), Int(_)]) => {
                self.authorize_storage(unit, *key, 1, None)?;
            }
            (31 | 33 | 34, [Opaque(3), Int(key)]) => {
                self.authorize_storage(unit, *key, 2, None)?;
            }
            (32, [Opaque(3), Int(key), value]) => {
                self.authorize_storage(unit, *key, 2, Some(heap.bytes(*value)?.len()))?;
            }
            _ => {}
        }
        let result = match (id, arguments) {
            (2, [Int(value)]) => scalar(self.call(id, &[*value])?),
            (3, [Int(key)]) => scalar(self.call(3, &[*key])?),
            (4, [Int(key), Int(value)]) => scalar(self.call(4, &[*key, *value])?),
            (5 | 9 | 10, []) => scalar(self.call(id, &[])?),
            (11, []) => scalar(self.call(id, &[])?),
            (12, [destination, Int(destination_offset), Int(source_offset), Int(length)]) => {
                self.copy_command(
                    heap,
                    *destination,
                    *destination_offset,
                    *source_offset,
                    *length,
                )?;
                BufferResult::Void
            }
            (13, [source, Int(source_offset), Int(length)]) => {
                self.write_response(heap, *source, *source_offset, *length)?;
                BufferResult::Void
            }
            (6, [Int(resource), Int(value)]) => {
                if self.transaction.transaction_involved() {
                    return Err(Error::Unauthorized);
                }
                let result = scalar(self.call(6, &[*resource, *value])?);
                self.irreversible_output = true;
                result
            }
            (7, [Opaque(3), Int(key)]) => scalar(self.call(7, &[0, *key])?),
            (8, [Opaque(3), Int(key), Int(value)]) => scalar(self.call(8, &[0, *key, *value])?),
            (20, [input]) => self.buffers(20, &[heap.bytes(*input)?])?,
            (22, [Opaque(2), Int(slot), Int(algorithm)]) => self.key_call(
                22,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*slot),
                    NativeArgument::Int(*algorithm),
                ],
            )?,
            (23 | 24, [Opaque(2), Int(slot)]) => {
                self.key_call(id, &[NativeArgument::Int(0), NativeArgument::Int(*slot)])?
            }
            (25 | 26, [handle, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (27 | 28, [handle, iv, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*iv)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (29 | 30, [handle, nonce, aad, input]) => self.key_call(
                id,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*nonce)?),
                    NativeArgument::Bytes(heap.bytes(*aad)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (31, [Opaque(3), Int(key)]) => {
                self.key_call(31, &[NativeArgument::Int(0), NativeArgument::Int(*key)])?
            }
            (32, [Opaque(3), Int(key), value]) => self.key_call(
                32,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                ],
            )?,
            (52, [Opaque(3), Int(key), value, Int(offset), Int(length)]) => self.key_call(
                52,
                &[
                    NativeArgument::Int(0),
                    NativeArgument::Int(*key),
                    NativeArgument::Bytes(heap.bytes(*value)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (33 | 34, [Opaque(3), Int(key)]) => {
                self.key_call(id, &[NativeArgument::Int(0), NativeArgument::Int(*key)])?
            }
            (35, [handle]) => self.key_call(
                35,
                &[NativeArgument::Bytes(heap.bytes(*handle)?)],
            )?,
            (36, [handle, input, Int(offset), Int(length)]) => self.key_call(
                36,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (38, [handle, input]) => self.key_call(
                38,
                &[
                    NativeArgument::Bytes(heap.bytes(*handle)?),
                    NativeArgument::Bytes(heap.bytes(*input)?),
                ],
            )?,
            (37, [public_key, data, signature]) => self.buffers(
                37,
                &[
                    heap.bytes(*public_key)?,
                    heap.bytes(*data)?,
                    heap.bytes(*signature)?,
                ],
            )?,
            (39, [destination, Int(offset), Int(length)]) => {
                self.fill_random(heap, *destination, *offset, *length)?;
                BufferResult::Void
            }
            (49, [input, Int(input_offset), Int(input_length), destination, Int(destination_offset)]) => {
                scalar(Some(self.sha256_into(
                    heap,
                    *input,
                    *input_offset,
                    *input_length,
                    *destination,
                    *destination_offset,
                )?))
            }
            (50, [Int(length)]) => BufferResult::Bytes(self.random_bytes(*length)?),
            (51, [left, Int(left_offset), Int(left_length), right, Int(right_offset), Int(right_length)]) => {
                scalar(Some(self.fixed_time_equals(
                    heap,
                    (*left, *left_offset, *left_length),
                    (*right, *right_offset, *right_length),
                )?))
            }
            (40, [Int(slot), pin, Int(pin_offset), Int(pin_length), Int(pin_retries), puk, Int(puk_offset), Int(puk_length), Int(puk_retries)]) => self
                .credential_call(
                    40,
                    &[
                        NativeArgument::Int(*slot),
                        NativeArgument::Bytes(heap.bytes(*pin)?),
                        NativeArgument::Int(*pin_offset),
                        NativeArgument::Int(*pin_length),
                        NativeArgument::Int(*pin_retries),
                        NativeArgument::Bytes(heap.bytes(*puk)?),
                        NativeArgument::Int(*puk_offset),
                        NativeArgument::Int(*puk_length),
                        NativeArgument::Int(*puk_retries),
                    ],
                )?,
            (41, [Int(slot), candidate, Int(offset), Int(length)]) => self.credential_call(
                41,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*candidate)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (42, [Int(slot)]) => {
                self.credential_call(42, &[NativeArgument::Int(*slot)])?
            }
            (43, [Int(slot), new_pin, Int(offset), Int(length)]) => self.credential_call(
                43,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*new_pin)?),
                    NativeArgument::Int(*offset),
                    NativeArgument::Int(*length),
                ],
            )?,
            (44, [Int(slot), puk, Int(puk_offset), Int(puk_length), new_pin, Int(new_pin_offset), Int(new_pin_length)]) => self.credential_call(
                44,
                &[
                    NativeArgument::Int(*slot),
                    NativeArgument::Bytes(heap.bytes(*puk)?),
                    NativeArgument::Int(*puk_offset),
                    NativeArgument::Int(*puk_length),
                    NativeArgument::Bytes(heap.bytes(*new_pin)?),
                    NativeArgument::Int(*new_pin_offset),
                    NativeArgument::Int(*new_pin_length),
                ],
            )?,
            (45, [Int(slot), Int(kind)]) => self.credential_call(
                45,
                &[NativeArgument::Int(*slot), NativeArgument::Int(*kind)],
            )?,
            (46, [Opaque(3)]) => {
                if self.irreversible_output {
                    return Err(Error::Unauthorized);
                }
                self.transaction.begin()?;
                BufferResult::Void
            }
            (47, [Opaque(3)]) => {
                self.transaction.commit()?;
                BufferResult::Void
            }
            (48, [Opaque(3)]) => {
                self.transaction.abort()?;
                BufferResult::Void
            }
            _ => return Err(Error::Unauthorized),
        };
        match result {
            BufferResult::Bytes(bytes) => Ok(Some(heap.allocate_bytes(bytes)?)),
            BufferResult::Scalar(value) => Ok(Some(Int(value))),
            BufferResult::Void => Ok(None),
        }
    }
}
impl<P: Platform> Host<'_, P> {
    fn authorize_storage(
        &self,
        unit: usize,
        key: i32,
        kind: u8,
        value_length: Option<usize>,
    ) -> Result<()> {
        let package = &self
            .units
            .and_then(|units| units.get(unit))
            .ok_or(Error::Unauthorized)?
            .package;
        if package.manifest.incarnation != self.owner {
            return Err(Error::Unauthorized);
        }
        fn find(schema: &[StorageDeclaration], key: i32) -> Option<&StorageDeclaration> {
            schema
                .binary_search_by_key(&key, |declaration| declaration.key)
                .ok()
                .map(|index| &schema[index])
        }
        let declaration = find(&package.manifest.storage, key).ok_or(Error::Unauthorized)?;
        if declaration.kind != kind || find(self.domain_schema, key) != Some(declaration) {
            return Err(Error::Unauthorized);
        }
        if value_length.is_some_and(|length| length > usize::from(declaration.max_bytes)) {
            return Err(Error::Quota);
        }
        Ok(())
    }

    fn credential_call(&mut self, id: u8, args: &[NativeArgument<'_>]) -> Result<BufferResult> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let signature = crate::native_abi::signature(id)?;
        if args.len() != usize::from(signature.arguments) {
            return Err(Error::Bounds);
        }
        let byte_total = match id {
            40 => native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                .len()
                .checked_add(
                    native_range(args[5].bytes()?, args[6].int()?, args[7].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            41 | 43 => {
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len()
            }
            44 => native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?
                .len()
                .checked_add(
                    native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            _ => 0,
        };
        if byte_total > 96 {
            return Err(Error::Quota);
        }
        let cost = 64 + byte_total;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        let result = match id {
            40 => {
                self.credentials.create(
                    self.owner,
                    args[0].int()?,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    native_range(args[5].bytes()?, args[6].int()?, args[7].int()?)?,
                    (args[4].int()?, args[8].int()?),
                    self.platform,
                )?;
                BufferResult::Void
            }
            41 => {
                let slot = args[0].int()?;
                let verified =
                    self.credentials
                        .verify_pin(
                            self.owner,
                            slot,
                            native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                            self.platform,
                        )?;
                if verified {
                    self.authorized_credentials.insert(slot)?;
                } else {
                    self.authorized_credentials.remove(slot);
                    self.record_credential_retry_floor(slot)?;
                }
                BufferResult::Scalar(i32::from(verified))
            }
            42 => BufferResult::Scalar(i32::from(
                self.authorized_credentials.contains(args[0].int()?),
            )),
            43 => {
                let slot = args[0].int()?;
                if !self.authorized_credentials.contains(slot) {
                    return Err(Error::Unauthorized);
                }
                self.credentials.change_pin(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    self.platform,
                )?;
                BufferResult::Void
            }
            44 => {
                let slot = args[0].int()?;
                let unblocked = self.credentials.unblock(
                    self.owner,
                    slot,
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                    native_range(args[4].bytes()?, args[5].int()?, args[6].int()?)?,
                    self.platform,
                )?;
                if unblocked {
                    self.authorized_credentials.insert(slot)?;
                } else {
                    self.record_credential_retry_floor(slot)?;
                }
                BufferResult::Scalar(i32::from(unblocked))
            }
            45 => {
                let (pin, puk) = self.credentials.retries(self.owner, args[0].int()?)?;
                BufferResult::Scalar(i32::from(match args[1].int()? {
                    0 => pin,
                    1 => puk,
                    _ => return Err(Error::Bounds),
                }))
            }
            _ => return Err(Error::Unauthorized),
        };
        Ok(result)
    }

    fn record_credential_retry_floor(&mut self, slot: i32) -> Result<()> {
        let remaining = self.credentials.retries(self.owner, slot)?;
        self.credential_retry_floor.record(slot, remaining)
    }

    fn key_call(&mut self, id: u8, args: &[NativeArgument<'_>]) -> Result<BufferResult> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let signature = crate::native_abi::signature(id)?;
        if args.len() != usize::from(signature.arguments) {
            return Err(Error::Bounds);
        }
        let mut complete_byte_total = 0usize;
        for argument in args {
            if let NativeArgument::Bytes(bytes) = argument {
                let argument_limit = if id == 32 {
                    usize::from(MAX_DECLARED_BLOB_BYTES)
                } else {
                    MAX_KEY_SERVICE_ARGUMENT_BYTES
                };
                if bytes.len() > argument_limit {
                    return Err(Error::Quota);
                }
                complete_byte_total = complete_byte_total
                    .checked_add(bytes.len())
                    .ok_or(Error::Quota)?;
            }
        }
        let byte_total = match id {
            36 => args[0]
                .bytes()?
                .len()
                .checked_add(
                    native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?.len(),
                )
                .ok_or(Error::Quota)?,
            52 => native_range(args[2].bytes()?, args[3].int()?, args[4].int()?)?.len(),
            _ => complete_byte_total,
        };
        if byte_total > MAX_KEY_SERVICE_TOTAL_BYTES {
            return Err(Error::Quota);
        }
        let cost = if matches!(id, 35 | 36 | 38) { 512 } else { 32 } + byte_total / 16;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        // Management credentials never enter this store. A caller can access only its current SSD.
        let bytes = match id {
            22 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                if self.keys.len() >= self.max_key_slots {
                    return Err(Error::Quota);
                }
                self.keys
                    .generate(self.owner, args[1].int()?, args[2].int()?, |b| {
                        self.platform.random(b)
                    })?
            }
            23 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                self.keys.open(self.owner, args[1].int()?)?
            }
            24 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                self.keys.delete(args[1].int()?)?;
                return Ok(BufferResult::Void);
            }
            25 => self.keys.hmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            26 => self.keys.cmac(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            27 | 28 => self.keys.cbc(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                args[2].bytes()?,
                id == 27,
                self.platform,
            )?,
            29 | 30 => {
                let buffers = [args[1].bytes()?, args[2].bytes()?, args[3].bytes()?];
                self.keys.ccm(
                    self.owner,
                    args[0].bytes()?,
                    &buffers,
                    id == 29,
                    self.platform,
                )?
            }
            35 => self.keys.p256_public_key(
                self.owner,
                args[0].bytes()?,
                self.platform,
            )?,
            36 => self.keys.p256_sign(
                self.owner,
                args[0].bytes()?,
                native_range(args[1].bytes()?, args[2].int()?, args[3].int()?)?,
                self.platform,
            )?,
            38 => self.keys.p256_ecdh(
                self.owner,
                args[0].bytes()?,
                args[1].bytes()?,
                self.platform,
            )?,
            31 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                match self.blobs.get(&args[1].int()?) {
                    Some(value) => Self::copy_buffer(value)?,
                    None => Vec::new(),
                }
            }
            32 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let key = args[1].int()?;
                let value = args[2].bytes()?;
                if value.len() > usize::from(MAX_DECLARED_BLOB_BYTES) {
                    return Err(Error::Quota);
                }
                let old = self.blobs.get(&key).map_or(0, Vec::len);
                let total = self.blobs.values().map(Vec::len).sum::<usize>() - old + value.len();
                if (!self.blobs.contains_key(&key) && self.blobs.len() >= self.max_blob_records)
                    || total > self.max_blob_bytes
                {
                    return Err(Error::Quota);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                return Ok(BufferResult::Void);
            }
            52 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let key = args[1].int()?;
                let value = native_range(args[2].bytes()?, args[3].int()?, args[4].int()?)?;
                if value.len() > usize::from(MAX_DECLARED_BLOB_BYTES) {
                    return Err(Error::Quota);
                }
                let old = self.blobs.get(&key).map_or(0, Vec::len);
                let total = self.blobs.values().map(Vec::len).sum::<usize>() - old + value.len();
                if (!self.blobs.contains_key(&key) && self.blobs.len() >= self.max_blob_records)
                    || total > self.max_blob_bytes
                {
                    return Err(Error::Quota);
                }
                let replacement = Self::copy_buffer(value)?;
                self.blobs.insert(key, replacement)?;
                return Ok(BufferResult::Void);
            }
            33 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                let mut removed = self.blobs.remove(&args[1].int()?).ok_or(Error::Missing)?;
                removed.zeroize();
                return Ok(BufferResult::Void);
            }
            34 => {
                if args[0].int()? != 0 {
                    return Err(Error::Unauthorized);
                }
                return Ok(BufferResult::Scalar(
                    self.blobs.contains_key(&args[1].int()?) as i32,
                ));
            }
            _ => return Err(Error::Native),
        };
        Ok(BufferResult::Bytes(bytes))
    }

    fn buffers(&mut self, id: u8, args: &[&[u8]]) -> Result<BufferResult> {
        let cost = if matches!(id, 21 | 37) { 512 } else { 1 }
            + args.iter().map(|value| value.len()).sum::<usize>() / 32;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        match id {
            20 if args.len() == 1 => {
                let mut output = crate::crypto::zeroizing_buffer(32)?;
                self.platform.sha256_into(
                    args[0],
                    output.as_mut_slice().try_into().unwrap(),
                )?;
                Ok(BufferResult::Bytes(core::mem::take(&mut *output)))
            }
            37 if args.len() == 3 => {
                let valid = self.platform.p256_ecdsa_verify(args[0], args[1], args[2])?;
                Ok(BufferResult::Scalar(valid as i32))
            }
            _ => Err(Error::Native),
        }
    }
    fn copy_buffer(value: &[u8]) -> Result<Vec<u8>> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(value.len())
            .map_err(|_| Error::Quota)?;
        copy.extend_from_slice(value);
        Ok(copy)
    }
    fn call(&mut self, id: u8, a: &[i32]) -> Result<Option<i32>> {
        self.charge(id, 0)?;
        let (id, a) = match id {
            7 => (3, &a[1..]),
            8 => (4, &a[1..]),
            _ => (id, a),
        };
        match id {
            9 => Ok(Some(self.level as i32)),
            10 => Ok(Some((self.level != 0) as i32)),
            11 => Ok(Some(i32::try_from(self.data.len()).map_err(|_| Error::Bounds)?)),
            2 => {
                self.sw = u16::try_from(a[0]).map_err(|_| Error::Bounds)?;
                Ok(None)
            }
            3 => Ok(Some(*self.store.get(&a[0]).unwrap_or(&0))),
            4 => {
                if !self.store.contains_key(&a[0]) && self.store.len() >= self.max_int_records {
                    return Err(Error::Quota);
                }
                self.store.insert(a[0], a[1])?;
                Ok(None)
            }
            5 => {
                let mut b = [0; 4];
                self.platform.random(&mut b)?;
                Ok(Some(i32::from_le_bytes(b)))
            }
            6 => {
                self.platform.gpio(a[0], a[1])?;
                Ok(None)
            }
            _ => Err(Error::Native),
        }
    }

    fn fill_random(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        destination: crate::mc04_vm::RuntimeValue,
        offset: i32,
        length: i32,
    ) -> Result<()> {
        if !self.capabilities.contains(&39) {
            return Err(Error::Unauthorized);
        }
        let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        let output = heap
            .bytes_mut(destination)?
            .get_mut(offset..end)
            .ok_or(Error::Bounds)?;
        let cost = length.checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        if let Err(error) = self.platform.random(output) {
            output.fill(0);
            return Err(error);
        }
        Ok(())
    }

    fn sha256_into(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        input: crate::mc04_vm::RuntimeValue,
        input_offset: i32,
        input_length: i32,
        destination: crate::mc04_vm::RuntimeValue,
        destination_offset: i32,
    ) -> Result<i32> {
        if !self.capabilities.contains(&49) {
            return Err(Error::Unauthorized);
        }
        let input_offset = usize::try_from(input_offset).map_err(|_| Error::Bounds)?;
        let input_length = usize::try_from(input_length).map_err(|_| Error::Bounds)?;
        let input_end = input_offset.checked_add(input_length).ok_or(Error::Bounds)?;
        let destination_offset =
            usize::try_from(destination_offset).map_err(|_| Error::Bounds)?;
        let destination_end = destination_offset.checked_add(32).ok_or(Error::Bounds)?;
        heap.bytes(destination)?
            .get(destination_offset..destination_end)
            .ok_or(Error::Bounds)?;
        let input = heap
            .bytes(input)?
            .get(input_offset..input_end)
            .ok_or(Error::Bounds)?;
        let cost = input_length / 32 + 1;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        let mut digest = zeroize::Zeroizing::new([0u8; 32]);
        self.platform.sha256_into(input, &mut digest)?;
        heap.bytes_mut(destination)?[destination_offset..destination_end]
            .copy_from_slice(digest.as_slice());
        Ok(32)
    }

    fn random_bytes(&mut self, length: i32) -> Result<Vec<u8>> {
        if !self.capabilities.contains(&50) {
            return Err(Error::Unauthorized);
        }
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        if length > 1024 {
            return Err(Error::Bounds);
        }
        let cost = length.checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        if length == 0 {
            self.budget -= cost;
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(|_| Error::Quota)?;
        output.resize(length, 0);
        self.budget -= cost;
        if let Err(error) = self.platform.random(&mut output) {
            output.zeroize();
            return Err(error);
        }
        Ok(output)
    }

    fn fixed_time_equals(
        &mut self,
        heap: &crate::mc04_vm::Heap,
        left: (crate::mc04_vm::RuntimeValue, i32, i32),
        right: (crate::mc04_vm::RuntimeValue, i32, i32),
    ) -> Result<i32> {
        if !self.capabilities.contains(&51) {
            return Err(Error::Unauthorized);
        }
        let left_offset = usize::try_from(left.1).map_err(|_| Error::Bounds)?;
        let left_length = usize::try_from(left.2).map_err(|_| Error::Bounds)?;
        let right_offset = usize::try_from(right.1).map_err(|_| Error::Bounds)?;
        let right_length = usize::try_from(right.2).map_err(|_| Error::Bounds)?;
        if left_length > 1024 || right_length > 1024 {
            return Err(Error::Bounds);
        }
        let left_end = left_offset.checked_add(left_length).ok_or(Error::Bounds)?;
        let right_end = right_offset.checked_add(right_length).ok_or(Error::Bounds)?;
        let left = heap
            .bytes(left.0)?
            .get(left_offset..left_end)
            .ok_or(Error::Bounds)?;
        let right = heap
            .bytes(right.0)?
            .get(right_offset..right_end)
            .ok_or(Error::Bounds)?;
        let cost = left_length.max(right_length).checked_add(1).ok_or(Error::Budget)?;
        if self.budget < cost {
            return Err(Error::Budget);
        }
        self.budget -= cost;
        Ok((left.len() == right.len() && bool::from(left.ct_eq(right))) as i32)
    }

    fn copy_command(
        &mut self,
        heap: &mut crate::mc04_vm::Heap,
        destination: crate::mc04_vm::RuntimeValue,
        destination_offset: i32,
        source_offset: i32,
        length: i32,
    ) -> Result<()> {
        let destination_offset = usize::try_from(destination_offset).map_err(|_| Error::Bounds)?;
        let source_offset = usize::try_from(source_offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let source_end = source_offset.checked_add(length).ok_or(Error::Bounds)?;
        let destination_end = destination_offset.checked_add(length).ok_or(Error::Bounds)?;
        let source = self.data.get(source_offset..source_end).ok_or(Error::Bounds)?;
        heap.bytes(destination)?
            .get(destination_offset..destination_end)
            .ok_or(Error::Bounds)?;
        self.charge(12, length)?;
        heap.bytes_mut(destination)?[destination_offset..destination_end].copy_from_slice(source);
        Ok(())
    }

    fn write_response(
        &mut self,
        heap: &crate::mc04_vm::Heap,
        source: crate::mc04_vm::RuntimeValue,
        source_offset: i32,
        length: i32,
    ) -> Result<()> {
        let source_offset = usize::try_from(source_offset).map_err(|_| Error::Bounds)?;
        let length = usize::try_from(length).map_err(|_| Error::Bounds)?;
        let source_end = source_offset.checked_add(length).ok_or(Error::Bounds)?;
        let source = heap
            .bytes(source)?
            .get(source_offset..source_end)
            .ok_or(Error::Bounds)?;
        let output_end = self.out.len().checked_add(length).ok_or(Error::Bounds)?;
        if output_end > MAX_MANAGED_RESPONSE_BYTES {
            return Err(Error::Quota);
        }
        self.out.try_reserve(length).map_err(|_| Error::Quota)?;
        self.charge(13, length)?;
        self.out.extend_from_slice(source);
        Ok(())
    }

    fn charge(&mut self, id: u8, bytes: usize) -> Result<()> {
        if !self.capabilities.contains(&id) {
            return Err(Error::Unauthorized);
        }
        let cost = bytes.checked_add(1).ok_or(Error::Budget)?;
        self.budget = self.budget.checked_sub(cost).ok_or(Error::Budget)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
