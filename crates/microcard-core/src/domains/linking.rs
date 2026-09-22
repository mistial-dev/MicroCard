//! Resolve authenticated dependencies and validate the complete MC04 call graph.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]

pub(super) struct ResolvedDependency {

    pub(super) digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]

pub(super) struct ResolvedCall {
    pub(super) member: u16,
    pub(super) target: CallTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]

pub(super) enum CallTarget {
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

pub(super) fn resolve_calls<F: crate::image_store::ImageReader>(
    state: &State,
    package: &impl PackageData,
    bindings: &[ResolvedDependency],
    flash: &F,
    crypto: &mut impl crate::crypto::CryptoProvider,
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
    // Several imports can target the same provider; authenticate and borrow it once.
    let mut providers = Vec::new();
    providers.try_reserve_exact(bindings.len()).map_err(|_| Error::Quota)?;
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
            let metadata = provider.package_metadata(provider_name)?;
            let index = match providers.iter().position(|(index, _)| *index == dependency) {
                Some(index) => index,
                None => {
                    let descriptor = provider.image_refs.get(provider_name).ok_or(Error::Storage)?;
                    let raw = descriptor.read_verified(flash, crypto)?;
                    providers.push((dependency, raw));
                    providers.len() - 1
                }
            };
            let provider = metadata.view(&providers[index].1)?;
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

pub(super) struct ExecutionUnit<'a> {
    pub(super) package: StoredPackageView<'a>,
    pub(super) bindings: &'a [ResolvedDependency],
    pub(super) calls: &'a [ResolvedCall],
}

type PackageSource<'a> = (&'a str, &'a str, &'a Domain);

pub(super) fn push_execution_source<'a>(state: &'a State, sources: &mut Vec<PackageSource<'a>>, domain: &'a str,
        assembly: &'a str, expected: Option<[u8; 32]>) -> Result<()> {
        let source = state.domain(domain).ok_or(Error::Domain)?;
        let metadata = source.package_metadata(assembly)?;
        if sources.iter().any(|(d, a, _)| *d == domain && *a == assembly) {
            if expected.is_some_and(|digest| digest != metadata.digest) { return Err(Error::Storage); }
            return Ok(());
        }
        if expected.is_some_and(|digest| digest != metadata.digest) { return Err(Error::Unauthorized); }
        if sources.len() >= MAX_EXECUTION_UNITS { return Err(Error::Quota); }
        sources.push((domain, assembly, source));
        Ok(())
    }

fn execution_sources<'a>(state: &'a State, domain: &str, assembly: &str) -> Result<Vec<PackageSource<'a>>> {
    let (domain, source) = state.domain_entry(domain).ok_or(Error::Domain)?;
    let (assembly, _) = source.packages.get_key_value(assembly).ok_or(Error::Missing)?;
    let mut sources = Vec::new();
    sources.try_reserve_exact(MAX_EXECUTION_UNITS).map_err(|_| Error::Quota)?;
    push_execution_source(state, &mut sources, domain, assembly, None)?;
    let mut cursor = 0;
    while cursor < sources.len() {
        let (_, name, source) = sources[cursor];
        let calls = source.imports.get(name).ok_or(Error::Storage)?;
        let bindings = source.bindings.get(name).ok_or(Error::Storage)?;
        for call in calls {
            if let CallTarget::Managed { dependency, .. } = call.target {
                let digest = bindings.get(usize::from(dependency)).ok_or(Error::Storage)?.digest;
                let (domain, assembly, _) = state.assembly_by_digest(&digest)?;
                push_execution_source(state, &mut sources, domain, assembly, Some(digest))?;
            }
        }
        cursor += 1;
    }
    Ok(sources)
}

enum PackageBytes<'a, F: crate::image_store::ImageReader + 'a> {
    Stored(F::Image<'a>),
    Candidate(&'a [u8]),
}
impl<F: crate::image_store::ImageReader> core::ops::Deref for PackageBytes<'_, F> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self { Self::Stored(bytes) => bytes, Self::Candidate(bytes) => bytes }
    }
}

struct BorrowedPackage<'a, F: crate::image_store::ImageReader + 'a> {
    metadata: &'a StoredPackage,
    raw: PackageBytes<'a, F>,
    bindings: &'a [ResolvedDependency],
    calls: &'a [ResolvedCall],
}

pub(super) struct BorrowedExecution<'a, F: crate::image_store::ImageReader + 'a> {
    packages: Vec<BorrowedPackage<'a, F>>,
}

impl<'a, F: crate::image_store::ImageReader + 'a> BorrowedExecution<'a, F> {
    pub(super) fn new(state: &'a State, flash: &'a F, provider: &mut impl crate::crypto::CryptoProvider,
        domain: &str, assembly: &str) -> Result<Self> {
        Self::load(state, flash, provider, domain, assembly, None)
    }

    /// The candidate has already passed package verification, but has not been staged.
    pub(super) fn with_candidate(state: &'a State, flash: &'a F,
        provider: &mut impl crate::crypto::CryptoProvider, domain: &str, assembly: &str,
        candidate: &'a [u8]) -> Result<Self> {
        Self::load(state, flash, provider, domain, assembly, Some(candidate))
    }

    fn load(state: &'a State, flash: &'a F, provider: &mut impl crate::crypto::CryptoProvider,
        domain: &str, assembly: &str, candidate: Option<&'a [u8]>) -> Result<Self> {
        let sources = execution_sources(state, domain, assembly)?;
        let mut packages = Vec::new();
        packages.try_reserve_exact(sources.len()).map_err(|_| Error::Quota)?;
        for (_, name, source) in sources {
            let raw = match (packages.is_empty(), candidate) {
                (true, Some(candidate)) => PackageBytes::Candidate(candidate),
                _ => {
                    let descriptor = source.image_refs.get(name).ok_or(Error::Storage)?;
                    PackageBytes::Stored(descriptor.read_verified(flash, provider)?)
                }
            };
            packages.push(BorrowedPackage {
                metadata: source.package_metadata(name)?,
                raw,
                bindings: source.bindings.get(name).ok_or(Error::Storage)?,
                calls: source.imports.get(name).ok_or(Error::Storage)?,
            });
        }
        Ok(Self { packages })
    }

    pub(super) fn units(&self) -> Result<Vec<ExecutionUnit<'_>>> {
        let mut units = Vec::new();
        units.try_reserve_exact(self.packages.len()).map_err(|_| Error::Quota)?;
        for package in &self.packages {
            units.push(ExecutionUnit { package: package.metadata.view(&package.raw)?,
                bindings: package.bindings, calls: package.calls });
        }
        validate_linked_program(&units)?;
        Ok(units)
    }
}

pub(super) fn validate_program_graph(
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

pub(super) fn push_link_edge(edges: &mut Vec<(usize, usize)>, edge: (usize, usize)) -> Result<()> {
    if edges.len() >= MAX_LINKED_CALL_EDGES {
        return Err(Error::Quota);
    }
    edges.try_reserve(1).map_err(|_| Error::Quota)?;
    edges.push(edge);
    Ok(())
}

pub(super) fn validate_linked_program(units: &[ExecutionUnit<'_>]) -> Result<()> {
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

pub(super) trait PackageData {
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

pub(super) fn resolve_dependency(
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
            .and_then(|d| d.package_metadata(dependency.assembly.as_str()).ok())
            .filter(|provider| {
                dependency.matches_parts(&provider.manifest, provider.signer, provider.digest)
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
