//! Persisted MC04 ownership, package metadata, and application state.
use super::*;

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub(super) struct State {
    pub(super) isd: Domain,
    pub(super) domains: Domains,
    /// First SCP03 sequence counter value never yet handed out, SCP03 1.1.2.6 §6.2.2.1.
    ///
    /// Reserved ahead of use so a power cut can only skip values, never repeat one.
    pub(super) scp03_sequence: u32,
}

impl State {
    pub(super) fn domain(&self, id: &str) -> Option<&Domain> {
        if id == "ISD" {
            Some(&self.isd)
        } else {
            self.domains.get(id)
        }
    }

    #[cfg(test)]
    pub(super) fn domain_mut(&mut self, id: &str) -> Option<&mut Domain> {
        if id == "ISD" {
            Some(&mut self.isd)
        } else {
            self.domains.get_mut(id)
        }
    }

    pub(super) fn domain_entry(&self, id: &str) -> Option<(&str, &Domain)> {
        if id == "ISD" {
            Some(("ISD", &self.isd))
        } else {
            self.domains
                .get_key_value(id)
                .map(|(identifier, domain)| (identifier.as_str(), domain))
        }
    }

    pub(super) fn is_owned(&self) -> bool {
        self.isd.key.is_some() && self.isd.image_refs.contains_key("mscorlib")
    }

    pub(super) fn assembly_by_digest(&self, digest: &[u8; 32]) -> Result<(&str, &str, &Domain)> {
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

    pub(super) fn provider_in_use(&self, provider_domain: &str, provider_assembly: &str) -> bool {
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

    pub(super) fn registry_aid_in_use(&self, aid: RegistryAid) -> bool {
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

    pub(super) fn registry_aid_reserved_by_non_assembly(&self, aid: RegistryAid) -> bool {
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

    pub(super) fn domain_identifier_by_registry_aid(&self, aid: RegistryAid) -> Option<&str> {
        if aid == RegistryAid::isd() {
            return Some("ISD");
        }
        self.domains
            .iter()
            .find(|(_, domain)| domain.registry_aid == aid)
            .map(|(identifier, _)| identifier.as_str())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredPackage {
    pub(super) manifest: Manifest,
    pub(super) image: core::ops::Range<usize>,
    pub(super) signer: [u8; 32],
    pub(super) digest: [u8; 32],
}

impl StoredPackage {
    pub(super) fn view<'a>(&'a self, raw: &'a [u8]) -> Result<StoredPackageView<'a>> {
        Ok(StoredPackageView {
            #[cfg(test)]
            raw,
            manifest: &self.manifest,
            image: raw.get(self.image.clone()).ok_or(Error::Storage)?,
            signer: self.signer,
            digest: self.digest,
        })
    }

    pub(super) fn from_verified(package: PackageView<'_>) -> Self {
        let start = package.image.as_ptr() as usize - package.raw.as_ptr() as usize;
        Self {
            image: start..start + package.image.len(),
            manifest: package.manifest,
            signer: package.signer,
            digest: package.digest,
        }
    }
}

pub(super) struct StoredPackageView<'a> {
    #[cfg(test)]
    pub(super) raw: &'a [u8],
    pub(super) manifest: &'a Manifest,
    pub(super) image: &'a [u8],
    pub(super) signer: [u8; 32],
    pub(super) digest: [u8; 32],
}

#[cfg(test)]
impl<'a> From<&'a PackageView<'a>> for StoredPackageView<'a> {
    fn from(package: &'a PackageView<'a>) -> Self {
        Self {
            raw: package.raw,
            manifest: &package.manifest,
            image: package.image,
            signer: package.signer,
            digest: package.digest,
        }
    }
}

impl PackageData for StoredPackageView<'_> {
    fn manifest(&self) -> &Manifest {
        self.manifest
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

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Domain {
    pub(super) incarnation: [u8; 16],
    pub(super) registry_aid: RegistryAid,
    pub(super) key: Option<[u8; 32]>,
    pub(super) packages: NameMap<Rc<StoredPackage>>,
    pub(super) image_refs: NameMap<crate::image_store::Descriptor>,
    pub(super) bindings: NameMap<Vec<ResolvedDependency>>,
    pub(super) imports: NameMap<Vec<ResolvedCall>>,
    pub(super) versions: NameMap<(u32, [u8; 32])>,
    pub(super) storage_schema: Rc<Vec<StorageDeclaration>>,
    pub(super) instances: Instances,
    pub(super) store: IntStore,
    pub(super) blobs: BlobStore,
    pub(super) keys: crate::key_store::KeyStore,
    pub(super) credentials: crate::credential_store::CredentialStore,
    pub(super) policy: DomainPolicy,
}

impl Drop for Domain {
    fn drop(&mut self) {
        self.zeroize_application_state();
    }
}

impl Domain {
    pub(super) fn package_metadata(&self, name: &str) -> Result<&StoredPackage> {
        self.packages
            .get(name)
            .map(Rc::as_ref)
            .ok_or(Error::Missing)
    }

    pub(super) fn new(
        incarnation: [u8; 16],
        registry_aid: RegistryAid,
        policy: DomainPolicy,
    ) -> Self {
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

    pub(super) fn zeroize_application_state(&mut self) {
        for value in self.store.values_mut() {
            value.zeroize();
        }
        for value in self.blobs.values_mut() {
            value.zeroize();
        }
    }

    pub(super) fn intern_assembly_names(&mut self) -> Result<()> {
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

    pub(super) fn storage_declaration(&self, key: i32) -> Option<&StorageDeclaration> {
        self.storage_schema
            .binary_search_by_key(&key, |declaration| declaration.key)
            .ok()
            .map(|index| &self.storage_schema[index])
    }

    pub(super) fn merged_storage_schema(
        &self,
        declarations: &[StorageDeclaration],
    ) -> Result<Rc<Vec<StorageDeclaration>>> {
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
            if let Err(index) =
                merged.binary_search_by_key(&declaration.key, |existing| existing.key)
            {
                merged.insert(index, *declaration);
            }
        }
        Ok(Rc::new(merged))
    }

    pub(super) fn is_unbound_and_empty(&self) -> bool {
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
