//! MicroCard domain profile, not a GlobalPlatform card implementation.
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
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub use crate::hal::RuntimePlatform as Platform;

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
const STORAGE_SCHEMA_GROWTH: usize = 16;
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

impl<V: Serialize> Serialize for NameMap<V> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (name, value) in self.iter() {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for NameMap<V> {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::{fmt, marker::PhantomData};
        use serde::de::{MapAccess, Visitor};

        struct NameMapVisitor<V>(PhantomData<V>);

        impl<'de, V: Deserialize<'de>> Visitor<'de> for NameMapVisitor<V> {
            type Value = NameMap<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of up to eight assembly identities")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = NameMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if values.len() >= MAX_ASSEMBLIES_PER_DOMAIN as usize {
                        return Err(serde::de::Error::custom("assembly map quota"));
                    }
                    if values.contains_key(&name) {
                        return Err(serde::de::Error::custom("duplicate assembly identity"));
                    }
                    values
                        .reserve_entry()
                        .map_err(|_| serde::de::Error::custom("assembly map allocation"))?;
                    let value = map.next_value::<V>()?;
                    values
                        .insert(Rc::from(name), value)
                        .map_err(|_| serde::de::Error::custom("assembly map quota"))?;
                }
                Ok(values)
            }
        }

        deserializer.deserialize_map(NameMapVisitor(PhantomData))
    }
}

mod package_map {
    use super::*;
    use core::fmt;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;

    type Packages = NameMap<Rc<Vec<u8>>>;

    const ENCODE_CHUNK_BYTES: usize = 48;
    const ENCODE_CHUNK_CHARS: usize = 64;

    struct Base64Display<'a>(&'a [u8]);

    impl fmt::Display for Base64Display<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut encoded = [0; ENCODE_CHUNK_CHARS];
            for chunk in self.0.chunks(ENCODE_CHUNK_BYTES) {
                let value = Base64::encode(chunk, &mut encoded).map_err(|_| fmt::Error)?;
                formatter.write_str(value)?;
            }
            Ok(())
        }
    }

    impl Serialize for Base64Display<'_> {
        fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.collect_str(self)
        }
    }

    fn canonical(raw: &[u8], encoded: &str) -> bool {
        if encoded.len() != raw.len().div_ceil(3) * 4 {
            return false;
        }
        let mut position = 0;
        let mut output = [0; ENCODE_CHUNK_CHARS];
        for chunk in raw.chunks(ENCODE_CHUNK_BYTES) {
            let Ok(value) = Base64::encode(chunk, &mut output) else {
                return false;
            };
            let end = position + value.len();
            if encoded.as_bytes().get(position..end) != Some(value.as_bytes()) {
                return false;
            }
            position = end;
        }
        position == encoded.len()
    }

    fn decode<E: serde::de::Error>(encoded: &str) -> core::result::Result<Vec<u8>, E> {
        const MAX_ENCODED_PACKAGE_BYTES: usize = MAX_PACKAGE_BYTES.div_ceil(3) * 4;
        if encoded.len() > MAX_ENCODED_PACKAGE_BYTES || !encoded.len().is_multiple_of(4) {
            return Err(E::custom("invalid package encoding length"));
        }
        let padding = encoded
            .as_bytes()
            .iter()
            .rev()
            .take_while(|byte| **byte == b'=')
            .count();
        if padding > 2 {
            return Err(E::custom("invalid package encoding padding"));
        }
        let decoded_len = encoded.len() / 4 * 3 - padding;
        let mut raw = Vec::new();
        raw.try_reserve_exact(decoded_len)
            .map_err(|_| E::custom("package allocation failed"))?;
        raw.resize(decoded_len, 0);
        let length = Base64::decode(encoded, &mut raw).map_err(E::custom)?.len();
        if length != raw.len() {
            return Err(E::custom("invalid package encoding length"));
        }
        if !canonical(&raw, encoded) {
            return Err(E::custom("noncanonical package encoding"));
        }
        Ok(raw)
    }

    struct PackageBytes(Vec<u8>);

    impl<'de> Deserialize<'de> for PackageBytes {
        fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct PackageVisitor;

            impl Visitor<'_> for PackageVisitor {
                type Value = PackageBytes;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("canonical Base64 package bytes")
                }

                fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    decode(value).map(PackageBytes)
                }

                fn visit_borrowed_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    self.visit_str(value)
                }
            }

            deserializer.deserialize_str(PackageVisitor)
        }
    }

    pub(super) fn serialize<S>(
        packages: &Packages,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(packages.len()))?;
        for (name, raw) in packages.iter() {
            map.serialize_entry(name.as_ref(), &Base64Display(raw))?;
        }
        map.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Packages, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PackagesVisitor;

        impl<'de> Visitor<'de> for PackagesVisitor {
            type Value = Packages;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a package map")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut packages = NameMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if packages.len() >= MAX_ASSEMBLIES_PER_DOMAIN as usize {
                        return Err(serde::de::Error::custom("package map quota"));
                    }
                    if packages.contains_key(&name) {
                        return Err(serde::de::Error::custom("duplicate package name"));
                    }
                    packages
                        .reserve_entry()
                        .map_err(|_| serde::de::Error::custom("package map allocation"))?;
                    let PackageBytes(raw) = map.next_value::<PackageBytes>()?;
                    packages
                        .insert(Rc::from(name), Rc::new(raw))
                        .map_err(|_| serde::de::Error::custom("package map quota"))?;
                }
                Ok(packages)
            }
        }

        deserializer.deserialize_map(PackagesVisitor)
    }
}

mod storage_schema {
    use super::*;
    use core::fmt;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;

    type Schema = Rc<Vec<StorageDeclaration>>;

    pub fn serialize<S>(schema: &Schema, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(schema.len()))?;
        for declaration in schema.iter() {
            sequence.serialize_element(&(
                declaration.key,
                declaration.kind,
                declaration.max_bytes,
            ))?;
        }
        sequence.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> core::result::Result<Schema, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SchemaVisitor;

        impl<'de> Visitor<'de> for SchemaVisitor {
            type Value = Schema;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sorted sequence of persistent storage declarations")
            }

            fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_DOMAIN_STORAGE_DECLARATIONS);
                let mut declarations = Vec::new();
                declarations
                    .try_reserve_exact(capacity)
                    .map_err(|_| serde::de::Error::custom("storage schema allocation"))?;
                while let Some((key, kind, max_bytes)) =
                    sequence.next_element::<(i32, u8, u16)>()?
                {
                    if declarations.len() >= MAX_DOMAIN_STORAGE_DECLARATIONS {
                        return Err(serde::de::Error::custom("storage schema quota"));
                    }
                    let declaration = StorageDeclaration { key, kind, max_bytes };
                    if !declaration.valid()
                        || declarations
                            .last()
                            .is_some_and(|previous: &StorageDeclaration| previous.key >= key)
                    {
                        return Err(serde::de::Error::custom("invalid storage schema"));
                    }
                    if declarations.len() == declarations.capacity() {
                        let target = (declarations.len() + STORAGE_SCHEMA_GROWTH)
                            .min(MAX_DOMAIN_STORAGE_DECLARATIONS);
                        declarations
                            .try_reserve_exact(target - declarations.len())
                            .map_err(|_| serde::de::Error::custom("storage schema allocation"))?;
                    }
                    declarations.push(declaration);
                }
                Ok(Rc::new(declarations))
            }
        }

        deserializer.deserialize_seq(SchemaVisitor)
    }
}

mod digest_bytes {
    use super::*;
    use core::fmt;
    use serde::de::Visitor;

    pub(super) fn serialize<S>(
        digest: &[u8; 32],
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut encoded = [0; 44];
        let value = Base64::encode(digest, &mut encoded).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(value)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DigestVisitor;

        impl Visitor<'_> for DigestVisitor {
            type Value = [u8; 32];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical Base64-encoded 32-byte digest")
            }

            fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut digest = [0; 32];
                let decoded = Base64::decode(value, &mut digest).map_err(E::custom)?;
                if decoded.len() != digest.len() {
                    return Err(E::custom("digest must be 32 bytes"));
                }
                let mut encoded = [0; 44];
                if Base64::encode(&digest, &mut encoded).map_err(E::custom)? != value {
                    return Err(E::custom("noncanonical digest encoding"));
                }
                Ok(digest)
            }

            fn visit_borrowed_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }
        }

        deserializer.deserialize_str(DigestVisitor)
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

impl Serialize for Domains {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (id, domain) in self.iter() {
            map.serialize_entry(id, domain)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Domains {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::{MapAccess, Visitor};

        struct DomainsVisitor;

        impl<'de> Visitor<'de> for DomainsVisitor {
            type Value = Domains;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of at most eight security domains")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut domains = Domains::new();
                domains
                    .0
                    .try_reserve_exact(MAX_SSDS)
                    .map_err(|_| serde::de::Error::custom("domain allocation"))?;
                while let Some(id) = map.next_key::<String>()? {
                    if domains.len() >= MAX_SSDS {
                        return Err(serde::de::Error::custom("domain quota"));
                    }
                    if domains.contains_key(&id) {
                        return Err(serde::de::Error::custom("duplicate domain"));
                    }
                    let domain = map.next_value::<Domain>()?;
                    domains
                        .insert(id, domain)
                        .map_err(|_| serde::de::Error::custom("domain quota"))?;
                }
                Ok(domains)
            }
        }

        deserializer.deserialize_map(DomainsVisitor)
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

impl Serialize for IntStore {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for IntStore {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::{MapAccess, Visitor};

        struct IntStoreVisitor;

        impl<'de> Visitor<'de> for IntStoreVisitor {
            type Value = IntStore;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of at most 512 integer records")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut store = IntStore::new();
                while let Some(key) = map.next_key::<i32>()? {
                    if store.len() >= MAX_INT_RECORDS {
                        return Err(serde::de::Error::custom("integer record quota"));
                    }
                    if store.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate integer record"));
                    }
                    let value = map.next_value::<i32>()?;
                    store
                        .insert(key, value)
                        .map_err(|_| serde::de::Error::custom("integer record allocation"))?;
                }
                Ok(store)
            }
        }

        deserializer.deserialize_map(IntStoreVisitor)
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

impl Serialize for BlobStore {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for BlobStore {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::{MapAccess, Visitor};

        struct BlobStoreVisitor;

        impl<'de> Visitor<'de> for BlobStoreVisitor {
            type Value = BlobStore;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of at most 64 byte records")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut store = BlobStore::new();
                while let Some(key) = map.next_key::<i32>()? {
                    if store.len() >= MAX_BLOB_RECORDS {
                        return Err(serde::de::Error::custom("byte record quota"));
                    }
                    if store.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate byte record"));
                    }
                    let value = map.next_value::<Vec<u8>>()?;
                    store
                        .insert(key, value)
                        .map_err(|_| serde::de::Error::custom("byte record allocation"))?;
                }
                Ok(store)
            }
        }

        deserializer.deserialize_map(BlobStoreVisitor)
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    isd: Domain,
    domains: Domains,
    /// First SCP03 sequence counter value never yet handed out, SCP03 1.1.2.6 §6.2.2.1.
    ///
    /// Reserved ahead of use so a power cut can only skip values, never repeat one. A
    /// card that has opened no derived-challenge session omits the field, which keeps
    /// existing snapshots byte-identical through the canonical re-encoding check.
    #[serde(default, skip_serializing_if = "sequence_unused")]
    scp03_sequence: u32,
}

fn sequence_unused(reserved: &u32) -> bool {
    *reserved == 0
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedDependency {
    #[serde(with = "digest_bytes")]
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedCall {
    member: u16,
    target: CallTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
            let provider_raw = provider.assemblies.get(provider_name).ok_or(Error::Missing)?;
            let provider = PackageView::verify(provider_raw)?;
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
    package: PackageView<'a>,
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
    let package = PackageView::verify(source.assemblies.get(assembly).ok_or(Error::Missing)?)?;
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
        self.key
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
        self.key
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
            .and_then(|d| d.assemblies.get(dependency.assembly.as_str()))
            .and_then(|raw| PackageView::verify(raw).ok())
            .filter(|provider| {
                dependency.matches_view(provider)
                    && provider
                        .manifest
                        .export
                        .allows(provider.key, consumer.key())
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        capabilities.try_reserve_exact(45).map_err(|_| Error::Quota)?;
        capabilities.extend((2..=13).chain(20..=52));
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryAid {
    bytes: [u8; 16],
    len: u8,
}

impl RegistryAid {
    fn new(value: &[u8]) -> Result<Self> {
        if !(5..=16).contains(&value.len()) {
            return Err(Error::Format);
        }
        let mut bytes = [0; 16];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }

    fn isd() -> Self {
        Self::new(&crate::globalplatform::ISD_AID).unwrap()
    }

    fn synthetic(kind: u8, stable: &[u8]) -> Self {
        Self {
            bytes: crate::globalplatform::synthetic_aid(kind, stable),
            len: 16,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn valid(&self) -> bool {
        (5..=16).contains(&self.len)
            && self.bytes[usize::from(self.len)..]
                .iter()
                .all(|byte| *byte == 0)
    }
}

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

impl Serialize for Instances {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (aid, assembly) in self.iter() {
            map.serialize_entry(aid, assembly)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Instances {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::{MapAccess, Visitor};

        struct InstancesVisitor;

        impl<'de> Visitor<'de> for InstancesVisitor {
            type Value = Instances;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of up to eight installed instances")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut instances = Instances::new();
                while let Some(aid) = map.next_key::<String>()? {
                    if instances.len() >= MAX_INSTANCES_PER_DOMAIN as usize {
                        return Err(serde::de::Error::custom("instance quota"));
                    }
                    if instances.contains_key(&aid) {
                        return Err(serde::de::Error::custom("duplicate instance"));
                    }
                    instances
                        .reserve_entry()
                        .map_err(|_| serde::de::Error::custom("instance allocation"))?;
                    let assembly = map.next_value::<Rc<str>>()?;
                    instances
                        .insert(aid, assembly)
                        .map_err(|_| serde::de::Error::custom("instance quota"))?;
                }
                Ok(instances)
            }
        }

        deserializer.deserialize_map(InstancesVisitor)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    incarnation: [u8; 16],
    registry_aid: RegistryAid,
    key: Option<[u8; 32]>,
    #[serde(with = "package_map")]
    assemblies: NameMap<Rc<Vec<u8>>>,
    bindings: NameMap<Vec<ResolvedDependency>>,
    imports: NameMap<Vec<ResolvedCall>>,
    versions: NameMap<(u32, [u8; 32])>,
    #[serde(with = "storage_schema")]
    storage_schema: Rc<Vec<StorageDeclaration>>,
    instances: Instances,
    store: IntStore,
    #[serde(default, skip_serializing_if = "BlobStore::is_empty")]
    blobs: BlobStore,
    #[serde(default)]
    keys: crate::key_store::KeyStore,
    #[serde(default)]
    credentials: crate::credential_store::CredentialStore,
    policy: DomainPolicy,
}
impl Drop for Domain {
    fn drop(&mut self) {
        self.zeroize_application_state();
    }
}
impl Domain {
    fn new(incarnation: [u8; 16], registry_aid: RegistryAid, policy: DomainPolicy) -> Self {
        Self {
            incarnation,
            registry_aid,
            key: None,
            assemblies: NameMap::new(),
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
        raw: &'a [u8],
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
                for (assembly, raw) in domain.assemblies.iter() {
                    let digest = domain.versions.get(assembly).ok_or(Error::Storage)?.1;
                    let aid = crate::globalplatform::synthetic_aid(0x4c, &digest);
                    visit(
                        &aid,
                        RegistryEntry::Load {
                            domain_id,
                            domain,
                            assembly,
                            raw,
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
            raw,
        } => {
            let package = PackageView::verify(raw)?;
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
            domain.registry_aid.bytes,
            usize::from(domain.registry_aid.len),
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
    serde_json::from_slice(data).map_err(|_| Error::Format)
}

fn management_names_wire(first: &str, second: &str) -> Result<Vec<u8>> {
    if !crate::package::valid_identifier(first) || !crate::package::valid_identifier(second) {
        return Err(Error::Format);
    }
    let capacity = first
        .len()
        .checked_add(second.len())
        .and_then(|length| length.checked_add(7))
        .ok_or(Error::Quota)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Quota)?;
    output.extend_from_slice(b"[\"");
    output.extend_from_slice(first.as_bytes());
    output.extend_from_slice(b"\",\"");
    output.extend_from_slice(second.as_bytes());
    output.extend_from_slice(b"\"]");
    Ok(output)
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
    hash: [u8; 32],
    total: Option<usize>,
    next_block: u16,
    /// Which engine the block is for, decided from the first block's own bytes.
    payload: Option<crate::globalplatform::Payload>,
}

pub struct Card<F: Flash, P: Platform, S: PackageStaging = RamStaging> {
    journal: Journal<F>,
    state: State,
    platform: P,
    staging: S,
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
impl<F: Flash, P: Platform> Card<F, P, RamStaging> {
    pub fn open(flash: F, platform: P, storage_key: impl Into<JournalKey>) -> Result<Self> {
        Self::open_with_staging(flash, platform, storage_key, RamStaging::default())
    }
}

impl<F: Flash, P: Platform, S: PackageStaging> Card<F, P, S> {
    pub fn open_with_staging(
        flash: F,
        mut platform: P,
        storage_key: impl Into<JournalKey>,
        staging: S,
    ) -> Result<Self> {
        let (mut journal, data) = Journal::open_with(flash, storage_key, &mut platform)?;
        let state: State = match data {
            Some(d) => {
                if d.len() > 49152 {
                    return Err(Error::Storage);
                }
                let mut state: State = serde_json::from_slice(&d).map_err(|_| Error::Storage)?;
                // Writers emit canonical snapshots. Reject duplicate map keys and ignored fields.
                let canonical =
                    Zeroizing::new(serde_json::to_vec(&state).map_err(|_| Error::Storage)?);
                if canonical.as_slice() != d.as_slice() {
                    return Err(Error::Storage);
                }
                state.isd.intern_assembly_names()?;
                for domain in state.domains.values_mut() {
                    domain.intern_assembly_names()?;
                }
                state
            }
            None => {
                let mut incarnation = [0; 16];
                platform.random(&mut incarnation)?;
                let state = State {
                    isd: Domain::new(incarnation, RegistryAid::isd(), DomainPolicy::standard()?),
                    domains: Domains::new(),
                    scp03_sequence: 0,
                };
                let encoded =
                    Zeroizing::new(serde_json::to_vec(&state).map_err(|_| Error::Storage)?);
                journal.commit_with(encoded.as_slice(), &mut platform)?;
                state
            }
        };
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
            if let Some(key) = d.key {
                if !platform.ed25519_public_key_valid(&key)? {
                    return Err(Error::Storage);
                }
            }
            d.keys.validate()?;
            d.credentials.validate(d.incarnation)?;
            let mut domain_package_bytes = 0usize;
            for (name, raw) in d.assemblies.iter() {
                total_bytes += raw.len();
                domain_package_bytes += raw.len();
                let p = PackageView::verify_with(raw, &mut platform)?;
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
                    || Some(p.key) != d.key
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
                let raw = d
                    .assemblies
                    .get(assembly.as_ref())
                    .ok_or(Error::Storage)?;
                let p = PackageView::verify_with(raw, &mut platform)?;
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
        should_cancel: &mut impl FnMut() -> bool,
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
        should_cancel: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        self.abort_transaction();
        if verified.level & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
            return Err(Error::Unauthorized);
        }
        let command = verified.command;
        if command.ins == 0xe6 && command.p1 == 0x02 {
            let request = crate::globalplatform::load_request(&command)?;
            let load_aid = RegistryAid::new(request.load_aid)?;
            if load_aid != RegistryAid::synthetic(0x4c, &request.hash) {
                return Err(Error::Format);
            }
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
                hash: request.hash,
                total: None,
                next_block: 0,
                payload: None,
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
            let aid = encode_aid(install.instance_aid)?;
            debug_assert_eq!(install.module_aid, install.instance_aid);
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
        should_cancel: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        if command.ins != 0xe8 || !matches!(command.p1, 0 | 0x80) || command.data.is_empty() {
            return Err(Error::Format);
        }
        let load = self.globalplatform_load.as_mut().ok_or(Error::Format)?;
        if load.next_block > u16::from(u8::MAX) || command.p2 != load.next_block as u8 {
            return Err(Error::Format);
        }
        let chunk = if load.next_block == 0 {
            let (total, value) = crate::globalplatform::load_file_data(&command.data)?;
            load.total = Some(total);
            // The first block is where a load file says which engine it belongs to, so the
            // card decides once and from the bytes themselves.
            let payload = crate::globalplatform::payload_kind(value)?;
            if payload == crate::globalplatform::Payload::JavaCard {
                // The Java Card engine runs a load file the simulator hands it directly.
                // Nothing delivers one through GlobalPlatform yet, so refusing here keeps
                // the card from staging bytes it has no way to activate.
                return Err(Error::Unsupported);
            }
            load.payload = Some(payload);
            value
        } else {
            &command.data
        };
        let total = load.total.ok_or(Error::Format)?;
        let end = self
            .staging
            .len()
            .checked_add(chunk.len())
            .ok_or(Error::Bounds)?;
        if end > total || end > MAX_PACKAGE_BYTES {
            return Err(Error::Quota);
        }
        self.staging.append(chunk)?;
        load.next_block += 1;
        let last = command.p1 == 0x80;
        if !last {
            if end == total || command.p2 == u8::MAX {
                return Err(Error::Format);
            }
            return fallible_filled(1, 0);
        }
        if end != total {
            return Err(Error::Format);
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
        should_cancel: &mut impl FnMut() -> bool,
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
    fn commit(&mut self, next: State) -> Result<()> {
        if self.state == next {
            return Ok(());
        }
        let data = Zeroizing::new(serde_json::to_vec(&next).map_err(|_| Error::Storage)?);
        if data.len() > 49152 {
            return Err(Error::Quota);
        }
        self.journal
            .commit_with(data.as_slice(), &mut self.platform)?;
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
        should_cancel: &mut impl FnMut() -> bool,
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
                    expected.as_ref().map(|(hash, _)| hash),
                )?;
                if expected
                    .as_ref()
                    .is_some_and(|(_, domain)| p.manifest.domain != *domain)
                {
                    return Err(Error::Domain);
                }
                let registry_aid = RegistryAid::synthetic(0x4c, &p.digest);
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
                if d.key.is_some_and(|key| key != p.key) {
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
                let signing_key = p.key;
                let version = p.manifest.version;
                let digest = p.digest;
                let activated_domain = fallible_string(&p.manifest.domain)?;
                let activated_assembly: Rc<str> = Rc::from(p.manifest.assembly.as_str());
                drop(p);

                let raw = Rc::new(match materialized {
                    Some(raw) => raw,
                    None => self.staging.take()?,
                });
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
                        .assemblies
                        .values()
                        .filter_map(|raw| PackageView::verify(raw).ok())
                        .find(|package| {
                            package
                                .manifest
                                .entry_points
                                .iter()
                                .any(|entry| entry.aid == args.1)
                        })
                        .map(|package| package.manifest.assembly)
                        .ok_or(Error::Missing)?;
                    Some(execution_units(&self.state, args.0, &assembly)?)
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
        should_cancel: &mut impl FnMut() -> bool,
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
        should_cancel: &mut impl FnMut() -> bool,
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
        should_cancel: &mut impl FnMut() -> bool,
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
        should_cancel: &mut impl FnMut() -> bool,
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
    should_cancel: &mut impl FnMut() -> bool,
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
    should_cancel: &mut impl FnMut() -> bool,
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
            (21, [public_key, data, signature]) => self.buffers(
                21,
                &[
                    heap.bytes(*public_key)?,
                    heap.bytes(*data)?,
                    heap.bytes(*signature)?,
                ],
            )?,
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
                    |bytes| self.platform.random(bytes),
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
                    |bytes| self.platform.random(bytes),
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
                    |bytes| self.platform.random(bytes),
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
            21 if args.len() == 3 => {
                let valid = self.platform.ed25519_verify(args[0], args[2], args[1])?;
                Ok(BufferResult::Scalar(valid as i32))
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
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    mod vm {
        pub(super) use super::super::{BufferResult, NativeArgument};
    }
    use crate::{
        apdu::Command,
        crypto::CryptoProvider,
        journal::MemoryFlash,
        package::{
            AssemblyEntry, CONTEXT, Dependency, DependencyExport, Limits, Manifest, VersionRange,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    const STORAGE_KEY: [u8; 16] = [0x5a; 16];
    struct TestPlatform(u8);
    impl crate::crypto::CryptoProvider for TestPlatform {}
    impl crate::hal::Entropy for TestPlatform {
        fn fill_entropy(&mut self, b: &mut [u8]) -> Result<()> {
            self.0 += 1;
            b.fill(self.0);
            Ok(())
        }
    }
    impl crate::hal::LogicalGpio for TestPlatform {
        fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
            Err(Error::Native)
        }
    }
    struct FailingEntropy;
    impl crate::crypto::CryptoProvider for FailingEntropy {}
    impl crate::hal::Entropy for FailingEntropy {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
            output.fill(0xa5);
            Err(Error::Native)
        }
    }
    impl crate::hal::LogicalGpio for FailingEntropy {
        fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
            Err(Error::Native)
        }
    }

    #[derive(Clone)]
    struct TestStagingFlash {
        bytes: Rc<RefCell<[u8; MAX_PACKAGE_BYTES]>>,
        erases: Rc<Cell<usize>>,
    }

    impl TestStagingFlash {
        fn new() -> Self {
            Self {
                bytes: Rc::new(RefCell::new([0xff; MAX_PACKAGE_BYTES])),
                erases: Rc::new(Cell::new(0)),
            }
        }
    }

    impl crate::hal::StagingFlash for TestStagingFlash {
        fn capacity(&self) -> usize {
            MAX_PACKAGE_BYTES
        }
        fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
            let end = offset.checked_add(output.len()).ok_or(Error::Bounds)?;
            let bytes = self.bytes.borrow();
            let source = bytes.get(offset..end).ok_or(Error::Bounds)?;
            output.copy_from_slice(source);
            Ok(())
        }
        fn erase(&mut self) -> Result<()> {
            self.bytes.borrow_mut().fill(0xff);
            self.erases.set(self.erases.get() + 1);
            Ok(())
        }
        fn program(&mut self, offset: usize, input: &[u8]) -> Result<()> {
            let end = offset.checked_add(input.len()).ok_or(Error::Bounds)?;
            let mut bytes = self.bytes.borrow_mut();
            let destination = bytes.get_mut(offset..end).ok_or(Error::Bounds)?;
            if destination.iter().zip(input).any(|(old, new)| old & new != *new) {
                return Err(Error::Storage);
            }
            for (old, new) in destination.iter_mut().zip(input) {
                *old = *new;
            }
            Ok(())
        }
    }
    #[derive(Clone)]
    struct SharedJournalFlash(Rc<RefCell<MemoryFlash>>);
    impl Flash for SharedJournalFlash {
        fn slot_size(&self) -> usize {
            self.0.borrow().slot_size()
        }
        fn monotonic_capacity(&self) -> u64 {
            self.0.borrow().monotonic_capacity()
        }
        fn monotonic_generation(&self) -> Result<u64> {
            self.0.borrow().monotonic_generation()
        }
        fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
            self.0.borrow_mut().advance_monotonic(generation)
        }
        fn is_erased(&self, slot: usize) -> Result<bool> {
            self.0.borrow().is_erased(slot)
        }
        fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<()> {
            self.0.borrow().read(slot, offset, output)
        }
        fn erase(&mut self, slot: usize) -> Result<()> {
            self.0.borrow_mut().erase(slot)
        }
        fn program(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<()> {
            self.0.borrow_mut().program(slot, offset, bytes)
        }
    }
    fn fresh_card() -> Card<MemoryFlash, TestPlatform> {
        Card::open(MemoryFlash::new(16384), TestPlatform(0), STORAGE_KEY).unwrap()
    }
    fn card() -> Card<MemoryFlash, TestPlatform> {
        let mut card = fresh_card();
        let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
        load(&mut card, &package).unwrap();
        card
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct PackageMapFixture {
        #[serde(with = "package_map")]
        packages: NameMap<Rc<Vec<u8>>>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct DigestFixture {
        #[serde(with = "digest_bytes")]
        digest: [u8; 32],
    }

    #[test]
    fn durable_binary_serializers_round_trip_canonically_at_bounds() {
        for length in [0, 1, 2, 3, 47, 48, 49, MAX_PACKAGE_BYTES] {
            let raw: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let mut packages = NameMap::new();
            packages
                .insert("assembly".into(), Rc::new(raw.clone()))
                .unwrap();
            let fixture = PackageMapFixture { packages };
            let encoded = serde_json::to_string(&fixture).unwrap();
            assert!(encoded.contains(&Base64::encode_string(&raw)));
            assert_eq!(
                serde_json::from_str::<PackageMapFixture>(&encoded).unwrap(),
                fixture
            );
        }

        let digest = DigestFixture { digest: [0xa5; 32] };
        let encoded = serde_json::to_string(&digest).unwrap();
        assert!(encoded.contains(&Base64::encode_string(&digest.digest)));
        assert_eq!(
            serde_json::from_str::<DigestFixture>(&encoded).unwrap(),
            digest
        );
    }

    #[test]
    fn assembly_name_maps_are_compact_sorted_bounded_and_unique() {
        let mut values = NameMap::new();
        for index in (0..MAX_ASSEMBLIES_PER_DOMAIN).rev() {
            values
                .insert(Rc::from(alloc::format!("a{index}")), i32::from(index))
                .unwrap();
        }
        let pointer = values.0.as_ptr();
        assert_eq!(
            values.insert(Rc::from("overflow"), 9),
            Err(Error::Quota)
        );
        values.insert(Rc::from("a0"), 99).unwrap();
        assert_eq!(values.0.as_ptr(), pointer);
        assert_eq!(values.get("a0"), Some(&99));

        let encoded = serde_json::to_string(&values).unwrap();
        assert!(encoded.find("\"a0\"").unwrap() < encoded.find("\"a7\"").unwrap());
        assert!(serde_json::from_str::<NameMap<i32>>(&encoded).unwrap() == values);
        assert!(serde_json::from_str::<NameMap<i32>>(r#"{"a":1,"a":2}"#).is_err());

        let mut oversized = String::from("{\"packages\":{");
        for index in 0..=MAX_ASSEMBLIES_PER_DOMAIN {
            if index != 0 {
                oversized.push(',');
            }
            let value = if index == MAX_ASSEMBLIES_PER_DOMAIN {
                "!"
            } else {
                "AQ=="
            };
            oversized.push_str(&alloc::format!("\"a{index}\":\"{value}\""));
        }
        oversized.push_str("}}");
        let error = alloc::format!(
            "{}",
            serde_json::from_str::<PackageMapFixture>(&oversized).unwrap_err()
        );
        assert!(error.contains("quota"), "{error}");
    }

    #[test]
    fn lifecycle_management_names_borrow_the_command_buffer() {
        let encoded = br#"["payments","F04D430001"]"#;
        let (domain, instance) = management_names(encoded).unwrap();
        let start = encoded.as_ptr() as usize;
        let end = start + encoded.len();
        for value in [domain, instance] {
            let pointer = value.as_ptr() as usize;
            assert!(pointer >= start && pointer + value.len() <= end);
        }
        assert_eq!(
            management_names(br#"["pay\u006dents","F04D430001"]"#),
            Err(Error::Format)
        );
    }

    #[test]
    fn domain_creation_rejects_noncanonical_identifiers() {
        let mut card = card();
        for identifier in [
            ".hidden",
            "bad/name",
            "bad\\name",
            "bad\"name",
            "bad name",
            "é",
        ] {
            assert_eq!(
                card.manage(command(0xe0, identifier.as_bytes())),
                Err(Error::Domain)
            );
        }
        assert!(card.state.domains.is_empty());
    }

    #[test]
    fn credential_invocation_state_uses_fixed_capacity() {
        let mut authorizations = CredentialAuthorizations::default();
        for slot in 0..crate::credential_store::MAX_SLOTS as i32 {
            authorizations.insert(slot).unwrap();
        }
        authorizations.insert(0).unwrap();
        assert_eq!(authorizations.insert(99), Err(Error::Quota));
        authorizations.remove(3);
        authorizations.insert(99).unwrap();
        assert!(!authorizations.contains(3));
        assert!(authorizations.contains(99));

        let mut floors = CredentialRetryFloors::default();
        assert!(floors.is_empty());
        for slot in 0..crate::credential_store::MAX_SLOTS as i32 {
            floors.record(slot, (3, 2)).unwrap();
        }
        floors.record(0, (2, 1)).unwrap();
        assert_eq!(floors.record(99, (1, 1)), Err(Error::Quota));
        assert!(floors.iter().any(|entry| entry == (0, (2, 1))));
    }

    #[test]
    fn managed_response_reserves_its_complete_bound() {
        let response = managed_response_buffer().unwrap();
        assert!(response.is_empty());
        assert!(response.capacity() >= MAX_MANAGED_RESPONSE_WITH_STATUS);
    }

    #[test]
    fn management_name_encoding_is_bounded_and_canonical() {
        let encoded = management_names_wire("payments", "Wallet").unwrap();
        assert_eq!(encoded, br#"["payments","Wallet"]"#);
        assert_eq!(management_names(&encoded), Ok(("payments", "Wallet")));
        assert!(encoded.capacity() >= encoded.len());
        assert_eq!(management_names_wire("bad/name", "Wallet"), Err(Error::Format));
    }

    #[test]
    fn durable_binary_serializers_reject_noncanonical_and_oversized_input() {
        assert!(
            serde_json::from_str::<PackageMapFixture>(r#"{"packages":{"assembly":"AR=="}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<PackageMapFixture>(
                r#"{"packages":{"assembly":"AA==","assembly":"AA=="}}"#
            )
            .is_err()
        );

        let oversized = "A".repeat(MAX_PACKAGE_BYTES.div_ceil(3) * 4 + 4);
        let document = alloc::format!(r#"{{"packages":{{"assembly":"{oversized}"}}}}"#);
        assert!(serde_json::from_str::<PackageMapFixture>(&document).is_err());

        let mut noncanonical_digest = Base64::encode_string(&[0_u8; 32]);
        noncanonical_digest.replace_range(42..43, "B");
        let document = alloc::format!(r#"{{"digest":"{noncanonical_digest}"}}"#);
        assert!(serde_json::from_str::<DigestFixture>(&document).is_err());
    }

    #[test]
    fn durable_domains_require_an_explicit_fallible_policy() {
        let policy = DomainPolicy::standard().unwrap();
        assert_eq!(policy.capabilities.len(), 45);
        assert!(policy.valid());

        let mut value = serde_json::to_value(&card().state).unwrap();
        value["isd"].as_object_mut().unwrap().remove("policy");
        assert!(serde_json::from_value::<State>(value).is_err());
    }

    fn command(ins: u8, data: &[u8]) -> Verified<'_> {
        Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins,
                p1: 0,
                p2: 0,
                data: data.to_vec().into(),
                le: None,
            },
        }
    }
    fn create(c: &mut Card<MemoryFlash, TestPlatform>, id: &str) -> [u8; 16] {
        c.manage(command(0xe0, id.as_bytes()))
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn globalplatform_registry_reports_isd_domains_and_loads_in_bounded_records() {
        let unowned = fresh_card();
        let (isd, more) = unowned.get_status_record(0x80, 0, &[0xff, 0xff]).unwrap();
        assert!(!more);
        assert_eq!(
            &isd[..12],
            &[0xe3, 0x13, 0x4f, 8, 0xa0, 0, 0, 1, 0x51, 0, 0, 0]
        );
        assert!(isd.windows(4).any(|value| value == [0x9f, 0x70, 1, 1]));

        let mut owned = card();
        let incarnation = create(&mut owned, "payments");
        let (ssd, more) = owned
            .get_status_record(0x40, 0, &[0xa0, 0, 0, 1, 0x51])
            .unwrap();
        assert!(!more);
        let expected = crate::globalplatform::synthetic_aid(0x53, &incarnation);
        assert!(ssd.windows(16).any(|value| value == expected));
        assert!(ssd.windows(4).any(|value| value == [0x9f, 0x70, 1, 7]));

        let (load_record, more) = owned.get_status_record(0x20, 0, &[]).unwrap();
        assert!(!more);
        assert_eq!(load_record[0], 0xe3);
        assert!(
            load_record
                .windows(4)
                .any(|value| value == [0x9f, 0x70, 1, 1])
        );
        assert!(load_record.windows(2).any(|value| value == [0xce, 8]));

        let managed = package("payments", incarnation, "Wallet", 1, 7, &[0x2a]);
        load(&mut owned, &managed).unwrap();
        owned
            .manage(command(
                0xec,
                &serde_json::to_vec(&("payments", "F04D430001")).unwrap(),
            ))
            .unwrap();
        let (application, more) = owned.get_status_record(0x40, 1, &[]).unwrap();
        assert!(!more);
        assert!(
            application
                .windows(5)
                .any(|value| value == [0x4f, 5, 0xf0, 0x4d, 0x43])
        );
        assert!(application.windows(2).any(|value| value == [0xc4, 16]));
        let (load_with_module, more) = owned.get_status_record(0x10, 1, &[]).unwrap();
        assert!(!more);
        assert!(
            load_with_module
                .windows(7)
                .any(|value| value == [0x84, 5, 0xf0, 0x4d, 0x43, 0x00, 0x01])
        );

        let delete = |aid: &[u8]| Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins: 0xe4,
                p1: 0,
                p2: 0x80,
                data: core::iter::once(0x4f)
                    .chain(core::iter::once(aid.len() as u8))
                    .chain(aid.iter().copied())
                    .collect(),
                le: None,
            },
        };
        owned
            .manage_globalplatform(delete(&[0xf0, 0x4d, 0x43, 0x00, 0x01]))
            .unwrap();
        assert!(owned.state.domains["payments"].instances.is_empty());
        let digest = owned.state.domains["payments"].versions["Wallet"].1;
        owned
            .manage_globalplatform(delete(&crate::globalplatform::synthetic_aid(0x4c, &digest)))
            .unwrap();
        assert!(
            !owned.state.domains["payments"]
                .assemblies
                .contains_key("Wallet")
        );
    }

    #[test]
    fn globalplatform_ssd_creation_and_deletion_are_durable_and_aid_addressed() {
        let requested = [0xf0, 0x4d, 0x43, 0x53, 0x44];
        let mut install_data = Vec::new();
        for value in [
            &[0xa0, 0, 0, 1, 0x51, 0x53, 0x50][..],
            &[0xa0, 0, 0, 1, 0x51, 0x53, 0x50, 0x41],
            &requested,
            &[0x80],
            &[0xc9, 4, 0x81, 2, 3, crate::scp03::SCP03_I],
        ] {
            install_data.push(value.len() as u8);
            install_data.extend_from_slice(value);
        }
        install_data.push(0); // No install token in this profile.
        let install = || Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins: 0xe6,
                p1: 0x0c,
                p2: 0,
                data: install_data.clone().into(),
                le: None,
            },
        };
        assert_eq!(
            fresh_card().manage_globalplatform(install()),
            Err(Error::Unauthorized)
        );

        let mut owned = card();
        owned.manage_globalplatform(install()).unwrap();
        assert_eq!(
            owned.state.domains["F04D435344"].registry_aid.as_slice(),
            requested
        );
        let (record, more) = owned.get_status_record(0x40, 0, &requested).unwrap();
        assert!(!more);
        assert!(
            record
                .windows(7)
                .any(|value| value == [0x4f, 5, 0xf0, 0x4d, 0x43, 0x53, 0x44])
        );

        let mut reopened = Card::open(owned.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
        reopened.globalplatform_load = Some(GlobalPlatformLoad {
            domain_aid: RegistryAid::new(&requested).unwrap(),
            hash: [7; 32],
            total: Some(1),
            next_block: 1,
            payload: Some(crate::globalplatform::Payload::Mp03),
        });
        reopened.staging.bytes.push(0xaa);
        let delete = Verified {
            level: 0x13,
            command: Command {
                cla: 0x80,
                ins: 0xe4,
                p1: 0,
                p2: 0x80,
                data: [0x4f, 5, 0xf0, 0x4d, 0x43, 0x53, 0x44].to_vec().into(),
                le: None,
            },
        };
        reopened.manage_globalplatform(delete).unwrap();
        assert!(!reopened.state.domains.contains_key("F04D435344"));
        assert!(reopened.globalplatform_load.is_none());
        assert!(reopened.staging.bytes.is_empty());
        let final_state = Card::open(reopened.into_flash(), TestPlatform(30), STORAGE_KEY).unwrap();
        assert!(!final_state.state.domains.contains_key("F04D435344"));
    }

    #[test]
    fn globalplatform_load_stream_activates_only_a_complete_matching_package() {
        let mut owned = card();
        let incarnation = create(&mut owned, "payments");
        let package = package("payments", incarnation, "Wallet", 1, 7, &[0x2a]);
        let hash = owned.platform.sha256(&package).unwrap();
        let mut wrong_hash = hash;
        wrong_hash[0] ^= 1;
        assert!(matches!(
            PackageView::verify_with_expected_digest(
                &package,
                &mut owned.platform,
                Some(&wrong_hash)
            ),
            Err(Error::Signature)
        ));
        let load_aid = RegistryAid::synthetic(0x4c, &hash);
        let domain_aid = owned.state.domains["payments"].registry_aid;
        let mut request = Vec::new();
        for value in [
            load_aid.as_slice(),
            domain_aid.as_slice(),
            &hash[..],
            &[] as &[u8],
            &[],
        ] {
            request.push(value.len() as u8);
            request.extend_from_slice(value);
        }
        assert_eq!(
            owned
                .manage_globalplatform(Verified {
                    level: 0x13,
                    command: Command {
                        cla: 0x80,
                        ins: 0xe6,
                        p1: 0x02,
                        p2: 0,
                        data: request.into(),
                        le: None,
                    },
                })
                .unwrap(),
            [0]
        );
        assert_eq!(
            owned.globalplatform_load.as_ref().unwrap().domain_aid,
            domain_aid
        );

        let mut load_file =
            alloc::vec![0xc4, 0x82, (package.len() >> 8) as u8, package.len() as u8,];
        load_file.extend_from_slice(&package);
        let blocks = load_file.len().div_ceil(180);
        for (block, chunk) in load_file.chunks(180).enumerate() {
            let last = block + 1 == blocks;
            assert_eq!(
                owned
                    .manage_globalplatform(Verified {
                        level: 0x13,
                        command: Command {
                            cla: 0x80,
                            ins: 0xe8,
                            p1: if last { 0x80 } else { 0 },
                            p2: block as u8,
                            data: chunk.to_vec().into(),
                            le: None,
                        },
                    })
                    .unwrap(),
                [0]
            );
            if !last {
                assert!(
                    !owned.state.domains["payments"]
                        .assemblies
                        .contains_key("Wallet")
                );
            }
        }
        assert!(
            owned.state.domains["payments"]
                .assemblies
                .contains_key("Wallet")
        );
        assert!(owned.staging.bytes.is_empty());
        assert!(!owned.globalplatform_load_active());

        let instance_aid = [0xf0, 0x4d, 0x43, 0x00, 0x01];
        let mut install = Vec::new();
        for value in [
            load_aid.as_slice(),
            &instance_aid,
            &instance_aid,
            &[0][..],
            &[0xc9, 0],
            &[],
        ] {
            install.push(value.len() as u8);
            install.extend_from_slice(value);
        }
        assert_eq!(
            owned
                .manage_globalplatform(Verified {
                    level: 0x13,
                    command: Command {
                        cla: 0x80,
                        ins: 0xe6,
                        p1: 0x0c,
                        p2: 0,
                        data: install.into(),
                        le: None,
                    },
                })
                .unwrap(),
            [0]
        );
        assert_eq!(
            owned.state.domains["payments"].instances["F04D430001"].as_ref(),
            "Wallet"
        );
    }

    #[test]
    fn a_java_card_load_file_is_recognised_and_refused_before_anything_is_staged() {
        let mut owned = card();
        create(&mut owned, "payments");
        // The first bytes of a Java Card load file, JCVM §6.3. The Header component leads,
        // carrying the magic that tells the two payload formats apart.
        let mut package = alloc::vec![0x01, 0x00, 0x13, 0xde, 0xca, 0xff, 0xed];
        package.extend_from_slice(&[0x01, 0x02, 0x04, 0x0a, 0x01, 0x09]);
        let hash = owned.platform.sha256(&package).unwrap();
        let load_aid = RegistryAid::synthetic(0x4c, &hash);
        let domain_aid = owned.state.domains["payments"].registry_aid;
        let mut request = Vec::new();
        for value in [
            load_aid.as_slice(),
            domain_aid.as_slice(),
            &hash[..],
            &[] as &[u8],
            &[],
        ] {
            request.push(value.len() as u8);
            request.extend_from_slice(value);
        }
        owned
            .manage_globalplatform(Verified {
                level: 0x13,
                command: Command {
                    cla: 0x80,
                    ins: 0xe6,
                    p1: 0x02,
                    p2: 0,
                    data: request.into(),
                    le: None,
                },
            })
            .unwrap();

        // A short definite length, because this block is the whole load file.
        let mut load_file = alloc::vec![0xc4, package.len() as u8];
        load_file.extend_from_slice(&package);
        assert_eq!(
            owned.manage_globalplatform(Verified {
                level: 0x13,
                command: Command {
                    cla: 0x80,
                    ins: 0xe8,
                    p1: 0x80,
                    p2: 0,
                    data: load_file.into(),
                    le: None,
                },
            }),
            Err(Error::Unsupported)
        );
        // The card refused before keeping any of it, so a later load starts clean.
        assert!(owned.staging.is_empty());
        assert!(owned.globalplatform_load.is_none());
    }
    // Explicit test-only signing seeds; never deployment keys.
    fn package(
        id: &str,
        inc: [u8; 16],
        name: &str,
        version: u32,
        seed: u8,
        code: &[u8],
    ) -> Vec<u8> {
        signed_package(id, inc, name, version, seed, code, true)
    }
    fn library_package(id: &str, inc: [u8; 16], name: &str, version: u32, seed: u8) -> Vec<u8> {
        signed_package(id, inc, name, version, seed, &[0x2a], false)
    }

    fn multi_entry_package(
        id: &str,
        inc: [u8; 16],
        name: &str,
        seed: u8,
        first_aid: u16,
        count: usize,
    ) -> Vec<u8> {
        let manifest = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: name.into(),
            assembly_version: [1, 0, 0, 0],
            version: 1,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: (0..count)
                .map(|offset| AssemblyEntry {
                    aid: alloc::format!("F04D43{:04X}", first_aid + offset as u16),
                    process: 0,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                })
                .collect(),
            dependencies: Vec::new(),
            capabilities: alloc::vec![3, 4],
            storage: Vec::new(),
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        signed_compiled_package(&manifest, &test_assembly(name, &[0x2a]), seed)
    }

    fn test_assembly(name: &str, body: &[u8]) -> Vec<u8> {
        let valid = (1u64 << crate::mc04_schema::TABLE_MODULE)
            | (1u64 << crate::mc04_schema::TABLE_TYPEDEF)
            | (1u64 << crate::mc04_schema::TABLE_METHODDEF)
            | (1u64 << crate::mc04_schema::TABLE_ASSEMBLY);
        let mut tables = alloc::vec![2, 0, 0, 0];
        tables.extend(valid.to_le_bytes());
        for _ in 0..4 {
            tables.extend(1u16.to_le_bytes());
        }
        tables.push(1); // Module.Name
        tables.extend([0, 1, 0, 0, 3, 0, 0, 0, 1, 1]); // sealed TypeDef
        tables.extend([0, 0, 0, 0, 0, 0, 0x10, 0, 5, 1]); // static MethodDef
        tables.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]); // Assembly
        let mut strings = Vec::from(b"\0M\0T\0Run\0" as &[u8]);
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let blobs = [0, 3, 0, 0, 1]; // static parameterless void
        let mut code = alloc::vec![0, 0];
        code.extend(1u16.to_le_bytes());
        code.extend((body.len() as u32).to_le_bytes());
        code.extend([0, 0, 0, 0]);
        code.extend_from_slice(body);
        let sections: [&[u8]; 4] = [&tables, &strings, &blobs, &code];
        let header_size = 56usize;
        let file_size = header_size + sections.iter().map(|section| section.len()).sum::<usize>();
        let mut bytes = Vec::from(b"MC04" as &[u8]);
        bytes.extend([4, 0, 0, 0, 4, 2]);
        bytes.extend((header_size as u16).to_le_bytes());
        bytes.extend((file_size as u32).to_le_bytes());
        let mut offset = header_size;
        for (index, section) in sections.iter().enumerate() {
            bytes.extend([index as u8 + 1, 0]);
            bytes.extend((offset as u32).to_le_bytes());
            bytes.extend((section.len() as u32).to_le_bytes());
            offset += section.len();
        }
        for section in sections {
            bytes.extend(section);
        }
        bytes
    }
    fn signed_package(
        id: &str,
        inc: [u8; 16],
        name: &str,
        version: u32,
        seed: u8,
        code: &[u8],
        has_entry: bool,
    ) -> Vec<u8> {
        signed_package_with_storage(
            id,
            inc,
            name,
            version,
            seed,
            code,
            has_entry,
            alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_package_with_storage(
        id: &str,
        inc: [u8; 16],
        name: &str,
        version: u32,
        seed: u8,
        code: &[u8],
        has_entry: bool,
        storage: Vec<StorageDeclaration>,
    ) -> Vec<u8> {
        let m = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: name.into(),
            assembly_version: [1, 0, 0, 0],
            version,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: if has_entry {
                alloc::vec![AssemblyEntry {
                    aid: "F04D430001".into(),
                    process: 0,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                }]
            } else {
                Vec::new()
            },
            dependencies: Vec::new(),
            capabilities: alloc::vec![3, 4],
            storage,
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        let meta = serde_json::to_vec(&m).unwrap();
        let image = test_assembly(name, code);
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut raw = Vec::from(b"MP03" as &[u8]);
        raw.extend(CONTEXT);
        raw.extend((meta.len() as u32).to_le_bytes());
        raw.extend((image.len() as u32).to_le_bytes());
        raw.extend(meta);
        raw.extend(image);
        raw.extend(key.verifying_key().to_bytes());
        let signature = key.sign(&raw).to_bytes();
        raw.extend(signature);
        raw
    }

    fn counter_package(id: &str, inc: [u8; 16], version: u32, seed: u8) -> Vec<u8> {
        counter_package_with_storage(
            id,
            inc,
            version,
            seed,
            alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
        )
    }

    fn counter_package_with_storage(
        id: &str,
        inc: [u8; 16],
        version: u32,
        seed: u8,
        storage: Vec<StorageDeclaration>,
    ) -> Vec<u8> {
        let manifest = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: "Counter".into(),
            assembly_version: [1, 0, 0, 0],
            version,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: alloc::vec![
                AssemblyEntry {
                    aid: "F04D430001".into(),
                    process: 1,
                    install: Some(0),
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
                AssemblyEntry {
                    aid: "F04D430002".into(),
                    process: 28,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
            ],
            dependencies: Vec::new(),
            capabilities: alloc::vec![2, 7, 8, 9, 11, 12, 13, 20],
            storage,
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        signed_compiled_package(
            &manifest,
            include_bytes!("../../../fuzz/fixtures/counter.mca"),
            seed,
        )
    }

    fn transaction_records_package(
        id: &str,
        inc: [u8; 16],
        version: u32,
        seed: u8,
    ) -> Vec<u8> {
        let manifest = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: "TransactionRecords".into(),
            assembly_version: [1, 0, 0, 0],
            version,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: alloc::vec![
                AssemblyEntry {
                    aid: "F04D430020".into(),
                    process: 0,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
                AssemblyEntry {
                    aid: "F04D430021".into(),
                    process: 2,
                    install: Some(1),
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
            ],
            dependencies: Vec::new(),
            capabilities: alloc::vec![2, 7, 8, 11, 12, 13, 31, 32, 34, 46, 47, 48],
            storage: alloc::vec![
                StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 2, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 3, kind: 2, max_bytes: 1 },
            ],
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        signed_compiled_package(
            &manifest,
            include_bytes!("../../../tests/fixtures/transaction_records.mca"),
            seed,
        )
    }

    fn transaction_negative_package(
        id: &str,
        inc: [u8; 16],
        version: u32,
        seed: u8,
    ) -> Vec<u8> {
        let manifest = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: "TransactionRuntimeNegative".into(),
            assembly_version: [1, 0, 0, 0],
            version,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: alloc::vec![AssemblyEntry {
                aid: "F04D430022".into(),
                process: 0,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            }],
            dependencies: Vec::new(),
            capabilities: alloc::vec![6, 7, 8, 11, 12, 46, 47, 48],
            storage: alloc::vec![StorageDeclaration {
                key: 1,
                kind: 1,
                max_bytes: 0,
            }],
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        signed_compiled_package(
            &manifest,
            include_bytes!("../../../tests/fixtures/transaction_runtime_negative.mca"),
            seed,
        )
    }

    fn key_operations_package(id: &str, inc: [u8; 16], version: u32, seed: u8) -> Vec<u8> {
        key_operations_package_with_storage(
            id,
            inc,
            version,
            seed,
            alloc::vec![
                StorageDeclaration { key: 10, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 20, kind: 2, max_bytes: 3 },
                StorageDeclaration { key: 21, kind: 2, max_bytes: 1 },
                StorageDeclaration { key: 30, kind: 1, max_bytes: 0 },
            ],
        )
    }

    fn key_operations_package_with_storage(
        id: &str,
        inc: [u8; 16],
        version: u32,
        seed: u8,
        storage: Vec<StorageDeclaration>,
    ) -> Vec<u8> {
        let manifest = Manifest {
            domain: id.into(),
            incarnation: inc,
            assembly: "KeyOperations".into(),
            assembly_version: [1, 0, 0, 0],
            version,
            export: DependencyExport {
                access: 0,
                key: None,
            },
            entry_points: alloc::vec![
                AssemblyEntry {
                    aid: "F04D430010".into(),
                    process: 1,
                    install: Some(0),
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
                AssemblyEntry {
                    aid: "F04D430011".into(),
                    process: 3,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
                AssemblyEntry {
                    aid: "F04D430012".into(),
                    process: 4,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
                AssemblyEntry {
                    aid: "F04D430013".into(),
                    process: 5,
                    install: None,
                    uninstall: None,
                    select: None,
                    deselect: None,
                },
            ],
            dependencies: Vec::new(),
            capabilities: alloc::vec![
                2, 5, 7, 8, 11, 12, 13, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                34,
            ],
            storage,
            limits: Limits {
                arena: 16384,
                stack: 256,
                frames: 32,
                instructions: 100000,
            },
        };
        signed_compiled_package(
            &manifest,
            include_bytes!("../../../fuzz/fixtures/key_operations.mca"),
            seed,
        )
    }

    fn signed_compiled_package(manifest: &Manifest, image: &[u8], seed: u8) -> Vec<u8> {
        let meta = serde_json::to_vec(manifest).unwrap();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut raw = Vec::from(b"MP03" as &[u8]);
        raw.extend(CONTEXT);
        raw.extend((meta.len() as u32).to_le_bytes());
        raw.extend((image.len() as u32).to_le_bytes());
        raw.extend(meta);
        raw.extend(image);
        raw.extend(key.verifying_key().to_bytes());
        let signature = key.sign(&raw).to_bytes();
        raw.extend(signature);
        raw
    }
    fn load<P: Platform>(c: &mut Card<MemoryFlash, P>, p: &[u8]) -> Result<Vec<u8>> {
        c.manage(command(0xe6, &[]))?;
        for (i, chunk) in p.chunks(200).enumerate() {
            let mut data = (i as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            c.manage(command(0xe8, &data))?;
        }
        c.manage(command(0xea, &[]))
    }
    fn run_loaded(
        card: &mut Card<MemoryFlash, TestPlatform>,
        domain: &str,
        assembly: &str,
        entry: u16,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let raw = card.state.domain(domain).unwrap().assemblies[assembly].clone();
        let bindings = card.state.domain(domain).unwrap().bindings[assembly].clone();
        let calls = card.state.domain(domain).unwrap().imports[assembly].clone();
        let package = PackageView::verify(&raw)?;
        let units = [ExecutionUnit {
            package,
            bindings: &bindings,
            calls: &calls,
        }];
        run_context(
            card.state.domain_mut(domain).unwrap(),
            &units[0].package,
            Some(&units),
            entry,
            data,
            &mut card.platform,
            0,
        )
    }
    mod signing_tests;
    mod budget_tests;

    #[test]
    fn linked_frame_graph_rejects_cycles_and_paths_over_runtime_limit() {
        let within_limit = (0..31).map(|index| (index, index + 1)).collect::<Vec<_>>();
        validate_program_graph(32, &within_limit, &[false; 32], &[false; 32]).unwrap();

        let over_limit = (0..32).map(|index| (index, index + 1)).collect::<Vec<_>>();
        assert_eq!(
            validate_program_graph(33, &over_limit, &[false; 33], &[false; 33]),
            Err(Error::Quota)
        );
        assert_eq!(
            validate_program_graph(2, &[(0, 1), (1, 0)], &[false; 2], &[false; 2]),
            Err(Error::Quota)
        );
    }

    #[test]
    fn linked_transaction_graph_rejects_indirect_irreversible_output() {
        let edges = [(0, 1), (1, 2)];
        assert_eq!(
            validate_program_graph(3, &edges, &[false, false, true], &[true, false, false]),
            Err(Error::Unsupported)
        );
        validate_program_graph(3, &edges, &[false, false, true], &[false, false, false]).unwrap();
        validate_program_graph(3, &edges, &[false, false, false], &[true, false, false]).unwrap();
    }

    #[test]
    fn signed_mc04_transaction_bits_drive_linked_effect_validation() {
        let mut card = card();
        let incarnation = create(&mut card, "effects");
        load(&mut card, &counter_package("effects", incarnation, 1, 7)).unwrap();
        let calls = card
            .state
            .domains
            .get_mut("effects")
            .unwrap()
            .imports
            .get_mut("Counter")
            .unwrap();
        calls
            .iter_mut()
            .find(|binding| binding.target == CallTarget::Native(11))
            .unwrap()
            .target = CallTarget::Native(6);
        execution_units(&card.state, "effects", "Counter").unwrap();

        let calls = card
            .state
            .domains
            .get_mut("effects")
            .unwrap()
            .imports
            .get_mut("Counter")
            .unwrap();
        calls
            .iter_mut()
            .find(|binding| binding.target == CallTarget::Native(8))
            .unwrap()
            .target = CallTarget::Native(6);
        assert!(matches!(
            execution_units(&card.state, "effects", "Counter"),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn signed_forged_platform_identity_is_rejected_before_binding() {
        let mut card = card();
        for (identifier, identity, seed) in [
            ("framework-forgery", crate::mc04_imports::FRAMEWORK_HASH, 7),
            ("runtime-forgery", crate::mc04_imports::SYSTEM_RUNTIME_TOKEN, 8),
        ] {
            let incarnation = create(&mut card, identifier);
            let mut package = counter_package(identifier, incarnation, 1, seed);
            let positions = package
                .windows(identity.len())
                .enumerate()
                .filter_map(|(index, value)| (value == identity).then_some(index))
                .collect::<Vec<_>>();
            assert_eq!(positions.len(), 1);
            package[positions[0]] ^= 1;
            let signed_length = package.len() - 64;
            let key = SigningKey::from_bytes(&[seed; 32]);
            let signature = key.sign(&package[..signed_length]).to_bytes();
            package[signed_length..].copy_from_slice(&signature);

            assert_eq!(load(&mut card, &package), Err(Error::Unauthorized));
            let domain = &card.state.domains[identifier];
            assert!(domain.key.is_none());
            assert!(domain.assemblies.is_empty());
            assert!(domain.imports.is_empty());
        }
    }

    #[test]
    fn execution_unit_queue_is_deduplicated_and_bounded() {
        let mut card = card();
        let incarnation = create(&mut card, "queue");
        load(&mut card, &counter_package("queue", incarnation, 1, 7)).unwrap();

        let mut units = Vec::new();
        units.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
        push_execution_unit(&card.state, &mut units, "queue", "Counter", None).unwrap();
        let digest = units[0].package.digest;
        push_execution_unit(&card.state, &mut units, "queue", "Counter", Some(digest)).unwrap();
        assert_eq!(units.len(), 1);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert_eq!(
            push_execution_unit(
                &card.state,
                &mut units,
                "queue",
                "Counter",
                Some(wrong_digest),
            ),
            Err(Error::Storage)
        );

        let isd = &card.state.isd;
        let raw = isd.assemblies.get("mscorlib").unwrap();
        let bindings = isd.bindings.get("mscorlib").unwrap();
        let calls = isd.imports.get("mscorlib").unwrap();
        let mut full = Vec::new();
        full.try_reserve_exact(MAX_EXECUTION_UNITS).unwrap();
        for _ in 0..MAX_EXECUTION_UNITS {
            full.push(ExecutionUnit {
                package: PackageView::verify(raw).unwrap(),
                bindings,
                calls,
            });
        }
        assert_eq!(
            push_execution_unit(&card.state, &mut full, "queue", "Counter", None),
            Err(Error::Quota)
        );
    }

    #[test]
    fn linked_verifier_rejects_working_sets_before_unbounded_growth() {
        let raw = counter_package("a", [0; 16], 1, 7);
        let mut units = Vec::new();
        for _ in 0..=MAX_EXECUTION_UNITS {
            units.push(ExecutionUnit {
                package: PackageView::verify(&raw).unwrap(),
                bindings: &[],
                calls: &[],
            });
        }
        assert_eq!(validate_linked_program(&units), Err(Error::Quota));
        assert_eq!(MAX_LINKED_METHODS, 4352);

        let mut edges = Vec::new();
        for edge in 0..MAX_LINKED_CALL_EDGES {
            push_link_edge(&mut edges, (edge, edge)).unwrap();
        }
        assert_eq!(
            push_link_edge(&mut edges, (MAX_LINKED_CALL_EDGES, 0)),
            Err(Error::Quota)
        );
    }

    #[test]
    fn mscorlib_takes_permanent_isd_ownership_before_ssd_creation() {
        let mut c = fresh_card();
        let inc = c.state.isd.incarnation;
        assert_eq!(c.manage(command(0xe0, b"a")), Err(Error::Unauthorized));
        assert_eq!(
            load(&mut c, &library_package("ISD", inc, "Kdf108", 1, 42)),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            load(&mut c, &package("ISD", inc, "mscorlib", 1, 42, &[0x2a])),
            Err(Error::Unauthorized)
        );
        load(&mut c, &library_package("ISD", inc, "mscorlib", 1, 42)).unwrap();
        assert_eq!(
            c.manage(command(0xf0, br#"["ISD","mscorlib"]"#)),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            load(&mut c, &library_package("ISD", inc, "Kdf108", 1, 7)),
            Err(Error::KeyMismatch)
        );
        create(&mut c, "a");
        let c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert!(c.state.is_owned());
        assert_eq!(
            c.state.isd.key,
            Some(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes())
        );
    }

    #[test]
    fn domain_capacity_is_bounded_and_survives_reboot() {
        let mut card = card();
        for index in (0..MAX_SSDS).rev() {
            create(&mut card, &alloc::format!("d{index}"));
        }
        assert_eq!(card.manage(command(0xe0, b"overflow")), Err(Error::Quota));

        let inventory = card.manage(command(0xe2, &[MAX_SSDS as u8])).unwrap();
        assert_eq!(inventory[0], 1);
        assert_eq!(inventory[1] as usize, MAX_SSDS + 1);
        assert_eq!(inventory[2] as usize, MAX_SSDS);

        let mut reopened = Card::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
        assert_eq!(reopened.state.domains.len(), MAX_SSDS);
        assert_eq!(
            reopened.manage(command(0xe0, b"overflow")),
            Err(Error::Quota)
        );

        let invalid = DomainPolicy {
            max_assemblies: MAX_ASSEMBLIES_PER_DOMAIN + 1,
            ..DomainPolicy::standard().unwrap()
        };
        assert!(!invalid.valid());
        let invalid = DomainPolicy {
            max_instances: MAX_INSTANCES_PER_DOMAIN + 1,
            ..DomainPolicy::standard().unwrap()
        };
        assert!(!invalid.valid());
    }

    #[test]
    fn domain_registry_serialization_is_sorted_bounded_and_unique() {
        let policy = DomainPolicy::standard().unwrap();
        let domain = Domain::new(
            [1; 16],
            RegistryAid::synthetic(0x53, &[1; 16]),
            policy.clone(),
        );
        let encoded_domain = serde_json::to_string(&domain).unwrap();
        let duplicate = alloc::format!(
            "{{\"same\":{encoded_domain},\"same\":{encoded_domain}}}"
        );
        assert!(serde_json::from_str::<Domains>(&duplicate).is_err());

        let mut oversized = String::from("{");
        for index in 0..=MAX_SSDS {
            if index != 0 {
                oversized.push(',');
            }
            oversized.push_str(&alloc::format!("\"d{index}\":{encoded_domain}"));
        }
        oversized.push('}');
        assert!(serde_json::from_str::<Domains>(&oversized).is_err());

        let mut domains = Domains::new();
        for id in ["z", "a", "m"] {
            let stable = [id.as_bytes()[0]; 16];
            domains
                .insert(
                    String::from(id),
                    Domain::new(
                        [id.as_bytes()[0]; 16],
                        RegistryAid::synthetic(0x53, &stable),
                        policy.clone(),
                    ),
                )
                .unwrap();
        }
        let encoded = serde_json::to_string(&domains).unwrap();
        assert!(encoded.find("\"a\"").unwrap() < encoded.find("\"m\"").unwrap());
        assert!(encoded.find("\"m\"").unwrap() < encoded.find("\"z\"").unwrap());
        assert!(serde_json::from_str::<Domains>(&encoded).unwrap() == domains);
    }

    #[test]
    fn integer_store_is_compact_sorted_bounded_and_unique() {
        let mut store = IntStore::new();
        for key in (0..MAX_INT_RECORDS as i32).rev() {
            store.insert(key, key).unwrap();
        }
        let pointer = store.0.as_ptr();
        assert_eq!(store.insert(MAX_INT_RECORDS as i32, 1), Err(Error::Quota));
        assert_eq!(store.len(), MAX_INT_RECORDS);
        assert_eq!(store.0.as_ptr(), pointer);
        store.insert(0, -1).unwrap();
        assert_eq!(store.get(&0), Some(&-1));

        let mut small = IntStore::new();
        small.insert(2, 20).unwrap();
        small.insert(-1, -10).unwrap();
        small.insert(1, 10).unwrap();
        let encoded = serde_json::to_string(&small).unwrap();
        assert_eq!(encoded, r#"{"-1":-10,"1":10,"2":20}"#);
        assert!(serde_json::from_str::<IntStore>(&encoded).unwrap() == small);
        assert!(serde_json::from_str::<IntStore>(r#"{"1":1,"1":2}"#).is_err());

        let mut oversized = String::from("{");
        for key in 0..=MAX_INT_RECORDS {
            if key != 0 {
                oversized.push(',');
            }
            oversized.push_str(&alloc::format!("\"{key}\":{key}"));
        }
        oversized.push('}');
        assert!(serde_json::from_str::<IntStore>(&oversized).is_err());
    }

    #[test]
    fn byte_store_is_compact_sorted_bounded_and_unique() {
        let mut store = BlobStore::new();
        for key in (0..MAX_BLOB_RECORDS as i32).rev() {
            store.insert(key, alloc::vec![key as u8]).unwrap();
        }
        let entries_pointer = store.0.as_ptr();
        let first_value_pointer = store.get(&0).unwrap().as_ptr();
        assert_eq!(
            store.insert(MAX_BLOB_RECORDS as i32, alloc::vec![0xaa]),
            Err(Error::Quota)
        );
        assert_eq!(store.len(), MAX_BLOB_RECORDS);
        assert_eq!(store.0.as_ptr(), entries_pointer);
        assert_eq!(store.get(&0).unwrap().as_ptr(), first_value_pointer);

        let replacement = alloc::vec![0x55; 3];
        let replacement_pointer = replacement.as_ptr();
        store.insert(0, replacement).unwrap();
        assert_eq!(store.get(&0).unwrap().as_ptr(), replacement_pointer);

        let mut small = BlobStore::new();
        small.insert(2, alloc::vec![2]).unwrap();
        small.insert(-1, alloc::vec![1]).unwrap();
        let encoded = serde_json::to_string(&small).unwrap();
        assert_eq!(encoded, r#"{"-1":[1],"2":[2]}"#);
        assert!(serde_json::from_str::<BlobStore>(&encoded).unwrap() == small);
        assert!(serde_json::from_str::<BlobStore>(r#"{"1":[1],"1":[2]}"#).is_err());

        let mut oversized = String::from("{");
        for key in 0..=MAX_BLOB_RECORDS {
            if key != 0 {
                oversized.push(',');
            }
            oversized.push_str(&alloc::format!("\"{key}\":[{key}]"));
        }
        oversized.push('}');
        assert!(serde_json::from_str::<BlobStore>(&oversized).is_err());
    }

    #[test]
    fn installed_instances_are_compact_sorted_bounded_and_unique() {
        let mut instances = Instances::new();
        for index in (0..MAX_INSTANCES_PER_DOMAIN).rev() {
            instances
                .insert(
                    alloc::format!("F04D4301{index:02}"),
                    Rc::from("Counter"),
                )
                .unwrap();
        }
        let pointer = instances.0.as_ptr();
        assert_eq!(
            instances.insert(String::from("F04D4301FF"), Rc::from("Counter")),
            Err(Error::Quota)
        );
        assert_eq!(
            instances.insert(String::from("F04D430100"), Rc::from("Other")),
            Err(Error::Busy)
        );
        assert_eq!(instances.0.as_ptr(), pointer);
        assert_eq!(instances.get("F04D430100").unwrap().as_ref(), "Counter");

        let encoded = serde_json::to_string(&instances).unwrap();
        assert!(
            encoded.find("\"F04D430100\"").unwrap()
                < encoded.find("\"F04D430107\"").unwrap()
        );
        assert!(serde_json::from_str::<Instances>(&encoded).unwrap() == instances);
        assert!(
            serde_json::from_str::<Instances>(
                r#"{"F04D430100":"Counter","F04D430100":"Other"}"#
            )
            .is_err()
        );

        let mut oversized = String::from("{");
        for index in 0..=MAX_INSTANCES_PER_DOMAIN {
            if index != 0 {
                oversized.push(',');
            }
            oversized.push_str(&alloc::format!(
                "\"F04D4301{index:02}\":\"Counter\""
            ));
        }
        oversized.push('}');
        assert!(serde_json::from_str::<Instances>(&oversized).is_err());
    }

    #[test]
    fn installed_instance_capacity_is_enforced_per_domain_and_card() {
        let mut card = card();
        let a = create(&mut card, "a");
        let b = create(&mut card, "b");
        let c = create(&mut card, "c");
        load(
            &mut card,
            &multi_entry_package("a", a, "ManyA1", 7, 0x100, 4),
        )
        .unwrap();
        load(
            &mut card,
            &multi_entry_package("a", a, "ManyA2", 7, 0x104, 4),
        )
        .unwrap();
        load(
            &mut card,
            &multi_entry_package("a", a, "ExtraA", 7, 0x108, 1),
        )
        .unwrap();
        load(
            &mut card,
            &multi_entry_package("b", b, "ManyB1", 8, 0x200, 4),
        )
        .unwrap();
        load(
            &mut card,
            &multi_entry_package("b", b, "ManyB2", 8, 0x204, 4),
        )
        .unwrap();
        load(
            &mut card,
            &multi_entry_package("c", c, "ManyC", 9, 0x300, 1),
        )
        .unwrap();

        let install = |card: &mut Card<MemoryFlash, TestPlatform>, domain: &str, aid: u16| {
            let request = alloc::format!(r#"["{domain}","F04D43{aid:04X}"]"#);
            card.manage(command(0xec, request.as_bytes()))
        };
        for aid in 0x100..0x108 {
            install(&mut card, "a", aid).unwrap();
        }
        assert_eq!(install(&mut card, "a", 0x108), Err(Error::Quota));
        for aid in 0x200..0x208 {
            install(&mut card, "b", aid).unwrap();
        }
        assert_eq!(install(&mut card, "c", 0x300), Err(Error::Quota));

        let reopened = Card::open(card.into_flash(), TestPlatform(20), STORAGE_KEY).unwrap();
        assert_eq!(
            reopened
                .state
                .domains
                .values()
                .map(|domain| domain.instances.len())
                .sum::<usize>(),
            MAX_TOTAL_INSTANCES
        );
    }

    #[test]
    fn pin_survives_unload_and_reboot() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let p = package("a", inc, "one", 1, 7, &[0x2a]);
        load(&mut c, &p).unwrap();
        c.manage(command(0xf0, br#"["a","one"]"#)).unwrap();
        let mut c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(
            load(&mut c, &package("a", inc, "two", 1, 8, &[0x2a])),
            Err(Error::KeyMismatch)
        );
        load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])).unwrap();
    }
    #[test]
    fn signature_covers_every_byte() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let p = package("a", inc, "one", 1, 7, &[0x2a]);
        let mut previous_format = p.clone();
        previous_format[..4].copy_from_slice(b"MP02");
        assert!(matches!(
            Package::verify(&previous_format),
            Err(Error::Format)
        ));
        for i in 0..p.len() {
            let mut b = p.clone();
            b[i] ^= 1;
            assert!(Package::verify(&b).is_err(), "byte {}", i);
        }
        assert!(c.state.domains["a"].key.is_none());
    }
    #[test]
    fn versions_and_incarnations() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let p = package("a", inc, "one", 2, 7, &[0x2a]);
        load(&mut c, &p).unwrap();
        load(&mut c, &p).unwrap();
        assert_eq!(
            load(&mut c, &package("a", inc, "one", 1, 7, &[0x2a])),
            Err(Error::Rollback)
        );
        assert_eq!(
            load(&mut c, &package("a", inc, "one", 2, 7, &[0x00, 0x2a])),
            Err(Error::Rollback)
        );
        c.manage(command(0xe4, b"a")).unwrap();
        let new = create(&mut c, "a");
        assert_ne!(new, inc);
        assert_eq!(load(&mut c, &p), Err(Error::Domain));
        load(&mut c, &package("a", new, "one", 1, 8, &[0x2a])).unwrap();
    }
    #[test]
    fn management_level_and_isd() {
        let mut c = card();
        // Command integrity is the floor. A session without C-MAC carries no proof of
        // origin, so management is refused whatever else it negotiated.
        let mut plain = command(0xe0, b"a");
        plain.level = 0;
        assert_eq!(c.manage(plain), Err(Error::Unauthorized));
        // Every level that carries C-MAC is served, so a host may choose how much
        // confidentiality it wants without losing management access.
        for level in [0x01, 0x03, 0x11, 0x13] {
            let mut cmd = command(0xe0, b"ISD");
            cmd.level = level;
            assert_eq!(c.manage(cmd), Err(Error::Domain), "level {level:#04x}");
        }
    }

    #[test]
    fn domain_policy_is_immutable_and_enforced() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let mut policy = DomainPolicy {
            capabilities: alloc::vec![3],
            max_assemblies: 1,
            max_instances: 1,
            max_int_records: 1,
            max_blob_records: 1,
            max_blob_bytes: 3,
            max_key_slots: 1,
            max_package_bytes: 8192,
        };
        let request = |policy: DomainPolicy| {
            let mut data = alloc::vec![1, 1, b'a'];
            data.extend(&policy.wire().unwrap()[1..]);
            data
        };
        c.manage(command(0xe1, &request(policy.clone()))).unwrap();
        assert_eq!(
            c.manage(command(0xe3, b"a")).unwrap(),
            policy.wire().unwrap()
        );
        let mut empty_policy = policy.clone();
        empty_policy.capabilities.clear();
        c.manage(command(0xe1, &request(empty_policy.clone())))
            .unwrap();
        assert_eq!(
            c.manage(command(0xe3, b"a")).unwrap(),
            empty_policy.wire().unwrap()
        );
        c.manage(command(0xe1, &request(policy.clone()))).unwrap();
        assert_eq!(
            load(&mut c, &package("a", inc, "one", 1, 7, &[0x2a])),
            Err(Error::Unauthorized)
        );
        assert!(c.state.domains["a"].key.is_none());

        policy.capabilities = alloc::vec![2, 3, 4, 7, 8, 9, 11, 12, 13, 20];
        c.manage(command(0xe1, &request(policy.clone()))).unwrap();
        load(&mut c, &counter_package("a", inc, 1, 7)).unwrap();
        assert_eq!(
            load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])),
            Err(Error::Quota)
        );
        c.state
            .domains
            .get_mut("a")
            .unwrap()
            .store
            .insert(2, 99)
            .unwrap();
        assert_eq!(
            c.manage(command(0xec, br#"["a","F04D430001"]"#)),
            Err(Error::Quota)
        );
        assert_eq!(c.state.domains["a"].store.get(&2), Some(&99));
        assert!(c.state.domains["a"].instances.is_empty());
        let store = &mut c.state.domains.get_mut("a").unwrap().store;
        let index = store.position(2).unwrap();
        store.0[index].1.zeroize();
        store.0.remove(index);
        c.manage(command(0xf0, br#"["a","Counter"]"#)).unwrap();
        assert_eq!(
            load(&mut c, &package("a", inc, "two", 1, 7, &[0x2a])),
            Err(Error::Quota)
        );
        assert_eq!(
            c.manage(command(0xe1, &request(policy.clone()))),
            Err(Error::Busy)
        );
        let mut invalid = request(policy);
        invalid[3] = 1;
        assert_eq!(c.manage(command(0xe1, &invalid)), Err(Error::Format));
        let reopened = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(reopened.state.domains["a"].policy.max_int_records, 1);
    }
    #[test]
    fn failed_invocation_rolls_back_store() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let p = counter_package("a", inc, 1, 7);
        load(&mut c, &p).unwrap();
        c.manage(command(0xec, br#"["a","F04D430001"]"#)).unwrap();
        c.state
            .domains
            .get_mut("a")
            .unwrap()
            .store
            .insert(1, i32::MAX)
            .unwrap();
        assert_eq!(c.invoke("F04D430001", &[]), Err(Error::Arithmetic));
        assert_eq!(c.state.domains["a"].store.get(&1), Some(&i32::MAX));
        assert_eq!(
            c.manage(command(0xf0, br#"["a","Counter"]"#)),
            Err(Error::Busy)
        );
    }

    #[test]
    fn selected_identity_buffers_are_reused_across_processing() {
        let mut card = card();
        let incarnation = create(&mut card, "selected-buffer");
        load(
            &mut card,
            &counter_package("selected-buffer", incarnation, 1, 7),
        )
        .unwrap();
        card.manage(command(
            0xec,
            br#"["selected-buffer","F04D430001"]"#,
        ))
        .unwrap();
        card.select("F04D430001").unwrap();
        let pointers = {
            let (domain, _, aid) = card.selected.as_ref().unwrap();
            (domain.as_ptr(), aid.as_ptr())
        };

        card.process(&[]).unwrap();
        card.process_verified(Verified {
            command: Command {
                cla: 0x80,
                ins: 0x10,
                p1: 0,
                p2: 0,
                data: Vec::new().into(),
                le: None,
            },
            level: 0x13,
        })
        .unwrap();

        let (domain, _, aid) = card.selected.as_ref().unwrap();
        assert_eq!((domain.as_ptr(), aid.as_ptr()), pointers);

        card.select_isd_with_cancel(&mut || false).unwrap();
        assert!(card.selected.is_none());
        card.select("F04D430001").unwrap();
        *card
            .state
            .domains
            .get_mut("selected-buffer")
            .unwrap()
            .instances
            .get_mut("F04D430001")
            .unwrap() = Rc::from("Missing");
        let pointers = {
            let (domain, _, aid) = card.selected.as_ref().unwrap();
            (domain.as_ptr(), aid.as_ptr())
        };
        assert_eq!(
            card.select_isd_with_cancel(&mut || false),
            Err(Error::Missing)
        );
        let (domain, _, aid) = card.selected.as_ref().unwrap();
        assert_eq!((domain.as_ptr(), aid.as_ptr()), pointers);
    }

    #[test]
    fn signed_multi_command_transactions_commit_abort_and_expire() {
        let mut card = card();
        let incarnation = create(&mut card, "transaction");
        load(
            &mut card,
            &transaction_records_package("transaction", incarnation, 1, 7),
        )
        .unwrap();
        load(
            &mut card,
            &transaction_negative_package("transaction", incarnation, 1, 7),
        )
        .unwrap();
        card.manage(command(0xec, br#"["transaction","F04D430020"]"#))
            .unwrap();
        card.manage(command(0xec, br#"["transaction","F04D430022"]"#))
            .unwrap();
        assert_eq!(
            card.manage(command(0xec, br#"["transaction","F04D430021"]"#)),
            Err(Error::Unauthorized)
        );
        assert!(!card.state.domains["transaction"]
            .instances
            .contains_key("F04D430021"));
        assert!(card.transaction.is_none());
        for command in [0, 1, 2] {
            assert_eq!(
                card.invoke("F04D430022", &[command]),
                Err(Error::Unauthorized)
            );
            assert!(card.transaction.is_none());
            assert!(card.state.domains["transaction"].store.is_empty());
        }

        assert_eq!(card.invoke("F04D430020", &[6]).unwrap(), [0, 0, 0, 0x90, 0]);
        assert_eq!(card.invoke("F04D430020", &[4]), Err(Error::Missing));
        assert_eq!(card.invoke("F04D430020", &[5]), Err(Error::Missing));
        card.invoke("F04D430020", &[0]).unwrap();
        card.invoke("F04D430020", &[1, 11]).unwrap();
        card.invoke("F04D430020", &[2, 22]).unwrap();
        card.invoke("F04D430020", &[3, 33]).unwrap();
        assert_eq!(
            card.invoke("F04D430020", &[6]).unwrap(),
            [11, 22, 33, 0x90, 0]
        );
        assert!(card.state.domains["transaction"].store.is_empty());
        assert!(card.state.domains["transaction"].blobs.is_empty());

        let mut card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert!(card.transaction.is_none());
        assert_eq!(card.invoke("F04D430020", &[6]).unwrap(), [0, 0, 0, 0x90, 0]);

        card.invoke("F04D430020", &[0]).unwrap();
        let domain_registry_aid = card.state.domains["transaction"].registry_aid;
        let owner_aid_pointer = card.transaction.as_ref().unwrap().owner.2.as_ptr();
        card.invoke("F04D430020", &[1, 11]).unwrap();
        let owner = &card.transaction.as_ref().unwrap().owner;
        assert_eq!(owner.0, domain_registry_aid);
        assert_eq!(owner.2.as_ptr(), owner_aid_pointer);
        card.invoke("F04D430020", &[2, 22]).unwrap();
        card.invoke("F04D430020", &[3, 33]).unwrap();
        card.invoke("F04D430020", &[4]).unwrap();
        assert!(card.transaction.is_none());
        assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));
        assert_eq!(card.state.domains["transaction"].store.get(&2), Some(&22));
        assert_eq!(card.state.domains["transaction"].blobs.get(&3).unwrap(), &[33]);

        let mut card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(
            card.invoke("F04D430020", &[6]).unwrap(),
            [11, 22, 33, 0x90, 0]
        );
        card.invoke("F04D430020", &[0]).unwrap();
        card.invoke("F04D430020", &[1, 44]).unwrap();
        card.invoke("F04D430020", &[5]).unwrap();
        assert_eq!(
            card.invoke("F04D430020", &[6]).unwrap(),
            [11, 22, 33, 0x90, 0]
        );

        card.invoke("F04D430020", &[0]).unwrap();
        card.invoke("F04D430020", &[1, 55]).unwrap();
        assert_eq!(card.invoke("F04D430020", &[0]), Err(Error::Busy));
        assert!(card.transaction.is_none());
        assert_eq!(
            card.invoke("F04D430020", &[6]).unwrap(),
            [11, 22, 33, 0x90, 0]
        );

        card.invoke("F04D430020", &[0]).unwrap();
        for _ in 0..14 {
            card.invoke("F04D430020", &[6]).unwrap();
        }
        assert_eq!(card.invoke("F04D430020", &[6]), Err(Error::Budget));
        assert!(card.transaction.is_none());

        card.invoke("F04D430020", &[0]).unwrap();
        card.invoke("F04D430020", &[1, 77]).unwrap();
        assert_eq!(card.invoke("F04D430020", &[0; 256]), Err(Error::Bounds));
        assert!(card.transaction.is_none());

        card.invoke("F04D430020", &[7]).unwrap();
        assert!(card.transaction.is_none());
        assert_eq!(card.state.domains["transaction"].store.get(&1), Some(&11));

        card.invoke("F04D430020", &[0]).unwrap();
        card.invoke("F04D430020", &[1, 66]).unwrap();
        card.select("F04D430020").unwrap();
        assert!(card.transaction.is_none());
        assert_eq!(
            card.invoke("F04D430020", &[6]).unwrap(),
            [11, 22, 33, 0x90, 0]
        );
    }

    #[test]
    fn representative_simulator_runtime_peaks_stay_within_budget() {
        let mut card = card();
        let incarnation = create(&mut card, "metrics");
        load(
            &mut card,
            &key_operations_package("metrics", incarnation, 1, 7),
        )
        .unwrap();
        for aid in ["F04D430010", "F04D430011"] {
            card.manage(command(
                0xec,
                alloc::format!(r#"["metrics","{aid}"]"#).as_bytes(),
            ))
            .unwrap();
        }
        let mut peak = crate::mc04_vm::ExecutionMetrics::default();
        for (aid, data) in [
            ("F04D430010", &[0][..]),
            ("F04D430010", &[1][..]),
            ("F04D430010", &[2][..]),
            ("F04D430010", &[3][..]),
            ("F04D430011", &[][..]),
        ] {
            let (_, measured) = card.invoke_context_with_metrics(aid, data, 0).unwrap();
            peak.instructions = peak.instructions.max(measured.instructions);
            peak.peak_evaluation_slots = peak
                .peak_evaluation_slots
                .max(measured.peak_evaluation_slots);
            peak.peak_local_slots = peak.peak_local_slots.max(measured.peak_local_slots);
            peak.peak_frames = peak.peak_frames.max(measured.peak_frames);
            peak.peak_transient_bytes =
                peak.peak_transient_bytes.max(measured.peak_transient_bytes);
            peak.peak_transient_objects = peak
                .peak_transient_objects
                .max(measured.peak_transient_objects);
            peak.native_work_units = peak.native_work_units.max(measured.native_work_units);
        }
        assert_eq!(
            peak,
            crate::mc04_vm::ExecutionMetrics {
                instructions: 256,
                peak_evaluation_slots: 7,
                peak_local_slots: 10,
                peak_frames: 2,
                peak_transient_bytes: 177,
                peak_transient_objects: 7,
                native_work_units: 124,
            }
        );
        assert!(peak.instructions <= 512);
        assert!(peak.peak_evaluation_slots <= 8);
        assert!(peak.peak_local_slots <= 16);
        assert!(peak.peak_frames <= 4);
        assert!(peak.peak_transient_bytes <= 256);
        assert!(peak.peak_transient_objects <= 8);
        assert!(peak.native_work_units <= 128);
    }

    #[test]
    fn native_failure_and_fuel_exhaustion_roll_back_all_writes() {
        let mut card = card();
        let incarnation = create(&mut card, "atomic");
        load(
            &mut card,
            &key_operations_package("atomic", incarnation, 1, 7),
        )
        .unwrap();

        card.manage(command(0xec, br#"["atomic","F04D430011"]"#))
            .unwrap();
        assert_eq!(card.invoke("F04D430011", &[]), Err(Error::Missing));
        assert!(!card.state.domains["atomic"].store.contains_key(&10));

        card.manage(command(0xec, br#"["atomic","F04D430013"]"#))
            .unwrap();
        assert_eq!(card.invoke("F04D430013", &[]), Err(Error::Budget));
        assert!(!card.state.domains["atomic"].store.contains_key(&30));

        let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert!(!reopened.state.domains["atomic"].store.contains_key(&10));
        assert!(!reopened.state.domains["atomic"].store.contains_key(&30));
    }

    #[test]
    fn cooperative_cancellation_rolls_back_all_writes() {
        let mut card = card();
        let incarnation = create(&mut card, "cancel");
        load(
            &mut card,
            &key_operations_package("cancel", incarnation, 1, 7),
        )
        .unwrap();
        card.manage(command(0xec, br#"["cancel","F04D430013"]"#))
            .unwrap();

        let mut polls = 0;
        let result = card.invoke_context_with_cancel("F04D430013", &[], 0, &mut || {
            polls += 1;
            polls == 2
        });
        assert_eq!(result, Err(Error::Cancelled));
        assert_eq!(polls, 2);
        assert!(!card.state.domains["cancel"].store.contains_key(&30));

        let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert!(!reopened.state.domains["cancel"].store.contains_key(&30));
    }

    #[test]
    fn every_invocation_commit_mutation_recovers_old_or_new_state() {
        let mut card = card();
        let incarnation = create(&mut card, "atomic");
        load(&mut card, &counter_package("atomic", incarnation, 1, 7)).unwrap();
        card.manage(command(0xec, br#"["atomic","F04D430001"]"#))
            .unwrap();
        let previous = serde_json::to_vec(&card.state).unwrap();
        let base = card.into_flash();

        let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        complete.invoke("F04D430001", &[]).unwrap();
        let committed = serde_json::to_vec(&complete.state).unwrap();
        let mutations = 16384 + 35 + committed.len();
        for cut in 0..=mutations {
            let mut flash = base.clone();
            flash.fail_after = Some(cut);
            let mut interrupted = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let _ = interrupted.invoke("F04D430001", &[]);
            let mut flash = interrupted.into_flash();
            flash.fail_after = None;
            let recovered = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let actual = serde_json::to_vec(&recovered.state).unwrap();
            assert!(
                actual == previous || actual == committed,
                "partial invocation commit at cut {cut}"
            );
        }
    }
    #[test]
    fn domain_application_state_is_zeroized_before_release() {
        let mut domain = Domain::new(
            [7; 16],
            RegistryAid::synthetic(1, b"zeroize-test"),
            DomainPolicy::standard().unwrap(),
        );
        domain.store.insert(1, 0x1122_3344).unwrap();
        domain.blobs.insert(2, alloc::vec![0x5a; 32]).unwrap();

        domain.zeroize_application_state();

        assert_eq!(domain.store[&1], 0);
        assert!(domain.blobs[&2].is_empty());
    }

    #[test]
    fn stores_are_domain_scoped() {
        let mut c = card();
        let a = create(&mut c, "a");
        let b = create(&mut c, "b");
        load(&mut c, &counter_package("a", a, 1, 7)).unwrap();
        assert_eq!(
            run_loaded(&mut c, "a", "Counter", 1, &[]).unwrap(),
            [1, 0x90, 0]
        );
        assert_eq!(
            run_loaded(&mut c, "a", "Counter", 28, &[]).unwrap(),
            [1, 0, 0, 0, 0x90, 0]
        );
        c.manage(command(0xf0, br#"["a","Counter"]"#)).unwrap();
        load(&mut c, &counter_package("b", b, 1, 8)).unwrap();
        assert_eq!(
            run_loaded(&mut c, "b", "Counter", 28, &[]).unwrap(),
            [0, 0, 0, 0, 0x90, 0]
        );
    }

    #[test]
    fn persistent_storage_schema_is_pinned_until_domain_deletion() {
        let mut card = card();
        let incarnation = create(&mut card, "schema");
        load(&mut card, &counter_package("schema", incarnation, 1, 7)).unwrap();
        let pinned_schema = Rc::clone(&card.state.domains["schema"].storage_schema);
        load(
            &mut card,
            &library_package("schema", incarnation, "Library", 1, 7),
        )
        .unwrap();
        assert!(Rc::ptr_eq(
            &pinned_schema,
            &card.state.domains["schema"].storage_schema
        ));
        assert_eq!(
            card.state.domains["schema"].storage_declaration(1),
            Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
        );
        card.manage(command(0xf0, br#"["schema","Counter"]"#))
            .unwrap();
        card.manage(command(0xf0, br#"["schema","Library"]"#))
            .unwrap();
        let conflicting = signed_package_with_storage(
            "schema",
            incarnation,
            "Conflict",
            1,
            7,
            &[0x2a],
            false,
            alloc::vec![
                StorageDeclaration { key: 0, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 1, kind: 2, max_bytes: 16 },
            ],
        );
        assert_eq!(load(&mut card, &conflicting), Err(Error::KeyMismatch));
        assert!(card.state.domains["schema"].assemblies.is_empty());
        assert!(card.state.domains["schema"].storage_declaration(0).is_none());
        assert!(Rc::ptr_eq(
            &pinned_schema,
            &card.state.domains["schema"].storage_schema
        ));
        let card = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(
            card.state.domains["schema"].storage_declaration(1),
            Some(&StorageDeclaration { key: 1, kind: 1, max_bytes: 0 })
        );
        let mut card = card;
        card.manage(command(0xe4, b"schema")).unwrap();
        let replacement = create(&mut card, "schema");
        let replacement_package = signed_package_with_storage(
            "schema",
            replacement,
            "Replacement",
            1,
            8,
            &[0x2a],
            false,
            alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
        );
        load(&mut card, &replacement_package).unwrap();
        assert_eq!(
            card.state.domains["schema"].storage_declaration(1),
            Some(&StorageDeclaration { key: 1, kind: 2, max_bytes: 16 })
        );
    }

    #[test]
    fn recovery_rejects_missing_or_retyped_persistent_schema() {
        let mut card = card();
        let incarnation = create(&mut card, "schema-recovery");
        load(
            &mut card,
            &counter_package("schema-recovery", incarnation, 1, 7),
        )
        .unwrap();
        run_loaded(&mut card, "schema-recovery", "Counter", 1, &[]).unwrap();
        let canonical = serde_json::to_value(&card.state).unwrap();
        assert_eq!(
            canonical["domains"]["schema-recovery"]["storage_schema"],
            serde_json::json!([[1, 1, 0]])
        );
        let mut legacy = canonical.clone();
        legacy["domains"]["schema-recovery"]["storage_schema"] =
            serde_json::json!([{"key": 1, "kind": 1, "max_bytes": 0}]);
        assert!(serde_json::from_value::<State>(legacy).is_err());
        let schema = |count: i32| {
            serde_json::Value::Array(
                (0..count)
                    .map(|key| serde_json::json!([key, 1, 0]))
                    .collect(),
            )
        };
        let mut maximum = canonical.clone();
        maximum["domains"]["schema-recovery"]["storage_schema"] =
            schema(MAX_DOMAIN_STORAGE_DECLARATIONS as i32);
        let maximum = serde_json::from_value::<State>(maximum).unwrap();
        assert_eq!(
            maximum.domains["schema-recovery"].storage_schema.len(),
            MAX_DOMAIN_STORAGE_DECLARATIONS
        );
        let mut oversized = canonical.clone();
        oversized["domains"]["schema-recovery"]["storage_schema"] =
            schema(MAX_DOMAIN_STORAGE_DECLARATIONS as i32 + 1);
        assert!(serde_json::from_value::<State>(oversized).is_err());
        let mut duplicate = canonical;
        duplicate["domains"]["schema-recovery"]["storage_schema"] =
            serde_json::json!([[1, 1, 0], [1, 1, 0]]);
        assert!(serde_json::from_value::<State>(duplicate).is_err());
        let mut corrupted = card.state.try_clone().unwrap();
        let domain = corrupted.domains.get_mut("schema-recovery").unwrap();
        let mut schema = domain.storage_schema.as_ref().clone();
        schema[0].kind = 2;
        schema[0].max_bytes = 1;
        domain.storage_schema = Rc::new(schema);
        card.commit(corrupted).unwrap();
        assert!(matches!(
            Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY),
            Err(Error::Storage)
        ));
    }

    #[test]
    fn managed_storage_access_requires_the_calling_assembly_declaration() {
        let mut card = card();
        let undeclared_incarnation = create(&mut card, "undeclared");
        let undeclared = counter_package_with_storage(
            "undeclared",
            undeclared_incarnation,
            1,
            7,
            Vec::new(),
        );
        load(&mut card, &undeclared).unwrap();
        assert_eq!(
            run_loaded(&mut card, "undeclared", "Counter", 0, &[]),
            Err(Error::Unauthorized)
        );
        assert!(card.state.domains["undeclared"].store.is_empty());

        let wrong_kind_incarnation = create(&mut card, "wrong-kind");
        let wrong_kind = counter_package_with_storage(
            "wrong-kind",
            wrong_kind_incarnation,
            1,
            8,
            alloc::vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 16 }],
        );
        load(&mut card, &wrong_kind).unwrap();
        assert_eq!(
            run_loaded(&mut card, "wrong-kind", "Counter", 0, &[]),
            Err(Error::Unauthorized)
        );
        assert!(card.state.domains["wrong-kind"].store.is_empty());
    }

    #[test]
    fn persistent_byte_declaration_bounds_each_native_write() {
        let mut card = card();
        let incarnation = create(&mut card, "blob-bound");
        let package = key_operations_package_with_storage(
            "blob-bound",
            incarnation,
            1,
            7,
            alloc::vec![
                StorageDeclaration { key: 10, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 20, kind: 2, max_bytes: 2 },
                StorageDeclaration { key: 21, kind: 2, max_bytes: 1 },
                StorageDeclaration { key: 30, kind: 1, max_bytes: 0 },
            ],
        );
        load(&mut card, &package).unwrap();
        assert_eq!(
            run_loaded(&mut card, "blob-bound", "KeyOperations", 4, &[0]),
            Err(Error::Quota)
        );
        assert!(card.state.domains["blob-bound"].blobs.is_empty());
    }

    #[test]
    fn issuer_dependency_code_cannot_reach_caller_domain_storage() {
        let raw = signed_package_with_storage(
            "ISD",
            [2; 16],
            "Provider",
            1,
            7,
            &[0x2a],
            false,
            alloc::vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
        );
        let package = PackageView::verify(&raw).unwrap();
        let calls = [ResolvedCall { member: 1, target: CallTarget::Native(3) }];
        let units = [ExecutionUnit { package, bindings: &[], calls: &calls }];
        let schema = [StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }];
        let mut store = IntStore::new();
        let mut blobs = BlobStore::new();
        let mut keys = crate::key_store::KeyStore::default();
        let mut credentials = crate::credential_store::CredentialStore::default();
        let mut platform = TestPlatform(0);
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: &[],
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 32,
            capabilities: &[],
            domain_schema: &schema,
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: Some(&units),
            transaction: &mut transaction,
            irreversible_output: false,
        };
        let mut heap = crate::mc04_vm::Heap::new();
        assert_eq!(
            crate::mc04_vm::External::invoke(
                &mut host,
                0,
                1,
                3,
                &[crate::mc04_vm::RuntimeValue::Int(1)],
                &mut heap,
            ),
            Err(Error::Unauthorized)
        );
        assert!(host.store.is_empty());
    }

    #[test]
    fn execution_units_borrow_persisted_packages_and_link_tables() {
        let mut card = card();
        let incarnation = create(&mut card, "borrowed");
        load(
            &mut card,
            &package("borrowed", incarnation, "library", 1, 7, &[0x2a]),
        )
        .unwrap();
        let domain = &card.state.domains["borrowed"];
        let raw = &domain.assemblies["library"];
        let calls = &domain.imports["library"];
        let units = execution_units(&card.state, "borrowed", "library").unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].package.raw.as_ptr(), raw.as_ptr());
        assert_eq!(units[0].calls.as_ptr(), calls.as_ptr());
        let image_offset = units[0].package.image.as_ptr() as usize - raw.as_ptr() as usize;
        assert!(image_offset >= 12 && image_offset < raw.len());
    }

    #[test]
    fn owned_package_indexes_image_inside_its_signed_envelope() {
        let raw = counter_package("owned", [7; 16], 1, 7);
        let package = Package::verify(&raw).unwrap();
        let raw_start = package.raw.as_ptr() as usize;
        let raw_end = raw_start + package.raw.len();
        let image_start = package.image().as_ptr() as usize;
        assert!(image_start >= raw_start && image_start + package.image().len() <= raw_end);
        assert_eq!(
            package.image(),
            include_bytes!("../../../fuzz/fixtures/counter.mca")
        );
    }

    #[test]
    fn state_snapshots_share_signed_packages_and_preserve_wire_state() {
        fn assert_shared_names(domain: &Domain, name: &str) {
            let package_name = domain.assemblies.get_key_value(name).unwrap().0;
            let version_name = domain.versions.get_key_value(name).unwrap().0;
            let binding_name = domain.bindings.get_key_value(name).unwrap().0;
            let import_name = domain.imports.get_key_value(name).unwrap().0;
            assert!(Rc::ptr_eq(package_name, version_name));
            assert!(Rc::ptr_eq(package_name, binding_name));
            assert!(Rc::ptr_eq(package_name, import_name));
            for instance_name in domain
                .instances
                .values()
                .filter(|instance_name| instance_name.as_ref() == name)
            {
                assert!(Rc::ptr_eq(package_name, instance_name));
            }
        }

        let mut card = card();
        let incarnation = create(&mut card, "shared");
        let counter = counter_package("shared", incarnation, 1, 7);
        let keys = key_operations_package("shared", incarnation, 1, 7);
        load(&mut card, &counter).unwrap();
        load(&mut card, &keys).unwrap();
        card.manage(command(0xec, br#"["shared","F04D430001"]"#))
            .unwrap();
        let shared = card.state.domains.get_mut("shared").unwrap();
        shared.store.insert(7, 11).unwrap();
        shared.blobs.insert(8, alloc::vec![1, 2, 3, 4]).unwrap();
        shared
            .keys
            .generate(shared.incarnation, 0, 1, |bytes| {
                bytes.fill(0x5a);
                Ok(())
            })
            .unwrap();
        shared
            .credentials
            .create(
                shared.incarnation,
                0,
                b"1234",
                b"12345678",
                (3, 3),
                |bytes| {
                    bytes.fill(0xa5);
                    Ok(())
                },
            )
            .unwrap();
        assert!(serde_json::to_vec(&card.state).unwrap().len() <= 49152);
        assert_shared_names(&card.state.isd, "mscorlib");
        assert_shared_names(&card.state.domains["shared"], "Counter");
        assert_shared_names(&card.state.domains["shared"], "KeyOperations");
        let wire_state = serde_json::to_vec(&card.state).unwrap();
        let mut clone_context = crate::fallible_clone::CloneContext::new();
        let snapshot = card.state.try_clone_with(&mut clone_context).unwrap();
        let allocation_count = clone_context.allocations();
        assert!(allocation_count > 16);
        for fail_at in 0..allocation_count {
            let mut context = crate::fallible_clone::CloneContext::failing_at(fail_at);
            assert!(matches!(
                card.state.try_clone_with(&mut context),
                Err(Error::Quota)
            ));
            assert_eq!(serde_json::to_vec(&card.state).unwrap(), wire_state);
        }
        assert!(Rc::ptr_eq(
            &card.state.isd.assemblies["mscorlib"],
            &snapshot.isd.assemblies["mscorlib"]
        ));
        assert!(Rc::ptr_eq(
            &card.state.domains["shared"].storage_schema,
            &snapshot.domains["shared"].storage_schema
        ));
        for name in ["Counter", "KeyOperations"] {
            assert!(Rc::ptr_eq(
                &card.state.domains["shared"].assemblies[name],
                &snapshot.domains["shared"].assemblies[name]
            ));
            assert_shared_names(&snapshot.domains["shared"], name);
        }
        assert_eq!(
            serde_json::to_vec(&card.state).unwrap(),
            serde_json::to_vec(&snapshot).unwrap()
        );
        let mut noncanonical = serde_json::to_value(&card.state).unwrap();
        let mut encoded = String::from(
            noncanonical["domains"]["shared"]["assemblies"]["Counter"]
                .as_str()
                .unwrap(),
        );
        encoded.push('=');
        noncanonical["domains"]["shared"]["assemblies"]["Counter"] =
            serde_json::Value::String(encoded);
        assert!(serde_json::from_value::<State>(noncanonical).is_err());

        let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_shared_names(&reopened.state.isd, "mscorlib");
        assert_shared_names(&reopened.state.domains["shared"], "Counter");
        assert_shared_names(&reopened.state.domains["shared"], "KeyOperations");
    }

    #[test]
    fn maximum_container_state_clone_is_fallible_and_atomic() {
        let mut card = card();
        let incarnation = create(&mut card, "maximum-clone");
        let domain = card.state.domains.get_mut("maximum-clone").unwrap();
        domain.key = Some([0x44; 32]);
        for index in 0..MAX_ASSEMBLIES_PER_DOMAIN {
            let name: Rc<str> = Rc::from(alloc::format!("Assembly{index}"));
            domain
                .assemblies
                .insert(Rc::clone(&name), Rc::new(alloc::vec![index]))
                .unwrap();
            domain
                .bindings
                .insert(Rc::clone(&name), Vec::new())
                .unwrap();
            domain
                .imports
                .insert(Rc::clone(&name), Vec::new())
                .unwrap();
            domain
                .versions
                .insert(Rc::clone(&name), (1, [index; 32]))
                .unwrap();
            domain
                .instances
                .insert(alloc::format!("F04D4301{index:02X}"), name)
                .unwrap();
        }
        let mut schema = Vec::new();
        schema
            .try_reserve_exact(MAX_DOMAIN_STORAGE_DECLARATIONS)
            .unwrap();
        for key in 0..MAX_DOMAIN_STORAGE_DECLARATIONS as i32 {
            schema.push(StorageDeclaration { key, kind: 1, max_bytes: 0 });
            domain.store.insert(key, key).unwrap();
        }
        domain.storage_schema = Rc::new(schema);
        for index in 0..MAX_BLOB_RECORDS {
            domain
                .blobs
                .insert(1_000 + index as i32, alloc::vec![index as u8; 128])
                .unwrap();
        }
        for slot in 0..8 {
            domain
                .keys
                .generate(incarnation, slot, 1, |output| {
                    output.fill(slot as u8 + 1);
                    Ok(())
                })
                .unwrap();
            domain
                .credentials
                .create(
                    incarnation,
                    slot,
                    b"1234",
                    b"12345678",
                    (3, 3),
                    |output| {
                        output.fill(slot as u8 + 1);
                        Ok(())
                    },
                )
                .unwrap();
        }

        let before = serde_json::to_vec(&card.state).unwrap();
        let mut complete_context = crate::fallible_clone::CloneContext::new();
        let complete = card.state.try_clone_with(&mut complete_context).unwrap();
        assert!(Rc::ptr_eq(
            &card.state.domains["maximum-clone"].storage_schema,
            &complete.domains["maximum-clone"].storage_schema
        ));
        let allocations = complete_context.allocations();
        assert!(allocations > 70, "allocations={allocations}");
        for fail_at in 0..allocations {
            let mut context = crate::fallible_clone::CloneContext::failing_at(fail_at);
            assert!(matches!(
                card.state.try_clone_with(&mut context),
                Err(Error::Quota)
            ));
            assert_eq!(serde_json::to_vec(&card.state).unwrap(), before);
        }
    }

    #[test]
    fn first_load_power_loss_never_pins_alone() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let p = package("a", inc, "one", 1, 7, &[0x2a]);
        let previous = serde_json::to_vec(&c.state).unwrap();
        let base = c.into_flash();
        let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        load(&mut complete, &p).unwrap();
        let serialized = serde_json::to_vec(&complete.state).unwrap(); // Journal mutation behavior is exhaustively tested separately.
        for cut in 0..=16384 + 35 + serialized.len() {
            let mut f = base.clone();
            f.fail_after = Some(cut);
            let mut c = Card::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
            let _ = load(&mut c, &p);
            let mut f = c.into_flash();
            f.fail_after = None;
            let mut recovered = Card::open(f, TestPlatform(10), STORAGE_KEY).unwrap();
            let actual = serde_json::to_vec(&recovered.state).unwrap();
            assert!(
                actual == previous || actual == serialized,
                "partial activation at cut {cut}"
            );
            load(&mut recovered, &p).unwrap();
            assert_eq!(serde_json::to_vec(&recovered.state).unwrap(), serialized);
            let reopened =
                Card::open(recovered.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
            assert_eq!(serde_json::to_vec(&reopened.state).unwrap(), serialized);
        }
    }
    #[test]
    fn activation_moves_staging_and_restores_it_after_commit_failure() {
        let mut card = card();
        let incarnation = create(&mut card, "move");
        let initial = package("move", incarnation, "one", 1, 7, &[0x2a]);
        for (index, chunk) in initial.chunks(200).enumerate() {
            let mut data = (index as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            card.manage(command(0xe8, &data)).unwrap();
        }
        let staged_pointer = card.staging.bytes.as_ptr();
        card.manage(command(0xea, &[])).unwrap();
        assert!(card.staging.bytes.is_empty());
        assert_eq!(
            card.state.domains["move"].assemblies["one"]
                .as_ref()
                .as_ptr(),
            staged_pointer
        );

        let mut flash = card.into_flash();
        flash.fail_after = Some(0);
        let mut card = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
        let replacement = signed_package_with_storage(
            "move",
            incarnation,
            "one",
            2,
            7,
            &[0x2a],
            true,
            alloc::vec![
                StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
                StorageDeclaration { key: 2, kind: 2, max_bytes: 8 },
            ],
        );
        for (index, chunk) in replacement.chunks(200).enumerate() {
            let mut data = (index as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            card.manage(command(0xe8, &data)).unwrap();
        }
        let staged_pointer = card.staging.bytes.as_ptr();
        assert_eq!(card.manage(command(0xea, &[])), Err(Error::Storage));
        assert_eq!(card.staging.bytes, replacement);
        assert_eq!(card.staging.bytes.as_ptr(), staged_pointer);
        assert_eq!(card.state.domains["move"].versions["one"].0, 1);
        assert!(card.state.domains["move"].storage_declaration(2).is_none());
    }
    #[test]
    fn flash_staging_streams_and_activates_without_a_ram_upload_buffer() {
        let flash = TestStagingFlash::new();
        let erases = Rc::clone(&flash.erases);
        let mut card = Card::open_with_staging(
            MemoryFlash::new(16384),
            TestPlatform(0),
            STORAGE_KEY,
            crate::staging::FlashStaging::new(flash),
        )
        .unwrap();
        let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
        for (index, chunk) in package.chunks(200).enumerate() {
            let mut data = (index as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            card.manage(command(0xe8, &data)).unwrap();
        }
        assert!(card.staging.as_slice().is_none());
        assert_eq!(erases.get(), 1);
        card.manage(command(0xea, &[])).unwrap();
        assert_eq!(card.state.isd.assemblies["mscorlib"].as_slice(), package);
        assert_eq!(card.staging.len(), 0);

        let mut corrupted = package.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        for (index, chunk) in corrupted.chunks(200).enumerate() {
            let mut data = (index as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            card.manage(command(0xe8, &data)).unwrap();
        }
        assert_eq!(erases.get(), 2);
        assert_eq!(card.manage(command(0xea, &[])), Err(Error::Signature));
        assert_eq!(card.staging.len(), corrupted.len());
        let mut retry = 0u32.to_le_bytes().to_vec();
        retry.extend(&corrupted[..200.min(corrupted.len())]);
        card.manage(command(0xe8, &retry)).unwrap();
        assert_eq!(erases.get(), 2);
        card.manage(command(0xe6, &[])).unwrap();
        assert_eq!(card.staging.len(), 0);
    }
    #[test]
    fn flash_staging_survives_journal_failure_for_activation_retry() {
        let journal = Rc::new(RefCell::new(MemoryFlash::new(16384)));
        let flash = TestStagingFlash::new();
        let erases = Rc::clone(&flash.erases);
        let mut card = Card::open_with_staging(
            SharedJournalFlash(Rc::clone(&journal)),
            TestPlatform(0),
            STORAGE_KEY,
            crate::staging::FlashStaging::new(flash),
        )
        .unwrap();
        let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
        for (index, chunk) in package.chunks(200).enumerate() {
            let mut data = (index as u32 * 200).to_le_bytes().to_vec();
            data.extend(chunk);
            card.manage(command(0xe8, &data)).unwrap();
        }
        journal.borrow_mut().fail_after = Some(0);
        assert_eq!(card.manage(command(0xea, &[])), Err(Error::Storage));
        assert_eq!(card.staging.len(), package.len());
        assert!(card.state.isd.key.is_none());
        assert_eq!(erases.get(), 1);

        journal.borrow_mut().fail_after = None;
        card.manage(command(0xea, &[])).unwrap();
        assert_eq!(card.state.isd.assemblies["mscorlib"].as_slice(), package);
        assert_eq!(card.staging.len(), 0);
        assert_eq!(erases.get(), 1);
    }
    #[test]
    fn staged_upload_quota_failure_preserves_existing_bytes() {
        let mut card = card();
        card.staging.bytes = alloc::vec![0xa5; MAX_PACKAGE_BYTES];
        let staged_pointer = card.staging.bytes.as_ptr();
        let mut data = (MAX_PACKAGE_BYTES as u32).to_le_bytes().to_vec();
        data.push(0x5a);

        assert_eq!(card.manage(command(0xe8, &data)), Err(Error::Quota));
        assert_eq!(card.staging.len(), MAX_PACKAGE_BYTES);
        assert!(card.staging.bytes.iter().all(|byte| *byte == 0xa5));
        assert_eq!(card.staging.bytes.as_ptr(), staged_pointer);
    }
    #[test]
    fn domain_accepts_packages_above_eight_kib_with_a_sixteen_kib_ceiling() {
        let mut card = card();
        let incarnation = create(&mut card, "large");
        let mut body = alloc::vec![0; 8 * 1024];
        body.push(0x2a);
        let package = package("large", incarnation, "large", 1, 7, &body);
        assert!(package.len() > 8 * 1024);
        assert!(package.len() <= MAX_PACKAGE_BYTES);
        load(&mut card, &package).unwrap();
        assert_eq!(
            card.state.domains["large"].assemblies["large"].len(),
            package.len()
        );

        assert!(matches!(
            PackageView::verify(&alloc::vec![0; MAX_PACKAGE_BYTES + 1]),
            Err(Error::Format)
        ));
    }
    #[test]
    fn failed_install_is_invisible_and_durable() {
        let mut c = card();
        let inc = create(&mut c, "a");
        let mut p = Package::verify(&package("a", inc, "one", 1, 7, &[0x2b, 0xfe])).unwrap();
        p.manifest.entry_points[0].install = Some(0);
        let meta = serde_json::to_vec(&p.manifest).unwrap();
        let mut raw = Vec::from(b"MP03" as &[u8]);
        raw.extend(CONTEXT);
        raw.extend((meta.len() as u32).to_le_bytes());
        raw.extend((p.image().len() as u32).to_le_bytes());
        raw.extend(meta);
        raw.extend(p.image());
        let key = SigningKey::from_bytes(&[7; 32]);
        raw.extend(key.verifying_key().to_bytes());
        let signature = key.sign(&raw).to_bytes();
        raw.extend(signature);
        load(&mut c, &raw).unwrap();
        assert_eq!(
            c.manage(command(0xec, br#"["a","F04D430001"]"#)),
            Err(Error::Budget)
        );
        let c = Card::open(c.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert!(c.state.domains["a"].instances.is_empty());
        assert!(c.state.domains["a"].key.is_some());
    }

    #[test]
    fn bulk_command_io_validates_before_charging_or_mutating() {
        let mut store = IntStore::new();
        let mut blobs = BlobStore::new();
        let mut keys = crate::key_store::KeyStore::default();
        let mut credentials = crate::credential_store::CredentialStore::default();
        let mut platform = TestPlatform(0);
        let capabilities = [12, 13];
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: b"abcdef",
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 32,
            capabilities: &capabilities,
            domain_schema: &[],
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: None,
            transaction: &mut transaction,
            irreversible_output: false,
        };
        let mut heap = crate::mc04_vm::Heap::new();
        let destination = heap.allocate_bytes(alloc::vec![0; 5]).unwrap();

        host.copy_command(&mut heap, destination, 1, 1, 3)
            .unwrap();
        assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
        assert_eq!(host.budget, 28);

        assert_eq!(
            host.copy_command(&mut heap, destination, 4, 0, 2),
            Err(Error::Bounds)
        );
        assert_eq!(heap.bytes(destination).unwrap(), b"\0bcd\0");
        assert_eq!(host.budget, 28);

        host.write_response(&heap, destination, 1, 2).unwrap();
        assert_eq!(host.out, b"bc");
        assert_eq!(host.budget, 25);

        let oversized = heap.allocate_bytes(alloc::vec![0; 247]).unwrap();
        assert_eq!(
            host.write_response(&heap, oversized, 0, 247),
            Err(Error::Quota)
        );
        assert_eq!(host.out, b"bc");
        assert_eq!(host.budget, 25);

        host.capabilities = &[];
        assert_eq!(
            host.copy_command(&mut heap, destination, 0, 0, 1),
            Err(Error::Unauthorized)
        );
        assert_eq!(host.budget, 25);
    }

    #[test]
    fn bulk_random_and_fixed_time_comparison_validate_ranges() {
        let mut store = IntStore::new();
        let mut blobs = BlobStore::new();
        let mut keys = crate::key_store::KeyStore::default();
        let mut credentials = crate::credential_store::CredentialStore::default();
        let mut platform = FailingEntropy;
        let capabilities = [39, 50, 51];
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: &[],
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 32,
            capabilities: &capabilities,
            domain_schema: &[],
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: None,
            transaction: &mut transaction,
            irreversible_output: false,
        };
        let mut heap = crate::mc04_vm::Heap::new();
        let destination = heap.allocate_bytes(alloc::vec![0x7e; 8]).unwrap();
        assert_eq!(
            host.fill_random(&mut heap, destination, 6, 3),
            Err(Error::Bounds)
        );
        assert_eq!(heap.bytes(destination).unwrap(), [0x7e; 8]);
        assert_eq!(host.budget, 32);

        assert_eq!(
            host.fill_random(&mut heap, destination, 2, 4),
            Err(Error::Native)
        );
        assert_eq!(heap.bytes(destination).unwrap(), [0x7e, 0x7e, 0, 0, 0, 0, 0x7e, 0x7e]);
        assert_eq!(host.budget, 27);

        assert_eq!(host.random_bytes(-1), Err(Error::Bounds));
        assert_eq!(host.random_bytes(1025), Err(Error::Bounds));
        assert_eq!(host.budget, 27);
        assert_eq!(host.random_bytes(0), Ok(Vec::new()));
        assert_eq!(host.budget, 26);
        assert_eq!(host.random_bytes(4), Err(Error::Native));
        assert_eq!(host.budget, 21);

        let left = heap.allocate_bytes(alloc::vec![9, 1, 2, 3, 8]).unwrap();
        let right = heap.allocate_bytes(alloc::vec![7, 1, 2, 3, 6]).unwrap();
        host.budget = 16;
        assert_eq!(
            host.fixed_time_equals(&heap, (left, 1, 3), (right, 1, 3)),
            Ok(1)
        );
        assert_eq!(host.budget, 12);
        assert_eq!(
            host.fixed_time_equals(&heap, (left, 0, 5), (right, 0, 4)),
            Ok(0)
        );
        assert_eq!(host.budget, 6);
        assert_eq!(
            host.fixed_time_equals(&heap, (left, -1, 1), (right, 0, 1)),
            Err(Error::Bounds)
        );
        assert_eq!(host.budget, 6);
        assert_eq!(
            host.fixed_time_equals(&heap, (left, 4, 2), (right, 0, 2)),
            Err(Error::Bounds)
        );
        assert_eq!(host.budget, 6);
    }

    #[test]
    fn credential_native_api_tracks_retries_and_scopes_authorization_to_invocation() {
        let mut store = IntStore::new();
        let mut blobs = BlobStore::new();
        let mut keys = crate::key_store::KeyStore::default();
        let mut credentials = crate::credential_store::CredentialStore::default();
        let mut platform = TestPlatform(9);
        let capabilities = [40, 41, 42, 43, 44, 45];
        {
            let mut transaction = TransactionDisposition::Inactive;
            let mut host = Host {
                store: &mut store,
                blobs: &mut blobs,
                keys: &mut keys,
                credentials: &mut credentials,
                authorized_credentials: CredentialAuthorizations::default(),
                credential_retry_floor: CredentialRetryFloors::default(),
                owner: [1; 16],
                data: &[],
                out: Vec::new(),
                sw: 0x9000,
                platform: &mut platform,
                budget: 4096,
                capabilities: &capabilities,
                domain_schema: &[],
                max_int_records: 512,
                max_blob_records: 64,
                max_blob_bytes: 8192,
                max_key_slots: 8,
                level: 0,
                units: None,
                transaction: &mut transaction,
                irreversible_output: false,
            };
            assert_eq!(
                host.credential_call(
                    40,
                    &[
                        NativeArgument::Int(2),
                        NativeArgument::Bytes(b"x1234y"),
                        NativeArgument::Int(1),
                        NativeArgument::Int(4),
                        NativeArgument::Int(3),
                        NativeArgument::Bytes(b"x12345678y"),
                        NativeArgument::Int(1),
                        NativeArgument::Int(8),
                        NativeArgument::Int(2),
                    ],
                ),
                Ok(BufferResult::Void)
            );
            assert_eq!(
                host.credential_call(
                    41,
                    &[
                        NativeArgument::Int(2),
                        NativeArgument::Bytes(b"x9999y"),
                        NativeArgument::Int(1),
                        NativeArgument::Int(4),
                    ],
                ),
                Ok(BufferResult::Scalar(0))
            );
            assert_eq!(
                host.credential_call(
                    41,
                    &[
                        NativeArgument::Int(2),
                        NativeArgument::Bytes(b"1234"),
                        NativeArgument::Int(3),
                        NativeArgument::Int(2),
                    ],
                ),
                Err(Error::Bounds)
            );
            assert_eq!(
                host.credential_call(
                    45,
                    &[NativeArgument::Int(2), NativeArgument::Int(0)],
                ),
                Ok(BufferResult::Scalar(2))
            );
            assert_eq!(
                host.credential_call(
                    41,
                    &[
                        NativeArgument::Int(2),
                        NativeArgument::Bytes(b"x1234y"),
                        NativeArgument::Int(1),
                        NativeArgument::Int(4),
                    ],
                ),
                Ok(BufferResult::Scalar(1))
            );
            assert_eq!(
                host.credential_call(42, &[NativeArgument::Int(2)]),
                Ok(BufferResult::Scalar(1))
            );
            assert_eq!(
                host.credential_call(
                    43,
                    &[
                        NativeArgument::Int(2),
                        NativeArgument::Bytes(b"x5678y"),
                        NativeArgument::Int(1),
                        NativeArgument::Int(4),
                    ],
                ),
                Ok(BufferResult::Void)
            );
        }
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: &[],
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 4096,
            capabilities: &capabilities,
            domain_schema: &[],
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: None,
            transaction: &mut transaction,
            irreversible_output: false,
        };
        assert_eq!(
            host.credential_call(42, &[NativeArgument::Int(2)]),
            Ok(BufferResult::Scalar(0))
        );
        assert_eq!(
            host.credential_call(
                41,
                &[
                    NativeArgument::Int(2),
                    NativeArgument::Bytes(b"x5678y"),
                    NativeArgument::Int(1),
                    NativeArgument::Int(4),
                ],
            ),
            Ok(BufferResult::Scalar(1))
        );
    }

    #[test]
    fn credential_retry_floor_is_committed_and_recovers_after_invocation_failure() {
        let mut card = card();
        let incarnation = create(&mut card, "credential-floor");
        load(
            &mut card,
            &counter_package("credential-floor", incarnation, 1, 7),
        )
        .unwrap();
        let mut next = card.state.try_clone().unwrap();
        next.domains
            .get_mut("credential-floor")
            .unwrap()
            .credentials
            .create(
                incarnation,
                4,
                b"1234",
                b"12345678",
                (3, 2),
                |out| {
                    out.fill(0x5a);
                    Ok(())
                },
            )
            .unwrap();
        card.commit(next).unwrap();

        let mut floor = CredentialRetryFloors::default();
        floor.record(4, (2, 1)).unwrap();
        let domain_registry_aid = card.state.domains["credential-floor"].registry_aid;
        card.commit_credential_retry_floor(domain_registry_aid, &floor)
            .unwrap();
        assert_eq!(
            card.state.domains["credential-floor"]
                .credentials
                .retries(incarnation, 4)
                .unwrap(),
            (2, 1)
        );
        let reopened = Card::open(card.into_flash(), TestPlatform(10), STORAGE_KEY).unwrap();
        assert_eq!(
            reopened.state.domains["credential-floor"]
                .credentials
                .retries(incarnation, 4)
                .unwrap(),
            (2, 1)
        );
    }

    #[test]
    fn credential_retry_floor_power_loss_recovers_prior_or_consumed_count() {
        let mut card = card();
        let incarnation = create(&mut card, "credential-cut");
        load(
            &mut card,
            &counter_package("credential-cut", incarnation, 1, 7),
        )
        .unwrap();
        let mut initial = card.state.try_clone().unwrap();
        initial
            .domains
            .get_mut("credential-cut")
            .unwrap()
            .credentials
            .create(
                incarnation,
                4,
                b"1234",
                b"12345678",
                (3, 2),
                |out| {
                    out.fill(0x5a);
                    Ok(())
                },
            )
            .unwrap();
        card.commit(initial).unwrap();
        let domain_registry_aid = card.state.domains["credential-cut"].registry_aid;
        let base = card.into_flash();
        let mut floor = CredentialRetryFloors::default();
        floor.record(4, (2, 1)).unwrap();
        let mut complete = Card::open(base.clone(), TestPlatform(10), STORAGE_KEY).unwrap();
        complete
            .commit_credential_retry_floor(domain_registry_aid, &floor)
            .unwrap();
        let serialized = serde_json::to_vec(&complete.state).unwrap();

        for cut in 0..=16384 + 35 + serialized.len() {
            let mut flash = base.clone();
            flash.fail_after = Some(cut);
            let mut interrupted = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let _ = interrupted.commit_credential_retry_floor(domain_registry_aid, &floor);
            let mut flash = interrupted.into_flash();
            flash.fail_after = None;
            let recovered = Card::open(flash, TestPlatform(10), STORAGE_KEY).unwrap();
            let retries = recovered.state.domains["credential-cut"]
                .credentials
                .retries(incarnation, 4)
                .unwrap();
            assert!(retries == (3, 2) || retries == (2, 1), "cut {cut}: {retries:?}");
        }
    }

    #[test]
    fn byte_storage_native_api_enforces_ownership_and_quotas() {
        let mut store = IntStore::new();
        let mut blobs = BlobStore::new();
        let mut keys = crate::key_store::KeyStore::default();
        let mut credentials = crate::credential_store::CredentialStore::default();
        let mut platform = TestPlatform(0);
        let capabilities = [4, 22, 25, 29, 31, 32, 33, 34, 52];
        let mut transaction = TransactionDisposition::Inactive;
        let mut host = Host {
            store: &mut store,
            blobs: &mut blobs,
            keys: &mut keys,
            credentials: &mut credentials,
            authorized_credentials: CredentialAuthorizations::default(),
            credential_retry_floor: CredentialRetryFloors::default(),
            owner: [1; 16],
            data: &[],
            out: Vec::new(),
            sw: 0x9000,
            platform: &mut platform,
            budget: 4096,
            capabilities: &capabilities,
            domain_schema: &[],
            max_int_records: 512,
            max_blob_records: 64,
            max_blob_bytes: 8192,
            max_key_slots: 8,
            level: 0,
            units: None,
            transaction: &mut transaction,
            irreversible_output: false,
        };
        let oversized = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES + 1];
        assert_eq!(
            host.key_call(
                25,
                &[
                    vm::NativeArgument::Bytes(&[]),
                    vm::NativeArgument::Bytes(&oversized),
                ]
            ),
            Err(Error::Quota)
        );
        let maximum = alloc::vec![0u8; MAX_KEY_SERVICE_ARGUMENT_BYTES];
        assert_eq!(
            host.key_call(
                29,
                &[
                    vm::NativeArgument::Bytes(&[]),
                    vm::NativeArgument::Bytes(&maximum),
                    vm::NativeArgument::Bytes(&maximum),
                    vm::NativeArgument::Bytes(&maximum),
                ]
            ),
            Err(Error::Quota)
        );
        assert_eq!(
            host.key_call(
                52,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(7),
                    vm::NativeArgument::Bytes(b"xvaluey"),
                    vm::NativeArgument::Int(1),
                    vm::NativeArgument::Int(5),
                ],
            ),
            Ok(vm::BufferResult::Void)
        );
        assert!(matches!(
            host.key_call(
                31,
                &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(7)]
            ),
            Ok(vm::BufferResult::Bytes(value)) if value == b"value"
        ));
        assert!(matches!(
            host.key_call(
                34,
                &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(7)]
            ),
            Ok(vm::BufferResult::Scalar(1))
        ));
        assert_eq!(
            host.key_call(
                52,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(7),
                    vm::NativeArgument::Bytes(b"value"),
                    vm::NativeArgument::Int(4),
                    vm::NativeArgument::Int(2),
                ],
            ),
            Err(Error::Bounds)
        );
        host.max_blob_bytes = 4;
        assert_eq!(
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(7),
                    vm::NativeArgument::Bytes(b"value"),
                ]
            ),
            Err(Error::Quota)
        );
        host.max_blob_bytes = 8192;
        host.max_blob_records = 1;
        assert_eq!(
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(8),
                    vm::NativeArgument::Bytes(&[]),
                ]
            ),
            Err(Error::Quota)
        );
        host.max_blob_records = 64;
        host.max_int_records = 1;
        assert_eq!(host.call(4, &[1, 1]), Ok(None));
        assert_eq!(host.call(4, &[2, 2]), Err(Error::Quota));
        assert!(matches!(
            host.key_call(
                22,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(1),
                ]
            ),
            Ok(vm::BufferResult::Bytes(token)) if token.len() == 32
        ));
        host.max_key_slots = 1;
        assert_eq!(
            host.key_call(
                22,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(1),
                    vm::NativeArgument::Int(1),
                ]
            ),
            Err(Error::Quota)
        );
        assert_eq!(
            host.key_call(
                31,
                &[vm::NativeArgument::Int(1), vm::NativeArgument::Int(7)]
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(8),
                    vm::NativeArgument::Bytes(&[0; MAX_DECLARED_BLOB_BYTES as usize + 1]),
                ]
            ),
            Err(Error::Quota)
        );
        for slot in 0..8 {
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(slot),
                    vm::NativeArgument::Bytes(&[slot as u8; 1024]),
                ],
            )
            .unwrap();
        }
        assert_eq!(
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(8),
                    vm::NativeArgument::Bytes(&[0]),
                ]
            ),
            Err(Error::Quota)
        );
        for slot in 0..8 {
            assert_eq!(
                host.key_call(
                    33,
                    &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(slot)]
                ),
                Ok(vm::BufferResult::Void)
            );
        }
        for slot in 0..64 {
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(slot),
                    vm::NativeArgument::Bytes(&[]),
                ],
            )
            .unwrap();
        }
        assert_eq!(
            host.key_call(
                32,
                &[
                    vm::NativeArgument::Int(0),
                    vm::NativeArgument::Int(64),
                    vm::NativeArgument::Bytes(&[]),
                ]
            ),
            Err(Error::Quota)
        );
        assert_eq!(
            host.key_call(
                33,
                &[vm::NativeArgument::Int(0), vm::NativeArgument::Int(100)]
            ),
            Err(Error::Missing)
        );
    }

    #[test]
    fn package_trust_boundaries_use_the_platform_crypto_provider() {
        use core::cell::Cell;

        struct TrackingPlatform {
            random: u8,
            calls: Rc<Cell<[usize; 3]>>,
        }
        impl crate::crypto::CryptoProvider for TrackingPlatform {
            fn sha256(&mut self, data: &[u8]) -> Result<[u8; 32]> {
                let mut calls = self.calls.get();
                calls[0] += 1;
                self.calls.set(calls);
                Ok(crate::crypto::sha256(data))
            }

            fn ed25519_verify(
                &mut self,
                key: &[u8],
                signature: &[u8],
                message: &[u8],
            ) -> Result<bool> {
                let mut calls = self.calls.get();
                calls[1] += 1;
                self.calls.set(calls);
                Ok(crate::crypto::ed25519_verify(key, signature, message))
            }

            fn ed25519_public_key_valid(&mut self, key: &[u8; 32]) -> Result<bool> {
                let mut calls = self.calls.get();
                calls[2] += 1;
                self.calls.set(calls);
                Ok(crate::crypto::ed25519_public_key_valid(key))
            }
        }
        impl crate::hal::Entropy for TrackingPlatform {
            fn fill_entropy(&mut self, bytes: &mut [u8]) -> Result<()> {
                self.random = self.random.wrapping_add(1);
                bytes.fill(self.random);
                Ok(())
            }
        }
        impl crate::hal::LogicalGpio for TrackingPlatform {
            fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
                Err(Error::Native)
            }
        }

        let calls = Rc::new(Cell::new([0; 3]));
        let platform = TrackingPlatform {
            random: 0,
            calls: Rc::clone(&calls),
        };
        let mut card = Card::open(MemoryFlash::new(16384), platform, STORAGE_KEY).unwrap();
        let package = library_package("ISD", card.state.isd.incarnation, "mscorlib", 1, 42);
        load(&mut card, &package).unwrap();
        assert_eq!(calls.get(), [1, 1, 0]);

        let flash = card.into_flash();
        let platform = TrackingPlatform {
            random: 0,
            calls: Rc::clone(&calls),
        };
        Card::open(flash, platform, STORAGE_KEY).unwrap();
        assert_eq!(calls.get(), [2, 2, 1]);
    }
}
