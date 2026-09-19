//! Versioned MC04 metadata snapshot. Immutable packages live in separate image slots.
use super::*;
use crate::cbor::{Decoder, Encoder};

const MAX_BYTES: usize = 48 * 1024;

fn reserve<T>(output: &mut Vec<T>, count: usize) -> Result<()> {
    output.try_reserve_exact(count).map_err(|_| Error::Quota)
}
fn bytes(d: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>> {
    let value = d.bytes(maximum)?;
    let mut output = Vec::new();
    reserve(&mut output, value.len())?;
    output.extend_from_slice(value);
    Ok(output)
}
fn identifier(d: &mut Decoder<'_>) -> Result<String> {
    let value = d.owned_text(64)?;
    if !crate::package::valid_identifier(&value) {
        return Err(Error::Format);
    }
    Ok(value)
}
fn ordered<T: PartialOrd>(previous: &mut Option<T>, next: T) -> Result<()> {
    if previous.as_ref().is_some_and(|p| *p >= next) {
        return Err(Error::Format);
    }
    *previous = Some(next);
    Ok(())
}
fn read_names<T>(
    d: &mut Decoder<'_>,
    mut read: impl FnMut(&mut Decoder<'_>) -> Result<T>,
) -> Result<NameMap<T>> {
    let count = d.array(MAX_ASSEMBLIES_PER_DOMAIN as usize)?;
    let mut values: Vec<(Rc<str>, T)> = Vec::new();
    reserve(&mut values, count)?;
    for _ in 0..count {
        d.record(2)?;
        let name = identifier(d)?;
        if values
            .last()
            .is_some_and(|(previous, _)| previous.as_ref() >= name.as_str())
        {
            return Err(Error::Format);
        }
        let value = read(d)?;
        values.push((Rc::from(name), value));
    }
    Ok(NameMap(values))
}
fn write_names<T>(
    e: &mut Encoder,
    values: &NameMap<T>,
    mut write: impl FnMut(&mut Encoder, &T) -> Result<()>,
) -> Result<()> {
    e.array(values.len())?;
    for (name, value) in values.iter() {
        e.array(2)?;
        e.text(name)?;
        write(e, value)?;
    }
    Ok(())
}
fn read_policy(d: &mut Decoder<'_>) -> Result<DomainPolicy> {
    d.record(8)?;
    let policy = DomainPolicy {
        capabilities: bytes(d, 46)?,
        max_assemblies: d.number()?,
        max_instances: d.number()?,
        max_int_records: d.number()?,
        max_blob_records: d.number()?,
        max_blob_bytes: d.number()?,
        max_key_slots: d.number()?,
        max_package_bytes: d.number()?,
    };
    if !policy.valid() {
        return Err(Error::Format);
    }
    Ok(policy)
}
fn write_policy(e: &mut Encoder, p: &DomainPolicy) -> Result<()> {
    e.array(8)?;
    e.bytes(&p.capabilities)?;
    for value in [
        u64::from(p.max_assemblies),
        u64::from(p.max_instances),
        u64::from(p.max_int_records),
        u64::from(p.max_blob_records),
        u64::from(p.max_blob_bytes),
        u64::from(p.max_key_slots),
        u64::from(p.max_package_bytes),
    ] {
        e.unsigned(value)?;
    }
    Ok(())
}
fn read_call(d: &mut Decoder<'_>) -> Result<ResolvedCall> {
    d.record(2)?;
    let member = d.number()?;
    let fields = d.array(3)?;
    let kind = d.unsigned()?;
    let target = match (kind, fields) {
        (0, 1) => CallTarget::ObjectConstructor,
        (1, 1) => CallTarget::CurrentDomain,
        (2, 1) => CallTarget::DomainStorage,
        (3, 1) => CallTarget::DomainKeys,
        (4, 2) => CallTarget::Native(d.number()?),
        (5, 3) => CallTarget::Managed {
            dependency: d.number()?,
            method: d.number()?,
        },
        _ => return Err(Error::Format),
    };
    Ok(ResolvedCall { member, target })
}
fn write_call(e: &mut Encoder, call: &ResolvedCall) -> Result<()> {
    e.array(2)?;
    e.unsigned(u64::from(call.member))?;
    match call.target {
        CallTarget::ObjectConstructor => {
            e.array(1)?;
            e.unsigned(0)?;
        }
        CallTarget::CurrentDomain => {
            e.array(1)?;
            e.unsigned(1)?;
        }
        CallTarget::DomainStorage => {
            e.array(1)?;
            e.unsigned(2)?;
        }
        CallTarget::DomainKeys => {
            e.array(1)?;
            e.unsigned(3)?;
        }
        CallTarget::Native(id) => {
            e.array(2)?;
            e.unsigned(4)?;
            e.unsigned(u64::from(id))?;
        }
        CallTarget::Managed { dependency, method } => {
            e.array(3)?;
            e.unsigned(5)?;
            e.unsigned(u64::from(dependency))?;
            e.unsigned(u64::from(method))?;
        }
    }
    Ok(())
}
fn read_domain(d: &mut Decoder<'_>, package_total: &mut usize) -> Result<Domain> {
    d.record(14)?;
    let incarnation = d.fixed()?;
    let aid = RegistryAid::new(d.bytes(16)?)?;
    let key = if d.null() { None } else { Some(d.fixed()?) };
    let policy = read_policy(d)?;
    let mut domain = Domain::new(incarnation, aid, policy);
    domain.key = key;
    domain.image_refs = read_names(d, |d| {
        d.record(3)?;
        let descriptor = crate::image_store::Descriptor {
            slot: d.number()?, length: d.number()?, digest: d.fixed()?,
        };
        if descriptor.slot >= 64 || descriptor.length == 0 || descriptor.length as usize > MAX_PACKAGE_BYTES {
            return Err(Error::Format);
        }
        *package_total = package_total.checked_add(descriptor.length as usize).ok_or(Error::Quota)?;
        if *package_total > MAX_TOTAL_PACKAGE_BYTES { return Err(Error::Quota); }
        Ok(descriptor)
    })?;
    for (name, _) in domain.image_refs.iter() {
        domain.assemblies.insert(name.as_ref().into(), Rc::new(Vec::new()))?;
    }
    domain.bindings = read_names(d, |d| {
        let count = d.array(16)?;
        let mut values = Vec::new();
        reserve(&mut values, count)?;
        for _ in 0..count {
            values.push(ResolvedDependency { digest: d.fixed()? });
        }
        Ok(values)
    })?;
    domain.imports = read_names(d, |d| {
        let count = d.array(crate::mc04_schema::MAX_MEMBERREF_ROWS as usize)?;
        let mut values = Vec::new();
        reserve(&mut values, count)?;
        for _ in 0..count {
            values.push(read_call(d)?);
        }
        Ok(values)
    })?;
    domain.versions = read_names(d, |d| {
        d.record(2)?;
        Ok((d.number()?, d.fixed()?))
    })?;
    let count = d.array(MAX_DOMAIN_STORAGE_DECLARATIONS)?;
    let mut schema = Vec::new();
    reserve(&mut schema, count)?;
    let mut previous = None;
    for _ in 0..count {
        d.record(3)?;
        let entry = StorageDeclaration {
            key: d.number()?,
            kind: d.number()?,
            max_bytes: d.number()?,
        };
        if !entry.valid() {
            return Err(Error::Format);
        }
        ordered(&mut previous, entry.key)?;
        schema.push(entry);
    }
    domain.storage_schema = Rc::new(schema);
    let count = d.array(MAX_INSTANCES_PER_DOMAIN as usize)?;
    reserve(&mut domain.instances.0, count)?;
    for _ in 0..count {
        d.record(2)?;
        let aid = encode_aid(d.bytes(16)?)?;
        decode_aid(&aid)?;
        if domain
            .instances
            .0
            .last()
            .is_some_and(|(previous, _)| previous >= &aid)
        {
            return Err(Error::Format);
        }
        let name = identifier(d)?;
        domain.instances.0.push((aid, Rc::from(name)));
    }
    let count = d.array(MAX_INT_RECORDS)?;
    reserve(&mut domain.store.0, count)?;
    let mut previous = None;
    for _ in 0..count {
        d.record(2)?;
        let key = i32::try_from(d.integer()?).map_err(|_| Error::Format)?;
        ordered(&mut previous, key)?;
        let value = i32::try_from(d.integer()?).map_err(|_| Error::Format)?;
        domain.store.0.push((key, value));
    }
    let count = d.array(MAX_BLOB_RECORDS)?;
    reserve(&mut domain.blobs.0, count)?;
    let mut previous = None;
    let mut total = 0usize;
    for _ in 0..count {
        d.record(2)?;
        let key = i32::try_from(d.integer()?).map_err(|_| Error::Format)?;
        ordered(&mut previous, key)?;
        let raw = d.bytes(MAX_DECLARED_BLOB_BYTES as usize)?;
        total = total.checked_add(raw.len()).ok_or(Error::Quota)?;
        if total > domain.policy.max_blob_bytes as usize {
            return Err(Error::Quota);
        }
        let mut value = Vec::new();
        reserve(&mut value, raw.len())?;
        value.extend_from_slice(raw);
        domain.blobs.0.push((key, value));
    }
    domain.keys = crate::key_store::KeyStore::decode_state(d)?;
    domain.credentials = crate::credential_store::CredentialStore::decode_state(d, incarnation)?;
    domain.intern_assembly_names()?;
    Ok(domain)
}
fn write_domain(e: &mut Encoder, domain: &Domain) -> Result<()> {
    if !domain.registry_aid.valid() {
        return Err(Error::Format);
    }
    e.array(14)?;
    e.bytes(&domain.incarnation)?;
    e.bytes(domain.registry_aid.as_slice())?;
    match domain.key {
        Some(key) => e.bytes(&key)?,
        None => e.null()?,
    }
    write_policy(e, &domain.policy)?;
    e.array(domain.assemblies.len())?;
    for (name, _) in domain.assemblies.iter() {
        let descriptor = domain.image_refs.get(name).ok_or(Error::Missing)?;
        e.array(2)?;
        e.text(name)?;
        e.array(3)?;
        e.unsigned(u64::from(descriptor.slot))?;
        e.unsigned(u64::from(descriptor.length))?;
        e.bytes(&descriptor.digest)?;
    }
    write_names(e, &domain.bindings, |e, values| {
        e.array(values.len())?;
        for value in values {
            e.bytes(&value.digest)?;
        }
        Ok(())
    })?;
    write_names(e, &domain.imports, |e, values| {
        e.array(values.len())?;
        for value in values {
            write_call(e, value)?;
        }
        Ok(())
    })?;
    write_names(e, &domain.versions, |e, (version, digest)| {
        e.array(2)?;
        e.unsigned(u64::from(*version))?;
        e.bytes(digest)
    })?;
    e.array(domain.storage_schema.len())?;
    for entry in domain.storage_schema.iter() {
        e.array(3)?;
        e.unsigned(entry.key as u64)?;
        e.unsigned(u64::from(entry.kind))?;
        e.unsigned(u64::from(entry.max_bytes))?;
    }
    e.array(domain.instances.len())?;
    for (aid, name) in domain.instances.iter() {
        let (aid, length) = decode_aid(aid)?;
        e.array(2)?;
        e.bytes(&aid[..length])?;
        e.text(name)?;
    }
    e.array(domain.store.len())?;
    for (key, value) in domain.store.iter() {
        e.array(2)?;
        e.integer(i64::from(*key))?;
        e.integer(i64::from(*value))?;
    }
    e.array(domain.blobs.len())?;
    for (key, value) in domain.blobs.iter() {
        e.array(2)?;
        e.integer(i64::from(*key))?;
        e.bytes(value)?;
    }
    domain.keys.encode_state(e)?;
    domain.credentials.encode_state(e)?;
    Ok(())
}

impl State {
    pub(super) fn encode_snapshot(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new(MAX_BYTES);
        e.array(5)?;
        e.unsigned(2)?;
        e.unsigned(0)?;
        e.unsigned(u64::from(self.scp03_sequence))?;
        write_domain(&mut e, &self.isd)?;
        e.array(self.domains.len())?;
        for (name, domain) in self.domains.iter() {
            e.array(2)?;
            e.text(name)?;
            write_domain(&mut e, domain)?;
        }
        Ok(Zeroizing::new(e.finish()))
    }

    pub(super) fn decode_snapshot(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::Storage);
        }
        if bytes.first() != Some(&0x85) {
            return Err(Error::IncompatibleState);
        }
        let mut d = Decoder::new(bytes);
        d.record(5)?;
        if d.unsigned()? != 2 || d.unsigned()? != 0 {
            return Err(Error::IncompatibleState);
        }
        let sequence = d.number()?;
        let mut package_total = 0;
        let isd = read_domain(&mut d, &mut package_total)?;
        let count = d.array(MAX_SSDS)?;
        let mut domains = Vec::new();
        reserve(&mut domains, count)?;
        for _ in 0..count {
            d.record(2)?;
            let name = identifier(&mut d)?;
            if name == "ISD"
                || domains
                    .last()
                    .is_some_and(|(previous, _)| previous >= &name)
            {
                return Err(Error::Format);
            }
            let domain = read_domain(&mut d, &mut package_total)?;
            domains.push((name, domain));
        }
        d.finish()?;
        Ok(Self {
            isd,
            domains: Domains(domains),
            scp03_sequence: sequence,
        })
    }
}
