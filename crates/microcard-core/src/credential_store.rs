use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const MIN_PIN_BYTES: usize = 4;
const MIN_PUK_BYTES: usize = 6;
const MAX_SECRET_BYTES: usize = 32;
const MAX_RETRIES: u8 = 15;
pub(crate) const MAX_SLOTS: usize = 8;
const DIGEST_CONTEXT: &[u8] = b"MicroCard credential v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slot: i32,
    owner: [u8; 16],
    pin_salt: [u8; 16],
    pin_digest: [u8; 32],
    puk_salt: [u8; 16],
    puk_digest: [u8; 32],
    pin_retries: u8,
    pin_max_retries: u8,
    puk_retries: u8,
    puk_max_retries: u8,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.pin_salt.zeroize();
        self.pin_digest.zeroize();
        self.puk_salt.zeroize();
        self.puk_digest.zeroize();
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct Entries(Vec<(i32, Entry)>);

impl Entries {
    fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        let mut entries = Vec::new();
        context.reserve_exact(&mut entries, self.0.len())?;
        entries.extend(self.0.iter().map(|(slot, entry)| (*slot, entry.clone())));
        Ok(Self(entries))
    }

    fn position(&self, slot: i32) -> core::result::Result<usize, usize> {
        self.0
            .binary_search_by_key(&slot, |(candidate, _)| *candidate)
    }

    fn reserve_entry(&mut self) -> Result<()> {
        if self.0.len() >= MAX_SLOTS {
            return Err(Error::Quota);
        }
        if self.0.len() == self.0.capacity() {
            self.0
                .try_reserve_exact(1)
                .map_err(|_| Error::Quota)?;
        }
        Ok(())
    }

    fn insert(&mut self, slot: i32, entry: Entry) -> Result<()> {
        if slot < 0 {
            return Err(Error::Bounds);
        }
        match self.position(slot) {
            Ok(index) => {
                self.0[index].1 = entry;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_SLOTS {
                    return Err(Error::Quota);
                }
                self.reserve_entry()?;
                self.0.insert(index, (slot, entry));
                Ok(())
            }
        }
    }

    fn get(&self, slot: &i32) -> Option<&Entry> {
        self.position(*slot).ok().map(|index| &self.0[index].1)
    }

    fn get_mut(&mut self, slot: &i32) -> Option<&mut Entry> {
        self.position(*slot)
            .ok()
            .map(|index| &mut self.0[index].1)
    }

    fn contains_key(&self, slot: &i32) -> bool {
        self.position(*slot).is_ok()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn iter(&self) -> core::slice::Iter<'_, (i32, Entry)> {
        self.0.iter()
    }
}

impl Serialize for Entries {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (slot, entry) in self.iter() {
            map.serialize_entry(slot, entry)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::{MapAccess, Visitor};

        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of up to eight credential verifiers")
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Entries::default();
                while let Some(slot) = map.next_key::<i32>()? {
                    if entries.len() >= MAX_SLOTS {
                        return Err(serde::de::Error::custom("credential quota"));
                    }
                    if slot < 0 {
                        return Err(serde::de::Error::custom("credential slot"));
                    }
                    if entries.contains_key(&slot) {
                        return Err(serde::de::Error::custom("duplicate credential slot"));
                    }
                    entries
                        .reserve_entry()
                        .map_err(|_| serde::de::Error::custom("credential allocation"))?;
                    let entry = map.next_value::<Entry>()?;
                    entries
                        .insert(slot, entry)
                        .map_err(|_| serde::de::Error::custom("credential quota"))?;
                }
                Ok(entries)
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct CredentialStore(Entries);

impl CredentialStore {
    pub(crate) fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self(self.0.try_clone_with(context)?))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn validate(&self, owner: [u8; 16]) -> Result<()> {
        if self.0.len() > MAX_SLOTS {
            return Err(Error::Storage);
        }
        for (slot, entry) in self.0.iter() {
            if *slot < 0
                || *slot != entry.slot
                || entry.owner != owner
                || !valid_retries(entry.pin_max_retries)
                || !valid_retries(entry.puk_max_retries)
                || entry.pin_retries > entry.pin_max_retries
                || entry.puk_retries > entry.puk_max_retries
            {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }

    pub(crate) fn create(
        &mut self,
        owner: [u8; 16],
        slot: i32,
        pin: &[u8],
        puk: &[u8],
        retries: (i32, i32),
        random: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<()> {
        validate_secret(pin, MIN_PIN_BYTES)?;
        validate_secret(puk, MIN_PUK_BYTES)?;
        let pin_max_retries = retry_count(retries.0)?;
        let puk_max_retries = retry_count(retries.1)?;
        if slot < 0 || self.0.contains_key(&slot) {
            return Err(if slot < 0 { Error::Bounds } else { Error::Busy });
        }
        if self.0.len() >= MAX_SLOTS {
            return Err(Error::Quota);
        }
        self.0.reserve_entry()?;
        let mut salts = Zeroizing::new([0u8; 32]);
        random(&mut *salts)?;
        let mut pin_salt = Zeroizing::new([0; 16]);
        pin_salt.copy_from_slice(&salts[..16]);
        let mut puk_salt = Zeroizing::new([0; 16]);
        puk_salt.copy_from_slice(&salts[16..]);
        let mut pin_digest = Zeroizing::new(credential_digest(owner, slot, 1, &pin_salt, pin));
        let mut puk_digest = Zeroizing::new(credential_digest(owner, slot, 2, &puk_salt, puk));
        let entry = Entry {
            slot,
            owner,
            pin_salt: core::mem::take(&mut *pin_salt),
            pin_digest: core::mem::take(&mut *pin_digest),
            puk_salt: core::mem::take(&mut *puk_salt),
            puk_digest: core::mem::take(&mut *puk_digest),
            pin_retries: pin_max_retries,
            pin_max_retries,
            puk_retries: puk_max_retries,
            puk_max_retries,
        };
        self.0.insert(slot, entry)
    }

    pub(crate) fn verify_pin(
        &mut self,
        owner: [u8; 16],
        slot: i32,
        candidate: &[u8],
    ) -> Result<bool> {
        validate_secret(candidate, MIN_PIN_BYTES)?;
        let entry = self.entry_mut(owner, slot)?;
        if entry.pin_retries == 0 {
            return Ok(false);
        }
        let candidate = Zeroizing::new(credential_digest(
            owner,
            slot,
            1,
            &entry.pin_salt,
            candidate,
        ));
        if bool::from(candidate.ct_eq(&entry.pin_digest)) {
            entry.pin_retries = entry.pin_max_retries;
            Ok(true)
        } else {
            entry.pin_retries -= 1;
            Ok(false)
        }
    }

    pub(crate) fn change_pin(
        &mut self,
        owner: [u8; 16],
        slot: i32,
        new_pin: &[u8],
        random: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<()> {
        validate_secret(new_pin, MIN_PIN_BYTES)?;
        let mut salt = Zeroizing::new([0; 16]);
        random(&mut *salt)?;
        let digest = Zeroizing::new(credential_digest(owner, slot, 1, &salt, new_pin));
        let entry = self.entry_mut(owner, slot)?;
        entry.pin_salt.zeroize();
        entry.pin_digest.zeroize();
        entry.pin_salt.copy_from_slice(&*salt);
        entry.pin_digest.copy_from_slice(&*digest);
        entry.pin_retries = entry.pin_max_retries;
        Ok(())
    }

    pub(crate) fn unblock(
        &mut self,
        owner: [u8; 16],
        slot: i32,
        puk: &[u8],
        new_pin: &[u8],
        random: impl FnOnce(&mut [u8]) -> Result<()>,
    ) -> Result<bool> {
        validate_secret(puk, MIN_PUK_BYTES)?;
        validate_secret(new_pin, MIN_PIN_BYTES)?;
        let entry = self.entry_mut(owner, slot)?;
        if entry.puk_retries == 0 {
            return Ok(false);
        }
        let candidate = Zeroizing::new(credential_digest(owner, slot, 2, &entry.puk_salt, puk));
        if !bool::from(candidate.ct_eq(&entry.puk_digest)) {
            entry.puk_retries -= 1;
            return Ok(false);
        }
        let mut salt = Zeroizing::new([0; 16]);
        random(&mut *salt)?;
        let digest = Zeroizing::new(credential_digest(owner, slot, 1, &salt, new_pin));
        let entry = self.entry_mut(owner, slot)?;
        entry.pin_salt.zeroize();
        entry.pin_digest.zeroize();
        entry.pin_salt.copy_from_slice(&*salt);
        entry.pin_digest.copy_from_slice(&*digest);
        entry.pin_retries = entry.pin_max_retries;
        entry.puk_retries = entry.puk_max_retries;
        Ok(true)
    }

    pub(crate) fn retries(&self, owner: [u8; 16], slot: i32) -> Result<(u8, u8)> {
        let entry = self.0.get(&slot).ok_or(Error::Missing)?;
        if entry.owner != owner {
            return Err(Error::Unauthorized);
        }
        Ok((entry.pin_retries, entry.puk_retries))
    }

    /// Apply only retry-counter decreases recorded before an invocation fault.
    /// Credential creation, resets and verifier changes remain rollbackable.
    pub(crate) fn apply_retry_floor(
        &mut self,
        owner: [u8; 16],
        floors: impl IntoIterator<Item = (i32, (u8, u8))>,
    ) -> Result<bool> {
        let mut changed = false;
        for (slot, (pin, puk)) in floors {
            let Some(entry) = self.0.get_mut(&slot) else {
                continue;
            };
            if entry.owner != owner || pin > entry.pin_max_retries || puk > entry.puk_max_retries {
                return Err(Error::Storage);
            }
            if entry.pin_retries > pin {
                entry.pin_retries = pin;
                changed = true;
            }
            if entry.puk_retries > puk {
                entry.puk_retries = puk;
                changed = true;
            }
        }
        Ok(changed)
    }

    fn entry_mut(&mut self, owner: [u8; 16], slot: i32) -> Result<&mut Entry> {
        let entry = self.0.get_mut(&slot).ok_or(Error::Missing)?;
        if entry.owner != owner {
            return Err(Error::Unauthorized);
        }
        Ok(entry)
    }
}

fn credential_digest(
    owner: [u8; 16],
    slot: i32,
    purpose: u8,
    salt: &[u8; 16],
    secret: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DIGEST_CONTEXT);
    hash.update(owner);
    hash.update(slot.to_be_bytes());
    hash.update([purpose]);
    hash.update(salt);
    hash.update(secret);
    hash.finalize().into()
}

fn validate_secret(secret: &[u8], minimum: usize) -> Result<()> {
    if !(minimum..=MAX_SECRET_BYTES).contains(&secret.len()) {
        return Err(Error::Bounds);
    }
    Ok(())
}

fn retry_count(value: i32) -> Result<u8> {
    let value = u8::try_from(value).map_err(|_| Error::Bounds)?;
    if !valid_retries(value) {
        return Err(Error::Bounds);
    }
    Ok(value)
}

fn valid_retries(value: u8) -> bool {
    (1..=MAX_RETRIES).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    const OWNER: [u8; 16] = [7; 16];

    fn create(store: &mut CredentialStore) {
        store
            .create(OWNER, 1, b"1234", b"12345678", (3, 2), |out| {
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn compact_entries_are_sorted_bounded_and_unique() {
        let mut store = CredentialStore::default();
        for slot in (0..MAX_SLOTS as i32).rev() {
            store
                .create(OWNER, slot, b"1234", b"12345678", (3, 2), |out| {
                    out.fill(slot as u8 + 1);
                    Ok(())
                })
                .unwrap();
        }
        let pointer = store.0.0.as_ptr();
        assert_eq!(
            store.create(OWNER, 8, b"1234", b"12345678", (3, 2), |_| {
                panic!("quota must be checked before entropy")
            }),
            Err(Error::Quota)
        );
        assert_eq!(store.0.0.as_ptr(), pointer);

        let encoded = serde_json::to_string(&store).unwrap();
        assert!(encoded.find("\"0\"").unwrap() < encoded.find("\"7\"").unwrap());
        let decoded = serde_json::from_str::<CredentialStore>(&encoded).unwrap();
        assert!(decoded == store);
        assert!(decoded.validate(OWNER).is_ok());

        let encoded_entry = serde_json::to_string(store.0.get(&0).unwrap()).unwrap();
        let duplicate = alloc::format!("{{\"0\":{encoded_entry},\"0\":{encoded_entry}}}");
        assert!(serde_json::from_str::<CredentialStore>(&duplicate).is_err());
        let negative = alloc::format!("{{\"-1\":{encoded_entry}}}");
        assert!(serde_json::from_str::<CredentialStore>(&negative).is_err());

        let mut oversized = alloc::string::String::from("{");
        for slot in 0..=MAX_SLOTS {
            if slot != 0 {
                oversized.push(',');
            }
            let value = serde_json::to_string(store.0.get(&(slot.min(7) as i32)).unwrap())
                .unwrap();
            oversized.push_str(&alloc::format!("\"{slot}\":{value}"));
        }
        oversized.push('}');
        assert!(serde_json::from_str::<CredentialStore>(&oversized).is_err());
    }

    #[test]
    fn retry_block_unblock_and_pin_change_are_transaction_ready() {
        let mut store = CredentialStore::default();
        create(&mut store);
        assert!(!store.verify_pin(OWNER, 1, b"9999").unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"9999").unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"9999").unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"1234").unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (0, 2));

        assert!(!store
            .unblock(OWNER, 1, b"00000000", b"5678", |out| {
                out.fill(4);
                Ok(())
            })
            .unwrap());
        assert!(store
            .unblock(OWNER, 1, b"12345678", b"5678", |out| {
                out.fill(5);
                Ok(())
            })
            .unwrap());
        assert!(store.verify_pin(OWNER, 1, b"5678").unwrap());
        store
            .change_pin(OWNER, 1, b"2468", |out| {
                out.fill(6);
                Ok(())
            })
            .unwrap();
        assert!(!store.verify_pin(OWNER, 1, b"5678").unwrap());
        assert!(store.verify_pin(OWNER, 1, b"2468").unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (3, 2));
    }

    #[test]
    fn validation_and_entropy_failure_preserve_state() {
        let mut store = CredentialStore::default();
        assert_eq!(
            store.create(OWNER, 1, b"1234", b"12345678", (3, 2), |_| {
                Err(Error::Native)
            }),
            Err(Error::Native)
        );
        assert!(store.is_empty());
        create(&mut store);
        let before = store.clone();
        assert_eq!(
            store.change_pin(OWNER, 1, b"5678", |_| Err(Error::Native)),
            Err(Error::Native)
        );
        assert!(store == before);
        assert!(store.validate(OWNER).is_ok());
        assert_eq!(store.verify_pin([8; 16], 1, b"1234"), Err(Error::Unauthorized));
    }

    #[test]
    fn serialized_store_contains_digests_instead_of_secrets() {
        let mut store = CredentialStore::default();
        create(&mut store);
        let encoded = serde_json::to_vec(&store).unwrap();
        assert!(!encoded.windows(4).any(|window| window == b"1234"));
        assert!(!encoded.windows(8).any(|window| window == b"12345678"));
        let decoded: CredentialStore = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.validate(OWNER).is_ok());
    }

    #[test]
    fn retry_floor_can_only_consume_attempts() {
        let mut store = CredentialStore::default();
        create(&mut store);
        let mut floors = BTreeMap::new();
        floors.insert(1, (1, 1));
        assert!(store
            .apply_retry_floor(OWNER, floors.iter().map(|(&slot, &counts)| (slot, counts)))
            .unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (1, 1));
        floors.insert(1, (3, 2));
        assert!(!store
            .apply_retry_floor(OWNER, floors.iter().map(|(&slot, &counts)| (slot, counts)))
            .unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (1, 1));
    }
}
