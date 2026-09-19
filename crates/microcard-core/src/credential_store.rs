use alloc::vec::Vec;
use crate::{crypto::CryptoProvider, hal::Entropy};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const MIN_PIN_BYTES: usize = 4;
const MIN_PUK_BYTES: usize = 6;
const MAX_SECRET_BYTES: usize = 32;
const MAX_RETRIES: u8 = 15;
pub(crate) const MAX_SLOTS: usize = 8;
const DIGEST_CONTEXT: &[u8] = b"MicroCard credential v1";

#[derive(Clone, PartialEq, Eq)]

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

#[derive(Clone, Default, PartialEq, Eq)]

pub(crate) struct CredentialStore(Entries);

impl CredentialStore {
    pub(crate) fn encode_state(&self, e: &mut crate::cbor::Encoder) -> Result<()> {
        e.array(self.0.len())?;
        for (slot, entry) in self.0.iter() {
            if *slot != entry.slot { return Err(Error::Storage); }
            e.array(10)?; e.unsigned(*slot as u64)?; e.bytes(&entry.owner)?;
            e.bytes(&entry.pin_salt)?; e.bytes(&entry.pin_digest)?;
            e.bytes(&entry.puk_salt)?; e.bytes(&entry.puk_digest)?;
            for value in [entry.pin_retries, entry.pin_max_retries, entry.puk_retries, entry.puk_max_retries] { e.unsigned(u64::from(value))?; }
        }
        Ok(())
    }

    pub(crate) fn decode_state(d: &mut crate::cbor::Decoder<'_>, owner: [u8; 16]) -> Result<Self> {
        let count = d.array(MAX_SLOTS)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| Error::Quota)?;
        let mut previous = None;
        for _ in 0..count {
            d.record(10)?;
            let slot: i32 = d.number()?;
            if previous.is_some_and(|p| p >= slot) { return Err(Error::Format); }
            previous = Some(slot);
            let mut entry = Entry { slot, owner: [0; 16], pin_salt: [0; 16], pin_digest: [0; 32],
                puk_salt: [0; 16], puk_digest: [0; 32], pin_retries: 0, pin_max_retries: 0, puk_retries: 0, puk_max_retries: 0 };
            entry.owner.copy_from_slice(d.bytes(16)?.get(..16).ok_or(Error::Format)?);
            entry.pin_salt.copy_from_slice(d.bytes(16)?.get(..16).ok_or(Error::Format)?);
            entry.pin_digest.copy_from_slice(d.bytes(32)?.get(..32).ok_or(Error::Format)?);
            entry.puk_salt.copy_from_slice(d.bytes(16)?.get(..16).ok_or(Error::Format)?);
            entry.puk_digest.copy_from_slice(d.bytes(32)?.get(..32).ok_or(Error::Format)?);
            entry.pin_retries = d.number()?; entry.pin_max_retries = d.number()?;
            entry.puk_retries = d.number()?; entry.puk_max_retries = d.number()?;
            entries.push((slot, entry));
        }
        let result = Self(Entries(entries));
        result.validate(owner)?;
        Ok(result)
    }

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
        provider: &mut (impl CryptoProvider + Entropy),
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
        provider.fill_entropy(&mut *salts)?;
        let mut pin_salt = Zeroizing::new([0; 16]);
        pin_salt.copy_from_slice(&salts[..16]);
        let mut puk_salt = Zeroizing::new([0; 16]);
        puk_salt.copy_from_slice(&salts[16..]);
        let mut pin_digest = Zeroizing::new(credential_digest(owner, slot, 1, &pin_salt, pin, provider)?);
        let mut puk_digest = Zeroizing::new(credential_digest(owner, slot, 2, &puk_salt, puk, provider)?);
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
        provider: &mut impl CryptoProvider,
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
            provider,
        )?);
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
        provider: &mut (impl CryptoProvider + Entropy),
    ) -> Result<()> {
        validate_secret(new_pin, MIN_PIN_BYTES)?;
        let mut salt = Zeroizing::new([0; 16]);
        provider.fill_entropy(&mut *salt)?;
        let digest = Zeroizing::new(credential_digest(owner, slot, 1, &salt, new_pin, provider)?);
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
        provider: &mut (impl CryptoProvider + Entropy),
    ) -> Result<bool> {
        validate_secret(puk, MIN_PUK_BYTES)?;
        validate_secret(new_pin, MIN_PIN_BYTES)?;
        let entry = self.entry_mut(owner, slot)?;
        if entry.puk_retries == 0 {
            return Ok(false);
        }
        let candidate = Zeroizing::new(credential_digest(owner, slot, 2, &entry.puk_salt, puk, provider)?);
        if !bool::from(candidate.ct_eq(&entry.puk_digest)) {
            entry.puk_retries -= 1;
            return Ok(false);
        }
        let mut salt = Zeroizing::new([0; 16]);
        provider.fill_entropy(&mut *salt)?;
        let digest = Zeroizing::new(credential_digest(owner, slot, 1, &salt, new_pin, provider)?);
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
    provider: &mut impl CryptoProvider,
) -> Result<[u8; 32]> {
    let mut input = Zeroizing::new([0; DIGEST_CONTEXT.len() + 16 + 4 + 1 + 16 + MAX_SECRET_BYTES]);
    let mut cursor = 0;
    for part in [DIGEST_CONTEXT, &owner, &slot.to_be_bytes(), &[purpose], salt, secret] {
        input[cursor..cursor + part.len()].copy_from_slice(part);
        cursor += part.len();
    }
    provider.sha256(&input[..cursor])
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

    struct TestProvider<F>(F);
    impl<F> CryptoProvider for TestProvider<F> {}
    impl<F: FnMut(&mut [u8]) -> Result<()>> Entropy for TestProvider<F> {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> { (self.0)(output) }
    }

    const OWNER: [u8; 16] = [7; 16];

    fn create(store: &mut CredentialStore) {
        store
            .create(OWNER, 1, b"1234", b"12345678", (3, 2), &mut TestProvider(|out: &mut [u8]| {
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                Ok(())
            }))
            .unwrap();
    }

    #[test]
    fn binary_state_roundtrip_and_truncation() {
        let mut store = CredentialStore::default();
        create(&mut store);
        let mut encoder = crate::cbor::Encoder::new(2048);
        store.encode_state(&mut encoder).unwrap();
        let raw = zeroize::Zeroizing::new(encoder.finish());
        assert!(!raw.windows(4).any(|window| window == b"1234"));
        assert!(!raw.windows(8).any(|window| window == b"12345678"));
        for end in 0..raw.len() {
            assert!(CredentialStore::decode_state(&mut crate::cbor::Decoder::new(&raw[..end]), OWNER).is_err());
        }
        let mut decoder = crate::cbor::Decoder::new(&raw);
        let decoded = CredentialStore::decode_state(&mut decoder, OWNER).unwrap();
        decoder.finish().unwrap();
        assert!(decoded == store);
        assert!(CredentialStore::decode_state(&mut crate::cbor::Decoder::new(&raw), [8; 16]).is_err());
    }

    #[test]
    fn compact_entries_are_sorted_bounded_and_unique() {
        let mut store = CredentialStore::default();
        for slot in (0..MAX_SLOTS as i32).rev() {
            store
                .create(OWNER, slot, b"1234", b"12345678", (3, 2), &mut TestProvider(|out: &mut [u8]| {
                    out.fill(slot as u8 + 1);
                    Ok(())
                }))
                .unwrap();
        }
        let pointer = store.0.0.as_ptr();
        assert_eq!(
            store.create(OWNER, 8, b"1234", b"12345678", (3, 2), &mut TestProvider(|_: &mut [u8]| {
                panic!("quota must be checked before entropy")
            })),
            Err(Error::Quota)
        );
        assert_eq!(store.0.0.as_ptr(), pointer);

        assert!(store.0.0.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for case in 0..3 {
            let mut invalid = store.clone();
            match case {
                0 => invalid.0.0.insert(0, invalid.0.0[0].clone()),
                1 => { invalid.0.0.truncate(1); invalid.0.0[0].0 = -1; invalid.0.0[0].1.slot = -1; }
                _ => { invalid.0.0.truncate(2); invalid.0.0[1] = invalid.0.0[0].clone(); }
            }
            let mut encoder = crate::cbor::Encoder::new(2048);
            invalid.encode_state(&mut encoder).unwrap();
            let raw = zeroize::Zeroizing::new(encoder.finish());
            assert!(CredentialStore::decode_state(&mut crate::cbor::Decoder::new(&raw), OWNER).is_err());
        }
    }

    #[test]
    fn retry_block_unblock_and_pin_change_are_transaction_ready() {
        let mut store = CredentialStore::default();
        create(&mut store);
        assert!(!store.verify_pin(OWNER, 1, b"9999", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"9999", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"9999", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert!(!store.verify_pin(OWNER, 1, b"1234", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (0, 2));

        assert!(!store
            .unblock(OWNER, 1, b"00000000", b"5678", &mut TestProvider(|out: &mut [u8]| {
                out.fill(4);
                Ok(())
            }))
            .unwrap());
        assert!(store
            .unblock(OWNER, 1, b"12345678", b"5678", &mut TestProvider(|out: &mut [u8]| {
                out.fill(5);
                Ok(())
            }))
            .unwrap());
        assert!(store.verify_pin(OWNER, 1, b"5678", &mut crate::crypto::SoftwareCrypto).unwrap());
        store
            .change_pin(OWNER, 1, b"2468", &mut TestProvider(|out: &mut [u8]| {
                out.fill(6);
                Ok(())
            }))
            .unwrap();
        assert!(!store.verify_pin(OWNER, 1, b"5678", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert!(store.verify_pin(OWNER, 1, b"2468", &mut crate::crypto::SoftwareCrypto).unwrap());
        assert_eq!(store.retries(OWNER, 1).unwrap(), (3, 2));
    }

    #[test]
    fn validation_and_entropy_failure_preserve_state() {
        let mut store = CredentialStore::default();
        assert_eq!(
            store.create(OWNER, 1, b"1234", b"12345678", (3, 2), &mut TestProvider(|_: &mut [u8]| {
                Err(Error::Native)
            })),
            Err(Error::Native)
        );
        assert!(store.is_empty());
        create(&mut store);
        let before = store.clone();
        assert_eq!(
            store.change_pin(OWNER, 1, b"5678", &mut TestProvider(|_: &mut [u8]| Err(Error::Native))),
            Err(Error::Native)
        );
        assert!(store == before);
        assert!(store.validate(OWNER).is_ok());
        assert_eq!(store.verify_pin([8; 16], 1, b"1234", &mut crate::crypto::SoftwareCrypto), Err(Error::Unauthorized));
    }

    #[test]
    fn provider_hash_failure_preserves_credentials_and_retry_counts() {
        struct FailedHash;
        impl CryptoProvider for FailedHash {
            fn sha256_into(&mut self, _: &[u8], output: &mut [u8; 32]) -> Result<()> {
                output.fill(0);
                Err(Error::Native)
            }
        }
        impl Entropy for FailedHash {
            fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
                output.fill(0x5a);
                Ok(())
            }
        }
        let mut store = CredentialStore::default();
        assert_eq!(store.create(OWNER, 1, b"1234", b"12345678", (3, 2), &mut FailedHash), Err(Error::Native));
        assert!(store.is_empty());
        create(&mut store);
        let before = store.clone();
        assert_eq!(store.verify_pin(OWNER, 1, b"1234", &mut FailedHash), Err(Error::Native));
        assert_eq!(store.change_pin(OWNER, 1, b"5678", &mut FailedHash), Err(Error::Native));
        assert_eq!(store.unblock(OWNER, 1, b"12345678", b"5678", &mut FailedHash), Err(Error::Native));
        assert!(store == before);
    }

    #[test]
    fn provider_digest_keeps_the_existing_credential_encoding() {
        use sha2::{Digest, Sha256};
        let secret = [0x35; MAX_SECRET_BYTES];
        let salt = [0x79; 16];
        let mut reference = Sha256::new();
        reference.update(DIGEST_CONTEXT);
        reference.update(OWNER);
        reference.update(3i32.to_be_bytes());
        reference.update([2]);
        reference.update(salt);
        reference.update(secret);
        let expected: [u8; 32] = reference.finalize().into();
        assert_eq!(credential_digest(OWNER, 3, 2, &salt, &secret, &mut crate::crypto::SoftwareCrypto).unwrap(), expected);
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
