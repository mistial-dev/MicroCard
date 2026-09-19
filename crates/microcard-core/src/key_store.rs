//! Persistent framework keys, separate from application values. Handles bind to an incarnation.
use crate::{crypto::{zeroizing_buffer, CryptoProvider}, Error, Result};
use alloc::vec::Vec;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    HmacSha256,
    Aes128,
    P256,
}
#[derive(Clone)]
struct Entry {
    algorithm: Algorithm,
    nonce: [u8; 16],
    key: [u8; 32],
}
impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
            && bool::from(self.nonce.ct_eq(&other.nonce) & self.key.ct_eq(&other.key))
    }
}
impl Eq for Entry {}
impl Drop for Entry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

const MAX_ENTRIES: usize = 8;

#[derive(Clone, Default, PartialEq, Eq)]
struct Entries(Vec<(i32, Entry)>);

impl Entries {
    #[cfg(feature = "mc04")]
    pub(crate) fn try_clone_with(
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
        if self.0.len() >= MAX_ENTRIES {
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
        if !(0..MAX_ENTRIES as i32).contains(&slot) {
            return Err(Error::Bounds);
        }
        match self.position(slot) {
            Ok(index) => {
                self.0[index].1 = entry;
                Ok(())
            }
            Err(index) => {
                if self.0.len() >= MAX_ENTRIES {
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

    #[cfg(test)]
    fn get_mut(&mut self, slot: &i32) -> Option<&mut Entry> {
        self.position(*slot)
            .ok()
            .map(|index| &mut self.0[index].1)
    }

    fn contains_key(&self, slot: &i32) -> bool {
        self.position(*slot).is_ok()
    }

    fn remove(&mut self, slot: &i32) -> Option<Entry> {
        self.position(*slot)
            .ok()
            .map(|index| self.0.remove(index).1)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn keys(&self) -> impl Iterator<Item = &i32> {
        self.0.iter().map(|(slot, _)| slot)
    }

    fn values(&self) -> impl Iterator<Item = &Entry> {
        self.0.iter().map(|(_, entry)| entry)
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeyStore {
    entries: Entries,
}
impl KeyStore {
    pub fn encode_state(&self, e: &mut crate::cbor::Encoder) -> Result<()> {
        e.array(self.entries.len())?;
        for (slot, entry) in &self.entries.0 {
            e.array(4)?; e.unsigned(*slot as u64)?;
            e.unsigned(match entry.algorithm { Algorithm::HmacSha256 => 1, Algorithm::Aes128 => 2, Algorithm::P256 => 3 })?;
            e.bytes(&entry.nonce)?; e.bytes(&entry.key)?;
        }
        Ok(())
    }

    pub fn decode_state(d: &mut crate::cbor::Decoder<'_>) -> Result<Self> {
        let count = d.array(MAX_ENTRIES)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| Error::Quota)?;
        let mut previous = None;
        for _ in 0..count {
            d.record(4)?;
            let slot: i32 = d.number()?;
            if !(0..MAX_ENTRIES as i32).contains(&slot) || previous.is_some_and(|p| p >= slot) { return Err(Error::Format); }
            previous = Some(slot);
            let algorithm = match d.unsigned()? { 1 => Algorithm::HmacSha256, 2 => Algorithm::Aes128, 3 => Algorithm::P256, _ => return Err(Error::Format) };
            let mut entry = Entry { algorithm, nonce: [0; 16], key: [0; 32] };
            entry.nonce.copy_from_slice(d.bytes(16)?.get(..16).ok_or(Error::Format)?);
            entry.key.copy_from_slice(d.bytes(32)?.get(..32).ok_or(Error::Format)?);
            entries.push((slot, entry));
        }
        let result = Self { entries: Entries(entries) };
        result.validate()?;
        Ok(result)
    }

    #[cfg(feature = "mc04")]
    pub(crate) fn try_clone_with(
        &self,
        context: &mut crate::fallible_clone::CloneContext,
    ) -> Result<Self> {
        Ok(Self {
            entries: self.entries.try_clone_with(context)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > MAX_ENTRIES
            || self
                .entries
                .keys()
                .any(|slot| !(0..MAX_ENTRIES as i32).contains(slot))
        {
            return Err(Error::Storage);
        }
        let mut nonces = [[0; 16]; 8];
        for (nonce_count, entry) in self.entries.values().enumerate() {
            if nonces[..nonce_count].contains(&entry.nonce)
                || (entry.algorithm == Algorithm::Aes128 && entry.key[16..] != [0; 16])
                || (entry.algorithm == Algorithm::P256
                    && !crate::crypto::p256_private_key_valid(&entry.key))
            {
                return Err(Error::Storage);
            }
            nonces[nonce_count] = entry.nonce;
        }
        Ok(())
    }
    pub fn generate(
        &mut self,
        owner: [u8; 16],
        slot: i32,
        algorithm: i32,
        mut random: impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        if !(0..MAX_ENTRIES as i32).contains(&slot) {
            return Err(Error::Bounds);
        }
        if self.entries.contains_key(&slot) {
            return Err(Error::Busy);
        }
        self.entries.reserve_entry()?;
        let algorithm = match algorithm {
            1 => Algorithm::HmacSha256,
            2 => Algorithm::Aes128,
            3 => Algorithm::P256,
            _ => return Err(Error::Unsupported),
        };
        let mut entry = Entry {
            algorithm,
            nonce: [0; 16],
            key: [0; 32],
        };
        random(&mut entry.nonce)?;
        if algorithm == Algorithm::P256 {
            let mut valid = false;
            for _ in 0..8 {
                random(&mut entry.key)?;
                if crate::crypto::p256_private_key_valid(&entry.key) {
                    valid = true;
                    break;
                }
            }
            if !valid {
                return Err(Error::Native);
            }
        } else {
            random(if algorithm == Algorithm::Aes128 {
                &mut entry.key[..16]
            } else {
                &mut entry.key
            })?;
        }
        if self.entries.values().any(|e| e.nonce == entry.nonce) {
            return Err(Error::Native);
        }
        self.entries.insert(slot, entry)?;
        self.open(owner, slot)
    }
    pub fn open(&self, owner: [u8; 16], slot: i32) -> Result<Vec<u8>> {
        let entry = self.entries.get(&slot).ok_or(Error::Missing)?;
        let mut token = Vec::new();
        token.try_reserve_exact(32).map_err(|_| Error::Quota)?;
        token.extend_from_slice(&owner);
        token.extend_from_slice(&entry.nonce);
        Ok(token)
    }
    pub fn delete(&mut self, slot: i32) -> Result<()> {
        self.entries.remove(&slot).ok_or(Error::Missing)?;
        Ok(())
    }
    fn key(&self, owner: [u8; 16], token: &[u8], algorithm: Algorithm) -> Result<&[u8; 32]> {
        if token.len() != 32 || !bool::from(token[..16].ct_eq(&owner)) {
            return Err(Error::Unauthorized);
        }
        let entry = self
            .entries
            .values()
            .find(|e| bool::from(token[16..].ct_eq(&e.nonce)))
            .ok_or(Error::Missing)?;
        if entry.algorithm != algorithm {
            return Err(Error::Unauthorized);
        }
        Ok(&entry.key)
    }
    pub fn hmac(
        &self,
        owner: [u8; 16],
        token: &[u8],
        data: &[u8],
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let mut output = zeroizing_buffer(32)?;
        provider.hmac_sha256_into(
            self.key(owner, token, Algorithm::HmacSha256)?,
            data,
            output.as_mut_slice().try_into().unwrap(),
        )?;
        Ok(core::mem::take(&mut *output))
    }
    pub fn cmac(
        &self,
        owner: [u8; 16],
        token: &[u8],
        data: &[u8],
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let mut output = zeroizing_buffer(16)?;
        provider.aes_cmac_into(
            self.key(owner, token, Algorithm::Aes128)?[..16]
                .try_into()
                .unwrap(),
            data,
            output.as_mut_slice().try_into().unwrap(),
        )?;
        Ok(core::mem::take(&mut *output))
    }
    pub fn cbc(
        &self,
        owner: [u8; 16],
        token: &[u8],
        iv: &[u8],
        data: &[u8],
        encrypt: bool,
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let key = self.key(owner, token, Algorithm::Aes128)?[..16]
            .try_into()
            .unwrap();
        let iv = iv.try_into().map_err(|_| Error::Bounds)?;
        let capacity = if encrypt {
            data.len()
                .checked_div(16)
                .and_then(|blocks| blocks.checked_add(1))
                .and_then(|blocks| blocks.checked_mul(16))
                .ok_or(Error::Bounds)?
        } else {
            data.len()
        };
        let mut output = zeroizing_buffer(capacity)?;
        let result = if encrypt {
            provider.aes_cbc_encrypt(key, iv, data, &mut output)
        } else {
            provider.aes_cbc_decrypt(key, iv, data, &mut output)
        };
        let length = match result {
            Ok(length) => length,
            Err(error) => {
                return Err(error);
            }
        };
        if length > output.len() || encrypt && length != capacity {
            return Err(Error::Native);
        }
        output.truncate(length);
        Ok(core::mem::take(&mut *output))
    }
    pub fn ccm(
        &self,
        owner: [u8; 16],
        token: &[u8],
        buffers: &[&[u8]],
        encrypt: bool,
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        if buffers.len() != 3 {
            return Err(Error::Bounds);
        }
        let key = self.key(owner, token, Algorithm::Aes128)?[..16]
            .try_into()
            .unwrap();
        let nonce = buffers[0].try_into().map_err(|_| Error::Bounds)?;
        let capacity = if encrypt {
            buffers[2].len().checked_add(16).ok_or(Error::Bounds)?
        } else {
            buffers[2]
                .len()
                .checked_sub(16)
                .ok_or(Error::Authentication)?
        };
        let mut output = zeroizing_buffer(capacity)?;
        let result = if encrypt {
            provider.aes_ccm_encrypt(key, nonce, buffers[1], buffers[2], &mut output)
        } else {
            provider.aes_ccm_decrypt(key, nonce, buffers[1], buffers[2], &mut output)
        };
        let length = match result {
            Ok(length) => length,
            Err(error) => {
                return Err(error);
            }
        };
        if length != capacity {
            return Err(Error::Native);
        }
        output.truncate(length);
        Ok(core::mem::take(&mut *output))
    }

    pub fn p256_public_key(
        &self,
        owner: [u8; 16],
        token: &[u8],
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let mut output = zeroizing_buffer(65)?;
        provider.p256_public_key_into(
            self.key(owner, token, Algorithm::P256)?,
            output.as_mut_slice().try_into().unwrap(),
        )?;
        Ok(core::mem::take(&mut *output))
    }

    pub fn p256_sign(
        &self,
        owner: [u8; 16],
        token: &[u8],
        message: &[u8],
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let mut output = zeroizing_buffer(64)?;
        provider.p256_ecdsa_sign_into(
            self.key(owner, token, Algorithm::P256)?,
            message,
            output.as_mut_slice().try_into().unwrap(),
        )?;
        Ok(core::mem::take(&mut *output))
    }

    pub fn p256_ecdh(
        &self,
        owner: [u8; 16],
        token: &[u8],
        peer_public_key: &[u8],
        provider: &mut impl CryptoProvider,
    ) -> Result<Vec<u8>> {
        let mut output = zeroizing_buffer(32)?;
        provider.p256_ecdh_into(
            self.key(owner, token, Algorithm::P256)?,
            peer_public_key,
            output.as_mut_slice().try_into().unwrap(),
        )?;
        Ok(core::mem::take(&mut *output))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SoftwareCrypto;
    #[test]
    fn ownership_persistence_and_revocation() {
        let mut s = KeyStore::default();
        let mut seed = 0u8;
        let mut rng = |b: &mut [u8]| {
            seed += 1;
            b.fill(seed);
            Ok(())
        };
        let mut provider = SoftwareCrypto;
        let owner = [1; 16];
        let h = s.generate(owner, 0, 1, &mut rng).unwrap();
        let tag = s.hmac(owner, &h, b"x", &mut provider).unwrap();
        assert_eq!(
            s.hmac([2; 16], &h, b"x", &mut provider),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            s.cmac(owner, &h, b"x", &mut provider),
            Err(Error::Unauthorized)
        );
        let mut encoder = crate::cbor::Encoder::new(1024);
        s.encode_state(&mut encoder).unwrap();
        let raw = zeroize::Zeroizing::new(encoder.finish());
        for end in 0..raw.len() {
            assert!(KeyStore::decode_state(&mut crate::cbor::Decoder::new(&raw[..end])).is_err());
        }
        let mut decoder = crate::cbor::Decoder::new(&raw);
        let mut s = KeyStore::decode_state(&mut decoder).unwrap();
        decoder.finish().unwrap();
        assert_eq!(s.hmac(owner, &h, b"x", &mut provider).unwrap(), tag);
        s.delete(0).unwrap();
        let h2 = s.generate(owner, 0, 1, &mut rng).unwrap();
        assert_ne!(h, h2);
        assert_eq!(s.hmac(owner, &h, b"x", &mut provider), Err(Error::Missing));
    }
    #[test]
    fn quotas_and_entropy_failures() {
        let mut s = KeyStore::default();
        assert_eq!(
            s.generate([0; 16], 0, 1, |_| Err(Error::Native)),
            Err(Error::Native)
        );
        assert!(s.entries.is_empty());
        assert_eq!(s.generate([0; 16], 8, 1, |_| Ok(())), Err(Error::Bounds));

        assert_eq!(
            s.generate([0; 16], 0, 3, |bytes| {
                bytes.fill(0);
                Ok(())
            }),
            Err(Error::Native)
        );
        assert!(s.entries.is_empty());
    }

    #[test]
    fn compact_entries_are_sorted_bounded_and_unique() {
        let entry = |slot: i32| Entry {
            algorithm: Algorithm::HmacSha256,
            nonce: [slot as u8; 16],
            key: [slot as u8; 32],
        };
        let mut entries = Entries::default();
        for slot in (0..MAX_ENTRIES as i32).rev() {
            entries.insert(slot, entry(slot)).unwrap();
        }
        let pointer = entries.0.as_ptr();
        assert_eq!(entries.insert(MAX_ENTRIES as i32, entry(8)), Err(Error::Bounds));
        assert_eq!(entries.0.as_ptr(), pointer);

        assert!(entries.0.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for invalid in [
            alloc::vec![(0, entry(0)), (0, entry(1))],
            alloc::vec![(8, entry(0))],
            (0..=MAX_ENTRIES as i32).map(|slot| (slot, entry(slot))).collect(),
        ] {
            let mut encoder = crate::cbor::Encoder::new(2048);
            KeyStore { entries: Entries(invalid) }.encode_state(&mut encoder).unwrap();
            let raw = zeroize::Zeroizing::new(encoder.finish());
            assert!(KeyStore::decode_state(&mut crate::cbor::Decoder::new(&raw)).is_err());
        }
    }

    #[test]
    fn recovery_rejects_duplicate_key_nonces_without_allocation() {
        let mut store = KeyStore::default();
        for slot in 0..2 {
            store
                .entries
                .insert(
                    slot,
                    Entry {
                        algorithm: Algorithm::HmacSha256,
                        nonce: [0x5a; 16],
                        key: [slot as u8; 32],
                    },
                )
                .unwrap();
        }
        assert_eq!(store.validate(), Err(Error::Storage));
        store.entries.get_mut(&1).unwrap().nonce[0] ^= 1;
        assert_eq!(store.validate(), Ok(()));
    }

    #[test]
    fn p256_keys_are_opaque_owned_and_persistent() {
        let owner = [7; 16];
        let mut store = KeyStore::default();
        let mut calls = 0;
        let handle = store
            .generate(owner, 4, 3, |bytes| {
                calls += 1;
                bytes.fill(if calls == 1 { 9 } else { 1 });
                Ok(())
            })
            .unwrap();
        let mut provider = SoftwareCrypto;
        let public_key = store
            .p256_public_key(owner, &handle, &mut provider)
            .unwrap();
        assert_eq!(public_key.len(), 65);
        let signature = store
            .p256_sign(owner, &handle, b"message", &mut provider)
            .unwrap();
        assert!(provider
            .p256_ecdsa_verify(&public_key, b"message", &signature)
            .unwrap());
        assert_eq!(
            store.p256_sign([8; 16], &handle, b"message", &mut provider),
            Err(Error::Unauthorized)
        );

        let mut encoder = crate::cbor::Encoder::new(1024);
        store.encode_state(&mut encoder).unwrap();
        let encoded = zeroize::Zeroizing::new(encoder.finish());
        let reopened = KeyStore::decode_state(&mut crate::cbor::Decoder::new(&encoded)).unwrap();
        assert!(reopened.validate().is_ok());
        assert_eq!(
            reopened
                .p256_public_key(owner, &handle, &mut provider)
                .unwrap(),
            public_key
        );
    }
    #[test]
    fn structural_equality_includes_protected_key_bytes() {
        let mut store = KeyStore::default();
        store
            .generate([1; 16], 0, 1, |bytes| {
                bytes.fill(7);
                Ok(())
            })
            .unwrap();
        let mut changed = store.clone();
        assert!(store == changed);
        changed.entries.get_mut(&0).unwrap().key[31] ^= 1;
        assert!(store != changed);
    }

    #[test]
    fn key_operations_use_the_platform_crypto_provider_after_authorization() {
        struct RecordingProvider {
            calls: usize,
            fail: bool,
            key_pointer: usize,
            data_pointer: usize,
            output_pointer: usize,
        }
        impl CryptoProvider for RecordingProvider {
            fn hmac_sha256_into(
                &mut self,
                key: &[u8],
                data: &[u8],
                output: &mut [u8; 32],
            ) -> Result<()> {
                self.calls += 1;
                self.key_pointer = key.as_ptr() as usize;
                self.data_pointer = data.as_ptr() as usize;
                self.output_pointer = output.as_ptr() as usize;
                if self.fail {
                    Err(Error::Native)
                } else {
                    output.fill(0xa5);
                    Ok(())
                }
            }
        }

        let owner = [3; 16];
        let mut store = KeyStore::default();
        let handle = store
            .generate(owner, 0, 1, |bytes| {
                bytes.fill(7);
                Ok(())
            })
            .unwrap();
        let mut provider = RecordingProvider {
            calls: 0,
            fail: false,
            key_pointer: 0,
            data_pointer: 0,
            output_pointer: 0,
        };

        let message = b"message";
        let key_pointer = store.entries.get(&0).unwrap().key.as_ptr() as usize;
        let result = store
            .hmac(owner, &handle, message, &mut provider)
            .unwrap();
        assert_eq!(result, [0xa5; 32]);
        assert_eq!(provider.key_pointer, key_pointer);
        assert_eq!(provider.data_pointer, message.as_ptr() as usize);
        assert_eq!(provider.output_pointer, result.as_ptr() as usize);
        assert_eq!(provider.calls, 1);
        assert_eq!(
            store.hmac([4; 16], &handle, b"message", &mut provider),
            Err(Error::Unauthorized)
        );
        assert_eq!(provider.calls, 1);

        provider.fail = true;
        assert_eq!(
            store.hmac(owner, &handle, b"message", &mut provider),
            Err(Error::Native)
        );
        assert_eq!(provider.calls, 2);
    }

    #[test]
    fn key_service_rejects_invalid_provider_output_lengths() {
        struct InvalidLengthProvider;
        impl CryptoProvider for InvalidLengthProvider {
            fn aes_cbc_encrypt(
                &mut self,
                _: &[u8; 16],
                _: [u8; 16],
                _: &[u8],
                output: &mut [u8],
            ) -> Result<usize> {
                output.fill(0xa5);
                Ok(output.len() + 1)
            }
        }

        let owner = [5; 16];
        let mut store = KeyStore::default();
        let handle = store
            .generate(owner, 0, 2, |bytes| {
                bytes.fill(9);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.cbc(
                owner,
                &handle,
                &[0; 16],
                b"message",
                true,
                &mut InvalidLengthProvider,
            ),
            Err(Error::Native)
        );
    }
}
