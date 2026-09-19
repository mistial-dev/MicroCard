//! Heap regions are reclaimable only after the registry stops referencing them.
use crate::{
    crypto::CryptoProvider,
    journal::{Flash, JournalKey},
    Result,
};
use zeroize::Zeroizing;

/// Derive the engine's heap root from its registry key, identically on every backend.
pub fn heap_root(provider: &mut impl CryptoProvider, registry: &JournalKey) -> Result<JournalKey> {
    let mut output = Zeroizing::new([0; 32]);
    provider.hmac_sha256_into(
        registry.as_ref(),
        b"MicroCard JCVM heap root v1\0",
        &mut output,
    )?;
    Ok(JournalKey::from(
        <[u8; 16]>::try_from(&output[..16]).unwrap(),
    ))
}

pub trait HeapBanks {
    type Bank: Flash;

    fn bank_count(&self) -> usize;
    /// Open existing bytes without erasing or repairing an incompatible state.
    fn open(&mut self, bank: u8) -> Result<Self::Bank>;
    /// Explicitly erase an unreferenced bank, including its local counters.
    /// The caller must use a newly reserved installation identity and derived key.
    /// Partial preparation fails; it must never affect another bank.
    fn prepare(&mut self, bank: u8) -> Result<Self::Bank>;
}

pub(crate) fn heap_key(
    provider: &mut impl CryptoProvider,
    root: &JournalKey,
    bank: u8,
    identity: &[u8; 16],
    image: &[u8; 32],
) -> Result<JournalKey> {
    const CONTEXT: &[u8] = b"MicroCard JCVM heap key v1\0";
    let mut input = [0; CONTEXT.len() + 1 + 16 + 32];
    input[..CONTEXT.len()].copy_from_slice(CONTEXT);
    input[CONTEXT.len()] = bank;
    input[CONTEXT.len() + 1..CONTEXT.len() + 17].copy_from_slice(identity);
    input[CONTEXT.len() + 17..].copy_from_slice(image);
    let mut output = Zeroizing::new([0; 32]);
    provider.hmac_sha256_into(root.as_ref(), &input, &mut output)?;
    Ok(JournalKey::from(
        <[u8; 16]>::try_from(&output[..16]).unwrap(),
    ))
}
