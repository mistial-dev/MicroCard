//! Contract between the authenticated transport and an engine's durable card state.
use crate::{Result, crypto::CryptoProvider, scp03::Verified};
use alloc::vec::Vec;

pub trait CardEngine {
    type Provider: CryptoProvider;

    fn crypto_provider(&mut self) -> &mut Self::Provider;
    fn random(&mut self, output: &mut [u8]) -> Result<()>;
    /// Reserve durably before returning; a reboot must never repeat a value.
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32>;
    fn abort_staging(&mut self);
    fn abort_transaction(&mut self);
    fn globalplatform_load_active(&self) -> bool;
    fn get_status_record(&self, kind: u8, index: usize, filter: &[u8]) -> Result<(Vec<u8>, bool)>;
    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()>;
    fn select_aid_with_cancel(
        &mut self,
        aid: &[u8],
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()>;
    fn manage_globalplatform_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>>;
    fn manage_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>>;
    /// Return response data followed by a two-byte status word.
    fn process_verified_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>>;
}
