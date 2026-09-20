//! Contract between the authenticated transport and an engine's durable card state.
use crate::{apdu::Command, crypto::CryptoProvider, scp03::Verified, Result};
use alloc::vec::Vec;

pub trait CardEngine {
    type Provider: CryptoProvider;
    /// Native applet commands support plain interindustry APDUs and SCP03 delivery.
    const DIRECT_APDUS: bool = false;

    fn is_application_command(&self, command: &Command<'_>) -> bool {
        matches!(command.ins, 0xa4 | 0x10)
    }

    /// Plain APDUs never carry a transport authorization grant.
    fn select_plain_with_cancel(&mut self, _command: &Command<'_>, _cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        Err(crate::Error::Unauthorized)
    }
    fn process_plain_with_cancel(&mut self, _command: &Command<'_>, _cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        Err(crate::Error::Unauthorized)
    }
    fn take_security_reset(&mut self) -> bool { false }

    fn crypto_provider(&mut self) -> &mut Self::Provider;
    fn random(&mut self, output: &mut [u8]) -> Result<()>;
    /// Reserve durably before returning; a reboot must never repeat a value.
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32>;
    fn abort_staging(&mut self);
    fn abort_transaction(&mut self);
    /// Clear prior authority before INITIALIZE UPDATE. Engines may restore the
    /// selected application from durable state without retaining its credentials.
    fn restart_secure_channel(&mut self, _cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        self.abort_staging();
        self.abort_transaction();
        Ok(())
    }
    fn globalplatform_load_active(&self) -> bool;
    fn get_status_record(
        &mut self,
        kind: u8,
        index: usize,
        filter: &[u8],
    ) -> Result<(Vec<u8>, bool)>;
    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()>;
    /// Return the SELECT response data followed by its status word.
    fn select_verified_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>>;
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
