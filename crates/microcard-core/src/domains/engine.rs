use super::*;

impl<F: Flash, P: Platform, S: PackageStaging> crate::engine::CardEngine for Card<F, P, S> {
    type Provider = P;

    fn crypto_provider(&mut self) -> &mut P {
        Card::crypto_provider(self)
    }
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        Card::random(self, output)
    }
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32> {
        Card::next_secure_channel_sequence(self)
    }
    fn abort_staging(&mut self) {
        Card::abort_staging(self)
    }
    fn abort_transaction(&mut self) {
        Card::abort_transaction(self)
    }
    fn globalplatform_load_active(&self) -> bool {
        Card::globalplatform_load_active(self)
    }
    fn get_status_record(&self, kind: u8, index: usize, filter: &[u8]) -> Result<(Vec<u8>, bool)> {
        Card::get_status_record(self, kind, index, filter)
    }
    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        Card::select_isd_with_cancel(self, cancel)
    }
    fn select_aid_with_cancel(
        &mut self,
        aid: &[u8],
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        Card::select_with_cancel(self, &encode_aid(aid)?, cancel)
    }
    fn manage_globalplatform_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Card::manage_globalplatform_with_cancel(self, command, cancel)
    }
    fn manage_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Card::manage_with_cancel(self, command, cancel)
    }
    fn process_verified_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Card::process_verified_with_cancel(self, command, cancel)
    }
}
