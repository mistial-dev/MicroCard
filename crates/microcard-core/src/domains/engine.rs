use super::*;

impl<F: Flash + crate::image_store::ImageFlash, P: Platform, S: PackageStaging> crate::engine::CardEngine for Mc04Engine<F, P, S> {
    type Provider = P;

    fn crypto_provider(&mut self) -> &mut P {
        Mc04Engine::crypto_provider(self)
    }
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        Mc04Engine::random(self, output)
    }
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32> {
        Mc04Engine::next_secure_channel_sequence(self)
    }
    fn abort_staging(&mut self) {
        Mc04Engine::abort_staging(self)
    }
    fn abort_transaction(&mut self) {
        Mc04Engine::abort_transaction(self)
    }
    fn globalplatform_load_active(&self) -> bool {
        Mc04Engine::globalplatform_load_active(self)
    }
    fn get_status_record(&mut self, kind: u8, index: usize, filter: &[u8]) -> Result<(Vec<u8>, bool)> {
        Mc04Engine::get_status_record(self, kind, index, filter)
    }
    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        Mc04Engine::select_isd_with_cancel(self, cancel)
    }
    fn select_verified_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Mc04Engine::select_with_cancel(self, &encode_aid(&command.command().data)?, cancel)?;
        fallible_copy(&[0x90, 0])
    }
    fn manage_globalplatform_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Mc04Engine::manage_globalplatform_with_cancel(self, command, cancel)
    }
    fn manage_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Mc04Engine::manage_with_cancel(self, command, cancel)
    }
    fn process_verified_with_cancel(
        &mut self,
        command: Verified,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        Mc04Engine::process_verified_with_cancel(self, command, cancel)
    }
}
