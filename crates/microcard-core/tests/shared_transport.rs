//! This suite also runs with MC04 disabled, so transport cannot acquire VM dependencies.
#![cfg(feature = "software-crypto")]
use microcard_core::{
    Error, Result,
    crypto::SoftwareCrypto,
    engine::CardEngine,
    globalplatform,
    scp03::{Keys, Verified},
    transport::Endpoint,
};
use std::{cell::Cell, rc::Rc};

struct TestEngine {
    provider: SoftwareCrypto,
    resets: Rc<Cell<usize>>,
    selections: Rc<Cell<usize>>,
}

impl CardEngine for TestEngine {
    type Provider = SoftwareCrypto;
    fn crypto_provider(&mut self) -> &mut Self::Provider {
        &mut self.provider
    }
    fn random(&mut self, bytes: &mut [u8]) -> Result<()> {
        bytes.fill(1);
        Ok(())
    }
    #[cfg(feature = "scp03-pseudo-random")]
    fn next_secure_channel_sequence(&mut self) -> Result<u32> {
        Ok(1)
    }
    fn abort_staging(&mut self) {
        self.resets.set(self.resets.get() + 1);
    }
    fn abort_transaction(&mut self) {
        self.resets.set(self.resets.get() + 1);
    }
    fn globalplatform_load_active(&self) -> bool {
        false
    }
    fn get_status_record(&self, _: u8, _: usize, _: &[u8]) -> Result<(Vec<u8>, bool)> {
        panic!("unauthenticated registry request");
    }
    fn select_isd_with_cancel(&mut self, cancel: &mut dyn FnMut() -> bool) -> Result<()> {
        if cancel() {
            return Err(Error::Cancelled);
        }
        self.selections.set(self.selections.get() + 1);
        Ok(())
    }
    fn select_aid_with_cancel(&mut self, _: &[u8], _: &mut dyn FnMut() -> bool) -> Result<()> {
        panic!("unauthenticated application selection");
    }
    fn manage_globalplatform_with_cancel(
        &mut self,
        _: Verified,
        _: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        panic!("unauthenticated GP command");
    }
    fn manage_with_cancel(&mut self, _: Verified, _: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        panic!("unauthenticated management command");
    }
    fn process_verified_with_cancel(
        &mut self,
        _: Verified,
        _: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>> {
        panic!("unauthenticated invocation");
    }
}

#[test]
fn shared_transport_keeps_authentication_and_cancellation_above_the_engine() {
    let resets = Rc::new(Cell::new(0));
    let selections = Rc::new(Cell::new(0));
    let mut endpoint = Endpoint::new(
        TestEngine {
            provider: SoftwareCrypto,
            resets: resets.clone(),
            selections: selections.clone(),
        },
        Keys {
            enc: [1; 16],
            mac: [2; 16],
        },
    );
    let select_isd = [0, 0xa4, 4, 0, 0];
    assert_eq!(
        endpoint.exchange(&select_isd),
        globalplatform::isd_fci().unwrap()
    );
    assert_eq!(selections.get(), 1);
    for instruction in [0xe0, 0xe4, 0xe6, 0xe8, 0xea, 0x10, 0xf2] {
        assert_eq!(
            endpoint.exchange(&[0x80, instruction, 0, 0, 0]),
            [0x69, 0x82]
        );
    }
    let before = resets.get();
    assert_eq!(
        endpoint.exchange_with_cancel(&select_isd, &mut || true),
        [0x69, 0x82]
    );
    assert!(resets.get() >= before + 2);
    assert_eq!(selections.get(), 1);
    assert_eq!(
        endpoint.exchange(&select_isd),
        globalplatform::isd_fci().unwrap()
    );
    assert_eq!(selections.get(), 2);
}
