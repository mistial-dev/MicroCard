//! One installed applet with durable command boundaries.
use super::*;
use crate::{hal::Entropy, image_store::CodeImage, jcvm_services::Services};
use microcard_engine_jcvm::applet::Response;

pub struct Session<F: Flash, I: CodeImage = Vec<u8>> {
    store: Store<F>,
    image: I,
    sizes: Sizes,
    card: Option<Card>,
    recovery_required: bool,
    reset_requested: bool,
}

impl<F: Flash, I: CodeImage> Session<F, I> {
    /// The caller authenticates code before opening; this session binds state to it.
    pub fn open(
        flash: F,
        key: impl Into<JournalKey>,
        verified_image: I,
        installation: [u8; 16],
        sizes: Sizes,
        provider: &mut impl CryptoProvider,
    ) -> Result<Self> {
        let (store, card) = verified_image.with_bytes(provider, |image, provider| {
            Store::open(flash, key, image, installation, sizes, provider)
        })?;
        Ok(Self {
            store,
            image: verified_image,
            sizes,
            card,
            recovery_required: false,
            reset_requested: false,
        })
    }

    pub(crate) fn take_security_reset(&mut self) -> bool {
        core::mem::take(&mut self.reset_requested)
    }

    pub fn installed(&self) -> Result<bool> {
        if self.recovery_required {
            return Err(Error::Storage);
        }
        Ok(self.card.is_some())
    }

    pub fn selected(&self) -> Result<bool> {
        self.installed()?;
        Ok(self.card.as_ref().is_some_and(Card::selected))
    }

    pub fn retain_volatile(&mut self, maximum: usize) -> Result<microcard_engine_jcvm::applet::VolatileState> {
        self.installed()?;
        self.card.as_mut().ok_or(Error::Missing)?.retain_volatile(maximum).map_err(engine_error)
    }

    pub fn restore_volatile(&mut self, saved: &microcard_engine_jcvm::applet::VolatileState) -> Result<()> {
        self.installed()?;
        self.card.as_mut().ok_or(Error::Missing)?.restore_volatile(saved).map_err(engine_error)
    }

    pub fn deselect(
        &mut self,
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        if !self.selected()? {
            return Ok(());
        }
        let result = self.image.with_bytes(provider, |image, provider| {
            let file = LoadFile::parse(image).map_err(|_| Error::Format)?;
            let mut checkpoint = |view: PersistentView<'_>, provider: &mut _| self.store.commit_view(view, provider);
            let mut services = Services::new(provider).with_checkpoint(&mut checkpoint);
            let result = self.card.as_mut().ok_or(Error::Missing)?
                .deselect_with_cancel(&file, &mut services, cancel)
                .map_err(|error| services.take_persistence_error().unwrap_or_else(|| engine_error(error)));
            self.reset_requested |= services.reset_requested();
            result
        });
        self.finish(result, provider, cancel)
    }

    /// Also clears volatile applet data; transport must discard its selection.
    pub fn recover(&mut self, provider: &mut impl CryptoProvider) -> Result<()> {
        self.recovery_required = true;
        self.card = None;
        self.card = self.image.with_bytes(provider, |image, provider| {
            self.store.recover(image, self.sizes, provider)
        })?;
        self.recovery_required = false;
        Ok(())
    }

    pub fn install(
        &mut self,
        module: &[u8],
        parameters: &[u8],
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.install_inner(module, None, parameters, provider, cancel)
    }

    pub fn install_globalplatform(
        &mut self,
        request: &crate::globalplatform::ApplicationInstall<'_>,
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        self.image.with_bytes(provider, |image, _| {
            let file = LoadFile::parse(image).map_err(|_| Error::Format)?;
            if file.header().map_err(engine_error)?.package_aid != request.load_aid {
                return Err(Error::Missing);
            }
            Ok(())
        })?;
        let parameters = request.jcvm_parameters()?;
        self.install_inner(
            request.module_aid,
            Some(request.instance_aid),
            &parameters,
            provider,
            cancel,
        )
    }

    fn install_inner(
        &mut self,
        module: &[u8],
        instance: Option<&[u8]>,
        parameters: &[u8],
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        if self.installed()? {
            return Err(Error::Busy);
        }
        if cancel() {
            return Err(Error::Cancelled);
        }
        let result = self.image.with_bytes(provider, |image, provider| {
            let file = LoadFile::parse(image).map_err(|_| Error::Format)?;
            self.card = Some(Card::new(&file, self.sizes).map_err(engine_error)?);
            let card = self.card.as_mut().unwrap();
            match instance {
                Some(instance_aid) => card.install_instance_with_cancel(
                    &file,
                    &mut Services::new(provider),
                    microcard_engine_jcvm::applet::Installation {
                        module_aid: module,
                        instance_aid,
                        parameters,
                    },
                    cancel,
                ),
                None => card.install_module_with_cancel(
                    &file,
                    &mut Services::new(provider),
                    module,
                    parameters,
                    cancel,
                ),
            }
            .map_err(engine_error)
        });
        self.finish(result, provider, cancel)
    }

    pub fn process(
        &mut self,
        command: &[u8],
        selecting: bool,
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Response> {
        self.process_command(command, selecting, None, provider, cancel)
    }

    pub(crate) fn process_verified(
        &mut self,
        verified: crate::scp03::Verified<'_>,
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Response> {
        let mut command = zeroize::Zeroizing::new(verified.command().encode()?);
        // OpenFIPS201 requires both C-MAC and C-DECRYPTION for administrative access.
        // MAC-only transport retains ordinary applet semantics without this grant.
        if verified.level() & 3 != 3 {
            return self.process(&command, false, provider, cancel);
        }
        command[0] |= 0x04;
        if command.len() == 4 {
            command.try_reserve_exact(1).map_err(|_| Error::Quota)?;
            command.push(0);
        }
        self.process_command(&command, false, Some(verified.level()), provider, cancel)
    }

    fn process_command(
        &mut self,
        command: &[u8],
        selecting: bool,
        security: Option<u8>,
        provider: &mut (impl CryptoProvider + Entropy),
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<Response> {
        if !self.installed()? { return Err(Error::Missing); }
        if cancel() { return Err(Error::Cancelled); }
        // unwrap receives header and CDATA, not an optional trailing Le byte.
        let protected_length = if command.len() > 5 { 5 + usize::from(command[4]) } else { 5.min(command.len()) };
        let result = self.image.with_bytes(provider, |image, provider| {
            let file = LoadFile::parse(image).map_err(|_| Error::Format)?;
            let mut checkpoint = |view: PersistentView<'_>, provider: &mut _| self.store.commit_view(view, provider);
            let mut services = match security {
                Some(level) => Services::verified(provider, command.get(..protected_length).ok_or(Error::Format)?, level),
                None => Services::new(provider),
            }.with_checkpoint(&mut checkpoint);
            let result = self.card.as_mut().unwrap()
                .process_with_cancel(&file, &mut services, command, selecting, cancel)
                .map_err(|error| services.take_persistence_error().unwrap_or_else(|| engine_error(error)));
            self.reset_requested |= services.reset_requested();
            result
        });
        self.finish(result, provider, cancel)
    }

    fn finish<T>(
        &mut self,
        result: Result<T>,
        provider: &mut impl CryptoProvider,
        cancel: &mut dyn FnMut() -> bool,
    ) -> Result<T> {
        let result = result.and_then(|value| {
            // A completed callback's ordinary writes are already observable Java Card
            // state. Late cancellation suppresses its response, not its durability.
            self.store
                .commit(self.card.as_ref().ok_or(Error::Missing)?, provider)?;
            if cancel() {
                return Err(Error::Cancelled);
            }
            Ok(value)
        });
        if result.is_err() {
            // Drop mutated heap and frames before allocating recovery buffers. Never
            // guess whether an uncertain commit is old or new; the journal decides.
            self.recover(provider)?;
        }
        result
    }

    pub fn into_flash(self) -> F {
        self.store.into_flash()
    }
}

fn engine_error(error: microcard_engine_jcvm::Error) -> Error {
    use microcard_engine_jcvm::Error as E;
    match error {
        E::Cancelled => Error::Cancelled,
        E::Quota => Error::Quota,
        E::Storage => Error::Storage,
        E::Bounds => Error::Bounds,
        E::Missing => Error::Missing,
        E::Unsupported => Error::Unsupported,
        E::Unauthorized | E::Firewall => Error::Unauthorized,
        _ => Error::Format,
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::{crypto::SoftwareCrypto, journal::MemoryFlash};

    #[derive(Default)]
    struct Provider {
        fail_recovery: bool,
        encryptions: alloc::rc::Rc<core::cell::Cell<usize>>,
    }
    impl CryptoProvider for Provider {
        fn aes_ccm_encrypt_in_place(&mut self, key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], output: &mut [u8]) -> Result<usize> {
            let written = SoftwareCrypto.aes_ccm_encrypt_in_place(key, nonce, aad, output)?;
            self.encryptions.set(self.encryptions.get() + 1);
            Ok(written)
        }

        fn sha256_into(&mut self, data: &[u8], output: &mut [u8; 32]) -> Result<()> {
            if self.fail_recovery {
                output.fill(0);
                return Err(Error::Native);
            }
            SoftwareCrypto.sha256_into(data, output)
        }
    }
    impl Entropy for Provider {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
            output.fill(7);
            Ok(())
        }
    }

    const SELECT: [u8; 5] = [0, 0xa4, 4, 0, 0];
    const DEFINE_CERTIFICATE: [u8; 25] = [0x84, 0xdb, 0xff, 0xff, 0x14, 0x64, 0x12, 0x8b, 0x03, 0x5f, 0xc1, 0x0a, 0x8c, 0x01, 0x7f, 0x8d, 0x01, 0x7f, 0x91, 0x01, 0x9b, 0x92, 0x02, 0x10, 0x00];

    fn installed_session(provider: &mut Provider) -> Session<MemoryFlash> {
        let image = include_bytes!(
            "../../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let sizes = Sizes {
            heap_bytes: 65536,
            frame_words: 8192,
            ..Sizes::default()
        };
        let module = LoadFile::parse(image)
            .unwrap()
            .applets()
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .aid;
        let mut session = Session::open(
            MemoryFlash::new(65536),
            [3; 16],
            image.to_vec(),
            [4; 16],
            sizes,
            provider,
        )
        .unwrap();
        let request = crate::globalplatform::ApplicationInstall {
            load_aid: LoadFile::parse(image)
                .unwrap()
                .header()
                .unwrap()
                .package_aid,
            module_aid: module,
            instance_aid: &[0xf0, 1, 2, 3, 4],
            privileges: &[0],
            parameters: &[],
        };
        session
            .install_globalplatform(&request, provider, &mut || false)
            .unwrap();
        session
    }

    #[test]
    fn ordinary_object_definition_survives_cancel_after_callback_return() {
        let mut last_poll = None;
        for failure in [None, Some(false), Some(true)] {
            let mut provider = Provider::default();
            let mut session = installed_session(&mut provider);
            let select = SELECT;
            session.process(&select, true, &mut provider, &mut || false).unwrap();
            // CREATE OBJECT publishes ordinary fields, without an applet transaction.
            let define = DEFINE_CERTIFICATE;
            let before = provider.encryptions.get();
            if failure == Some(true) { session.store.journal.flash_mut().fail_after = Some(0); }
            let mut polls = 0;
            let result = session.process_command(&define, false, Some(3), &mut provider, &mut || {
                polls += 1;
                last_poll == Some(polls)
            });
            match failure {
                None => {
                    assert_eq!(result.unwrap().sw, 0x9000);
                    assert!(provider.encryptions.get() > before + 1, "ordinary writes publish before the final boundary");
                    last_poll = Some(polls);
                }
                Some(false) => assert_eq!(result, Err(Error::Cancelled)),
                Some(true) => assert_eq!(result, Err(Error::Storage)),
            }
            let sizes = session.sizes;
            let image = session.image.clone();
            let mut flash = session.into_flash();
            flash.fail_after = None;
            let mut rebooted = Session::open(flash, [3; 16], image, [4; 16], sizes, &mut provider).unwrap();
            rebooted.process(&select, true, &mut provider, &mut || false).unwrap();
            let duplicate = rebooted.process_command(&define, false, Some(3), &mut provider, &mut || false).unwrap();
            assert_eq!(duplicate.sw, if failure == Some(true) { 0x9000 } else { 0x6e27 },
                "completed ordinary definition must survive late cancellation");
        }
    }

    #[test]
    fn openfips_object_update_survives_interrupted_checkpoint_writes() {
        let mut cuts = alloc::vec![usize::MAX];
        let mut measured = None;
        while let Some(cut) = cuts.pop() {
            let mut provider = Provider::default();
            let mut session = installed_session(&mut provider);
            let select = SELECT;
            session.process(&select, true, &mut provider, &mut || false).unwrap();
            let define = DEFINE_CERTIFICATE;
            assert_eq!(session.process_command(&define, false, Some(3), &mut provider, &mut || false).unwrap().sw, 0x9000);
            let write = [0x04, 0xdb, 0x3f, 0xff, 0x0c, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x53, 0x05, 0x70, 0x01, 0x61, 0xfe, 0x00];
            let read = [0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x00];
            let previous = session.process(&read, false, &mut provider, &mut || false).unwrap();
            session.store.journal.flash_mut().fail_after = Some(cut);
            let result = session.process_command(&write, false, Some(3), &mut provider, &mut || false);
            let remaining = session.store.journal.flash_mut().fail_after.unwrap();
            if cut == usize::MAX {
                let mutations = cut - remaining;
                measured = Some(mutations);
                // Journal tests cover each frame/rotation boundary. Here sample the
                // complete applet update, which now spans several checkpoints.
                cuts.extend([0, 2, 4, mutations / 4, mutations / 2, 3 * mutations / 4,
                    mutations - 6, mutations - 5, mutations - 1, mutations]);
            }
            let complete = cut >= measured.unwrap();
            if complete { assert_eq!(result.unwrap().sw, 0x9000, "cut {cut}"); }
            else { assert_eq!(result, Err(Error::Storage), "cut {cut}"); }
            let sizes = session.sizes;
            let image = session.image.clone();
            let mut flash = session.into_flash();
            flash.fail_after = None;
            let mut rebooted = Session::open(flash, [3; 16], image, [4; 16], sizes, &mut provider).unwrap();
            rebooted.process(&select, true, &mut provider, &mut || false).unwrap();
            let response = rebooted.process(&read, false, &mut provider, &mut || false).unwrap();
            let updated = response.sw == 0x9000 && response.data == [0x53, 0x05, 0x70, 0x01, 0x61, 0xfe, 0x00];
            if complete {
                assert!(updated, "completed checkpoint lost at cut {cut}");
            } else {
                assert!(response == previous || updated, "torn object recovered at cut {cut}: {response:?}");
            }
        }
    }

    #[test]
    fn command_boundaries_preserve_pin_retries_and_refuse_use_until_recovery_succeeds() {
        let mut provider = Provider::default();
        let mut session = installed_session(&mut provider);
        let select = SELECT;
        let wrong_pin = [
            0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 255, 255,
        ];
        assert_eq!(
            session
                .process(&select, true, &mut provider, &mut || false)
                .unwrap()
                .sw,
            0x9000
        );
        let before = session
            .process(&wrong_pin, false, &mut provider, &mut || false)
            .unwrap()
            .sw;
        assert_eq!(before & 0xfff0, 0x63c0);

        // A rejected commit must not retain the PIN decrement in live memory.
        session.store.journal.flash_mut().fail_after = Some(0);
        assert_eq!(
            session.process(&wrong_pin, false, &mut provider, &mut || false),
            Err(Error::Storage)
        );
        assert_eq!(session.installed(), Ok(true));
        session.store.journal.flash_mut().fail_after = None;

        let encryptions = provider.encryptions.clone();
        let checkpoint_count = encryptions.get();
        assert_eq!(
            session.process(&wrong_pin, false, &mut provider, &mut || {
                encryptions.get() > checkpoint_count
            }),
            Err(Error::Cancelled)
        );
        assert_eq!(encryptions.get(), checkpoint_count + 1);

        // Recovery failure leaves no callable applet, even after the provider recovers.
        provider.fail_recovery = true;
        session.store.journal.flash_mut().fail_after = Some(0);
        assert_eq!(
            session.process(&wrong_pin, false, &mut provider, &mut || false),
            Err(Error::Native)
        );
        provider.fail_recovery = false;
        session.store.journal.flash_mut().fail_after = None;
        assert_eq!(
            session.process(&select, true, &mut provider, &mut || false),
            Err(Error::Storage)
        );
        session.recover(&mut provider).unwrap();
        assert_eq!(
            session
                .process(&select, true, &mut provider, &mut || false)
                .unwrap()
                .sw,
            0x9000
        );
        assert_eq!(
            session
                .process(&wrong_pin, false, &mut provider, &mut || false)
                .unwrap()
                .sw
                + 2,
            before
        );
    }
}
