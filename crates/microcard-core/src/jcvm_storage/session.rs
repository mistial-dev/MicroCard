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
        })
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
            self.card
                .as_mut()
                .ok_or(Error::Missing)?
                .deselect_with_cancel(&file, &mut Services(provider), cancel)
                .map_err(engine_error)
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
                    &mut Services(provider),
                    microcard_engine_jcvm::applet::Installation {
                        module_aid: module,
                        instance_aid,
                        parameters,
                    },
                    cancel,
                ),
                None => card.install_module_with_cancel(
                    &file,
                    &mut Services(provider),
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
        if !self.installed()? {
            return Err(Error::Missing);
        }
        if cancel() {
            return Err(Error::Cancelled);
        }
        let result = self.image.with_bytes(provider, |image, provider| {
            let file = LoadFile::parse(image).map_err(|_| Error::Format)?;
            self.card
                .as_mut()
                .unwrap()
                .process_with_cancel(&file, &mut Services(provider), command, selecting, cancel)
                .map_err(engine_error)
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
            if cancel() {
                return Err(Error::Cancelled);
            }
            self.store
                .commit(self.card.as_ref().ok_or(Error::Missing)?, provider)?;
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
    }
    impl CryptoProvider for Provider {
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

    #[test]
    fn command_boundaries_preserve_pin_retries_and_refuse_use_until_recovery_succeeds() {
        let image = include_bytes!(
            "../../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let sizes = Sizes {
            heap_bytes: 65536,
            frame_words: 8192,
            ..Sizes::default()
        };
        let mut provider = Provider::default();
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
            &mut provider,
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
            .install_globalplatform(&request, &mut provider, &mut || false)
            .unwrap();
        let select = [0, 0xa4, 4, 0, 0];
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

        let mut polls = 0;
        assert_eq!(
            session.process(&wrong_pin, false, &mut provider, &mut || {
                polls += 1;
                polls == 100
            }),
            Err(Error::Cancelled)
        );
        assert_eq!(polls, 100);

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
                + 1,
            before
        );
    }
}
