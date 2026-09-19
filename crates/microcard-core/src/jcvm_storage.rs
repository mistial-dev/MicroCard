//! Dedicated applet-state journal. Code remains outside the mutable snapshot.
//! Callers authenticate the load file and supply a fresh installation identity.
use crate::{
    cbor::{Decoder, Encoder},
    crypto::CryptoProvider,
    journal::{Flash, Journal, JournalKey},
    Error, Result,
};
use microcard_engine_jcvm::{
    applet::{Card, PersistentState, Sizes},
    cap::LoadFile,
};
use zeroize::Zeroizing;

pub struct Store<F: Flash> {
    journal: Journal<F>,
    image: [u8; 32],
    installation: [u8; 16],
    maximum: usize,
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::{crypto::SoftwareCrypto, journal::MemoryFlash};

    struct Host;
    impl microcard_engine_jcvm::host::Host for Host {
        fn supports_digest(&self, algorithm: u8) -> bool {
            algorithm == 4
        }
        fn supports_random(&self, algorithm: u8) -> bool {
            matches!(algorithm, 1 | 2)
        }
        fn random(&mut self, output: &mut [u8]) -> microcard_engine_jcvm::Result<()> {
            output.fill(7);
            Ok(())
        }
        fn digest(
            &mut self,
            _: u8,
            input: &[u8],
            output: &mut [u8],
        ) -> microcard_engine_jcvm::Result<usize> {
            SoftwareCrypto
                .sha256_into(input, (&mut output[..32]).try_into().unwrap())
                .unwrap();
            Ok(32)
        }
    }

    #[test]
    fn authenticated_state_is_bound_to_installation_and_failed_commit_preserves_it() {
        let image = include_bytes!(
            "../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let sizes = Sizes {
            heap_bytes: 64 * 1024,
            frame_words: 8192,
            ..Sizes::default()
        };
        let (mut store, empty) = Store::open(
            MemoryFlash::new(65536),
            [3; 16],
            image,
            [4; 16],
            sizes,
            &mut SoftwareCrypto,
        )
        .unwrap();
        assert!(empty.is_none());
        let file = LoadFile::parse(image).unwrap();
        let mut card = Card::new(&file, sizes).unwrap();
        card.install(&file, &mut Host, &[0, 0, 0]).unwrap();
        store.commit(&card, &mut SoftwareCrypto).unwrap();
        let flash = store.into_flash();
        for (key, installation) in [([2; 16], [4; 16]), ([3; 16], [5; 16])] {
            assert!(Store::open(
                flash.clone(),
                key,
                image,
                installation,
                sizes,
                &mut SoftwareCrypto
            )
            .is_err());
        }
        // Authentication alone cannot authorize another image or snapshot contract.
        for (case, expected) in [
            (0, Error::KeyMismatch),
            (1, Error::IncompatibleState),
            (2, Error::IncompatibleState),
            (3, Error::Format),
        ] {
            let (mut journal, snapshot) = Journal::open(flash.clone(), [3; 16]).unwrap();
            let mut snapshot = snapshot.unwrap();
            match case {
                0 => snapshot[5] ^= 1, // image digest follows the fixed CBOR prefix
                1 => snapshot[1] = 2,  // schema version
                2 => snapshot[2] = 0,  // other engine
                _ => snapshot.push(0),
            }
            journal.commit(&snapshot).unwrap();
            assert!(
                matches!(Store::open(journal.into_flash(), [3; 16], image, [4; 16], sizes, &mut SoftwareCrypto), Err(error) if error == expected)
            );
        }

        let mut interrupted = flash;
        interrupted.fail_after = Some(0);
        let (mut store, recovered) = Store::open(
            interrupted,
            [3; 16],
            image,
            [4; 16],
            sizes,
            &mut SoftwareCrypto,
        )
        .unwrap();
        let mut recovered = recovered.unwrap();
        assert_eq!(
            recovered
                .process(&file, &mut Host, &[0, 0xa4, 4, 0, 0], true)
                .unwrap()
                .sw,
            0x9000
        );
        assert_eq!(
            store.commit(&recovered, &mut SoftwareCrypto),
            Err(Error::Storage)
        );
        let mut flash = store.into_flash();
        flash.fail_after = None;
        assert!(
            Store::open(flash, [3; 16], image, [4; 16], sizes, &mut SoftwareCrypto)
                .unwrap()
                .1
                .is_some()
        );
    }
}

impl<F: Flash> Store<F> {
    /// The flash region and key belong exclusively to this applet-state journal.
    /// A mismatch is an error, never permission to reinstall or erase storage.
    pub fn open(
        flash: F,
        key: impl Into<JournalKey>,
        verified_image: &[u8],
        installation: [u8; 16],
        sizes: Sizes,
        provider: &mut impl CryptoProvider,
    ) -> Result<(Self, Option<Card>)> {
        let maximum = flash.slot_size().checked_sub(35).ok_or(Error::Storage)?;
        let mut image = [0; 32];
        provider.sha256_into(verified_image, &mut image)?;
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        let (journal, snapshot) = Journal::open_with(flash, key, provider)?;
        let card = snapshot
            .as_ref()
            .map(|bytes| {
                let mut decoder = Decoder::new(bytes);
                decoder.record(7).map_err(|_| Error::IncompatibleState)?;
                if decoder.unsigned()? != 1 || decoder.unsigned()? != 1 {
                    return Err(Error::IncompatibleState);
                }
                if decoder.fixed::<32>()? != image || decoder.fixed::<16>()? != installation {
                    return Err(Error::KeyMismatch);
                }
                let instance = decoder.number()?;
                let heap = decoder.bytes(sizes.heap_bytes)?;
                let statics = decoder
                    .bytes(file.static_fields().map_err(|_| Error::Format)?.image_size as usize)?;
                decoder.finish()?;
                Card::restore(
                    &file,
                    sizes,
                    PersistentState {
                        heap,
                        statics,
                        instance,
                    },
                )
                .map_err(|_| Error::Format)
            })
            .transpose()?;
        Ok((
            Self {
                journal,
                image,
                installation,
                maximum,
            },
            card,
        ))
    }

    /// Commit state of the applet installed from the image passed to `open`.
    /// The caller must roll back live mutations if this operation fails.
    pub fn commit(&mut self, card: &Card, provider: &mut impl CryptoProvider) -> Result<()> {
        if card.persistent_heap_bytes() > self.maximum {
            return Err(Error::Quota);
        }
        let mut heap = crate::crypto::zeroizing_buffer(card.persistent_heap_bytes())?;
        let state = card.save_into(&mut heap).map_err(|_| Error::Format)?;
        let mut encoder = Encoder::new(self.maximum);
        encoder.array(7)?;
        encoder.unsigned(1)?;
        encoder.unsigned(1)?;
        encoder.bytes(&self.image)?;
        encoder.bytes(&self.installation)?;
        encoder.unsigned(u64::from(state.instance))?;
        encoder.bytes(state.heap)?;
        encoder.bytes(state.statics)?;
        let snapshot = Zeroizing::new(encoder.finish());
        self.journal.commit_with(&snapshot, provider)
    }

    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
}
