//! Dedicated applet-state journal. Code remains outside the mutable snapshot.
//! Callers authenticate the load file and supply a fresh installation identity.
use crate::{
    cbor::{Decoder, Encoder},
    crypto::CryptoProvider,
    journal::{Flash, Journal, JournalKey},
    Error, Result,
};
use alloc::vec::Vec;
use microcard_engine_jcvm::{
    applet::{Card, PersistentState, PersistentView, Sizes},
    cap::LoadFile,
};
use zeroize::Zeroizing;
mod patch;
mod session;
pub use session::Session;
mod banks;
pub(crate) use banks::heap_key;
pub use banks::{heap_root, HeapBanks};

pub struct Store<F: Flash> {
    journal: Journal<F>,
    image: [u8; 32],
    installation: [u8; 16],
    maximum: usize,
    heap_length: Option<usize>,
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
    fn authenticated_state_is_bound_to_installation_and_snapshot_contract() {
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
        let aid = file.applets().unwrap().iter().next().unwrap().aid;
        let parameters = crate::globalplatform::ApplicationInstall {
            load_aid: file.header().unwrap().package_aid,
            module_aid: aid,
            instance_aid: aid,
            privileges: &[0],
            parameters: &[],
        }
        .jcvm_parameters()
        .unwrap();
        card.install(&file, &mut Host, &parameters).unwrap();
        // Rebuild a real installed applet from bounded sanitized records. Windows
        // split object headers and native fields; recovery must accept the result.
        let view = card.persistent_view().unwrap();
        let mut replayed = alloc::vec![0xa5; view.heap_bytes()];
        let mut used = 0;
        let mut generation = 1;
        for start in (0..view.heap_bytes()).step_by(127) {
            let end = (start + 127).min(view.heap_bytes());
            let record = patch::encode_heap_window(view, start..end, used, generation, 192).unwrap();
            used = patch::apply(&record, generation, &mut replayed, used).unwrap();
            generation += 1;
        }
        let mut expected = alloc::vec![0; view.heap_bytes()];
        view.save_into(&mut expected).unwrap();
        assert_eq!(replayed, expected);
        let (instance, statics) = view.metadata();
        Card::restore(&file, sizes, PersistentState { heap: &replayed, statics, instance }).unwrap();
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
            let (mut journal, snapshot) = Journal::open_with_replay(flash.clone(), [3; 16], &mut SoftwareCrypto,
                |snapshot, generation, delta| patch::replay_snapshot(snapshot, generation, delta, 65536)).unwrap();
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
        let maximum = flash
            .slot_size()
            .checked_sub(crate::journal::OVERHEAD)
            .ok_or(Error::Storage)?;
        let mut image = [0; 32];
        provider.sha256_into(verified_image, &mut image)?;
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        let (journal, snapshot) = Journal::open_with_replay(flash, key, provider,
            |snapshot, generation, delta| patch::replay_snapshot(snapshot, generation, delta, maximum))?;
        let card = decode_card(
            snapshot.as_deref().map(Vec::as_slice),
            &file,
            sizes,
            image,
            installation,
        )?;
        Ok((
            Self {
                journal,
                image,
                installation,
                maximum,
                heap_length: card.as_ref().map(Card::persistent_heap_bytes),
            },
            card,
        ))
    }

    /// Rebuild volatile state from the newest authenticated committed record.
    pub fn recover(
        &mut self,
        verified_image: &[u8],
        sizes: Sizes,
        provider: &mut impl CryptoProvider,
    ) -> Result<Option<Card>> {
        let mut digest = [0; 32];
        provider.sha256_into(verified_image, &mut digest)?;
        if digest != self.image {
            return Err(Error::KeyMismatch);
        }
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        let snapshot = self.journal.recover_with_replay(provider,
            |snapshot, generation, delta| patch::replay_snapshot(snapshot, generation, delta, self.maximum))?;
        let card = decode_card(
            snapshot.as_deref().map(Vec::as_slice),
            &file,
            sizes,
            self.image,
            self.installation,
        )?;
        self.heap_length = card.as_ref().map(Card::persistent_heap_bytes);
        Ok(card)
    }

    /// Commit state of the applet installed from the image passed to `open`.
    /// The caller must roll back live mutations if this operation fails.
    pub fn commit(&mut self, card: &Card, provider: &mut impl CryptoProvider) -> Result<()> {
        self.commit_view(card.persistent_view().map_err(|_| Error::Format)?, provider)
    }

    pub(crate) fn commit_view(&mut self, view: PersistentView<'_>, provider: &mut impl CryptoProvider) -> Result<()> {
        let (instance, statics) = view.metadata();
        if snapshot_size(u64::from(instance), view.heap_bytes(), statics.len())? > self.maximum {
            return Err(Error::Quota);
        }
        if let Some(before_length) = self.heap_length {
            let capacity = match self.journal.append_capacity() {
                Ok(capacity) => capacity,
                Err(Error::Quota) => 0,
                Err(error) => return Err(error),
            };
            if capacity != 0 {
                match patch::encode_view(view, before_length, self.journal.generation(), capacity) {
                    Ok(delta) => {
                        self.journal.append_owned_with(delta, provider)?;
                        self.heap_length = Some(view.heap_bytes());
                        return Ok(());
                    }
                    Err(Error::Quota) => {},
                    Err(error) => return Err(error),
                }
            }
        }
        // The fixed fields and all CBOR headers fit in 80 bytes. Reserve once so
        // appending statics cannot double a buffer already holding the heap. Keep
        // journal header/tag headroom so encryption can consume this allocation.
        let capacity = view
            .heap_bytes()
            .checked_add(statics.len())
            .and_then(|length| length.checked_add(80 + crate::journal::OVERHEAD))
            .ok_or(Error::Quota)?;
        let mut encoder = Encoder::with_capacity(self.maximum, capacity)?;
        encoder.array(7)?;
        encoder.unsigned(1)?;
        encoder.unsigned(1)?;
        encoder.bytes(&self.image)?;
        encoder.bytes(&self.installation)?;
        encoder.unsigned(u64::from(instance))?;
        encoder.bytes_with(view.heap_bytes(), |output| {
            view.save_into(output)
                .map(|_| ())
                .map_err(|_| Error::Format)
        })?;
        encoder.bytes(statics)?;
        let snapshot = Zeroizing::new(encoder.finish());
        self.journal.commit_owned_with(snapshot, provider)?;
        self.heap_length = Some(view.heap_bytes());
        Ok(())
    }

    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
}

fn snapshot_size(instance: u64, heap: usize, statics: usize) -> Result<usize> {
    // Array/version/engine plus the fixed image and installation byte strings.
    [crate::cbor::argument_size(instance), crate::cbor::argument_size(heap as u64), heap,
        crate::cbor::argument_size(statics as u64), statics]
        .into_iter().try_fold(54usize, |size, part| size.checked_add(part).ok_or(Error::Quota))
}

pub(crate) fn validate_seed_snapshot(snapshot: &[u8], file: &LoadFile, sizes: Sizes,
        image: [u8; 32], installation: [u8; 16]) -> Result<()> {
    decode_card(Some(snapshot), file, sizes, image, installation)?.ok_or(Error::Storage)?;
    Ok(())
}

fn decode_card(
    snapshot: Option<&[u8]>,
    file: &LoadFile,
    sizes: Sizes,
    image: [u8; 32],
    installation: [u8; 16],
) -> Result<Option<Card>> {
    snapshot
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
                file,
                sizes,
                PersistentState {
                    heap,
                    statics,
                    instance,
                },
            )
            .map_err(|_| Error::Format)
        })
        .transpose()
}
