//! Dedicated applet-state journal. Code remains outside the mutable snapshot.
//! Callers authenticate the load file and supply a fresh installation identity.
use crate::{
    cbor::{Decoder, SliceEncoder},
    crypto::CryptoProvider,
    journal::{Flash, Journal, JournalKey},
    Error, Result,
};
use alloc::vec::Vec;
use microcard_engine_jcvm::{
    applet::{AppletInstance, PersistentState, PersistentView, Sizes},
    cap::LoadFile,
    host::CheckpointReason,
};
use zeroize::Zeroizing;
mod patch;
#[cfg(feature = "latency-trace")]
mod trace;
#[cfg(feature = "latency-trace")]
pub(crate) use trace::record_session_error;
#[cfg(feature = "latency-trace")]
pub(crate) use trace::renewal_phase;
mod session;
pub use session::Session;
mod banks;
pub(crate) use banks::heap_key;
pub use banks::{heap_root, HeapBanks};

pub struct Store<F: Flash> {
    journal: Journal<F>,
    snapshot_workspace: Zeroizing<Vec<u8>>,
    image: [u8; 32],
    installation: [u8; 16],
    maximum: usize,
    heap_length: Option<usize>,
    heap_header: Option<u8>,
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
    fn security_checkpoint_admission_counts_possible_pin_writes() {
        let image = include_bytes!(
            "../../microcard-engine-jcvm/tests/vectors/openfips201-standard-cs2.lfdb"
        );
        let (mut store, _) = Store::open(MemoryFlash::new(65536), [3; 16], image,
            [4; 16], Sizes::default(), &mut SoftwareCrypto).unwrap();
        store.journal.flash_mut().leave_nonce_reservations_for_test(1);
        assert_eq!(store.ensure_checkpoint_capacity(1), Ok(()));
        assert_eq!(store.ensure_checkpoint_capacity(2), Err(Error::Quota));
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
        let mut card = AppletInstance::new(&file, sizes).unwrap();
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
        let mut projected = alloc::vec![0; view.heap_bytes()];
        let mut cursor = view.cursor().unwrap();
        for (index, chunk) in projected.chunks_mut(127).enumerate() {
            cursor.save_range(index * 127, chunk).unwrap();
        }
        cursor.finish().unwrap();
        assert_eq!(projected, expected, "one heap walk must sanitize every split window");
        let (instance, statics) = view.metadata();
        AppletInstance::restore(&file, sizes, PersistentState { heap: &replayed, statics, instance }).unwrap();
        AppletInstance::validate_persistent(&file, sizes, PersistentState { heap: &replayed, statics, instance }).unwrap();
        assert_eq!(AppletInstance::validate_persistent(&file, Sizes { heap_bytes: replayed.len() - 1, ..sizes },
            PersistentState { heap: &replayed, statics, instance }), Err(microcard_engine_jcvm::Error::Bounds));
        let workspace = store.snapshot_workspace.as_ptr();
        assert!(store.snapshot_workspace.capacity() >= 65536);
        store.commit(&card, &mut SoftwareCrypto).unwrap();
        assert_eq!(store.snapshot_workspace.as_ptr(), workspace);
        let anchors = store.journal.flash_mut().monotonic_generation().unwrap();
        let attempts = store.journal.flash_mut().nonce_generation().unwrap();
        store.compact_view(card.persistent_view().unwrap(), &mut SoftwareCrypto).unwrap();
        assert_eq!(store.snapshot_workspace.as_ptr(), workspace);
        assert_eq!(store.journal.flash_mut().monotonic_generation().unwrap(), anchors);
        assert_eq!(store.journal.flash_mut().nonce_generation().unwrap(), attempts + 1);
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
    fn ensure_checkpoint_capacity(&self, count: u32) -> Result<()> {
        if self.journal.remaining_commits()? < u64::from(count) { return Err(Error::Quota); }
        Ok(())
    }

    /// The flash region and key belong exclusively to this applet-state journal.
    /// A mismatch is an error, never permission to reinstall or erase storage.
    pub fn open(
        flash: F,
        key: impl Into<JournalKey>,
        verified_image: &[u8],
        installation: [u8; 16],
        sizes: Sizes,
        provider: &mut impl CryptoProvider,
    ) -> Result<(Self, Option<AppletInstance>)> {
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(40);
        let (mut store, snapshot) = Self::open_snapshot(flash, key, verified_image, installation, provider)?;
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(41);
        let mut workspace = snapshot.unwrap_or_else(|| Zeroizing::new(Vec::new()));
        reserve_snapshot_workspace(&mut workspace, store.maximum)?;
        let card = decode_card((!workspace.is_empty()).then_some(workspace.as_slice()),
            &file, sizes, store.image, installation)?;
        workspace.fill(0);
        workspace.clear();
        store.snapshot_workspace = workspace;
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(42);
        store.heap_length = card.as_ref().map(AppletInstance::persistent_heap_bytes);
        store.heap_header = card.as_ref().map(|card| card.persistent_view()
            .and_then(PersistentView::heap_header).map_err(|_| Error::Format)).transpose()?;
        Ok((store, card))
    }

    fn open_snapshot(flash: F, key: impl Into<JournalKey>, verified_image: &[u8],
            installation: [u8; 16], provider: &mut impl CryptoProvider)
            -> Result<(Self, Option<Zeroizing<Vec<u8>>>)> {
        let maximum = flash.slot_size().checked_sub(crate::journal::OVERHEAD).ok_or(Error::Storage)?;
        let mut image = [0; 32];
        provider.sha256_into(verified_image, &mut image)?;
        let (journal, snapshot) = Journal::open_with_replay(flash, key, provider,
            |snapshot, generation, delta| patch::replay_snapshot(snapshot, generation, delta, maximum))?;
        Ok((Self { journal, snapshot_workspace: Zeroizing::new(Vec::new()),
            image, installation, maximum, heap_length: None, heap_header: None }, snapshot))
    }

    pub(crate) fn validate_journal(flash: F, key: impl Into<JournalKey>, verified_image: &[u8],
            installation: [u8; 16], sizes: Sizes, provider: &mut impl CryptoProvider) -> Result<()> {
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        let (store, snapshot) = Self::open_snapshot(flash, key, verified_image, installation, provider)?;
        validate_seed_snapshot(snapshot.as_ref().ok_or(Error::Storage)?, &file, sizes, store.image, installation)
    }

    /// Rebuild volatile state from the newest authenticated committed record.
    pub fn recover(
        &mut self,
        verified_image: &[u8],
        sizes: Sizes,
        provider: &mut impl CryptoProvider,
    ) -> Result<Option<AppletInstance>> {
        let mut digest = [0; 32];
        provider.sha256_into(verified_image, &mut digest)?;
        if digest != self.image {
            return Err(Error::KeyMismatch);
        }
        let file = LoadFile::parse(verified_image).map_err(|_| Error::Format)?;
        self.snapshot_workspace = Zeroizing::new(Vec::new());
        let snapshot = self.journal.recover_with_replay(provider,
            |snapshot, generation, delta| patch::replay_snapshot(snapshot, generation, delta, self.maximum))?;
        let mut workspace = snapshot.unwrap_or_else(|| Zeroizing::new(Vec::new()));
        reserve_snapshot_workspace(&mut workspace, self.maximum)?;
        let card = decode_card((!workspace.is_empty()).then_some(workspace.as_slice()),
            &file, sizes, self.image, self.installation)?;
        workspace.fill(0);
        workspace.clear();
        self.snapshot_workspace = workspace;
        self.heap_length = card.as_ref().map(AppletInstance::persistent_heap_bytes);
        self.heap_header = card.as_ref().map(|card| card.persistent_view()
            .and_then(PersistentView::heap_header).map_err(|_| Error::Format)).transpose()?;
        Ok(card)
    }

    /// Commit state of the applet installed from the image passed to `open`.
    /// The caller must roll back live mutations if this operation fails.
    pub fn commit(&mut self, card: &AppletInstance, provider: &mut impl CryptoProvider) -> Result<()> {
        self.commit_view(card.persistent_view().map_err(|_| Error::Format)?, CheckpointReason::Installation, provider)
    }

    pub(crate) fn commit_view(&mut self, view: PersistentView<'_>, reason: CheckpointReason,
        provider: &mut impl CryptoProvider) -> Result<()> {
        #[cfg(feature = "latency-trace")]
        trace::capture_view(view);
        let heap_header = view.heap_header().map_err(|_| Error::Format)?;
        if reason == CheckpointReason::ApduEnd {
            if let Some((length, header)) = self.heap_length.zip(self.heap_header) {
                if view.same_state_after_deletion_request(length, header).map_err(|_| Error::Format)? {
                    return Ok(());
                }
            }
        }
        let (instance, statics) = view.metadata();
        let required = snapshot_size(u64::from(instance), view.heap_bytes(), statics.len())?;
        #[cfg(feature = "latency-trace")]
        trace::capacity(required, self.maximum, view.heap_bytes());
        if required > self.maximum {
            return Err(Error::Quota);
        }
        if let Some(before_length) = self.heap_length {
            let capacity = match self.journal.append_capacity() {
                Ok(capacity) => capacity,
                Err(Error::Quota) => 0,
                Err(error) => return Err(error),
            };
            if capacity != 0 {
                let generation = self.journal.generation();
                match patch::view_size(view, before_length, generation, capacity) {
                    Ok(length) => {
                        #[cfg(feature = "latency-trace")]
                        trace::patch(length);
                        self.journal.append_encoded_with(length, reason.into(), provider, |output| {
                            patch::encode_view_into(view, before_length, generation, output)
                        })?;
                        #[cfg(feature = "latency-trace")]
                        trace::committed_patch();
                        self.heap_length = Some(view.heap_bytes());
                        self.heap_header = Some(heap_header);
                        return Ok(());
                    }
                    Err(Error::Quota) => {
                        #[cfg(feature = "latency-trace")]
                        trace::fallback(3);
                    },
                    Err(error) => return Err(error),
                }
            }
            #[cfg(feature = "latency-trace")]
            if capacity == 0 { trace::fallback(2); }
        }
        #[cfg(feature = "latency-trace")]
        if self.heap_length.is_none() { trace::fallback(1); }
        self.commit_snapshot(view, reason, provider)?;
        #[cfg(feature = "latency-trace")]
        trace::committed_snapshot();
        self.heap_length = Some(view.heap_bytes());
        self.heap_header = Some(heap_header);
        Ok(())
    }

    /// Reclaim append space while idle, preserving the current heap key and
    /// security anchor. A new snapshot attempt still reserves a fresh nonce.
    pub(crate) fn compact_view(&mut self, view: PersistentView<'_>,
        provider: &mut impl CryptoProvider) -> Result<()> {
        self.commit_snapshot(view, CheckpointReason::ApduEnd, provider)?;
        #[cfg(feature = "latency-trace")]
        trace::committed_snapshot();
        self.heap_length = Some(view.heap_bytes());
        self.heap_header = Some(view.heap_header().map_err(|_| Error::Format)?);
        Ok(())
    }

    fn commit_snapshot(&mut self, view: PersistentView<'_>, reason: CheckpointReason,
        provider: &mut impl CryptoProvider) -> Result<()> {
        encode_snapshot_into(view, self.image, self.installation, self.maximum,
            &mut self.snapshot_workspace)?;
        let snapshot = core::mem::replace(&mut self.snapshot_workspace,
            Zeroizing::new(Vec::new()));
        let mut record = self.journal.commit_reusing_with_reason(snapshot, reason, provider)?;
        record.fill(0);
        record.clear();
        self.snapshot_workspace = record;
        Ok(())
    }

    fn prepare_epoch_record(
        &self,
        view: PersistentView<'_>,
        installation: [u8; 16],
        key: JournalKey,
        provider: &mut impl CryptoProvider,
    ) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(43);
        let snapshot = encode_snapshot(view, self.image, installation, self.maximum)?;
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(44);
        let record = crate::journal::SeedRecord::seal_new_epoch(snapshot, key, provider)?;
        #[cfg(feature = "latency-trace")]
        trace::renewal_phase(45);
        Ok(record)
    }

    pub fn into_flash(self) -> F {
        self.journal.into_flash()
    }
}

fn encode_snapshot(view: PersistentView<'_>, image: [u8; 32], installation: [u8; 16],
        maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    reserve_snapshot_workspace(&mut output, maximum)?;
    encode_snapshot_into(view, image, installation, maximum, &mut output)?;
    Ok(output)
}

fn reserve_snapshot_workspace(output: &mut Zeroizing<Vec<u8>>, maximum: usize) -> Result<()> {
    // Journal recovery already allocates a full-slot plaintext buffer. Reuse it
    // without moving decrypted state to a second large allocation.
    if output.capacity() >= maximum { return Ok(()); }
    let capacity = maximum.checked_add(crate::journal::OVERHEAD).ok_or(Error::Quota)?;
    // A Vec reallocation could leave a freed copy of decrypted card state.
    let mut replacement = Zeroizing::new(Vec::new());
    replacement.try_reserve_exact(capacity).map_err(|_| Error::Quota)?;
    replacement.extend_from_slice(output);
    *output = replacement;
    Ok(())
}

fn encode_snapshot_into(view: PersistentView<'_>, image: [u8; 32], installation: [u8; 16],
        maximum: usize, output: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    let result = (|| {
        let (instance, statics) = view.metadata();
        let length = snapshot_size(u64::from(instance), view.heap_bytes(), statics.len())?;
        if length > maximum || output.capacity() < length + crate::journal::RECORD_OVERHEAD {
            return Err(Error::Quota);
        }
        output.resize(length, 0);
        let mut encoder = SliceEncoder::new(output);
        encoder.array(7)?;
        encoder.unsigned(1)?;
        encoder.unsigned(1)?;
        encoder.bytes_with(image.len(), |bytes| { bytes.copy_from_slice(&image); Ok(()) })?;
        encoder.bytes_with(installation.len(), |bytes| {
            bytes.copy_from_slice(&installation); Ok(())
        })?;
        encoder.unsigned(u64::from(instance))?;
        encoder.bytes_with(view.heap_bytes(), |bytes| {
            view.save_into(bytes).map(|_| ()).map_err(|_| Error::Format)
        })?;
        encoder.bytes_with(statics.len(), |bytes| { bytes.copy_from_slice(statics); Ok(()) })?;
        encoder.finish()
    })();
    if result.is_err() { output.fill(0); output.clear(); }
    result
}

fn snapshot_size(instance: u64, heap: usize, statics: usize) -> Result<usize> {
    // Array/version/engine plus the fixed image and installation byte strings.
    [crate::cbor::argument_size(instance), crate::cbor::argument_size(heap as u64), heap,
        crate::cbor::argument_size(statics as u64), statics]
        .into_iter().try_fold(54usize, |size, part| size.checked_add(part).ok_or(Error::Quota))
}

pub(crate) fn validate_seed_snapshot(snapshot: &[u8], file: &LoadFile, sizes: Sizes,
        image: [u8; 32], installation: [u8; 16]) -> Result<()> {
    let saved = decode_snapshot(snapshot, file, sizes, image, installation)?;
    AppletInstance::validate_persistent(file, sizes, saved).map_err(|_| Error::Format)
}

fn decode_card(snapshot: Option<&[u8]>, file: &LoadFile, sizes: Sizes,
        image: [u8; 32], installation: [u8; 16]) -> Result<Option<AppletInstance>> {
    snapshot.map(|bytes| {
        let saved = decode_snapshot(bytes, file, sizes, image, installation)?;
        let mut card = AppletInstance::restore_without_frames(file, sizes, saved).map_err(|_| Error::Format)?;
        card.restore_execution_frames().map_err(|_| Error::Quota)?;
        Ok(card)
    }).transpose()
}

fn decode_snapshot<'a>(bytes: &'a [u8], file: &LoadFile, sizes: Sizes,
        image: [u8; 32], installation: [u8; 16]) -> Result<PersistentState<'a>> {
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
    let statics = decoder.bytes(file.static_fields().map_err(|_| Error::Format)?.image_size as usize)?;
    decoder.finish()?;
    Ok(PersistentState { heap, statics, instance })
}
