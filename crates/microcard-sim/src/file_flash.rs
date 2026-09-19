//! File-backed flash geometry shared by both engine simulators.
use crate::private_open_options;
use microcard_core::{journal::Flash, Error, Result};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const MONOTONIC_BYTES: usize = 65536;
const IO_CHUNK_BYTES: usize = 4096;

pub(crate) type FileFlash = Region<65536, 16384, 64>;

pub(crate) struct Region<const SLOT: usize, const IMAGE: usize, const COUNT: usize> {
    pub(crate) dir: std::path::PathBuf,
}
impl<const SLOT: usize, const IMAGE: usize, const COUNT: usize> Region<SLOT, IMAGE, COUNT> {
    pub(crate) fn path(&self, s: usize) -> std::path::PathBuf {
        self.dir.join(format!("slot{s}.bin"))
    }

    pub(crate) fn monotonic_path(&self) -> std::path::PathBuf {
        self.dir.join("monotonic.bin")
    }

    fn write_erased(file: &mut fs::File, mut remaining: usize) -> Result<()> {
        let erased = [0xff; IO_CHUNK_BYTES];
        while remaining != 0 {
            let length = remaining.min(erased.len());
            file.write_all(&erased[..length])
                .map_err(|_| Error::Storage)?;
            remaining -= length;
        }
        Ok(())
    }

    pub(crate) fn initialize(&mut self) -> Result<()> {
        let slot0 = self.path(0).exists();
        let slot1 = self.path(1).exists();
        let monotonic = self.monotonic_path().exists();
        let nonces = self.dir.join("nonces.bin").exists();
        if !slot0 && !slot1 && !monotonic && !nonces {
            if (0..COUNT).any(|index| self.dir.join(format!("image{index}.bin")).exists()) {
                return Err(Error::IncompatibleState);
            }
            self.erase(0)?;
            self.erase(1)?;
            let mut file = private_open_options()
                .create_new(true)
                .open(self.monotonic_path())
                .map_err(|_| Error::Storage)?;
            Self::write_erased(&mut file, MONOTONIC_BYTES)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            Self::erase_file(&self.dir.join("nonces.bin"), MONOTONIC_BYTES)?;
            return Ok(());
        }
        if slot0 && slot1 && monotonic && !nonces {
            return Err(Error::IncompatibleState);
        }
        if slot0 && slot1 && monotonic && nonces {
            return Ok(());
        }
        Err(Error::Storage)
    }

    pub(crate) fn require_existing(&self) -> Result<()> {
        for (path, size) in [
            (self.path(0), SLOT),
            (self.path(1), SLOT),
            (self.monotonic_path(), MONOTONIC_BYTES),
            (self.dir.join("nonces.bin"), MONOTONIC_BYTES),
        ] {
            if fs::metadata(path).map_err(|_| Error::Storage)?.len() != size as u64 {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }

    /// Explicitly reclaim an unreferenced heap. Its new key must precede reuse.
    pub(crate) fn prepare_heap(&mut self) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(|_| Error::Storage)?;
        self.erase(0)?;
        self.erase(1)?;
        Self::erase_file(&self.monotonic_path(), MONOTONIC_BYTES)?;
        Self::erase_file(&self.dir.join("nonces.bin"), MONOTONIC_BYTES)
    }
}
impl<const SLOT: usize, const IMAGE: usize, const COUNT: usize> Region<SLOT, IMAGE, COUNT> {
    pub(crate) fn erase_file(path: &Path, size: usize) -> Result<()> {
        let mut f = private_open_options()
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        Self::write_erased(&mut f, size)?;
        f.sync_all().map_err(|_| Error::Storage)?;
        #[cfg(unix)]
        fs::File::open(path.parent().ok_or(Error::Storage)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::Storage)?;
        Ok(())
    }
    fn program_file(path: &Path, size: usize, o: usize, b: &[u8]) -> Result<()> {
        let end = o.checked_add(b.len()).ok_or(Error::Bounds)?;
        if end > size {
            return Err(Error::Bounds);
        }
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        if f.metadata().map_err(|_| Error::Storage)?.len() != size as u64 {
            return Err(Error::Storage);
        }
        f.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        let mut old = [0; IO_CHUNK_BYTES];
        for chunk in b.chunks(old.len()) {
            f.read_exact(&mut old[..chunk.len()])
                .map_err(|_| Error::Storage)?;
            if old[..chunk.len()]
                .iter()
                .zip(chunk)
                .any(|(previous, next)| previous & next != *next)
            {
                return Err(Error::Storage);
            }
        }
        f.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        f.write_all(b).map_err(|_| Error::Storage)?;
        f.sync_all().map_err(|_| Error::Storage)
    }
    pub(crate) fn image_path(&self, index: usize) -> Result<std::path::PathBuf> {
        if index >= COUNT {
            return Err(Error::Bounds);
        }
        Ok(self.dir.join(format!("image{index}.bin")))
    }
}
impl<const SLOT: usize, const IMAGE: usize, const COUNT: usize>
    microcard_core::image_store::ImageFlash for Region<SLOT, IMAGE, COUNT>
{
    fn slot_count(&self) -> usize {
        COUNT
    }
    fn slot_size(&self) -> usize {
        IMAGE
    }
    fn with_slot<T>(&self, index: usize, read: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let mut file = fs::File::open(self.image_path(index)?).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != IMAGE as u64 {
            return Err(Error::Storage);
        }
        let mut bytes = vec![0; IMAGE];
        file.read_exact(&mut bytes).map_err(|_| Error::Storage)?;
        read(&bytes)
    }
    fn erase(&mut self, index: usize) -> Result<()> {
        Self::erase_file(&self.image_path(index)?, IMAGE)
    }
    fn program(&mut self, index: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        Self::program_file(&self.image_path(index)?, IMAGE, offset, bytes)
    }
}
impl<const SLOT: usize, const IMAGE: usize, const COUNT: usize> Region<SLOT, IMAGE, COUNT> {
    fn read_counter_file(path: &Path) -> Result<u64> {
        let mut file = fs::File::open(path).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != MONOTONIC_BYTES as u64 {
            return Err(Error::Storage);
        }
        let mut generation = 0u64;
        let mut saw_erased = false;
        let mut buffer = [0; 4096];
        for _ in 0..MONOTONIC_BYTES / buffer.len() {
            file.read_exact(&mut buffer).map_err(|_| Error::Storage)?;
            for word in buffer.chunks_exact(4) {
                let consumed = word.iter().any(|byte| *byte != 0xff);
                if consumed {
                    if saw_erased {
                        return Err(Error::Storage);
                    }
                    generation = generation.checked_add(1).ok_or(Error::Storage)?;
                } else {
                    saw_erased = true;
                }
            }
        }
        Ok(generation)
    }
    fn advance_counter_file(path: &Path, generation: u64) -> Result<()> {
        let index = generation.checked_sub(1).ok_or(Error::Storage)?;
        let offset = usize::try_from(index)
            .map_err(|_| Error::Storage)?
            .checked_mul(4)
            .ok_or(Error::Storage)?;
        if offset + 4 > MONOTONIC_BYTES {
            return Err(Error::Quota);
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| Error::Storage)?;
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| Error::Storage)?;
        let mut old = [0; 4];
        file.read_exact(&mut old).map_err(|_| Error::Storage)?;
        if old != [0xff; 4] {
            return Err(Error::Storage);
        }
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| Error::Storage)?;
        file.write_all(&[0; 4]).map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)
    }
}
impl<const SLOT: usize, const IMAGE: usize, const COUNT: usize> Flash
    for Region<SLOT, IMAGE, COUNT>
{
    fn slot_size(&self) -> usize {
        SLOT
    }
    fn monotonic_capacity(&self) -> u64 {
        (MONOTONIC_BYTES / 4) as u64
    }
    fn monotonic_generation(&self) -> Result<u64> {
        Self::read_counter_file(&self.monotonic_path())
    }
    fn advance_monotonic(&mut self, generation: u64) -> Result<()> {
        Self::advance_counter_file(&self.monotonic_path(), generation)
    }
    fn nonce_generation(&self) -> Result<u64> {
        Self::read_counter_file(&self.dir.join("nonces.bin"))
    }
    fn reserve_nonce(&mut self) -> Result<u64> {
        let next = self
            .nonce_generation()?
            .checked_add(1)
            .ok_or(Error::Quota)?;
        Self::advance_counter_file(&self.dir.join("nonces.bin"), next)?;
        Ok(next)
    }
    fn is_erased(&self, s: usize) -> Result<bool> {
        let mut file = fs::File::open(self.path(s)).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != self.slot_size() as u64 {
            return Err(Error::Storage);
        }
        let mut remaining = self.slot_size();
        let mut buffer = [0; IO_CHUNK_BYTES];
        while remaining != 0 {
            let length = remaining.min(buffer.len());
            file.read_exact(&mut buffer[..length])
                .map_err(|_| Error::Storage)?;
            if buffer[..length].iter().any(|byte| *byte != 0xff) {
                return Ok(false);
            }
            remaining -= length;
        }
        Ok(true)
    }
    fn read(&self, s: usize, o: usize, output: &mut [u8]) -> Result<()> {
        let end = o.checked_add(output.len()).ok_or(Error::Bounds)?;
        if end > self.slot_size() {
            return Err(Error::Bounds);
        }
        let mut file = fs::File::open(self.path(s)).map_err(|_| Error::Storage)?;
        if file.metadata().map_err(|_| Error::Storage)?.len() != self.slot_size() as u64 {
            return Err(Error::Storage);
        }
        file.seek(SeekFrom::Start(o as u64))
            .map_err(|_| Error::Storage)?;
        file.read_exact(output).map_err(|_| Error::Storage)
    }
    fn erase(&mut self, s: usize) -> Result<()> {
        Self::erase_file(&self.path(s), self.slot_size())
    }
    fn program(&mut self, s: usize, o: usize, b: &[u8]) -> Result<()> {
        Self::program_file(&self.path(s), self.slot_size(), o, b)
    }
}
