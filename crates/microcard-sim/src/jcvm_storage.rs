//! Persistent host regions for the authenticated JCVM transport.
use crate::{file_flash::Region, private_open_options, sim_hal::Hardware};
use microcard_core::{
    hal::Entropy,
    image_store::Images,
    jcvm_card::{Card, Storage},
    jcvm_registry::{Registry, Store},
    jcvm_storage::{heap_root, HeapBanks},
    scp03::Keys,
    staging::BoundedRamStaging,
    transport::Endpoint,
    Error, Result,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const LAYOUT: &[u8] = b"MicroCard JCVM simulator v1\n";
type Metadata = Region<8192, 0, 0>;
type Code = Region<0, 65536, 2>;
type Heap = Region<65536, 0, 0>;
type Staging = BoundedRamStaging<{ microcard_core::jcvm_package::MAX_PACKAGE_BYTES }>;
pub(crate) type ManagedCard = Card<Metadata, Code, Heaps, Hardware, Staging>;

pub(crate) struct Heaps {
    root: PathBuf,
}
impl Heaps {
    fn region(&self, bank: u8) -> Result<Heap> {
        if usize::from(bank) >= self.bank_count() {
            return Err(Error::Bounds);
        }
        Ok(Heap {
            dir: self.root.join(format!("heap{bank}")),
        })
    }
}
impl HeapBanks for Heaps {
    type Bank = Heap;
    fn bank_count(&self) -> usize {
        2
    }
    fn open(&mut self, bank: u8) -> Result<Heap> {
        let heap = self.region(bank)?;
        heap.require_existing()?;
        Ok(heap)
    }
    fn prepare(&mut self, bank: u8) -> Result<Heap> {
        let mut heap = self.region(bank)?;
        heap.prepare_heap()?;
        sync_directory(&self.root)?;
        Ok(heap)
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error::Storage)?;
    let _ = path;
    Ok(())
}

pub(crate) fn open(keys: Keys, root: &Path) -> Result<Endpoint<ManagedCard>> {
    fs::create_dir_all(root).map_err(|_| Error::Storage)?;
    let marker = root.join("layout");
    let fresh = !marker.exists();
    if fresh {
        if fs::read_dir(root)
            .map_err(|_| Error::Storage)?
            .any(|entry| entry.map_or(true, |entry| entry.file_name() != ".lock"))
        {
            return Err(Error::IncompatibleState);
        }
        let mut file = private_open_options()
            .create_new(true)
            .open(&marker)
            .map_err(|_| Error::Storage)?;
        file.write_all(LAYOUT)
            .and_then(|()| file.sync_all())
            .map_err(|_| Error::Storage)?;
    } else if fs::read(&marker).map_err(|_| Error::Storage)? != LAYOUT {
        return Err(Error::IncompatibleState);
    }
    let mut metadata = Metadata {
        dir: root.join("registry"),
    };
    let images = Code {
        dir: root.join("images"),
    };
    if fresh {
        fs::create_dir(&metadata.dir).map_err(|_| Error::Storage)?;
        fs::create_dir(&images.dir).map_err(|_| Error::Storage)?;
        sync_directory(root)?;
        metadata.initialize()?;
    } else {
        metadata.require_existing()?;
        if !images.dir.is_dir() {
            return Err(Error::Storage);
        }
    }
    let mut provider = Hardware;
    let key = keys.storage_key_with(&mut provider)?;
    let heap_key = heap_root(&mut provider, &key)?;
    let mut incarnation = [0; 16];
    provider.fill_entropy(&mut incarnation)?;
    let storage = Storage {
        registry: Store::open(
            metadata,
            key,
            Registry::new(incarnation, None),
            &mut provider,
        )?,
        images: Images::new(images)?,
        heaps: Heaps { root: root.into() },
        heap_key,
    };
    let card = Card::open(storage, provider, Staging::default(), vec![0; 16384])?;
    Ok(Endpoint::new(card, keys))
}
