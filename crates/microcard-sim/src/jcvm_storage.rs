//! Persistent host regions for the authenticated JCVM transport.
use crate::{file_flash::Region, private_open_options, sim_hal::Hardware};
use microcard_core::{
    hal::Entropy,
    image_store::Images,
    jcvm_card::{Card, Storage},
    jcvm_registry::{Registry, Store},
    jcvm_storage::{heap_root, HeapBanks},
    scp03::Keys,
    staging::BoundedFlashStaging,
    transport::Endpoint,
    Error, Result,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const LAYOUT: &[u8] = b"MicroCard JCVM simulator v2\n";
type Metadata = Region<8192, 0, 0>;
type Code = Region<0, 65536, 2>;
type Heap = Region<65536, 0, 0>;
type Staging = BoundedFlashStaging<crate::file_flash::Staging, { microcard_core::jcvm_package::MAX_PACKAGE_BYTES }>;
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
        crate::file_flash::Staging::initialize(&root.join("staging.bin"))?;
    } else {
        metadata.require_existing()?;
        if !images.dir.is_dir() {
            return Err(Error::Storage);
        }
    }
    let staging = Staging::new(crate::file_flash::Staging::open(root.join("staging.bin"))?);
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
    let card = Card::open(storage, provider, staging, vec![0; 16384])?;
    Ok(Endpoint::new(card, keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use microcard_core::hal::StagingFlash;

    #[test]
    fn durable_staging_survives_reopen_and_incomplete_layouts_fail_without_repair() {
        let root = std::env::temp_dir().join(format!("microcard-jcvm-staging-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let keys = || Keys { enc: [3; 16], mac: [4; 16] };
        drop(open(keys(), &root).unwrap());
        let path = root.join("staging.bin");
        let mut staging = crate::file_flash::Staging::open(path.clone()).unwrap();
        staging.program(0, &[0x12, 0x34]).unwrap();
        staging.program(staging.capacity() - 1, &[0x56]).unwrap();
        assert_eq!(staging.program(0, &[0xff]), Err(Error::Storage));
        assert_eq!(staging.program(usize::MAX, &[1]), Err(Error::Bounds));
        drop(staging);
        drop(open(keys(), &root).unwrap());
        let staging = crate::file_flash::Staging::open(path.clone()).unwrap();
        let mut bytes = [0; 2];
        staging.read(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x12, 0x34]);
        staging.read(staging.capacity() - 1, &mut bytes[..1]).unwrap();
        assert_eq!(bytes[0], 0x56);
        assert_eq!(staging.read(staging.capacity(), &mut bytes), Err(Error::Bounds));
        drop(staging);

        fs::write(root.join("layout"), b"MicroCard JCVM simulator v1\n").unwrap();
        assert!(matches!(open(keys(), &root), Err(Error::IncompatibleState)));
        assert_eq!(&fs::read(&path).unwrap()[..2], &[0x12, 0x34]);
        fs::write(root.join("layout"), LAYOUT).unwrap();
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(17).unwrap();
        assert!(matches!(open(keys(), &root), Err(Error::Storage)));
        assert_eq!(fs::metadata(&path).unwrap().len(), 17);
        fs::remove_file(&path).unwrap();
        assert!(matches!(open(keys(), &root), Err(Error::Storage)));
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
