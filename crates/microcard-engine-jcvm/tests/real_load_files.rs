//! Parse Load File Data Blocks produced from real CAP files.
//!
//! The synthetic cases in the crate pin each rejection. This pins the opposite direction,
//! that a package a real converter emits is accepted, which a hand-built fixture cannot
//! prove. CAP files are third-party build outputs and stay out of this repository, so the
//! blocks are supplied through `MICROCARD_JCVM_LOAD_FILES` and the test reports that it
//! found nothing when the variable is unset.
//!
//! Produce the blocks with `scripts/jcvm_cap_inventory.py <cap directory> --load-file <out>`.
use microcard_engine_jcvm::cap::{LoadFile, Tag};

#[test]
fn every_supplied_load_file_parses_as_a_supported_package() {
    let Ok(directory) = std::env::var("MICROCARD_JCVM_LOAD_FILES") else {
        eprintln!("MICROCARD_JCVM_LOAD_FILES is unset, so no real package was parsed");
        return;
    };
    let mut parsed = 0;
    for entry in std::fs::read_dir(&directory).expect("load file directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().is_none_or(|extension| extension != "lfdb") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("load file");
        let file = LoadFile::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        let header = file.header().expect("header");
        header
            .supported()
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        // What the profile says every target variant carries.
        assert_eq!((header.cap_major, header.cap_minor), (2, 1));
        assert_eq!(header.package_aid.len(), 9);
        let directory = file.directory().expect("directory");
        assert_eq!(directory.applet_count, 1);
        assert_eq!(directory.import_count, 6);
        assert!(file.component(Tag::Method).is_some());
        // Descriptor and Debug are excluded from a Load File Data Block, and their absence
        // is why the block is a third of the archive that carried it.
        assert!(file.component(Tag::Descriptor).is_none());
        assert!(file.component(Tag::Debug).is_none());
        parsed += 1;
    }
    assert!(parsed > 0, "no .lfdb file in {directory}");
}
