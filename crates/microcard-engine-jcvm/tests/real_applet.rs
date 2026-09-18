//! Install and drive a real applet, to see how far the engine gets.
//!
//! This is the test the whole engine exists to pass. It needs a Load File Data Block, which
//! is a third-party build output and stays out of this repository, so it reports that it
//! found nothing when `MICROCARD_JCVM_LOAD_FILES` is unset.
use microcard_engine_jcvm::applet::{Card, Sizes};
use microcard_engine_jcvm::cap::LoadFile;

fn load_files() -> Vec<(String, Vec<u8>)> {
    let Ok(directory) = std::env::var("MICROCARD_JCVM_LOAD_FILES") else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&directory).expect("load file directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|extension| extension != "lfdb") {
            continue;
        }
        files.push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            std::fs::read(&path).expect("load file"),
        ));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[test]
fn the_real_applet_installs_and_answers_a_select() {
    let files = load_files();
    if files.is_empty() {
        eprintln!("MICROCARD_JCVM_LOAD_FILES is unset, so no real applet was run");
        return;
    }
    for (name, bytes) in &files {
        let file = LoadFile::parse(bytes).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let mut card = Card::new(&file, Sizes::default())
            .unwrap_or_else(|error| panic!("{name}: sizes {error:?}"));
        // The parameters GlobalPlatform hands install: an instance AID, privileges and
        // applet data, each length prefixed.
        let parameters = [0u8, 0, 0];
        match card.install(&file, &parameters) {
            Ok(()) => {}
            Err(error) => panic!("{name}: install {error:?}"),
        }
        let response = card
            .process(&file, &[0x00, 0xa4, 0x04, 0x00, 0x00], true)
            .unwrap_or_else(|error| panic!("{name}: select {error:?}"));
        assert_eq!(response.sw, 0x9000, "{name}");
    }
}
