//! Install and drive a real applet, to see how far the engine gets.
//!
//! The committed applet runs by default. An external corpus can extend that coverage.
use microcard_engine_jcvm::applet::{Card, Sizes, PersistentState};
use microcard_engine_jcvm::cap::LoadFile;
use microcard_engine_jcvm::host::Host;

/// A card whose randomness is a counter, so a run is reproducible.
///
/// A real card answers from its entropy source. What matters for this test is that the
/// applet gets bytes at all, and that two runs of the test produce the same ones.
struct TestHost(u8);

impl Host for TestHost {
    fn supports_digest(&self, algorithm: u8) -> bool { matches!(algorithm, 4 | 5) }
    fn supports_random(&self, algorithm: u8) -> bool { matches!(algorithm, 1 | 2) }
    fn digest(
        &mut self,
        algorithm: u8,
        message: &[u8],
        output: &mut [u8],
    ) -> microcard_engine_jcvm::Result<usize> {
        use sha2::Digest;
        // The algorithms this applet uses. Anything else is refused rather than answered
        // with something that looks like a digest.
        match algorithm {
            4 => {
                let digest = sha2::Sha256::digest(message);
                output[..32].copy_from_slice(&digest);
                Ok(32)
            }
            5 => {
                let digest = sha2::Sha384::digest(message);
                output[..48].copy_from_slice(&digest);
                Ok(48)
            }
            _ => Err(microcard_engine_jcvm::Error::Unsupported),
        }
    }

    fn random(&mut self, output: &mut [u8]) -> microcard_engine_jcvm::Result<()> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

fn load_files() -> Vec<(String, Vec<u8>)> {
    let Ok(directory) = std::env::var("MICROCARD_JCVM_LOAD_FILES") else {
        return vec![(String::from("openfips201-standard-cs2"), include_bytes!("vectors/openfips201-standard-cs2.lfdb").to_vec())];
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
fn the_real_applet_gets_as_far_as_the_engine_can_take_it() {
    let files = load_files();
    assert!(!files.is_empty(), "the requested applet corpus is empty");
    let mut selected = 0;
    for (name, bytes) in &files {
        let file = LoadFile::parse(bytes).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        // A real applet allocates a great deal at install, so this is the card it would
        // be given rather than the smallest one that works.
        let sizes = Sizes {
            heap_bytes: 64 * 1024,
            frame_words: 8192,
            ..Sizes::default()
        };
        let mut card = Card::new(&file, sizes)
            .unwrap_or_else(|error| panic!("{name}: sizes {error:?}"));
        // The parameters GlobalPlatform hands install: an instance AID, privileges and
        // applet data, each length prefixed.
        let aid = file.applets().unwrap().iter().next().unwrap().aid;
        let mut parameters = vec![aid.len() as u8];
        parameters.extend_from_slice(aid);
        parameters.extend_from_slice(&[1, 0, 0]);
        let mut host = TestHost(0);
        match card.install(&file, &mut host, &parameters) {
            Ok(()) => {
                let response = card
                    .process(&file, &mut host, &[0x00, 0xa4, 0x04, 0x00, 0x00], true)
                    .unwrap_or_else(|error| panic!("{name}: select {error:?}"));
                assert_eq!(response.sw, 0x9000, "{name}");
                eprintln!("{name}: installed, registered and selected");
                // A PIV GET DATA for the card capability container. What matters is that
                // the applet's own process method ran and chose the answer, whatever that
                // answer is.
                let get_data = [
                    0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x07,
                ];
                match card.process(&file, &mut host, &get_data, false) {
                    Ok(response) => eprintln!(
                        "{name}: GET DATA answered {:04x} with {} bytes",
                        response.sw,
                        response.data.len()
                    ),
                    Err(error) => eprintln!("{name}: GET DATA stopped at {error:?}"),
                }
                selected += 1;
                let wrong_pin = [0x00, 0x20, 0x00, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff];
                let before = card.process(&file, &mut host, &wrong_pin, false).unwrap();
                assert_eq!(before.sw & 0xfff0, 0x63c0);
                let mut bytes = vec![0; card.persistent_heap_bytes()];
                let saved = card.save_into(&mut bytes).unwrap();
                let instance = saved.instance;
                let statics = saved.statics.to_vec();
                drop(card);
                let mut recovered = Card::restore(&file, sizes, PersistentState { heap: &bytes, statics: &statics, instance })
                    .unwrap_or_else(|error| panic!("{name}: restore {error:?}"));
                assert_eq!(recovered.process(&file, &mut host, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x9000);
                let after = recovered.process(&file, &mut host, &wrong_pin, false).unwrap();
                assert_eq!(after.sw + 1, before.sw, "PIN retry count did not survive recovery");
            }
            // The engine runs the applet's own install bytecode until it reaches
            // something this build does not do yet. That is the remaining work, and the
            // test records where it stopped rather than calling the engine broken.
            Err(error) => eprintln!("{name}: install stopped at {error:?}"),
        }
    }
    // At least one real package has to get all the way through, or the engine has
    // regressed from where it was when this was written.
    assert!(selected > 0, "no package installed and selected");
}
