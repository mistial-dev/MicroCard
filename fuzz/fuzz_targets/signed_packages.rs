#![no_main]
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use microcard_core::{
    assembly::Assembly,
    mc04_vm,
    package::{Package, CONTEXT},
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let mut image = include_bytes!("../fixtures/counter.mca").to_vec();
    let mut meta = br#"{"domain":"fuzz","incarnation":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"assembly":"Counter","assembly_version":[1,0,0,0],"version":1,"export":{"access":0,"key":null},"entry_points":[{"aid":"F04D430001","process":1,"install":0,"uninstall":null,"select":null,"deselect":null},{"aid":"F04D430002","process":28,"install":null,"uninstall":null,"select":null,"deselect":null},{"aid":"F04D430003","process":29,"install":null,"uninstall":null,"select":null,"deselect":null},{"aid":"F04D430004","process":30,"install":null,"uninstall":null,"select":null,"deselect":null}],"dependencies":[],"capabilities":[2,7,8,9,11,12,13,20],"storage":[{"key":1,"kind":1,"max_bytes":0}],"limits":{"arena":16384,"stack":256,"frames":32,"instructions":100000}}"#.to_vec();
    match data[0] % 4 {
        0 => {}
        1 => {
            image = data[1..].to_vec();
        }
        2 => {
            if data.len() > 1 {
                let index = usize::from(data[1]) % image.len();
                image[index] ^= data.last().copied().unwrap_or(1) | 1;
            }
        }
        _ => meta = data[1..].to_vec(),
    }
    // Public test-only key, used solely to reach validation behind the signature gate.
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let mut raw = b"MP03".to_vec();
    raw.extend(CONTEXT);
    raw.extend((meta.len() as u32).to_le_bytes());
    raw.extend((image.len() as u32).to_le_bytes());
    raw.extend(&meta);
    raw.extend(&image);
    raw.extend(key.verifying_key().to_bytes());
    let signature = key.sign(&raw).to_bytes();
    raw.extend(signature);
    if let Ok(package) = Package::verify(&raw) {
        let assembly = Assembly::parse(package.image()).expect("verified assembly must parse");
        for entry in &package.manifest.entry_points {
            let _ = mc04_vm::execute(&assembly, entry.process, &[]);
        }
    }
});
