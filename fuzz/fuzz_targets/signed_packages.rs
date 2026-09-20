#![no_main]

use libfuzzer_sys::fuzz_target;
use microcard_core::{
    assembly::Assembly,
    mc04_vm,
    package::{AssemblyEntry, DependencyExport, Limits, Manifest, Package, StorageDeclaration},
};

fn manifest() -> Manifest {
    Manifest {
        domain: "fuzz".into(),
        incarnation: [1; 16],
        assembly: "Counter".into(),
        assembly_version: [1, 0, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: vec![
            AssemblyEntry {
                aid: "F04D430001".into(),
                process: 1,
                install: Some(0),
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430002".into(),
                process: 28,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430003".into(),
                process: 29,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: "F04D430004".into(),
                process: 30,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
        dependencies: vec![],
        capabilities: vec![2, 7, 8, 9, 11, 12, 13, 20],
        storage: vec![StorageDeclaration {
            key: 1,
            kind: 1,
            max_bytes: 0,
        }],
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let mut image = include_bytes!("../fixtures/counter.mca").to_vec();
    let mut metadata = manifest().encode_cbor_unchecked().unwrap();
    match data[0] % 4 {
        0 => {}
        1 => image = data[1..].to_vec(),
        2 => {
            if data.len() > 1 {
                let index = usize::from(data[1]) % image.len();
                image[index] ^= data.last().copied().unwrap_or(1) | 1;
            }
        }
        _ => metadata = data[1..].to_vec(),
    }
    // Public test-only key, used solely to reach validation behind the signature gate.
    let private = [0x42; 32];
    let public = microcard_core::crypto::p256_public_key(&private).unwrap();
    let mut raw = microcard_core::package::envelope::signing_prefix(
        &metadata,
        image.len(),
        &microcard_core::crypto::sha256(&image),
        &public,
    )
    .unwrap();
    let signature = microcard_core::crypto::p256_ecdsa_sign_package(&private, &raw).unwrap();
    raw.extend(signature);
    raw.extend(&image);
    if let Ok(package) = Package::verify(&raw) {
        let assembly = Assembly::parse(package.image()).expect("verified assembly must parse");
        for entry in &package.manifest.entry_points {
            let _ = mc04_vm::execute(&assembly, entry.process, &[]);
        }
    }
});
