#![no_main]

use libfuzzer_sys::fuzz_target;
use microcard_core::{
    Error, Result,
    apdu::Command,
    domains::Card,
    hal::{Entropy, LogicalGpio},
    journal::MemoryFlash,
    package::{
        AssemblyEntry, Dependency, DependencyExport, Limits, Manifest, StorageDeclaration,
        VersionRange,
    },
};

const DOMAIN: &str = "fuzz";
const ASSEMBLY: &str = "Counter";
const AIDS: [&str; 8] = [
    "F04D430001",
    "F04D430002",
    "F04D430003",
    "F04D430010",
    "F04D430011",
    "F04D430012",
    "F04D430013",
    "F04D430108",
];

struct FuzzPlatform(u8);
impl microcard_core::crypto::CryptoProvider for FuzzPlatform {}
impl Entropy for FuzzPlatform {
    fn fill_entropy(&mut self, out: &mut [u8]) -> Result<()> {
        self.0 = self.0.wrapping_add(1);
        out.fill(self.0);
        Ok(())
    }
}
impl LogicalGpio for FuzzPlatform {
    fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
        Err(Error::Native)
    }
}

fn command(ins: u8, data: Vec<u8>) -> Command<'static> {
    Command {
        cla: 0x80,
        ins,
        p1: 0,
        p2: 0,
        data: data.into(),
        le: None,
    }
}

fn signed_package(manifest: &Manifest, image: &[u8], private: &[u8; 32]) -> Vec<u8> {
    let metadata = manifest.encode_cbor_unchecked().unwrap();
    let public = microcard_core::crypto::p256_public_key(private).unwrap();
    let mut raw = microcard_core::package::envelope::signing_prefix(
        &metadata,
        image.len(),
        &microcard_core::crypto::sha256(image),
        &public,
    )
    .unwrap();
    let signature = microcard_core::crypto::p256_ecdsa_sign_package(private, &raw).unwrap();
    raw.extend(signature);
    raw.extend(image);
    raw
}

fn management_names(first: &str, second: &str) -> Vec<u8> {
    let mut encoder = microcard_core::cbor::Encoder::new(134);
    encoder.array(3).unwrap();
    encoder.unsigned(1).unwrap();
    encoder.text(first).unwrap();
    encoder.text(second).unwrap();
    encoder.finish()
}

fn package(incarnation: [u8; 16]) -> Vec<u8> {
    let manifest = Manifest {
        domain: DOMAIN.into(),
        incarnation,
        assembly: ASSEMBLY.into(),
        assembly_version: [1, 0, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: vec![
            AssemblyEntry {
                aid: AIDS[0].into(),
                process: 1,
                install: Some(0),
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: AIDS[1].into(),
                process: 28,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: AIDS[2].into(),
                process: 29,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
        dependencies: Vec::new(),
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
    };
    let image = include_bytes!("../fixtures/counter.mca");
    let private = [0x53; 32]; // public, test-only seed
    signed_package(&manifest, image, &private)
}

fn core_package(incarnation: [u8; 16]) -> Vec<u8> {
    let manifest = Manifest {
        domain: "ISD".into(),
        incarnation,
        assembly: "mscorlib".into(),
        assembly_version: [0, 1, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 1,
            key: None,
        },
        entry_points: Vec::new(),
        dependencies: Vec::new(),
        capabilities: vec![53],
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    let image = include_bytes!("../fixtures/mscorlib.mca");
    let private = [0x11; 32];
    signed_package(&manifest, image, &private)
}

fn key_operations_package(incarnation: [u8; 16]) -> Vec<u8> {
    let manifest = Manifest {
        domain: DOMAIN.into(),
        incarnation,
        assembly: "KeyOperations".into(),
        assembly_version: [1, 0, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: vec![
            AssemblyEntry {
                aid: AIDS[3].into(),
                process: 1,
                install: Some(0),
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: AIDS[4].into(),
                process: 3,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: AIDS[5].into(),
                process: 4,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
            AssemblyEntry {
                aid: AIDS[6].into(),
                process: 5,
                install: None,
                uninstall: None,
                select: None,
                deselect: None,
            },
        ],
        dependencies: Vec::new(),
        capabilities: vec![
            2, 5, 7, 8, 11, 12, 13, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        ],
        storage: vec![
            StorageDeclaration {
                key: 10,
                kind: 1,
                max_bytes: 0,
            },
            StorageDeclaration {
                key: 20,
                kind: 2,
                max_bytes: 3,
            },
            StorageDeclaration {
                key: 21,
                kind: 2,
                max_bytes: 1,
            },
            StorageDeclaration {
                key: 30,
                kind: 1,
                max_bytes: 0,
            },
        ],
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    let image = include_bytes!("../fixtures/key_operations.mca");
    let private = [0x53; 32];
    signed_package(&manifest, image, &private)
}

fn provider_package(incarnation: [u8; 16], version: u32) -> Vec<u8> {
    let manifest = Manifest {
        domain: "ISD".into(),
        incarnation,
        assembly: "Kdf108".into(),
        assembly_version: [0, 1, 0, 0],
        version,
        export: DependencyExport {
            access: 1,
            key: None,
        },
        entry_points: Vec::new(),
        dependencies: Vec::new(),
        capabilities: vec![26],
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    let image = include_bytes!("../fixtures/kdf108.mca");
    let private = [0x11; 32];
    signed_package(&manifest, image, &private)
}

fn consumer_package(incarnation: [u8; 16]) -> Vec<u8> {
    let provider_key = microcard_core::crypto::signer_identity(
        &microcard_core::crypto::p256_public_key(&[0x11; 32]).unwrap(),
    );
    let manifest = Manifest {
        domain: DOMAIN.into(),
        incarnation,
        assembly: "Kdf108Consumer".into(),
        assembly_version: [0, 1, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: vec![AssemblyEntry {
            aid: AIDS[7].into(),
            process: 2,
            install: Some(0),
            uninstall: Some(1),
            select: None,
            deselect: None,
        }],
        dependencies: vec![Dependency {
            assembly: "Kdf108".into(),
            ranges: vec![VersionRange {
                min: Some([0, 1, 0, 0]),
                min_inclusive: true,
                max: Some([0, 1, 0, 0]),
                max_inclusive: true,
            }],
            package_version: 0,
            signer: Some(provider_key),
            digest: None,
            scope: 1,
        }],
        capabilities: vec![2, 11, 12, 13, 22, 23, 24],
        storage: Vec::new(),
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    let image = include_bytes!("../fixtures/kdf108_consumer.mca");
    let private = [0x53; 32];
    signed_package(&manifest, image, &private)
}

fn manage(card: &mut Card<MemoryFlash, FuzzPlatform>, ins: u8, data: Vec<u8>) -> Result<Vec<u8>> {
    card.manage_fuzz_authenticated(command(ins, data))
}

fn load(card: &mut Card<MemoryFlash, FuzzPlatform>, package: &[u8]) -> Result<()> {
    manage(card, 0xe6, Vec::new())?;
    for (index, chunk) in package.chunks(200).enumerate() {
        let mut data = ((index * 200) as u32).to_le_bytes().to_vec();
        data.extend(chunk);
        manage(card, 0xe8, data)?;
    }
    manage(card, 0xea, Vec::new()).map(|_| ())
}

fn create_domain(card: &mut Card<MemoryFlash, FuzzPlatform>) -> Result<()> {
    let inc: [u8; 16] = manage(card, 0xe0, DOMAIN.as_bytes().to_vec())?
        .try_into()
        .unwrap();
    load(card, &package(inc))?;
    load(card, &key_operations_package(inc))?;
    load(card, &consumer_package(inc))?;
    for aid in AIDS {
        manage(card, 0xec, management_names(DOMAIN, aid))?;
    }
    Ok(())
}

fn bootstrap(card: &mut Card<MemoryFlash, FuzzPlatform>) {
    let isd = manage(card, 0xe2, vec![0]).expect("query ISD");
    let incarnation_offset = 4 + usize::from(isd[3]);
    let isd_incarnation: [u8; 16] = isd[incarnation_offset..incarnation_offset + 16]
        .try_into()
        .unwrap();
    load(card, &core_package(isd_incarnation)).expect("load core");
    load(card, &provider_package(isd_incarnation, 1)).expect("load provider");
    create_domain(card).expect("create domain")
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    const STORAGE_KEY: [u8; 16] = [0x5a; 16];
    let mut card = Card::open(MemoryFlash::new(65536), FuzzPlatform(0), STORAGE_KEY).unwrap();
    bootstrap(&mut card);
    for chunk in data.chunks(5).take(64) {
        let op = chunk[0] % 12;
        let aid = AIDS[usize::from(*chunk.get(1).unwrap_or(&0)) % AIDS.len()];
        let mut args = [
            *chunk.get(2).unwrap_or(&0),
            *chunk.get(3).unwrap_or(&0),
            *chunk.get(4).unwrap_or(&0),
        ];
        if aid == AIDS[3] || aid == AIDS[5] {
            args[0] %= 6;
        }
        match op {
            0 => {
                let _ = card.invoke(aid, &args);
            }
            1 => {
                let _ = manage(&mut card, 0xee, management_names(DOMAIN, aid));
            }
            2 => {
                let _ = manage(&mut card, 0xec, management_names(DOMAIN, aid));
            }
            3 => {
                let _ = card.select(aid);
            }
            4 => {
                let _ = card.process(&args);
            }
            5 => {
                card = Card::open(card.into_flash(), FuzzPlatform(chunk[0]), STORAGE_KEY)
                    .expect("reopen");
            }
            6 => {
                let _ = manage(&mut card, 0xe2, vec![chunk[0] % 5]);
            }
            7 => {
                if manage(&mut card, 0xe4, DOMAIN.as_bytes().to_vec()).is_ok() {
                    create_domain(&mut card).unwrap();
                }
            }
            8 => {
                let mut flash = card.into_flash();
                flash.fail_after = Some(u16::from_le_bytes([args[0], args[1]]) as usize);
                let mut interrupted = Card::open(flash, FuzzPlatform(args[2]), STORAGE_KEY)
                    .expect("open before fault");
                let _ = interrupted.invoke(AIDS[0], &args);
                let mut flash = interrupted.into_flash();
                flash.fail_after = None;
                card = Card::open(flash, FuzzPlatform(args[2]), STORAGE_KEY)
                    .expect("recover after fault");
            }
            9 => {
                let _ = manage(&mut card, 0xe6, Vec::new());
                let mut staged = 0u32.to_le_bytes().to_vec();
                staged.extend(chunk);
                let _ = manage(&mut card, 0xe8, staged);
                let _ = manage(&mut card, 0xea, Vec::new());
            }
            10 => {
                let result = manage(&mut card, 0xf0, management_names("ISD", "Kdf108"));
                assert_eq!(result, Err(Error::Busy));
            }
            _ => {
                if manage(&mut card, 0xee, management_names(DOMAIN, AIDS[7])).is_ok() {
                    manage(&mut card, 0xf0, management_names(DOMAIN, "Kdf108Consumer")).unwrap();
                    manage(&mut card, 0xf0, management_names("ISD", "Kdf108")).unwrap();
                    let record = manage(&mut card, 0xe2, vec![0]).unwrap();
                    let offset = 4 + usize::from(record[3]);
                    let incarnation = record[offset..offset + 16].try_into().unwrap();
                    load(&mut card, &provider_package(incarnation, 2)).unwrap();
                    let record = manage(&mut card, 0xe2, vec![1]).unwrap();
                    let offset = 4 + usize::from(record[3]);
                    let incarnation = record[offset..offset + 16].try_into().unwrap();
                    load(&mut card, &consumer_package(incarnation)).unwrap();
                    let _ = manage(&mut card, 0xec, management_names(DOMAIN, AIDS[7]));
                }
            }
        }
    }
    let flash = card.into_flash();
    let _ = Card::open(flash, FuzzPlatform(0), STORAGE_KEY).expect("final state must recover");
});
