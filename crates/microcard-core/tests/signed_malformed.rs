use ed25519_dalek::{Signer, SigningKey};
use microcard_core::assembly::Assembly;
use microcard_core::package::{
    AssemblyEntry, DependencyExport, Limits, Manifest, Package, StorageDeclaration, CONTEXT,
};

type Mutation = (&'static str, Box<dyn Fn(&mut [u8])>);

fn minimal() -> Vec<u8> {
    let valid = (1u64 << 0) | (1u64 << 2) | (1u64 << 6) | (1u64 << 32);
    let mut tables = vec![2, 0, 0, 0];
    tables.extend(valid.to_le_bytes());
    for _ in 0..4 {
        tables.extend(1u16.to_le_bytes());
    }
    tables.push(1);
    tables.extend([0, 1, 0, 0, 3, 0, 0, 0, 1, 1]);
    tables.extend([0, 0, 0, 0, 0, 0, 0x10, 0, 5, 1]);
    tables.extend([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    let code = [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a];
    let sections: [&[u8]; 4] = [&tables, b"\0M\0T\0Run\0A\0", &[0, 3, 0, 0, 1], &code];
    let header_size = 56usize;
    let file_size = header_size + sections.iter().map(|section| section.len()).sum::<usize>();
    let mut bytes = b"MC04".to_vec();
    bytes.extend([4, 0, 0, 0, 4, 2]);
    bytes.extend((header_size as u16).to_le_bytes());
    bytes.extend((file_size as u32).to_le_bytes());
    let mut offset = header_size;
    for (index, section) in sections.iter().enumerate() {
        bytes.extend([index as u8 + 1, 0]);
        bytes.extend((offset as u32).to_le_bytes());
        bytes.extend((section.len() as u32).to_le_bytes());
        offset += section.len();
    }
    for section in sections {
        bytes.extend(section);
    }
    bytes
}

fn section(image: &[u8], directory_offset: usize) -> usize {
    u32::from_le_bytes(
        image[directory_offset + 2..directory_offset + 6]
            .try_into()
            .unwrap(),
    ) as usize
}

fn signed(image: &[u8]) -> Vec<u8> {
    signed_with_storage(image, Vec::new())
}

fn signed_with_storage(image: &[u8], storage: Vec<StorageDeclaration>) -> Vec<u8> {
    let manifest = Manifest {
        domain: "test".into(),
        incarnation: [1; 16],
        assembly: "A".into(),
        assembly_version: [1, 0, 0, 0],
        version: 1,
        export: DependencyExport {
            access: 0,
            key: None,
        },
        entry_points: vec![AssemblyEntry {
            aid: "F04D430001".into(),
            process: 0,
            install: None,
            uninstall: None,
            select: None,
            deselect: None,
        }],
        dependencies: vec![],
        capabilities: vec![],
        storage,
        limits: Limits {
            arena: 16384,
            stack: 256,
            frames: 32,
            instructions: 100000,
        },
    };
    let metadata = serde_json::to_vec(&manifest).unwrap();
    signed_metadata(image, &metadata)
}

fn signed_metadata(image: &[u8], metadata: &[u8]) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let mut package = b"MP03".to_vec();
    package.extend(CONTEXT);
    package.extend((metadata.len() as u32).to_le_bytes());
    package.extend((image.len() as u32).to_le_bytes());
    package.extend_from_slice(metadata);
    package.extend(image);
    package.extend(key.verifying_key().to_bytes());
    let signature = key.sign(&package).to_bytes();
    package.extend(signature);
    package
}

#[test]
fn signed_persistent_schema_is_validated_before_activation() {
    let image = minimal();
    let valid = vec![
        StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
        StorageDeclaration { key: 2, kind: 2, max_bytes: 2048 },
    ];
    Package::verify(&signed_with_storage(&image, valid)).unwrap();
    for storage in [
        vec![StorageDeclaration { key: -1, kind: 1, max_bytes: 0 }],
        vec![StorageDeclaration { key: 1, kind: 0, max_bytes: 0 }],
        vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 1 }],
        vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 0 }],
        vec![StorageDeclaration { key: 1, kind: 2, max_bytes: 2049 }],
        vec![
            StorageDeclaration { key: 2, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
        ],
        vec![
            StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
            StorageDeclaration { key: 1, kind: 1, max_bytes: 0 },
        ],
    ] {
        assert!(matches!(
            Package::verify(&signed_with_storage(&image, storage)),
            Err(microcard_core::Error::Format)
        ));
    }
}

#[test]
fn persistent_schema_is_covered_by_the_package_signature() {
    let mut package = signed_with_storage(
        &minimal(),
        vec![StorageDeclaration { key: 1, kind: 1, max_bytes: 0 }],
    );
    let offset = package
        .windows(6)
        .position(|window| window == b"key\":1")
        .unwrap()
        + 5;
    package[offset] = b'2';
    assert!(matches!(
        Package::verify(&package),
        Err(microcard_core::Error::Signature)
    ));
}

#[test]
fn packages_without_persistent_schema_have_no_compatibility_path() {
    let image = minimal();
    let package = signed_with_storage(&image, Vec::new());
    let manifest_length = u32::from_le_bytes(package[32..36].try_into().unwrap()) as usize;
    let metadata = &package[40..40 + manifest_length];
    let marker = b",\"storage\":[]";
    let offset = metadata.windows(marker.len()).position(|window| window == marker).unwrap();
    let mut retired = metadata.to_vec();
    retired.drain(offset..offset + marker.len());
    assert!(matches!(
        Package::verify(&signed_metadata(&image, &retired)),
        Err(microcard_core::Error::Format)
    ));
}

fn byte(offset: usize, value: u8) -> impl Fn(&mut [u8]) {
    move |image| image[offset] = value
}

#[test]
fn valid_signatures_do_not_bypass_structural_verification() {
    let valid = minimal();
    Assembly::parse(&valid).unwrap();
    Package::verify(&signed(&valid)).unwrap();
    let tables = section(&valid, 16);
    let strings = section(&valid, 26);
    let blobs = section(&valid, 36);
    let code = section(&valid, 46);
    let cases: Vec<Mutation> = vec![
        ("magic", Box::new(byte(0, 0))),
        ("format major", Box::new(byte(4, 5))),
        ("format minor", Box::new(byte(5, 1))),
        ("header flags", Box::new(byte(6, 1))),
        ("section count", Box::new(byte(8, 3))),
        ("token width", Box::new(byte(9, 4))),
        ("header size", Box::new(byte(10, 0))),
        ("file size", Box::new(byte(12, 0))),
        ("section kind", Box::new(byte(16, 2))),
        ("section flags", Box::new(byte(17, 1))),
        ("section gap", Box::new(byte(18, 57))),
        ("section length", Box::new(byte(22, 0))),
        ("retired schema major", Box::new(byte(tables, 1))),
        ("unknown schema major", Box::new(byte(tables, 3))),
        ("schema minor", Box::new(byte(tables + 1, 1))),
        ("heap flags", Box::new(byte(tables + 2, 4))),
        ("table reserved", Box::new(byte(tables + 3, 1))),
        ("table mask", Box::new(byte(tables + 4, 0))),
        ("row count", Box::new(byte(tables + 16, 0))),
        ("string index", Box::new(byte(tables + 20, 0xff))),
        ("coded token", Box::new(byte(tables + 27, 5))),
        ("method flags", Box::new(byte(tables + 37, 0))),
        ("assembly flags", Box::new(byte(tables + 49, 1))),
        ("invalid UTF-8", Box::new(byte(strings + 6, 0xff))),
        ("empty signature", Box::new(byte(blobs + 1, 0))),
        ("unsupported signature", Box::new(byte(blobs + 4, 0x0a))),
        ("method reserved", Box::new(byte(code + 1, 1))),
        ("resource declaration", Box::new(byte(code + 10, 1))),
        ("unsupported opcode", Box::new(byte(code + 12, 1))),
    ];
    for (name, mutate) in cases {
        let mut image = valid.clone();
        mutate(&mut image);
        assert!(Package::verify(&signed(&image)).is_err(), "accepted {name}");
    }
}
