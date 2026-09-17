use ed25519_dalek::{Signer, SigningKey};
use microcard_core::{
    package::{Package, CONTEXT},
    Error,
};

fn signed(image: &[u8]) -> Vec<u8> {
    let metadata = br#"{"domain":"test","incarnation":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"assembly":"Legacy","assembly_version":[1,0,0,0],"version":1,"export":{"access":0,"key":null},"entry_points":[],"dependencies":[],"capabilities":[],"storage":[],"limits":{"arena":16384,"stack":256,"frames":32,"instructions":100000}}"#;
    let key = SigningKey::from_bytes(&[0x41; 32]);
    let mut package = b"MP03".to_vec();
    package.extend(CONTEXT);
    package.extend((metadata.len() as u32).to_le_bytes());
    package.extend((image.len() as u32).to_le_bytes());
    package.extend(metadata);
    package.extend(image);
    package.extend(key.verifying_key().to_bytes());
    let signature = key.sign(&package).to_bytes();
    package.extend(signature);
    package
}

#[test]
fn signed_packages_accept_only_mc04_assemblies() {
    for image in [
        b"MC01\x01\0\0\0\0\x01\0\0\0\x14".as_slice(),
        b"MC02\x01\0\0\0\0\xff\x01\0\0\0\x14".as_slice(),
        b"MC03\x01\0\0\0\0\xff\0\x01\0\0\0\x14".as_slice(),
    ] {
        assert!(matches!(
            Package::verify(&signed(image)),
            Err(Error::Format)
        ));
    }
}
