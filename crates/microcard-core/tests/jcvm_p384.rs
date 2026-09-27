#![cfg(all(feature = "jcvm", feature = "software-p384"))]

use microcard_core::{crypto::CryptoProvider, hal::Entropy, jcvm_services::Services};
use microcard_engine_jcvm::{Error, host::Host};

struct Provider;
impl CryptoProvider for Provider {}
impl Entropy for Provider {
    fn fill_entropy(&mut self, output: &mut [u8]) -> microcard_core::Result<()> {
        output.fill(0);
        *output.last_mut().unwrap() = 1;
        Ok(())
    }
}

#[test]
fn p384_real_keygen_import_sign_verify_and_agreement() {
    let mut provider = Provider;
    let mut host = Services::new(&mut provider);
    assert!(host.p384_parameter(0).is_some());
    assert!(host.supports_signature(34));
    assert!(host.supports_agreement(3));
    let mut private = [0xaa; 48];
    let mut public = [0xaa; 97];
    Host::p384_generate(&mut host, &mut private, &mut public).unwrap();
    assert_eq!(private[47], 1);
    assert_eq!(&private[..47], &[0; 47]);
    assert_eq!(public, host.p384_parameter(3).unwrap());
    assert_eq!(host.p384_key_valid(true, &private), Ok(true));
    assert_eq!(host.p384_key_valid(false, &public), Ok(true));
    let mut off_curve = public;
    off_curve[96] ^= 1;
    assert_eq!(host.p384_key_valid(false, &off_curve), Ok(false));
    let mut shared = [0xaa; 48];
    Host::p384_agree(&mut host, &private, &public, &mut shared).unwrap();
    assert_eq!(&shared, &public[1..49]);
    assert_eq!(Host::p384_agree(&mut host, &private, &off_curve, &mut shared), Err(Error::Bounds));
    assert_eq!(shared, [0; 48]);
    let digest = [0x42; 48];
    let mut signature = [0xaa; 104];
    let size = Host::p384_sign_hash(&mut host, &private, &digest, &mut signature).unwrap();
    assert!((8..=104).contains(&size));
    assert_eq!(Host::p384_verify_hash(&mut host, &public, &digest, &signature[..size]), Ok(true));
    assert_eq!(Host::p384_verify_hash(&mut host, &public, &[0x43; 48], &signature[..size]), Ok(false));
    assert_eq!(Host::p384_verify_hash(&mut host, &public, &digest, &signature[..size - 1]), Ok(false));
    let zero = [0; 48];
    assert_eq!(Host::p384_sign_hash(&mut host, &zero, &digest, &mut signature), Err(Error::Bounds));
    assert_eq!(signature, [0; 104]);
}
