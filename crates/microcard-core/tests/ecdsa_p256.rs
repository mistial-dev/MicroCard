//! Wycheproof ECDSA verification, and the stricter shape a signed package must have.
use microcard_core::crypto::{p256_ecdsa_verify, p256_signature_acceptable};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn wycheproof_p256_ecdsa_sha256() {
    let raw = include_str!("vectors/ecdsa_secp256r1_sha256_p1363_test.json");
    let suite: serde_json::Value = serde_json::from_str(raw).unwrap();
    let expected = suite["numberOfTests"].as_u64().unwrap() as usize;
    let mut count = 0;
    for group in suite["testGroups"].as_array().unwrap() {
        let key = hex(group["publicKey"]["uncompressed"].as_str().unwrap());
        for case in group["tests"].as_array().unwrap() {
            let message = hex(case["msg"].as_str().unwrap());
            let signature = hex(case["sig"].as_str().unwrap());
            let result = case["result"].as_str().unwrap();
            // Every case is classified. An unknown classification fails rather than passing
            // quietly, which is how the vectors this replaced were read too.
            let valid = match result {
                "valid" => true,
                "invalid" => false,
                other => panic!("unknown classification {other}"),
            };
            assert_eq!(
                p256_ecdsa_verify(&key, &message, &signature),
                valid,
                "tcId {} {}",
                case["tcId"],
                case["comment"].as_str().unwrap_or("")
            );
            count += 1;
        }
    }
    assert_eq!(count, expected);
}

#[test]
fn a_package_refuses_signatures_the_primitive_accepts() {
    // Plain ECDSA admits two signatures for every message and Wycheproof classifies both as
    // valid. A package may carry only the low one, so that a signed package has one encoding,
    // therefore one digest, and therefore one registry identity. Find the high ones by their
    // arithmetic rather than by a label, and require every one to be refused.
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    let raw = include_str!("vectors/ecdsa_secp256r1_sha256_p1363_test.json");
    let suite: serde_json::Value = serde_json::from_str(raw).unwrap();
    let mut high = 0;
    for group in suite["testGroups"].as_array().unwrap() {
        let key = hex(group["publicKey"]["uncompressed"].as_str().unwrap());
        for case in group["tests"].as_array().unwrap() {
            if case["result"].as_str() != Some("valid") {
                continue;
            }
            let signature = hex(case["sig"].as_str().unwrap());
            if signature.len() != 64 || signature[32..] <= HALF_ORDER[..] {
                continue;
            }
            // The primitive accepts it, which is exactly why the package check must not.
            assert!(p256_ecdsa_verify(&key, &hex(case["msg"].as_str().unwrap()), &signature));
            assert!(
                !p256_signature_acceptable(&key, &signature),
                "tcId {} was accepted for a package",
                case["tcId"]
            );
            high += 1;
        }
    }
    assert!(high > 0, "the corpus carries no high signatures to reject");
}

#[test]
fn a_compressed_key_is_refused_for_a_package() {
    let raw = include_str!("vectors/ecdsa_secp256r1_sha256_p1363_test.json");
    let suite: serde_json::Value = serde_json::from_str(raw).unwrap();
    let group = &suite["testGroups"][0];
    let key = hex(group["publicKey"]["uncompressed"].as_str().unwrap());
    let signature = hex(group["tests"][0]["sig"].as_str().unwrap());
    let mut compressed = alloc_compressed(&key);
    assert_eq!(compressed.len(), 33);
    assert!(!p256_signature_acceptable(&compressed, &signature));
    compressed[0] = 0x04;
    assert!(!p256_signature_acceptable(&compressed, &signature));
}

fn alloc_compressed(uncompressed: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02 | (uncompressed[64] & 1); 33];
    out[1..].copy_from_slice(&uncompressed[1..33]);
    out
}
