use microcard_core::crypto::ed25519_verify;
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn wycheproof_strict_ed25519() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("vectors/ed25519_test.json")).unwrap();
    let mut count = 0;
    for group in data["testGroups"].as_array().unwrap() {
        let key = hex(group["publicKey"]["pk"].as_str().unwrap());
        for case in group["tests"].as_array().unwrap() {
            let expected = match case["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("unreviewed vector classification {other}"),
            };
            assert_eq!(
                ed25519_verify(
                    &key,
                    &hex(case["sig"].as_str().unwrap()),
                    &hex(case["msg"].as_str().unwrap())
                ),
                expected,
                "Wycheproof tcId={} flags={} comment={}",
                case["tcId"],
                case["flags"],
                case["comment"]
            );
            count += 1;
        }
    }
    assert_eq!(count, data["numberOfTests"].as_u64().unwrap());
    assert_eq!(count, 151);
}

#[test]
fn malformed_lengths_and_weak_keys_rejected() {
    for n in [0, 1, 31, 33, 64] {
        assert!(!ed25519_verify(&vec![0; n], &[0; 64], b"message"));
    }
    // Identity/small-order keys must not authenticate arbitrary messages.
    for first in [0, 1] {
        let mut key = [0; 32];
        key[0] = first;
        let mut sig = [0; 64];
        sig[0] = 1;
        assert!(!ed25519_verify(&key, &sig, b"message"));
    }
}
