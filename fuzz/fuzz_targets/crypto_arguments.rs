#![no_main]
use libfuzzer_sys::fuzz_target;
use microcard_core::crypto;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let mut aes_key = [0u8; 16];
    let mut iv = [0u8; 16];
    let mut nonce = [0u8; 13];
    for (index, byte) in data.iter().copied().enumerate() {
        aes_key[index % aes_key.len()] ^= byte;
        iv[index % iv.len()] = iv[index % iv.len()].wrapping_add(byte);
        nonce[index % nonce.len()] ^= byte.rotate_left((index % 8) as u32);
    }

    let split = data.len() / 2;
    let (aad, message) = data.split_at(split);
    let _ = crypto::sha256(data);
    let _ = crypto::hmac(data, message);
    let _ = crypto::cmac(&aes_key, data);

    let Ok(ciphertext) = crypto::encrypt(&aes_key, iv, data) else {
        return;
    };
    assert_eq!(crypto::decrypt(&aes_key, iv, &ciphertext).unwrap(), data);
    if !ciphertext.is_empty() {
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 1;
        let _ = crypto::decrypt(&aes_key, iv, &tampered);
    }

    let ciphertext = crypto::ccm_encrypt(&aes_key, &nonce, aad, message).unwrap();
    assert_eq!(
        crypto::ccm_decrypt(&aes_key, &nonce, aad, &ciphertext).unwrap(),
        message
    );
    if !ciphertext.is_empty() {
        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert!(crypto::ccm_decrypt(&aes_key, &nonce, aad, &tampered).is_err());
    }

    // Arbitrary bytes through the package shape check and the verifier behind it.
    let signature_len = data.len().min(64);
    let key_len = data.len().saturating_sub(signature_len).min(65);
    let candidate_key = &data[..key_len];
    let candidate_signature = &data[data.len().saturating_sub(signature_len)..];
    if crypto::p256_signature_acceptable(candidate_key, candidate_signature) {
        let _ = crypto::p256_ecdsa_verify(candidate_key, message, candidate_signature);
    }

    let private_key = crypto::sha256(data);
    if let Ok(public_key) = crypto::p256_public_key(&private_key) {
        let signature = crypto::p256_ecdsa_sign(&private_key, message).unwrap();
        assert!(crypto::p256_ecdsa_verify(
            &public_key,
            message,
            &signature
        ));
        assert_eq!(
            crypto::p256_ecdh(&private_key, &public_key).unwrap(),
            crypto::p256_ecdh(&private_key, &public_key).unwrap()
        );
    }
    let _ = crypto::p256_ecdsa_verify(data, message, data);
    let _ = crypto::p256_ecdh(&private_key, data);
});
