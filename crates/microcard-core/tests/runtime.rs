use microcard_core::{
    assembly::Assembly,
    journal::{Flash, Journal, MemoryFlash},
    *,
};

#[test]
fn short_apdu_cases() {
    for bytes in [
        &[0, 1, 2, 3][..],
        &[0, 1, 2, 3, 0],
        &[0, 1, 2, 3, 2, 4, 5],
        &[0, 1, 2, 3, 2, 4, 5, 0],
    ] {
        assert_eq!(
            apdu::Command::parse(bytes).unwrap().encode().unwrap(),
            bytes
        );
    }
    assert!(apdu::Command::parse(&[0, 1, 2, 3, 0, 1, 2]).is_err());
}

#[test]
fn nist_cmac_empty() {
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    assert_eq!(
        crypto::cmac(&key, &[]),
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ]
    );
}

#[test]
fn cbc_padding() {
    for length in 0..65 {
        let plain = vec![42; length];
        let encrypted = crypto::encrypt(&[3; 16], [4; 16], &plain).unwrap();
        assert_eq!(crypto::decrypt(&[3; 16], [4; 16], &encrypted), Ok(plain));
    }
}

#[test]
fn native_crypto_writes_bounded_outputs_and_clears_failed_plaintext() {
    let key = [3; 16];
    let iv = [4; 16];
    let mut encrypted = [0xcc; 48];
    let encrypted_len = crypto::encrypt_into(&key, iv, b"payload", &mut encrypted).unwrap();
    assert_eq!(encrypted_len, 16);
    assert_eq!(&encrypted[encrypted_len..], &[0xcc; 32]);

    let mut plaintext = [0xcc; 32];
    let plaintext_len =
        crypto::decrypt_into(&key, iv, &encrypted[..encrypted_len], &mut plaintext).unwrap();
    assert_eq!(&plaintext[..plaintext_len], b"payload");
    assert_eq!(&plaintext[encrypted_len..], &[0xcc; 16]);

    let padded_empty = crypto::encrypt(&key, iv, b"").unwrap();
    let mut wrong_iv = iv;
    wrong_iv[0] ^= 1;
    let mut rejected = [0xa5; 16];
    assert_eq!(
        crypto::decrypt_into(&key, wrong_iv, &padded_empty, &mut rejected),
        Err(Error::Authentication)
    );
    assert_eq!(rejected, [0; 16]);

    let nonce = [5; 13];
    let mut sealed = [0xcc; 40];
    let sealed_len =
        crypto::ccm_encrypt_into(&key, &nonce, b"aad", b"secret", &mut sealed).unwrap();
    assert_eq!(sealed_len, 22);
    assert_eq!(&sealed[sealed_len..], &[0xcc; 18]);
    sealed[sealed_len - 1] ^= 1;
    let mut opened = [0xa5; 16];
    assert_eq!(
        crypto::ccm_decrypt_into(&key, &nonce, b"aad", &sealed[..sealed_len], &mut opened),
        Err(Error::Authentication)
    );
    assert_eq!(&opened[..6], &[0; 6]);
    assert_eq!(&opened[6..], &[0xa5; 10]);
}

#[test]
fn every_journal_mutation_is_atomic() {
    const KEY: [u8; 16] = [0x33; 16];
    let (mut journal, _) = Journal::open(MemoryFlash::new(256), KEY).unwrap();
    journal.commit(b"old").unwrap();
    let base = journal.into_flash();
    for fail in 0..400 {
        let mut flash = base.clone();
        flash.fail_after = Some(fail);
        let (mut journal, _) = Journal::open(flash, KEY).unwrap();
        let result = journal.commit(b"new state");
        let mut flash = journal.into_flash();
        flash.fail_after = None;
        let (_, data) = Journal::open(flash, KEY).unwrap();
        assert!(
            data.as_ref().map(|value| value.as_slice()) == Some(b"old".as_slice())
                || data.as_ref().map(|value| value.as_slice()) == Some(b"new state".as_slice())
        );
        if result.is_ok() {
            assert_eq!(
                data.as_ref().map(|value| value.as_slice()),
                Some(b"new state".as_slice())
            );
        }
    }
}

#[test]
fn flash_rejects_zero_to_one() {
    let mut flash = MemoryFlash::new(64);
    flash.program(0, 0, &[0]).unwrap();
    assert_eq!(flash.program(0, 0, &[1]), Err(Error::Storage));
}

#[test]
fn ccm_authentication_and_aad() {
    let encrypted = crypto::ccm_encrypt(&[7; 16], &[3; 13], b"header", b"payload").unwrap();
    assert_eq!(
        crypto::ccm_decrypt(&[7; 16], &[3; 13], b"header", &encrypted).unwrap(),
        b"payload"
    );
    assert_eq!(
        crypto::ccm_decrypt(&[7; 16], &[3; 13], b"wrong", &encrypted),
        Err(Error::Authentication)
    );
    let mut bad = encrypted;
    bad[0] ^= 1;
    assert!(crypto::ccm_decrypt(&[7; 16], &[3; 13], b"header", &bad).is_err());
}

#[test]
fn malformed_input_smoke_fuzz() {
    let mut state = 0x4d435f46555a5au64;
    for length in 0..10_000 {
        let mut bytes = vec![0; length % 300];
        for value in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = state as u8;
        }
        let _ = apdu::Command::parse(&bytes);
        let _ = Assembly::parse(&bytes);
        let _ = package::Package::verify(&bytes);
        let mut session = scp03::Session::initiate(
            &scp03::Keys {
                enc: [1; 16],
                mac: [2; 16],
            },
            [0; scp03::CHALLENGE_BYTES],
            [1; scp03::CHALLENGE_BYTES],
        )
        .0;
        if let Ok(command) = apdu::Command::parse(&bytes) {
            let _ = session.authenticate(&command);
            let _ = session.unwrap(command);
        };
    }
}
