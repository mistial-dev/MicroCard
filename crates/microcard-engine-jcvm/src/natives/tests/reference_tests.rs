use super::*;

#[test]
fn native_reference_walk_includes_private_state_handles() {
    let mut payload = [0u8; 12];
    payload[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    payload[10..12].copy_from_slice(&0x5678u16.to_be_bytes());
    for (id, pending) in [
        (ClassId::AESKey, false),
        (ClassId::MessageDigest, true),
        (ClassId::KeyPair, true),
        (ClassId::RSAPublicKey, true),
        (ClassId::OwnerPINxWithPredecrement, true),
    ] {
        let class = PACKAGES.iter().enumerate().find_map(|(package, api)| api.classes.iter()
            .find(|entry| entry.id == id).map(|entry| native_class(package, entry.token))).unwrap();
        let info = heap::Info { class, length: 6, kind: heap::KIND_OBJECT, owner: 1, clear_event: 0 };
        let mut references = vec![];
        visit_native_reference_offsets(info, payload.len(), |at| {
            references.push(u16::from_be_bytes([payload[at], payload[at + 1]]));
            Ok(())
        }).unwrap();
        assert_eq!(references, if pending { vec![0x1234, 0x5678] } else { vec![0x1234] });
        assert_eq!(visit_native_reference_offsets(info, 10, |_| Ok(())), Err(Error::Format));
    }
}
