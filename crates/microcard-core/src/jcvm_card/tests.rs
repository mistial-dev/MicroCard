use super::*;
use crate::{
    crypto,
    jcvm_test::{signed, Heaps, Provider, Scratch},
    journal::MemoryFlash,
    scp03::{Keys, CHALLENGE_BYTES, CRYPTOGRAM_BITS, MAC_BYTES},
    staging::BoundedFlashStaging,
    transport::Endpoint,
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;
use microcard_engine_jcvm::cap::LoadFile;

type TestCard =
    Card<MemoryFlash, MemoryFlash, Heaps, Provider, BoundedFlashStaging<Scratch, MAX_PACKAGE_BYTES>>;

struct Host {
    key: [u8; 16],
    chain: [u8; 16],
}

impl Host {
    fn connect(endpoint: &mut Endpoint<TestCard>, level: u8) -> Self {
        let select = Command { cla: 0, ins: 0xa4, p1: 4, p2: 0,
            data: gp::ISD_AID.as_slice().into(), le: Some(256) };
        assert!(endpoint.exchange(&select.encode().unwrap()).ends_with(&[0x90, 0]));
        let challenge = [0x55; CHALLENGE_BYTES];
        let request = Command {
            cla: 0x80,
            ins: 0x50,
            p1: 0,
            p2: 0,
            data: challenge.as_slice().into(),
            le: None,
        };
        let response = endpoint.exchange(&request.encode().unwrap());
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
        let mut context = challenge.to_vec();
        context.extend_from_slice(&response[13..13 + CHALLENGE_BYTES]);
        let key = crypto::derive(&[2; 16], 6, 128, &context);
        let card = crypto::derive(&key, 0, CRYPTOGRAM_BITS, &context);
        assert_eq!(
            &response[13 + CHALLENGE_BYTES..13 + 2 * CHALLENGE_BYTES],
            &card[..CHALLENGE_BYTES]
        );
        let crypt = crypto::derive(&key, 1, CRYPTOGRAM_BITS, &context);
        let mut host = Self {
            key,
            chain: [0; 16],
        };
        assert_eq!(
            host.send(endpoint, 0x82, level, 0, &crypt[..CHALLENGE_BYTES]),
            [0x90, 0]
        );
        host
    }

    fn command(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let class = if ins == 0x20 { 0x04 } else { 0x84 };
        let header = [class, ins, p1, p2, (data.len() + MAC_BYTES) as u8];
        self.chain = crypto::cmac_parts(&self.key, &[&self.chain, &header, data]);
        let mut raw = header.to_vec();
        raw.extend_from_slice(data);
        raw.extend_from_slice(&self.chain[..MAC_BYTES]);
        raw
    }

    fn send(
        &mut self,
        endpoint: &mut Endpoint<TestCard>,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Vec<u8> {
        endpoint.exchange(&self.command(ins, p1, p2, data))
    }

    fn load(&mut self, endpoint: &mut Endpoint<TestCard>, raw: &[u8]) -> Vec<u8> {
        let mut data = vec![0xc4, 0x82];
        data.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        data.extend_from_slice(raw);
        let chunks = data.chunks(230);
        let count = chunks.len();
        assert!(count <= 256);
        let mut result = Vec::new();
        for (index, chunk) in chunks.enumerate() {
            result = self.send(
                endpoint,
                0xe8,
                if index + 1 == count { 0x80 } else { 0 },
                index as u8,
                chunk,
            );
            if index + 1 < count {
                assert_eq!(result, [0, 0x90, 0]);
            }
        }
        result
    }
}

fn lv(values: &[&[u8]]) -> Vec<u8> {
    let mut wire = Vec::new();
    for value in values {
        wire.push(value.len() as u8);
        wire.extend_from_slice(value);
    }
    wire
}

fn endpoint(storage: Storage<MemoryFlash, MemoryFlash, Heaps>) -> Endpoint<TestCard> {
    Endpoint::new(
        Card::open(
            storage,
            Provider,
            BoundedFlashStaging::new(Scratch(vec![0xff; MAX_PACKAGE_BYTES])),
            vec![0; 16384],
        )
        .unwrap(),
        Keys {
            enc: [1; 16],
            mac: [2; 16],
        },
    )
}

#[test]
fn authenticated_lifecycle_binds_load_requests_and_recovers_installed_applets() {
    let raw = signed(7, 1, 7);
    let package =
        crate::jcvm_package::Package::verify(&raw, &mut Provider, &mut [0; 16384]).unwrap();
    let file = LoadFile::parse(package.envelope.image).unwrap();
    let module = file.applets().unwrap().iter().next().unwrap().aid;
    let aid = [0xf0, 1, 2, 3, 4, 2];
    let install = lv(&[
        package.manifest.package,
        module,
        &aid,
        &[0],
        &[0xc9, 0],
        &[],
    ]);
    let load = |name: &[u8], hash: &[u8]| lv(&[name, &gp::ISD_AID, hash, &[], &[]]);
    let store = Store::open(
        MemoryFlash::new(4096),
        [3; 16],
        Registry::new([1; 16], None),
        &mut Provider,
    )
    .unwrap();
    let mut endpoint = endpoint(Storage {
        registry: store,
        images: Images::new(MemoryFlash::with_images(4096, 2, 65536).unwrap()).unwrap(),
        heaps: Heaps {
            banks: core::array::from_fn(|_| Rc::new(RefCell::new(MemoryFlash::new(65536)))),
            preparations: [0; 2],
            fail_write: None,
        },
        heap_key: JournalKey::from([9; 16]),
    });
    // An authenticated channel without the management level cannot load code.
    let mut host = Host::connect(&mut endpoint, 0);
    assert_eq!(
        host.send(
            &mut endpoint,
            0xe6,
            2,
            0,
            &load(package.manifest.package, &[])
        ),
        [0x69, 0x82]
    );
    let mut host = Host::connect(&mut endpoint, 1);
    let response = host.send(&mut endpoint, 0xe2, 0, 0, &[0]);
    assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../../format/jcvm-domain-cbor-v2.json")).unwrap();
    let hex = vector["hex"].as_str().unwrap();
    let expected: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect();
    assert_eq!(&response[..response.len() - 2], expected);

    // Valid signatures do not excuse a mismatched GP load identity or hash.
    for (name, hash) in [
        (&aid[..], &[][..]),
        (package.manifest.package, &[0; 32][..]),
    ] {
        assert_eq!(
            host.send(&mut endpoint, 0xe6, 2, 0, &load(name, hash)),
            [0, 0x90, 0]
        );
        assert_eq!(host.load(&mut endpoint, &raw), [0x69, 0x82]);
        assert_eq!(
            host.send(&mut endpoint, 0xf2, 0x20, 2, &[0x4f, 0]),
            [0x6a, 0x88]
        );
    }
    assert_eq!(
        host.send(
            &mut endpoint,
            0xe6,
            2,
            0,
            &load(package.manifest.package, &package.envelope.package_digest)
        ),
        [0, 0x90, 0]
    );
    assert_eq!(host.load(&mut endpoint, &raw), [0, 0x90, 0]);
    assert_eq!(
        host.send(&mut endpoint, 0xe6, 0x0c, 0, &install),
        [0, 0x90, 0]
    );
    let other_aid = [0xf0, 1, 2, 3, 4, 1];
    let other_install = lv(&[package.manifest.package, module, &other_aid, &[0], &[0xc9, 0], &[]]);
    assert_eq!(host.send(&mut endpoint, 0xe6, 0x0c, 0, &other_install), [0, 0x90, 0]);
    let modules = host.send(&mut endpoint, 0xf2, 0x10, 2, &[0x4f, 0]);
    assert!(modules.windows(module.len()).any(|value| value == module));
    assert_eq!(&modules[modules.len() - 2..], &[0x90, 0]);
    let select_response = host.send(&mut endpoint, 0xa4, 4, 0, &aid);
    assert_eq!(&select_response[..3], &[0x61, 0x81, 0x92]);
    assert_eq!(select_response.len(), 3 + 0x92 + 2);
    assert_eq!(&select_response[select_response.len() - 2..], &[0x90, 0]);
    let pin = [
        0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 255, 255,
    ];
    let response = host.send(&mut endpoint, 0x20, 0, 0x80, &pin[5..]);
    let before = u16::from_be_bytes(response.try_into().unwrap());
    assert_eq!(before & 0xfff0, 0x63c0);
    // A shared prefix chooses bytewise AID order, not installation order.
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &aid[..5]), select_response);
    let remaining = endpoint.exchange(&[0, 0x20, 0, 0x80]);
    assert_eq!(u16::from_be_bytes(remaining.try_into().unwrap()), before + 1);
    // Switching heaps preserves each installation's independent state.
    let mut host = Host::connect(&mut endpoint, 1);
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &other_aid), select_response);
    let response = endpoint.exchange(&pin);
    assert_eq!(u16::from_be_bytes(response.try_into().unwrap()), before);
    let mut select = vec![0, 0xa4, 4, 0, aid.len() as u8];
    select.extend_from_slice(&aid);
    assert_eq!(endpoint.exchange(&select), select_response);
    #[cfg(feature = "scp03-pseudo-random")]
    let previous_session_key = host.key;

    // Reopen the registry too, so this exercises persisted references rather than RAM.
    let mut card = endpoint.into_card();
    assert_eq!(card.select_plain_with_cancel(&Command::parse(&select).unwrap(), &mut || false).unwrap(), select_response);
    let old = *card.storage.registry.state().unwrap().instances()
        .find(|instance| instance.aid.as_slice() == aid).unwrap();
    let preparations = card.storage.heaps.preparations;
    {
        let mut bank = card.storage.heaps.banks[usize::from(old.heap_bank)].borrow_mut();
        while bank.nonce_generation().unwrap() < bank.nonce_capacity() - 1024 {
            bank.reserve_nonce().unwrap();
        }
    }
    let (selected_aid, mut live) = card.selected.take().unwrap();
    card.upload = Some(Upload { load: old.load, domain: old.domain, hash: None,
        receiver: LoadReceiver::new(Payload::SignedPackage, MAX_PACKAGE_BYTES) });
    assert!(card.staging.is_empty());
    assert_eq!(card.maintain_session(selected_aid, &mut live, &mut || false), Err(Error::Busy));
    card.upload = None;
    assert_eq!(card.maintain_session(selected_aid, &mut live, &mut || true), Err(Error::Cancelled));
    assert_eq!(card.storage.heaps.preparations, preparations);
    card.selected = Some((selected_aid, live));
    let status = Command::parse(&[0, 0x20, 0, 0x80]).unwrap();
    let reply = card.process_plain_with_cancel(&status, &mut || false).unwrap();
    assert_eq!(u16::from_be_bytes(reply.try_into().unwrap()), before);
    let current = card.storage.registry.state().unwrap().instances()
        .find(|instance| instance.aid == old.aid).unwrap();
    assert_ne!(current.identity, old.identity);
    assert_eq!(card.selected.as_ref().unwrap().1.selected(), Ok(true));
    assert!(card.storage.registry.pending_renewal().unwrap().is_none());
    assert!(card.staging.is_empty());
    for (bank, previous) in preparations.into_iter().enumerate() {
        assert_eq!(card.storage.heaps.preparations[bank], previous + usize::from(bank == usize::from(old.heap_bank)));
    }
    let mut storage = card.into_storage();
    storage.registry = Store::open(
        storage.registry.into_flash(),
        [3; 16],
        Registry::new([99; 16], None),
        &mut Provider,
    )
    .unwrap();
    let mut endpoint = self::endpoint(storage);
    let mut host = Host::connect(&mut endpoint, 1);
    #[cfg(feature = "scp03-pseudo-random")]
    assert_ne!(host.key, previous_session_key);
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &aid), select_response);
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &aid), select_response);
    let response = endpoint.exchange(&pin);
    assert_eq!(u16::from_be_bytes(response.try_into().unwrap()) + 1, before);
    let mut host = Host::connect(&mut endpoint, 1);
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &aid), select_response);

    // A MAC failure discards selection, so a new channel must select again.
    let mut corrupted = host.command(0x20, 0, 0x80, &pin[5..]);
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(endpoint.exchange(&corrupted), [0x69, 0x82]);
    let mut host = Host::connect(&mut endpoint, 1);
    assert_eq!(host.send(&mut endpoint, 0x20, 0, 0x80, &pin[5..]), [0x69, 0x82]);
    let mut host = Host::connect(&mut endpoint, 1);
    let delete = |aid: &[u8]| {
        let mut wire = vec![0x4f, aid.len() as u8];
        wire.extend_from_slice(aid);
        wire
    };
    assert_eq!(
        host.send(&mut endpoint, 0xe4, 0, 0, &delete(&aid)),
        [0x90, 0]
    );
    assert_eq!(host.send(&mut endpoint, 0xa4, 4, 0, &aid), [0x69, 0x85]);
    assert_eq!(host.send(&mut endpoint, 0xe4, 0, 0, &delete(&other_aid)), [0x90, 0]);
    assert_eq!(
        host.send(&mut endpoint, 0xe4, 0, 0, &delete(package.manifest.package)),
        [0x90, 0]
    );
    assert_eq!(
        host.send(&mut endpoint, 0xf2, 0x20, 2, &[0x4f, 0]),
        [0x6a, 0x88]
    );
}
