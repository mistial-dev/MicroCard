#![no_main]
use libfuzzer_sys::fuzz_target;
use microcard_core::{
    apdu::Command,
    assembly::Assembly,
    ccid, ccid_usb,
    package::Package,
    scp03::{Keys, Session},
};
fuzz_target!(|data: &[u8]| {
    let _ = Package::verify(data);
    let _ = Assembly::parse(data);
    let decoded = ccid::decode(data);
    if let (Ok(header), Err(error)) = (ccid::parse_header(data), decoded) {
        let _ = ccid::error_code(header, &error);
    }
    let mut bulk_out = ccid_usb::BulkOutAssembler::default();
    let mut controller = ccid_usb::Controller::new();
    let mut response = [0u8; ccid::MAX_RESPONSE_MESSAGE_BYTES];
    for packet in data.chunks(ccid_usb::BULK_PACKET_BYTES) {
        if let Some(message) = bulk_out.push(packet).ok().flatten() {
            let _ = controller.handle_bulk(message, &mut response);
            bulk_out.release();
            break;
        }
    }
    bulk_out.disconnect();
    controller.disconnect();
    if let Ok(mut bulk_in) = ccid_usb::BulkInPackets::new(data) {
        while bulk_in.next_packet().is_some() {}
    }
    if data.len() >= 8 {
        let _ = ccid_usb::parse_control(
            ccid_usb::SetupPacket {
                request_type: data[0],
                request: data[1],
                value: u16::from_le_bytes(data[2..4].try_into().unwrap()),
                index: u16::from_le_bytes(data[4..6].try_into().unwrap()),
                length: u16::from_le_bytes(data[6..8].try_into().unwrap()),
            },
            0,
        );
    }
    if let Ok(c) = Command::parse(data) {
        let (mut s, _) = Session::initiate(
            &Keys {
                enc: [1; 16],
                mac: [2; 16],
            },
            [3; microcard_core::scp03::CHALLENGE_BYTES],
            [4; microcard_core::scp03::CHALLENGE_BYTES],
        );
        let _ = s.authenticate(&c);
        let _ = s.unwrap(c);
    }
});
