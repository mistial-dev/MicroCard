//! Allocation-free USB descriptors for the MicroCard CCID profile.
//!
//! The interface, functional and endpoint layouts follow USB-IF CCID 1.1
//! §§4.3, 5.1 and 5.2. Device identifiers remain a product-board input; this
//! module does not claim a vendor or product identifier for MicroCard.

use crate::{ccid, Error, Result};

pub const DEVICE_DESCRIPTOR_BYTES: usize = 18;
pub const CONFIGURATION_DESCRIPTOR_BYTES: usize = 93;
pub const INTERFACE_DESCRIPTOR_BYTES: usize = 9;
pub const FUNCTIONAL_DESCRIPTOR_BYTES: usize = 54;
pub const ENDPOINT_DESCRIPTOR_BYTES: usize = 7;

pub const BULK_OUT_ENDPOINT: u8 = 0x01;
pub const BULK_IN_ENDPOINT: u8 = 0x81;
pub const INTERRUPT_IN_ENDPOINT: u8 = 0x82;
pub const FULL_SPEED_MAX_PACKET_BYTES: u16 = 64;
pub const INTERRUPT_PACKET_BYTES: u16 = 2;
pub const LANGUAGE_ID_DESCRIPTOR: [u8; 4] = [4, 0x03, 0x09, 0x04]; // English (United States).
pub const CLASS_INTERFACE_OUT: u8 = 0x21;
pub const CONTROL_ABORT: u8 = 0x01;

/// One full-speed bulk packet. The nRF52840 USBD EasyDMA endpoint uses this
/// bound while a complete CCID message is assembled in fixed storage.
pub const BULK_PACKET_BYTES: usize = FULL_SPEED_MAX_PACKET_BYTES as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlCommand {
    Abort { slot: u8, sequence: u8 },
}

/// Validate one CCID class-specific control request. Clock and data-rate
/// requests are omitted because this fixed profile advertises one of each.
pub fn parse_control(setup: SetupPacket, interface: u8) -> Result<ControlCommand> {
    if setup.request != CONTROL_ABORT {
        return Err(Error::Unsupported);
    }
    if setup.request_type != CLASS_INTERFACE_OUT || setup.length != 0 {
        return Err(Error::Format);
    }
    if setup.index != u16::from(interface) {
        return Err(Error::Missing);
    }
    let [slot, sequence] = setup.value.to_le_bytes();
    if slot != ccid::MAX_SLOT_INDEX {
        return Err(Error::Missing);
    }
    Ok(ControlCommand::Abort { slot, sequence })
}

/// Configuration, interface, CCID functional, bulk-OUT, bulk-IN and
/// interrupt-IN descriptors in the order required by a configuration reply.
pub const CONFIGURATION_DESCRIPTOR: [u8; CONFIGURATION_DESCRIPTOR_BYTES] = [
    // Standard configuration descriptor.
    9,
    0x02,
    CONFIGURATION_DESCRIPTOR_BYTES as u8,
    0,
    1,
    1,
    0,
    0x80,
    50, // Bus powered, 100 mA maximum.
    // CCID interface descriptor.
    9,
    0x04,
    0,
    0,
    3,
    0x0b,
    0,
    0,
    2,
    // CCID 1.1 functional descriptor.
    0x36,
    0x21,
    0x10,
    0x01,
    ccid::MAX_SLOT_INDEX,
    0x07,
    0x02,
    0,
    0,
    0, // T=1.
    0xa0,
    0x0f,
    0,
    0, // Default clock: 4 MHz.
    0xa0,
    0x0f,
    0,
    0, // Maximum clock: 4 MHz.
    0, // One clock value.
    0x80,
    0x25,
    0,
    0, // Default data rate: 9,600 bit/s.
    0x80,
    0x25,
    0,
    0, // Maximum data rate: 9,600 bit/s.
    0, // One data-rate value.
    0xfe,
    0,
    0,
    0, // Maximum T=1 IFSD.
    0,
    0,
    0,
    0, // No synchronous protocols.
    0,
    0,
    0,
    0, // No mechanical features.
    0x4a,
    0,
    0x02,
    0, // Short APDU and automatic profile features.
    ccid::MAX_COMMAND_MESSAGE_BYTES as u8,
    (ccid::MAX_COMMAND_MESSAGE_BYTES >> 8) as u8,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    ccid::MAX_BUSY_SLOTS,
    // Full-speed bulk OUT.
    7,
    0x05,
    BULK_OUT_ENDPOINT,
    0x02,
    FULL_SPEED_MAX_PACKET_BYTES as u8,
    0,
    0,
    // Full-speed bulk IN.
    7,
    0x05,
    BULK_IN_ENDPOINT,
    0x02,
    FULL_SPEED_MAX_PACKET_BYTES as u8,
    0,
    0,
    // Full-speed interrupt IN. CCID 1.1 recommends the 255 ms interval.
    7,
    0x05,
    INTERRUPT_IN_ENDPOINT,
    0x03,
    INTERRUPT_PACKET_BYTES as u8,
    0,
    255,
];

/// Write the standard device descriptor without assigning USB ownership.
/// Production builds must supply identifiers allocated to the product owner.
pub fn write_device_descriptor(
    output: &mut [u8],
    vendor_id: u16,
    product_id: u16,
    device_release: u16,
) -> Result<usize> {
    if output.len() < DEVICE_DESCRIPTOR_BYTES {
        return Err(Error::Bounds);
    }
    if vendor_id == 0 || product_id == 0 {
        return Err(Error::Format);
    }
    let vendor = vendor_id.to_le_bytes();
    let product = product_id.to_le_bytes();
    let release = device_release.to_le_bytes();
    output[..DEVICE_DESCRIPTOR_BYTES].copy_from_slice(&[
        18, 0x01, 0x00, 0x02, 0, 0, 0, 64, vendor[0], vendor[1], product[0], product[1],
        release[0], release[1], 1, 2, 3, 1,
    ]);
    Ok(DEVICE_DESCRIPTOR_BYTES)
}

/// Encode one USB string descriptor directly into endpoint-owned storage.
pub fn write_string_descriptor(output: &mut [u8], value: &str) -> Result<usize> {
    let units = value.encode_utf16().count();
    let length = units
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2))
        .filter(|bytes| *bytes <= u8::MAX as usize)
        .ok_or(Error::Bounds)?;
    if output.len() < length {
        return Err(Error::Bounds);
    }
    output[0] = length as u8;
    output[1] = 0x03;
    for (index, unit) in value.encode_utf16().enumerate() {
        let offset = 2 + index * 2;
        output[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(length)
}

/// Fixed-capacity bulk-OUT reassembly. A completed message stays borrowed and
/// immutable until the endpoint calls [`Self::release`].
pub struct BulkOutAssembler {
    buffer: [u8; ccid::MAX_COMMAND_MESSAGE_BYTES],
    received: usize,
    expected: Option<usize>,
    complete: bool,
}

impl Default for BulkOutAssembler {
    fn default() -> Self {
        Self {
            buffer: [0; ccid::MAX_COMMAND_MESSAGE_BYTES],
            received: 0,
            expected: None,
            complete: false,
        }
    }
}

impl BulkOutAssembler {
    pub const fn is_idle(&self) -> bool {
        self.received == 0 && !self.complete
    }

    pub fn message(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.buffer[..self.received])
    }

    /// Append one complete USB packet. The returned message borrows the fixed
    /// receive buffer, so it cannot be overwritten while it is being decoded.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<&[u8]>> {
        if self.complete {
            return Err(Error::Busy);
        }
        if packet.is_empty() {
            self.release();
            return Err(Error::Format);
        }
        if packet.len() > BULK_PACKET_BYTES
            || self
                .received
                .checked_add(packet.len())
                .is_none_or(|end| end > self.buffer.len())
        {
            self.release();
            return Err(Error::Bounds);
        }

        let end = self.received + packet.len();
        self.buffer[self.received..end].copy_from_slice(packet);
        self.received = end;

        if self.expected.is_none() && self.received >= ccid::HEADER_BYTES {
            let body = u32::from_le_bytes(self.buffer[1..5].try_into().unwrap()) as usize;
            let Some(expected) = ccid::HEADER_BYTES.checked_add(body) else {
                self.release();
                return Err(Error::Bounds);
            };
            if expected > self.buffer.len() {
                self.release();
                return Err(Error::Bounds);
            }
            self.expected = Some(expected);
        }

        if self
            .expected
            .is_some_and(|expected| self.received > expected)
        {
            self.release();
            return Err(Error::Bounds);
        }
        if self.expected == Some(self.received) {
            self.complete = true;
            return Ok(Some(&self.buffer[..self.received]));
        }
        if packet.len() < BULK_PACKET_BYTES {
            self.release();
            return Err(Error::Bounds);
        }
        Ok(None)
    }

    pub fn release(&mut self) {
        self.buffer[..self.received].fill(0);
        self.received = 0;
        self.expected = None;
        self.complete = false;
    }

    pub fn disconnect(&mut self) {
        self.release();
    }
}

/// Borrowed full-speed bulk-IN packet cursor. No response bytes are copied
/// between the CCID response buffer and the USB EasyDMA scheduling layer.
pub struct BulkInPackets<'a> {
    message: &'a [u8],
    position: usize,
    terminal_zero_length: bool,
}

impl<'a> BulkInPackets<'a> {
    pub fn new(message: &'a [u8]) -> Result<Self> {
        if !(ccid::HEADER_BYTES..=ccid::MAX_RESPONSE_MESSAGE_BYTES).contains(&message.len()) {
            return Err(Error::Bounds);
        }
        Ok(Self {
            message,
            position: 0,
            terminal_zero_length: message.len().is_multiple_of(BULK_PACKET_BYTES),
        })
    }

    pub fn next_packet(&mut self) -> Option<&'a [u8]> {
        if self.position < self.message.len() {
            let end = core::cmp::min(self.position + BULK_PACKET_BYTES, self.message.len());
            let packet = &self.message[self.position..end];
            self.position = end;
            return Some(packet);
        }
        if self.terminal_zero_length {
            self.terminal_zero_length = false;
            return Some(&self.message[self.message.len()..]);
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerAction<'a> {
    Response { length: usize },
    Dispatch { sequence: u8, apdu: &'a [u8] },
    AwaitAbortPair { sequence: u8 },
}

/// Portable CCID command controller. The nRF52840 layer supplies complete
/// reassembled messages and schedules the response or borrowed APDU action.
#[derive(Default)]
pub struct Controller {
    slot: ccid::SlotState,
}

impl Controller {
    pub const fn new() -> Self {
        Self {
            slot: ccid::SlotState::new(),
        }
    }

    pub fn command_in_flight(&self, sequence: u8) -> bool {
        self.slot.in_flight_sequence() == Some(sequence)
    }

    pub fn abort_pending(&self, sequence: u8) -> bool {
        self.slot.abort_pending(sequence)
    }

    pub const fn icc_status(&self) -> ccid::IccStatus {
        self.slot.icc_status()
    }

    pub fn handle_bulk<'a>(
        &mut self,
        input: &'a [u8],
        output: &mut [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
    ) -> Result<ControllerAction<'a>> {
        let command = match ccid::decode(input) {
            Ok(command) => command,
            Err(error) => {
                let header = ccid::parse_header(input)?;
                let icc = if header.slot == ccid::MAX_SLOT_INDEX {
                    self.slot.icc_status()
                } else {
                    ccid::IccStatus::NotPresent
                };
                let error = ccid::error_code(header, &error);
                let length = match response_kind_for_message(header.message_type) {
                    ccid::ResponseKind::DataBlock => ccid::write_data_block(
                        output,
                        header.slot,
                        header.sequence,
                        icc,
                        ccid::CommandStatus::Failed,
                        error,
                        &[],
                    )?,
                    ccid::ResponseKind::SlotStatus => ccid::write_slot_status(
                        output,
                        header.slot,
                        header.sequence,
                        icc,
                        ccid::CommandStatus::Failed,
                        error,
                    )?,
                };
                return Ok(ControllerAction::Response { length });
            }
        };

        match self.slot.accept(command) {
            ccid::SlotAction::DataBlock { sequence, data } => {
                let length = ccid::write_data_block(
                    output,
                    0,
                    sequence,
                    self.slot.icc_status(),
                    ccid::CommandStatus::Success,
                    0,
                    data,
                )?;
                Ok(ControllerAction::Response { length })
            }
            ccid::SlotAction::SlotStatus { sequence } => {
                let length = ccid::write_slot_status(
                    output,
                    0,
                    sequence,
                    self.slot.icc_status(),
                    ccid::CommandStatus::Success,
                    0,
                )?;
                Ok(ControllerAction::Response { length })
            }
            ccid::SlotAction::Dispatch { sequence, apdu } => {
                Ok(ControllerAction::Dispatch { sequence, apdu })
            }
            ccid::SlotAction::Failed {
                sequence,
                response,
                error,
            } => {
                let length = self.write_failure(output, sequence, response, error)?;
                Ok(ControllerAction::Response { length })
            }
            ccid::SlotAction::AwaitAbortPair { sequence } => {
                Ok(ControllerAction::AwaitAbortPair { sequence })
            }
        }
    }

    pub fn complete(
        &mut self,
        sequence: u8,
        response: &[u8],
        output: &mut [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
    ) -> Result<usize> {
        if response.len() > crate::hal::MAX_SHORT_RESPONSE_BYTES {
            return Err(Error::Bounds);
        }
        self.slot.complete(sequence)?;
        ccid::write_data_block(
            output,
            0,
            sequence,
            self.slot.icc_status(),
            ccid::CommandStatus::Success,
            0,
            response,
        )
    }

    pub fn fail(
        &mut self,
        sequence: u8,
        error: u8,
        output: &mut [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
    ) -> Result<usize> {
        self.slot.complete(sequence)?;
        self.write_failure(output, sequence, ccid::ResponseKind::DataBlock, error)
    }

    pub fn control_abort(
        &mut self,
        slot: u8,
        sequence: u8,
        output: &mut [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
    ) -> Result<Option<usize>> {
        let Some(ccid::SlotAction::SlotStatus { sequence }) =
            self.slot.control_abort(slot, sequence)?
        else {
            return Ok(None);
        };
        ccid::write_slot_status(
            output,
            slot,
            sequence,
            self.slot.icc_status(),
            ccid::CommandStatus::Success,
            0,
        )
        .map(Some)
    }

    pub fn disconnect(&mut self) {
        self.slot.disconnect();
    }

    fn write_failure(
        &self,
        output: &mut [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
        sequence: u8,
        response: ccid::ResponseKind,
        error: u8,
    ) -> Result<usize> {
        match response {
            ccid::ResponseKind::DataBlock => ccid::write_data_block(
                output,
                0,
                sequence,
                self.slot.icc_status(),
                ccid::CommandStatus::Failed,
                error,
                &[],
            ),
            ccid::ResponseKind::SlotStatus => ccid::write_slot_status(
                output,
                0,
                sequence,
                self.slot.icc_status(),
                ccid::CommandStatus::Failed,
                error,
            ),
        }
    }
}

fn response_kind_for_message(message_type: u8) -> ccid::ResponseKind {
    match message_type {
        ccid::PC_TO_RDR_ICC_POWER_ON | ccid::PC_TO_RDR_XFR_BLOCK => ccid::ResponseKind::DataBlock,
        _ => ccid::ResponseKind::SlotStatus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(kind: u8, sequence: u8, data: &[u8]) -> alloc::vec::Vec<u8> {
        let mut result = alloc::vec![kind];
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(&[0, sequence, 0, 0, 0]);
        result.extend_from_slice(data);
        result
    }

    #[test]
    fn device_descriptor_requires_owned_nonzero_identifiers() {
        let mut output = [0xa5; DEVICE_DESCRIPTOR_BYTES + 1];
        assert_eq!(
            write_device_descriptor(&mut output, 0x1234, 0xabcd, 0x0102),
            Ok(DEVICE_DESCRIPTOR_BYTES)
        );
        assert_eq!(
            &output[..DEVICE_DESCRIPTOR_BYTES],
            &[18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0xcd, 0xab, 2, 1, 1, 2, 3, 1]
        );
        assert_eq!(output[DEVICE_DESCRIPTOR_BYTES], 0xa5);
        assert_eq!(
            write_device_descriptor(&mut output, 0, 1, 1),
            Err(Error::Format)
        );
        assert_eq!(
            write_device_descriptor(&mut output, 1, 0, 1),
            Err(Error::Format)
        );
    }

    #[test]
    fn control_abort_requires_exact_class_interface_setup() {
        let setup = SetupPacket {
            request_type: CLASS_INTERFACE_OUT,
            request: CONTROL_ABORT,
            value: 0x3700,
            index: 2,
            length: 0,
        };
        assert_eq!(
            parse_control(setup, 2),
            Ok(ControlCommand::Abort {
                slot: 0,
                sequence: 0x37
            })
        );
        assert_eq!(
            parse_control(
                SetupPacket {
                    request_type: 0xa1,
                    ..setup
                },
                2
            ),
            Err(Error::Format)
        );
        assert_eq!(
            parse_control(
                SetupPacket {
                    request: 2,
                    ..setup
                },
                2
            ),
            Err(Error::Unsupported)
        );
        assert_eq!(
            parse_control(SetupPacket { length: 1, ..setup }, 2),
            Err(Error::Format)
        );
        assert_eq!(parse_control(setup, 1), Err(Error::Missing));
        assert_eq!(
            parse_control(
                SetupPacket {
                    value: 0x3701,
                    ..setup
                },
                2
            ),
            Err(Error::Missing)
        );
    }

    #[test]
    fn short_device_output_is_unchanged() {
        let mut output = [0x5a; DEVICE_DESCRIPTOR_BYTES - 1];
        assert_eq!(
            write_device_descriptor(&mut output, 1, 1, 1),
            Err(Error::Bounds)
        );
        assert_eq!(output, [0x5a; DEVICE_DESCRIPTOR_BYTES - 1]);
    }

    #[test]
    fn string_descriptors_encode_utf16_without_partial_failure() {
        assert_eq!(LANGUAGE_ID_DESCRIPTOR, [4, 3, 9, 4]);
        let mut output = [0xa5; 32];
        let written = write_string_descriptor(&mut output, "MicroCard 🔐").unwrap();
        assert_eq!(output[0] as usize, written);
        assert_eq!(output[1], 3);
        let decoded: alloc::vec::Vec<u16> = output[2..written]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
            .collect();
        assert_eq!(
            decoded,
            "MicroCard 🔐"
                .encode_utf16()
                .collect::<alloc::vec::Vec<_>>()
        );
        assert_eq!(output[written], 0xa5);

        let mut short = [0x5a; 3];
        assert_eq!(write_string_descriptor(&mut short, "a"), Err(Error::Bounds));
        assert_eq!(short, [0x5a; 3]);
        let oversized = "a".repeat(127);
        assert_eq!(
            write_string_descriptor(&mut output, &oversized),
            Err(Error::Bounds)
        );
    }

    #[test]
    fn configuration_descriptor_is_complete_and_self_consistent() {
        let descriptor = &CONFIGURATION_DESCRIPTOR;
        assert_eq!(descriptor.len(), CONFIGURATION_DESCRIPTOR_BYTES);
        assert_eq!(u16::from_le_bytes([descriptor[2], descriptor[3]]), 93);
        assert_eq!(&descriptor[9..18], &[9, 4, 0, 0, 3, 0x0b, 0, 0, 2]);

        let functional = &descriptor[18..18 + FUNCTIONAL_DESCRIPTOR_BYTES];
        assert_eq!(functional[0..4], [0x36, 0x21, 0x10, 0x01]);
        assert_eq!(functional[4], ccid::MAX_SLOT_INDEX);
        assert_eq!(
            u32::from_le_bytes(functional[6..10].try_into().unwrap()),
            ccid::PROTOCOLS
        );
        assert_eq!(
            u32::from_le_bytes(functional[40..44].try_into().unwrap()),
            ccid::FEATURES
        );
        assert_eq!(
            u32::from_le_bytes(functional[44..48].try_into().unwrap()),
            ccid::MAX_COMMAND_MESSAGE_BYTES as u32
        );
        assert_eq!(functional[53], ccid::MAX_BUSY_SLOTS);

        let endpoint_start = 18 + FUNCTIONAL_DESCRIPTOR_BYTES;
        assert_eq!(
            &descriptor[endpoint_start..endpoint_start + 7],
            &[7, 5, BULK_OUT_ENDPOINT, 2, 64, 0, 0]
        );
        assert_eq!(
            &descriptor[endpoint_start + 7..endpoint_start + 14],
            &[7, 5, BULK_IN_ENDPOINT, 2, 64, 0, 0]
        );
        assert_eq!(
            &descriptor[endpoint_start + 14..],
            &[7, 5, INTERRUPT_IN_ENDPOINT, 3, 2, 0, 255]
        );

        let mut offset = 0;
        while offset < descriptor.len() {
            let length = descriptor[offset] as usize;
            assert!(length > 0);
            offset += length;
        }
        assert_eq!(offset, descriptor.len());
    }

    #[test]
    fn bulk_out_reassembles_every_valid_message_length() {
        let mut message = [0u8; ccid::MAX_COMMAND_MESSAGE_BYTES];
        for length in ccid::HEADER_BYTES..=message.len() {
            message[0] = ccid::PC_TO_RDR_XFR_BLOCK;
            message[1..5].copy_from_slice(&((length - ccid::HEADER_BYTES) as u32).to_le_bytes());
            message[6] = 7;
            let mut assembler = BulkOutAssembler::default();
            let mut offset = 0;
            while offset < length {
                let end = core::cmp::min(offset + BULK_PACKET_BYTES, length);
                let result = assembler.push(&message[offset..end]).unwrap();
                if end == length {
                    assert_eq!(result, Some(&message[..length]));
                } else {
                    assert_eq!(result, None);
                }
                offset = end;
            }
            assembler.release();
        }
    }

    #[test]
    fn bulk_out_rejects_bad_packets_without_partial_reuse() {
        let mut assembler = BulkOutAssembler::default();
        assert_eq!(assembler.push(&[]), Err(Error::Format));
        assert_eq!(
            assembler.push(&[0; BULK_PACKET_BYTES + 1]),
            Err(Error::Bounds)
        );

        let mut oversized = [0u8; ccid::HEADER_BYTES];
        oversized[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(assembler.push(&oversized), Err(Error::Bounds));

        let mut empty = [0u8; ccid::HEADER_BYTES];
        empty[0] = ccid::PC_TO_RDR_GET_SLOT_STATUS;
        let complete = assembler.push(&empty).unwrap().unwrap();
        assert_eq!(complete, empty);
        assert_eq!(assembler.message(), Some(empty.as_slice()));
        assert_eq!(assembler.push(&empty), Err(Error::Busy));
        assembler.release();
        assert_eq!(assembler.message(), None);

        let mut one_byte = [0u8; ccid::HEADER_BYTES];
        one_byte[0] = ccid::PC_TO_RDR_XFR_BLOCK;
        one_byte[1] = 1;
        assert_eq!(assembler.push(&one_byte), Err(Error::Bounds));
        assert_eq!(
            assembler.push(&[0; ccid::HEADER_BYTES - 1]),
            Err(Error::Bounds)
        );
        assert_eq!(assembler.push(&empty), Ok(Some(empty.as_slice())));
        assembler.disconnect();
        assert_eq!(assembler.push(&empty), Ok(Some(empty.as_slice())));
    }

    #[test]
    fn bulk_in_borrows_packets_and_terminates_exact_multiples() {
        let message = [0x5a; ccid::MAX_RESPONSE_MESSAGE_BYTES];
        let mut packets = BulkInPackets::new(&message).unwrap();
        let mut position = 0;
        while let Some(packet) = packets.next_packet() {
            assert!(!packet.is_empty());
            assert_eq!(packet.as_ptr(), message[position..].as_ptr());
            assert!(packet.len() <= BULK_PACKET_BYTES);
            position += packet.len();
        }
        assert_eq!(position, message.len());

        let exact = [0xa5; BULK_PACKET_BYTES * 2];
        let mut packets = BulkInPackets::new(&exact).unwrap();
        assert_eq!(packets.next_packet().unwrap().len(), BULK_PACKET_BYTES);
        assert_eq!(packets.next_packet().unwrap().len(), BULK_PACKET_BYTES);
        assert_eq!(packets.next_packet(), Some(&[][..]));
        assert_eq!(packets.next_packet(), None);
    }

    #[test]
    fn bulk_in_rejects_non_messages() {
        assert!(matches!(BulkInPackets::new(&[]), Err(Error::Bounds)));
        assert!(matches!(
            BulkInPackets::new(&[0; ccid::HEADER_BYTES - 1]),
            Err(Error::Bounds)
        ));
        assert!(matches!(
            BulkInPackets::new(&[0; ccid::MAX_RESPONSE_MESSAGE_BYTES + 1]),
            Err(Error::Bounds)
        ));
    }

    #[test]
    fn controller_powers_dispatches_and_completes_borrowed_apdus() {
        let mut controller = Controller::new();
        let mut output = [0u8; ccid::MAX_RESPONSE_MESSAGE_BYTES];
        assert_eq!(controller.icc_status(), ccid::IccStatus::Inactive);

        assert_eq!(
            controller
                .handle_bulk(
                    &command(ccid::PC_TO_RDR_GET_SLOT_STATUS, 1, &[]),
                    &mut output
                )
                .unwrap(),
            ControllerAction::Response { length: 10 }
        );
        assert_eq!(&output[..10], &[0x81, 0, 0, 0, 0, 0, 1, 1, 0, 0]);

        assert_eq!(
            controller
                .handle_bulk(&command(ccid::PC_TO_RDR_ICC_POWER_ON, 2, &[]), &mut output)
                .unwrap(),
            ControllerAction::Response { length: 14 }
        );
        assert_eq!(&output[..10], &[0x80, 4, 0, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&output[10..14], &ccid::ATR);

        let transfer = command(ccid::PC_TO_RDR_XFR_BLOCK, 3, b"command");
        let ControllerAction::Dispatch { sequence, apdu } =
            controller.handle_bulk(&transfer, &mut output).unwrap()
        else {
            panic!()
        };
        assert_eq!(sequence, 3);
        assert_eq!(apdu, b"command");
        assert_eq!(apdu.as_ptr(), transfer[ccid::HEADER_BYTES..].as_ptr());

        assert_eq!(
            controller
                .handle_bulk(
                    &command(ccid::PC_TO_RDR_GET_SLOT_STATUS, 4, &[]),
                    &mut output
                )
                .unwrap(),
            ControllerAction::Response { length: 10 }
        );
        assert_eq!(output[7], ccid::CommandStatus::Failed as u8);
        assert_eq!(output[8], ccid::ERROR_SLOT_BUSY);
        assert_eq!(
            controller.complete(4, b"wrong", &mut output),
            Err(Error::Missing)
        );
        assert_eq!(controller.complete(3, b"reply", &mut output), Ok(15));
        assert_eq!(&output[10..15], b"reply");

        let transfer = command(ccid::PC_TO_RDR_XFR_BLOCK, 5, b"again");
        let _ = controller.handle_bulk(&transfer, &mut output);
        assert_eq!(
            controller.complete(
                5,
                &[0; crate::hal::MAX_SHORT_RESPONSE_BYTES + 1],
                &mut output
            ),
            Err(Error::Bounds)
        );
        assert_eq!(
            controller.fail(5, ccid::ERROR_ICC_MUTE, &mut output),
            Ok(10)
        );
        assert_eq!(output[7], ccid::CommandStatus::Failed as u8);
        assert_eq!(output[8], ccid::ERROR_ICC_MUTE);
    }

    #[test]
    fn controller_maps_decode_failures_without_changing_slot_state() {
        let mut controller = Controller::new();
        let mut output = [0xa5; ccid::MAX_RESPONSE_MESSAGE_BYTES];
        let mut wrong_slot = command(ccid::PC_TO_RDR_GET_SLOT_STATUS, 7, &[]);
        wrong_slot[5] = 4;
        assert_eq!(
            controller.handle_bulk(&wrong_slot, &mut output),
            Ok(ControllerAction::Response { length: 10 })
        );
        assert_eq!(&output[..10], &[0x81, 0, 0, 0, 0, 4, 7, 0x42, 5, 0]);
        assert_eq!(controller.icc_status(), ccid::IccStatus::Inactive);
        assert_eq!(
            controller.handle_bulk(&[0; 9], &mut output),
            Err(Error::Bounds)
        );
    }

    #[test]
    fn controller_completes_both_abort_pipe_orders_and_disconnects() {
        let mut controller = Controller::new();
        let mut output = [0u8; ccid::MAX_RESPONSE_MESSAGE_BYTES];
        let _ = controller.handle_bulk(&command(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]), &mut output);
        let first = command(ccid::PC_TO_RDR_XFR_BLOCK, 2, b"first");
        let _ = controller.handle_bulk(&first, &mut output);
        assert!(controller.command_in_flight(2));
        assert_eq!(controller.control_abort(0, 9, &mut output), Ok(None));
        assert!(controller.command_in_flight(2));
        assert!(controller.abort_pending(2));
        assert_eq!(
            controller.handle_bulk(&command(ccid::PC_TO_RDR_ABORT, 9, &[]), &mut output),
            Ok(ControllerAction::Response { length: 10 })
        );
        assert!(!controller.command_in_flight(2));
        assert!(!controller.abort_pending(2));

        let second = command(ccid::PC_TO_RDR_XFR_BLOCK, 3, b"second");
        let _ = controller.handle_bulk(&second, &mut output);
        assert_eq!(
            controller.handle_bulk(&command(ccid::PC_TO_RDR_ABORT, 10, &[]), &mut output),
            Ok(ControllerAction::AwaitAbortPair { sequence: 10 })
        );
        assert!(controller.command_in_flight(3));
        assert!(controller.abort_pending(3));
        assert_eq!(controller.control_abort(0, 10, &mut output), Ok(Some(10)));
        assert!(!controller.command_in_flight(3));
        assert!(!controller.abort_pending(3));
        assert_eq!(output[6], 10);
        assert_eq!(output[7], ccid::IccStatus::Active as u8);

        let third = command(ccid::PC_TO_RDR_XFR_BLOCK, 4, b"third");
        let _ = controller.handle_bulk(&third, &mut output);
        controller.disconnect();
        assert_eq!(controller.icc_status(), ccid::IccStatus::Inactive);
        assert_eq!(
            controller.complete(4, b"late", &mut output),
            Err(Error::Missing)
        );
    }
}
