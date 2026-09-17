//! Bounded USB CCID bulk-message codec for the one-slot short-APDU profile.
//!
//! Field positions and message values follow USB-IF CCID 1.1 §§6.1-6.3.
//! This module also owns the portable one-slot state and two-part abort
//! handshake. The USB backend only assembles endpoint packets and dispatches
//! borrowed APDUs returned by [`SlotState::accept`].

use crate::{
    hal::{MAX_SHORT_COMMAND_BYTES, MAX_SHORT_RESPONSE_BYTES},
    Error, Result,
};

pub const HEADER_BYTES: usize = 10;
pub const MAX_COMMAND_MESSAGE_BYTES: usize = HEADER_BYTES + MAX_SHORT_COMMAND_BYTES;
pub const MAX_RESPONSE_MESSAGE_BYTES: usize = HEADER_BYTES + MAX_SHORT_RESPONSE_BYTES;
pub const MAX_SLOT_INDEX: u8 = 0;
pub const MAX_BUSY_SLOTS: u8 = 1;
pub const PROTOCOLS: u32 = 0x0000_0002; // T=1 only.
pub const FEATURES: u32 = 0x0002_004a; // Short APDU, ATR parameters, auto voltage/negotiation.
/// Direct convention, T=1, no historical bytes; TCK makes T0 through TCK XOR to zero.
pub const ATR: [u8; 4] = [0x3b, 0x80, 0x01, 0x81];

pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6f;
pub const PC_TO_RDR_ABORT: u8 = 0x72;
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
pub const RDR_TO_PC_NOTIFY_SLOT_CHANGE: u8 = 0x50;
pub const ERROR_BAD_LENGTH: u8 = 1;
pub const ERROR_BAD_SLOT: u8 = 5;
pub const ERROR_BAD_POWER_SELECT: u8 = 7;
pub const ERROR_BAD_LEVEL_PARAMETER: u8 = 8;
pub const ERROR_COMMAND_NOT_SUPPORTED: u8 = 0;
pub const ERROR_COMMAND_ABORTED: u8 = 0xff;
pub const ERROR_ICC_MUTE: u8 = 0xfe;
pub const ERROR_SLOT_BUSY: u8 = 0xe0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub message_type: u8,
    pub data_length: u32,
    pub slot: u8,
    pub sequence: u8,
    pub parameters: [u8; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    PowerOn { sequence: u8 },
    PowerOff { sequence: u8 },
    GetSlotStatus { sequence: u8 },
    TransferBlock { sequence: u8, apdu: &'a [u8] },
    Abort { sequence: u8 },
}

impl Command<'_> {
    pub fn sequence(&self) -> u8 {
        match self {
            Self::PowerOn { sequence }
            | Self::PowerOff { sequence }
            | Self::GetSlotStatus { sequence }
            | Self::TransferBlock { sequence, .. }
            | Self::Abort { sequence } => *sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IccStatus {
    Active = 0,
    Inactive = 1,
    NotPresent = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandStatus {
    Success = 0,
    Failed = 0x40,
    TimeExtension = 0x80,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseKind {
    DataBlock,
    SlotStatus,
}

/// A validated action for the USB backend. APDU data continues to borrow the
/// complete bulk-OUT message until the command dispatcher has consumed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotAction<'a> {
    DataBlock {
        sequence: u8,
        data: &'static [u8],
    },
    SlotStatus {
        sequence: u8,
    },
    Dispatch {
        sequence: u8,
        apdu: &'a [u8],
    },
    Failed {
        sequence: u8,
        response: ResponseKind,
        error: u8,
    },
    AwaitAbortPair {
        sequence: u8,
    },
}

/// Portable CCID state for MicroCard's single, permanently present virtual ICC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotState {
    powered: bool,
    in_flight: Option<u8>,
    control_abort: Option<u8>,
    bulk_abort: Option<u8>,
}

impl SlotState {
    pub const fn new() -> Self {
        Self {
            powered: false,
            in_flight: None,
            control_abort: None,
            bulk_abort: None,
        }
    }

    pub const fn icc_status(&self) -> IccStatus {
        if self.powered {
            IccStatus::Active
        } else {
            IccStatus::Inactive
        }
    }

    pub const fn in_flight_sequence(&self) -> Option<u8> {
        self.in_flight
    }

    pub fn abort_pending(&self, sequence: u8) -> bool {
        self.in_flight == Some(sequence)
            && (self.control_abort.is_some() || self.bulk_abort.is_some())
    }

    /// Accept one decoded bulk-OUT command. CCID 1.1 permits one active command
    /// per slot, so a second command fails without disturbing the first.
    pub fn accept<'a>(&mut self, command: Command<'a>) -> SlotAction<'a> {
        let sequence = command.sequence();
        if let Some(abort_sequence) = self.control_abort {
            if matches!(command, Command::Abort { .. }) && sequence == abort_sequence {
                return self.finish_abort(sequence);
            }
            return SlotAction::Failed {
                sequence,
                response: response_kind(&command),
                error: ERROR_COMMAND_ABORTED,
            };
        }

        if matches!(command, Command::Abort { .. }) {
            if let Some(abort_sequence) = self.bulk_abort {
                return if sequence == abort_sequence {
                    SlotAction::AwaitAbortPair { sequence }
                } else {
                    SlotAction::Failed {
                        sequence,
                        response: ResponseKind::SlotStatus,
                        error: ERROR_SLOT_BUSY,
                    }
                };
            }
            if self.in_flight.is_none() {
                return SlotAction::Failed {
                    sequence,
                    response: ResponseKind::SlotStatus,
                    error: ERROR_COMMAND_NOT_SUPPORTED,
                };
            }
            self.bulk_abort = Some(sequence);
            return SlotAction::AwaitAbortPair { sequence };
        }

        if self.in_flight.is_some() {
            return SlotAction::Failed {
                sequence,
                response: response_kind(&command),
                error: ERROR_SLOT_BUSY,
            };
        }

        match command {
            Command::PowerOn { sequence } => {
                self.powered = true;
                SlotAction::DataBlock {
                    sequence,
                    data: &ATR,
                }
            }
            Command::PowerOff { sequence } => {
                self.powered = false;
                SlotAction::SlotStatus { sequence }
            }
            Command::GetSlotStatus { sequence } => SlotAction::SlotStatus { sequence },
            Command::TransferBlock { sequence, apdu } if self.powered => {
                self.in_flight = Some(sequence);
                SlotAction::Dispatch { sequence, apdu }
            }
            Command::TransferBlock { sequence, .. } => SlotAction::Failed {
                sequence,
                response: ResponseKind::DataBlock,
                error: ERROR_ICC_MUTE,
            },
            Command::Abort { .. } => unreachable!(),
        }
    }

    /// Register the class-specific control-pipe half of an abort. A matching
    /// bulk abort may have arrived first because the two USB pipes are async.
    pub fn control_abort(&mut self, slot: u8, sequence: u8) -> Result<Option<SlotAction<'static>>> {
        if slot != MAX_SLOT_INDEX {
            return Err(Error::Missing);
        }
        if self.bulk_abort == Some(sequence) {
            return Ok(Some(self.finish_abort(sequence)));
        }
        if self.in_flight.is_none() {
            return Err(Error::Missing);
        }
        self.control_abort = Some(sequence);
        Ok(None)
    }

    /// Complete the APDU whose borrowed input was returned by [`Self::accept`].
    /// The caller writes the data-block response only after this succeeds.
    pub fn complete(&mut self, sequence: u8) -> Result<()> {
        if self.in_flight != Some(sequence)
            || self.control_abort.is_some()
            || self.bulk_abort.is_some()
        {
            return Err(Error::Missing);
        }
        self.in_flight = None;
        Ok(())
    }

    /// USB reset, suspend, or disconnect requires a fresh power-on and cannot
    /// retain an orphaned command or half of an abort pair.
    pub fn disconnect(&mut self) {
        *self = Self::new();
    }

    fn finish_abort(&mut self, sequence: u8) -> SlotAction<'static> {
        self.in_flight = None;
        self.control_abort = None;
        self.bulk_abort = None;
        SlotAction::SlotStatus { sequence }
    }
}

fn response_kind(command: &Command<'_>) -> ResponseKind {
    match command {
        Command::PowerOn { .. } | Command::TransferBlock { .. } => ResponseKind::DataBlock,
        Command::PowerOff { .. } | Command::GetSlotStatus { .. } | Command::Abort { .. } => {
            ResponseKind::SlotStatus
        }
    }
}

fn status(icc: IccStatus, command: CommandStatus) -> u8 {
    icc as u8 | command as u8
}

/// Decode exactly one complete bulk-OUT message.
pub fn decode(input: &[u8]) -> Result<Command<'_>> {
    let header = parse_header(input)?;
    if input.len() > MAX_COMMAND_MESSAGE_BYTES {
        return Err(Error::Bounds);
    }
    let data_length = header.data_length as usize;
    if data_length > MAX_SHORT_COMMAND_BYTES || data_length != input.len() - HEADER_BYTES {
        return Err(Error::Bounds);
    }
    if header.slot != 0 {
        return Err(Error::Missing);
    }
    let sequence = header.sequence;
    let parameters = header.parameters;
    let data = &input[HEADER_BYTES..];
    match header.message_type {
        PC_TO_RDR_ICC_POWER_ON if data.is_empty() && parameters == [0, 0, 0] => {
            Ok(Command::PowerOn { sequence })
        }
        PC_TO_RDR_ICC_POWER_OFF if data.is_empty() && parameters == [0, 0, 0] => {
            Ok(Command::PowerOff { sequence })
        }
        PC_TO_RDR_GET_SLOT_STATUS if data.is_empty() && parameters == [0, 0, 0] => {
            Ok(Command::GetSlotStatus { sequence })
        }
        PC_TO_RDR_XFR_BLOCK if parameters == [0, 0, 0] => Ok(Command::TransferBlock {
            sequence,
            apdu: data,
        }),
        PC_TO_RDR_ABORT if data.is_empty() && parameters == [0, 0, 0] => {
            Ok(Command::Abort { sequence })
        }
        PC_TO_RDR_ICC_POWER_ON
        | PC_TO_RDR_ICC_POWER_OFF
        | PC_TO_RDR_GET_SLOT_STATUS
        | PC_TO_RDR_XFR_BLOCK
        | PC_TO_RDR_ABORT => Err(Error::Format),
        _ => Err(Error::Unsupported),
    }
}

/// Parse the fixed header without trusting or consuming the declared payload.
/// Endpoint code can retain slot and sequence when reporting a malformed body.
pub fn parse_header(input: &[u8]) -> Result<Header> {
    if input.len() < HEADER_BYTES {
        return Err(Error::Bounds);
    }
    Ok(Header {
        message_type: input[0],
        data_length: u32::from_le_bytes(input[1..5].try_into().unwrap()),
        slot: input[5],
        sequence: input[6],
        parameters: input[7..10].try_into().unwrap(),
    })
}

/// Map a validated header plus decode failure to the CCID 1.1 error byte.
pub fn error_code(header: Header, error: &Error) -> u8 {
    match error {
        Error::Bounds => ERROR_BAD_LENGTH,
        Error::Missing => ERROR_BAD_SLOT,
        Error::Format if header.message_type == PC_TO_RDR_ICC_POWER_ON => ERROR_BAD_POWER_SELECT,
        Error::Format if header.message_type == PC_TO_RDR_XFR_BLOCK => ERROR_BAD_LEVEL_PARAMETER,
        _ => ERROR_COMMAND_NOT_SUPPORTED,
    }
}

pub fn write_data_block(
    output: &mut [u8],
    slot: u8,
    sequence: u8,
    icc: IccStatus,
    command: CommandStatus,
    error: u8,
    data: &[u8],
) -> Result<usize> {
    if data.len() > MAX_SHORT_RESPONSE_BYTES || output.len() < HEADER_BYTES + data.len() {
        return Err(Error::Bounds);
    }
    let length = data.len();
    output[0] = RDR_TO_PC_DATA_BLOCK;
    output[1..5].copy_from_slice(&(length as u32).to_le_bytes());
    output[5] = slot;
    output[6] = sequence;
    output[7] = status(icc, command);
    output[8] = error;
    output[9] = 0;
    output[HEADER_BYTES..HEADER_BYTES + length].copy_from_slice(data);
    Ok(HEADER_BYTES + length)
}

pub fn write_slot_status(
    output: &mut [u8],
    slot: u8,
    sequence: u8,
    icc: IccStatus,
    command: CommandStatus,
    error: u8,
) -> Result<usize> {
    if output.len() < HEADER_BYTES {
        return Err(Error::Bounds);
    }
    output[..HEADER_BYTES].copy_from_slice(&[
        RDR_TO_PC_SLOT_STATUS,
        0,
        0,
        0,
        0,
        slot,
        sequence,
        status(icc, command),
        error,
        0, // Clock running; MicroCard presents a virtual, permanently inserted ICC.
    ]);
    Ok(HEADER_BYTES)
}

pub fn write_slot_change(output: &mut [u8], changed: bool) -> Result<usize> {
    if output.len() < 2 {
        return Err(Error::Bounds);
    }
    output[0] = RDR_TO_PC_NOTIFY_SLOT_CHANGE;
    output[1] = 1 | if changed { 2 } else { 0 };
    Ok(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn message(kind: u8, sequence: u8, parameters: [u8; 3], data: &[u8]) -> Vec<u8> {
        let mut result = vec![kind];
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());
        result.extend_from_slice(&[0, sequence]);
        result.extend_from_slice(&parameters);
        result.extend_from_slice(data);
        result
    }

    #[test]
    fn decodes_profiled_commands_and_borrows_transfer_data() {
        assert_eq!(MAX_SLOT_INDEX, 0);
        assert_eq!(MAX_BUSY_SLOTS, 1);
        assert_eq!(PROTOCOLS, 2);
        assert_eq!(FEATURES & 0x0007_0000, 0x0002_0000);
        assert_ne!(FEATURES & 2, 0);
        assert!(matches!(FEATURES & 0xc0, 0x40 | 0x80));
        assert_eq!(ATR[1..].iter().fold(0, |checksum, byte| checksum ^ byte), 0);
        assert_eq!(
            decode(&message(0x62, 1, [0; 3], &[])),
            Ok(Command::PowerOn { sequence: 1 })
        );
        assert_eq!(
            decode(&message(0x63, 2, [0; 3], &[])),
            Ok(Command::PowerOff { sequence: 2 })
        );
        assert_eq!(
            decode(&message(0x65, 3, [0; 3], &[])),
            Ok(Command::GetSlotStatus { sequence: 3 })
        );
        assert_eq!(
            decode(&message(0x72, 4, [0; 3], &[])),
            Ok(Command::Abort { sequence: 4 })
        );
        let raw = message(0x6f, 5, [0; 3], b"command");
        assert_eq!(
            parse_header(&raw),
            Ok(Header {
                message_type: 0x6f,
                data_length: 7,
                slot: 0,
                sequence: 5,
                parameters: [0; 3],
            })
        );
        let Command::TransferBlock { sequence, apdu } = decode(&raw).unwrap() else {
            panic!()
        };
        assert_eq!(sequence, 5);
        assert_eq!(apdu, b"command");
        assert_eq!(apdu.as_ptr(), raw[HEADER_BYTES..].as_ptr());
    }

    #[test]
    fn rejects_lengths_slots_parameters_and_unsupported_commands() {
        assert_eq!(decode(&[0; HEADER_BYTES - 1]), Err(Error::Bounds));
        let mut mismatch = message(0x6f, 1, [0; 3], b"a");
        mismatch[1] = 2;
        assert_eq!(
            error_code(
                parse_header(&mismatch).unwrap(),
                &decode(&mismatch).unwrap_err()
            ),
            1
        );
        assert_eq!(decode(&mismatch), Err(Error::Bounds));
        let mut huge = message(0x6f, 1, [0; 3], &[]);
        huge[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&huge), Err(Error::Bounds));
        let mut wrong_slot = message(0x65, 1, [0; 3], &[]);
        wrong_slot[5] = 1;
        assert_eq!(decode(&wrong_slot), Err(Error::Missing));
        assert_eq!(
            error_code(parse_header(&wrong_slot).unwrap(), &Error::Missing),
            5
        );
        assert_eq!(
            decode(&message(0x62, 1, [1, 0, 0], &[])),
            Err(Error::Format)
        );
        assert_eq!(
            error_code(
                parse_header(&message(0x62, 1, [1, 0, 0], &[])).unwrap(),
                &Error::Format
            ),
            7
        );
        assert_eq!(
            decode(&message(0x6f, 1, [1, 0, 0], b"a")),
            Err(Error::Format)
        );
        assert_eq!(
            error_code(
                parse_header(&message(0x6f, 1, [1, 0, 0], b"a")).unwrap(),
                &Error::Format
            ),
            8
        );
        assert_eq!(
            decode(&message(0x6b, 1, [0; 3], &[])),
            Err(Error::Unsupported)
        );
        assert_eq!(decode(&message(0x65, 1, [0; 3], b"a")), Err(Error::Format));
        assert_eq!(
            decode(&message(0x6f, 1, [0; 3], &[0; MAX_SHORT_COMMAND_BYTES + 1])),
            Err(Error::Bounds)
        );
    }

    #[test]
    fn writes_exact_bounded_responses_without_partial_failure() {
        let mut output = [0xa5; MAX_RESPONSE_MESSAGE_BYTES];
        let written = write_data_block(
            &mut output,
            0,
            0x37,
            IccStatus::Active,
            CommandStatus::Success,
            0,
            b"reply",
        )
        .unwrap();
        assert_eq!(written, 15);
        assert_eq!(&output[..10], &[0x80, 5, 0, 0, 0, 0, 0x37, 0, 0, 0]);
        assert_eq!(&output[10..15], b"reply");
        assert_eq!(output[15], 0xa5);

        let mut short = [0x5a; 9];
        assert_eq!(
            write_data_block(
                &mut short,
                0,
                1,
                IccStatus::Active,
                CommandStatus::Success,
                0,
                &[]
            ),
            Err(Error::Bounds)
        );
        assert_eq!(short, [0x5a; 9]);

        assert_eq!(
            write_slot_status(
                &mut output,
                4,
                9,
                IccStatus::Inactive,
                CommandStatus::Failed,
                7
            ),
            Ok(10)
        );
        assert_eq!(&output[..10], &[0x81, 0, 0, 0, 0, 4, 9, 0x41, 7, 0]);
        assert_eq!(write_slot_change(&mut output, true), Ok(2));
        assert_eq!(&output[..2], &[0x50, 3]);
    }

    #[test]
    fn every_short_message_length_is_bounded_and_panic_free() {
        for size in 0..=MAX_COMMAND_MESSAGE_BYTES + 1 {
            let input = vec![0; size];
            let _ = decode(&input);
        }
    }

    #[test]
    fn slot_state_requires_power_and_completes_only_the_active_sequence() {
        let mut slot = SlotState::new();
        assert_eq!(slot.icc_status(), IccStatus::Inactive);
        assert_eq!(
            slot.accept(Command::TransferBlock {
                sequence: 1,
                apdu: b"before-power"
            }),
            SlotAction::Failed {
                sequence: 1,
                response: ResponseKind::DataBlock,
                error: ERROR_ICC_MUTE
            }
        );
        assert_eq!(
            slot.accept(Command::PowerOn { sequence: 2 }),
            SlotAction::DataBlock {
                sequence: 2,
                data: &ATR
            }
        );
        assert_eq!(slot.icc_status(), IccStatus::Active);

        let raw = message(PC_TO_RDR_XFR_BLOCK, 3, [0; 3], b"borrowed");
        let action = slot.accept(decode(&raw).unwrap());
        let SlotAction::Dispatch { sequence, apdu } = action else {
            panic!()
        };
        assert_eq!(sequence, 3);
        assert_eq!(apdu.as_ptr(), raw[HEADER_BYTES..].as_ptr());
        assert_eq!(slot.in_flight_sequence(), Some(3));
        assert_eq!(slot.complete(4), Err(Error::Missing));
        assert_eq!(slot.in_flight_sequence(), Some(3));
        assert_eq!(slot.complete(3), Ok(()));
        assert_eq!(slot.in_flight_sequence(), None);
        assert_eq!(slot.complete(3), Err(Error::Missing));
    }

    #[test]
    fn slot_state_rejects_concurrent_commands_without_losing_the_first() {
        let mut slot = SlotState::new();
        let _ = slot.accept(Command::PowerOn { sequence: 1 });
        let _ = slot.accept(Command::TransferBlock {
            sequence: 2,
            apdu: b"first",
        });
        assert_eq!(
            slot.accept(Command::GetSlotStatus { sequence: 3 }),
            SlotAction::Failed {
                sequence: 3,
                response: ResponseKind::SlotStatus,
                error: ERROR_SLOT_BUSY
            }
        );
        assert_eq!(slot.in_flight_sequence(), Some(2));
        assert_eq!(slot.complete(2), Ok(()));
        assert_eq!(
            slot.accept(Command::PowerOff { sequence: 4 }),
            SlotAction::SlotStatus { sequence: 4 }
        );
        assert_eq!(slot.icc_status(), IccStatus::Inactive);
    }

    #[test]
    fn abort_pair_works_in_either_usb_pipe_order() {
        let mut slot = SlotState::new();
        let _ = slot.accept(Command::PowerOn { sequence: 1 });
        let _ = slot.accept(Command::TransferBlock {
            sequence: 2,
            apdu: b"first",
        });
        assert_eq!(slot.control_abort(0, 9), Ok(None));
        assert_eq!(
            slot.accept(Command::GetSlotStatus { sequence: 3 }),
            SlotAction::Failed {
                sequence: 3,
                response: ResponseKind::SlotStatus,
                error: ERROR_COMMAND_ABORTED
            }
        );
        assert_eq!(
            slot.accept(Command::Abort { sequence: 8 }),
            SlotAction::Failed {
                sequence: 8,
                response: ResponseKind::SlotStatus,
                error: ERROR_COMMAND_ABORTED
            }
        );
        assert_eq!(
            slot.accept(Command::Abort { sequence: 9 }),
            SlotAction::SlotStatus { sequence: 9 }
        );
        assert_eq!(slot.in_flight_sequence(), None);

        let _ = slot.accept(Command::TransferBlock {
            sequence: 10,
            apdu: b"second",
        });
        assert_eq!(
            slot.accept(Command::Abort { sequence: 11 }),
            SlotAction::AwaitAbortPair { sequence: 11 }
        );
        assert_eq!(
            slot.accept(Command::Abort { sequence: 13 }),
            SlotAction::Failed {
                sequence: 13,
                response: ResponseKind::SlotStatus,
                error: ERROR_SLOT_BUSY
            }
        );
        assert_eq!(
            slot.accept(Command::Abort { sequence: 11 }),
            SlotAction::AwaitAbortPair { sequence: 11 }
        );
        assert_eq!(slot.control_abort(0, 12), Ok(None));
        assert_eq!(
            slot.control_abort(0, 11),
            Ok(Some(SlotAction::SlotStatus { sequence: 11 }))
        );
        assert_eq!(slot.in_flight_sequence(), None);
        assert_eq!(slot.control_abort(1, 1), Err(Error::Missing));
    }

    #[test]
    fn disconnect_clears_power_command_and_abort_state() {
        let mut slot = SlotState::new();
        let _ = slot.accept(Command::PowerOn { sequence: 1 });
        let _ = slot.accept(Command::TransferBlock {
            sequence: 2,
            apdu: b"command",
        });
        let _ = slot.control_abort(0, 3);
        slot.disconnect();
        assert_eq!(slot, SlotState::new());
        assert_eq!(slot.icc_status(), IccStatus::Inactive);
        assert_eq!(slot.complete(2), Err(Error::Missing));
        assert_eq!(slot.control_abort(0, 3), Err(Error::Missing));
    }
}
