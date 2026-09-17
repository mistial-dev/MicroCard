use microcard_core::{
    ccid,
    ccid_usb::{
        self, BulkOutAssembler, ControlCommand, Controller, ControllerAction, SetupPacket,
        BULK_PACKET_BYTES,
    },
    Error,
};
use usb_device::{class_prelude::*, UsbError};

include!(concat!(env!("OUT_DIR"), "/usb_identity.rs"));

pub struct BoardUsbd;

unsafe impl nrf_usbd::UsbPeripheral for BoardUsbd {
    const REGISTERS: *const () = 0x4002_7000 as *const ();
}

pub type UsbBus = nrf_usbd::Usbd<BoardUsbd>;

pub fn power_ready() -> bool {
    const POWER_USBREGSTATUS: usize = 0x4000_0438;
    const READY: u32 = 0b11;
    // SAFETY: USBREGSTATUS is a read-only, word-aligned POWER register.
    unsafe { core::ptr::read_volatile(POWER_USBREGSTATUS as *const u32) & READY == READY }
}

pub struct CcidClass<'bus, B: usb_device::bus::UsbBus> {
    interface: InterfaceNumber,
    interface_string: StringIndex,
    bulk_out: EndpointOut<'bus, B>,
    bulk_in: EndpointIn<'bus, B>,
    interrupt_in: EndpointIn<'bus, B>,
    packet: [u8; BULK_PACKET_BYTES],
    assembler: BulkOutAssembler,
    controller: Controller,
    response: [u8; ccid::MAX_RESPONSE_MESSAGE_BYTES],
    response_length: usize,
    response_offset: usize,
    response_zlp: bool,
    final_packet_queued: bool,
    pending_sequence: Option<u8>,
    execution_active: bool,
    notification_pending: bool,
    session_reset_pending: bool,
}

impl<'bus, B: usb_device::bus::UsbBus> CcidClass<'bus, B> {
    pub fn new(allocator: &'bus UsbBusAllocator<B>) -> Self {
        Self {
            interface: allocator.interface(),
            interface_string: allocator.string(),
            bulk_out: allocator.bulk(BULK_PACKET_BYTES as u16),
            bulk_in: allocator.bulk(BULK_PACKET_BYTES as u16),
            interrupt_in: allocator.interrupt(ccid_usb::INTERRUPT_PACKET_BYTES, 255),
            packet: [0; BULK_PACKET_BYTES],
            assembler: BulkOutAssembler::default(),
            controller: Controller::new(),
            response: [0; ccid::MAX_RESPONSE_MESSAGE_BYTES],
            response_length: 0,
            response_offset: 0,
            response_zlp: false,
            final_packet_queued: false,
            pending_sequence: None,
            execution_active: false,
            notification_pending: true,
            session_reset_pending: false,
        }
    }

    pub fn take_session_reset(&mut self) -> bool {
        core::mem::take(&mut self.session_reset_pending)
    }

    pub fn pending_apdu(&mut self) -> Option<(u8, &[u8])> {
        if self.execution_active {
            return None;
        }
        let sequence = self.pending_sequence?;
        let message = self.assembler.message()?;
        self.execution_active = true;
        Some((sequence, &message[ccid::HEADER_BYTES..]))
    }

    pub fn execution_cancelled(&self, sequence: u8) -> bool {
        self.pending_sequence != Some(sequence)
            || !self.controller.command_in_flight(sequence)
    }

    pub fn acknowledge_cancelled(&mut self, sequence: u8) -> Result<(), Error> {
        if self.pending_sequence != Some(sequence)
            || self.controller.command_in_flight(sequence)
        {
            return Err(Error::Missing);
        }
        self.pending_sequence = None;
        self.execution_active = false;
        self.assembler.release();
        Ok(())
    }

    pub fn abort_pending(&self, sequence: u8) -> bool {
        self.pending_sequence == Some(sequence) && self.controller.abort_pending(sequence)
    }

    pub fn complete_apdu(&mut self, sequence: u8, response: &[u8]) -> Result<(), Error> {
        if self.pending_sequence != Some(sequence) {
            return Err(Error::Missing);
        }
        let length = self
            .controller
            .complete(sequence, response, &mut self.response)?;
        self.pending_sequence = None;
        self.execution_active = false;
        self.assembler.release();
        self.queue_response(length);
        Ok(())
    }

    pub fn fail_apdu(&mut self, sequence: u8, error: u8) -> Result<(), Error> {
        if self.pending_sequence != Some(sequence) {
            return Err(Error::Missing);
        }
        let length = self.controller.fail(sequence, error, &mut self.response)?;
        self.pending_sequence = None;
        self.execution_active = false;
        self.assembler.release();
        self.queue_response(length);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.reset_state();
        self.notification_pending = true;
        self.session_reset_pending = true;
    }

    fn queue_response(&mut self, length: usize) {
        self.response_length = length;
        self.response_offset = 0;
        self.response_zlp = length.is_multiple_of(BULK_PACKET_BYTES);
        self.final_packet_queued = false;
    }

    fn response_pending(&self) -> bool {
        self.response_length != 0 || self.final_packet_queued
    }

    fn pump_response(&mut self) {
        if self.final_packet_queued || self.response_length == 0 {
            return;
        }
        if self.response_offset < self.response_length {
            let end = core::cmp::min(
                self.response_offset + BULK_PACKET_BYTES,
                self.response_length,
            );
            match self
                .bulk_in
                .write(&self.response[self.response_offset..end])
            {
                Ok(_) => {
                    self.response_offset = end;
                    if end == self.response_length && !self.response_zlp {
                        self.final_packet_queued = true;
                    }
                }
                Err(UsbError::WouldBlock) => {}
                Err(_) => self.reset_state(),
            }
        } else if self.response_zlp {
            match self.bulk_in.write(&[]) {
                Ok(_) => {
                    self.response_zlp = false;
                    self.final_packet_queued = true;
                }
                Err(UsbError::WouldBlock) => {}
                Err(_) => self.reset_state(),
            }
        }
    }

    fn pump_notification(&mut self) {
        if !self.notification_pending {
            return;
        }
        let mut notification = [0u8; 2];
        let Ok(length) = ccid::write_slot_change(&mut notification, true) else {
            return;
        };
        match self.interrupt_in.write(&notification[..length]) {
            Ok(_) => self.notification_pending = false,
            Err(UsbError::WouldBlock) => {}
            Err(_) => self.notification_pending = false,
        }
    }

    fn reset_state(&mut self) {
        self.assembler.disconnect();
        self.controller.disconnect();
        self.pending_sequence = None;
        self.execution_active = false;
        self.response[..self.response_length].fill(0);
        self.response_length = 0;
        self.response_offset = 0;
        self.response_zlp = false;
        self.final_packet_queued = false;
    }

    fn release_completed_abort(&mut self) {
        let Some(sequence) = self.pending_sequence else {
            return;
        };
        if self.controller.command_in_flight(sequence) {
            return;
        }
        self.pending_sequence = None;
        self.execution_active = false;
        self.assembler.release();
    }

    fn handle_complete_message(&mut self) {
        let Some(message) = self.assembler.message() else {
            return;
        };
        if matches!(
            message.first(),
            Some(&ccid::PC_TO_RDR_ICC_POWER_ON) | Some(&ccid::PC_TO_RDR_ICC_POWER_OFF)
        ) {
            self.session_reset_pending = true;
        }
        match self.controller.handle_bulk(message, &mut self.response) {
            Ok(ControllerAction::Response { length }) => {
                self.assembler.release();
                self.queue_response(length);
            }
            Ok(ControllerAction::Dispatch { sequence, .. }) => {
                self.pending_sequence = Some(sequence);
            }
            Ok(ControllerAction::AwaitAbortPair { .. }) => self.assembler.release(),
            Err(_) => self.reset_state(),
        }
    }
}

impl<B: usb_device::bus::UsbBus> UsbClass<B> for CcidClass<'_, B> {
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.interface_alt(self.interface, 0, 0x0b, 0, 0, Some(self.interface_string))?;
        writer.write(0x21, &ccid_usb::CONFIGURATION_DESCRIPTOR[20..20 + 52])?;
        writer.endpoint(&self.bulk_out)?;
        writer.endpoint(&self.bulk_in)?;
        writer.endpoint(&self.interrupt_in)?;
        Ok(())
    }

    fn get_string(&self, index: StringIndex, _lang_id: LangID) -> Option<&str> {
        (index == self.interface_string).then_some("MicroCard CCID")
    }

    fn reset(&mut self) {
        self.disconnect();
    }

    fn poll(&mut self) {
        self.pump_response();
        self.pump_notification();
    }

    fn endpoint_in_complete(&mut self, address: EndpointAddress) {
        if address != self.bulk_in.address() {
            return;
        }
        if self.final_packet_queued {
            self.response[..self.response_length].fill(0);
            self.response_length = 0;
            self.response_offset = 0;
            self.final_packet_queued = false;
        } else {
            self.pump_response();
        }
    }

    fn endpoint_out(&mut self, address: EndpointAddress) {
        if address != self.bulk_out.address() || self.response_pending() {
            return;
        }
        let Ok(length) = self.bulk_out.read(&mut self.packet) else {
            return;
        };
        if self.pending_sequence.is_some() {
            match self
                .controller
                .handle_bulk(&self.packet[..length], &mut self.response)
            {
                Ok(ControllerAction::Response { length }) => self.queue_response(length),
                Ok(ControllerAction::AwaitAbortPair { .. }) => {}
                Ok(ControllerAction::Dispatch { .. }) | Err(_) => {}
            }
            self.release_completed_abort();
            return;
        }
        let first_packet = self.assembler.is_idle();
        match self.assembler.push(&self.packet[..length]) {
            Ok(Some(_)) => self.handle_complete_message(),
            Ok(None) => {}
            Err(_) if first_packet && length >= ccid::HEADER_BYTES => {
                if let Ok(ControllerAction::Response { length }) = self
                    .controller
                    .handle_bulk(&self.packet[..length], &mut self.response)
                {
                    self.queue_response(length);
                }
            }
            Err(_) => self.reset_state(),
        }
    }

    fn control_out(&mut self, transfer: ControlOut<B>) {
        use usb_device::control::{Recipient, RequestType};

        let request = *transfer.request();
        let request_type = if request.request_type == RequestType::Class
            && request.recipient == Recipient::Interface
        {
            ccid_usb::CLASS_INTERFACE_OUT
        } else {
            0
        };
        let setup = SetupPacket {
            request_type,
            request: request.request,
            value: request.value,
            index: request.index,
            length: request.length,
        };
        let interface = u8::from(self.interface);
        let accepted = match ccid_usb::parse_control(setup, interface) {
            Ok(ControlCommand::Abort { slot, sequence }) => {
                match self
                    .controller
                    .control_abort(slot, sequence, &mut self.response)
                {
                    Ok(Some(length)) => {
                        self.queue_response(length);
                        self.release_completed_abort();
                    }
                    Ok(None) => {}
                    Err(_) => {
                        let _ = transfer.reject();
                        return;
                    }
                }
                true
            }
            Err(_) => false,
        };
        if accepted {
            let _ = transfer.accept();
        } else {
            let _ = transfer.reject();
        }
    }
}
