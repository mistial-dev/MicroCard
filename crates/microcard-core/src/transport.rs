//! Shared basic-channel dispatcher for UART and simulator.
use crate::{
    apdu::Command,
    engine::CardEngine,
    globalplatform::{self, StatusCursor},
    scp03::{Keys, Session},
    Error, Result,
};
use alloc::vec::Vec;

pub const ENTER_BOOTLOADER_APDU: [u8; 4] = [0x80, 0xfe, 0x55, 0xaa];

fn fixed_response(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    response
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::Quota)?;
    response.extend_from_slice(bytes);
    Ok(response)
}

fn fixed_response_or_empty(bytes: &[u8]) -> Vec<u8> {
    fixed_response(bytes).unwrap_or_default()
}

pub struct Endpoint<C: CardEngine> {
    card: C,
    keys: Keys,
    session: Option<Session>,
    status_cursor: Option<StatusCursor>,
    bootloader_requested: bool,
}
impl<C: CardEngine> Endpoint<C> {
    pub fn new(card: C, keys: Keys) -> Self {
        Self {
            card,
            keys,
            session: None,
            status_cursor: None,
            bootloader_requested: false,
        }
    }

    /// Consume a board bootloader request accepted through authenticated management.
    ///
    /// The portable transport records intent only. The board owns the reset mechanism and
    /// waits until the protected response has reached its physical transport.
    pub fn take_bootloader_request(&mut self) -> bool {
        core::mem::take(&mut self.bootloader_requested)
    }
    pub fn exchange(&mut self, raw: &[u8]) -> Vec<u8> {
        self.exchange_with_cancel(raw, &mut || false)
    }

    pub fn maintenance(&mut self) -> Result<()> {
        self.maintenance_with_cancel(&mut || false)
    }

    pub fn maintenance_with_cancel(
        &mut self,
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Result<()> {
        let result = self.card.maintenance_with_cancel(should_cancel);
        if result.is_err() {
            self.reset();
        }
        result
    }

    pub fn into_card(mut self) -> C {
        self.reset();
        self.card
    }

    /// Drop all transport-scoped authority and volatile application work.
    pub fn reset(&mut self) {
        self.session = None;
        self.status_cursor = None;
        self.card.abort_staging();
        self.card.abort_transaction();
    }

    pub fn exchange_with_cancel(
        &mut self,
        raw: &[u8],
        should_cancel: &mut dyn FnMut() -> bool,
    ) -> Vec<u8> {
        let mut cancelled = false;
        let result = self.handle(raw, &mut || {
            let requested = should_cancel();
            cancelled |= requested;
            requested
        });
        if cancelled {
            self.reset();
            return fixed_response_or_empty(&[0x69, 0x82]);
        }
        match result {
            Ok(r) => r,
            Err(_) => {
                self.reset();
                fixed_response_or_empty(&[0x69, 0x82])
            }
        }
    }
    fn handle(&mut self, raw: &[u8], should_cancel: &mut dyn FnMut() -> bool) -> Result<Vec<u8>> {
        let c = Command::parse(raw)?;
        if globalplatform::is_isd_select(&c) {
            let result = self.card.select_isd_with_cancel(should_cancel);
            self.reset();
            result?;
            return globalplatform::isd_fci();
        }
        if C::DIRECT_APDUS && matches!(c.cla, 0x00 | 0x10) {
            self.card.abort_staging();
            self.status_cursor = None;
            let result = if c.ins == 0xa4 && c.p1 == 4 {
                self.card.select_plain_with_cancel(&c, should_cancel)
            } else {
                self.card.process_plain_with_cancel(&c, should_cancel)
            };
            if self.card.take_security_reset() { self.session = None; }
            return match result {
                Ok(response) => Ok(response),
                Err(Error::Missing) => fixed_response(&[0x6a, 0x82]),
                Err(error) => Err(error),
            };
        }
        if c.cla == 0x00 && c.ins == 0xa4 && c.p1 == 0x04 {
            return fixed_response(&[0x6a, 0x82]);
        }
        if self.session.is_none() && c.cla == 0x80 && c.ins == 0xca {
            if let Some(mut data) = globalplatform::get_data(&c)? {
                data.extend_from_slice(&[0x90, 0x00]);
                return Ok(data);
            }
            return fixed_response(&[0x6a, 0x88]);
        }
        if c.cla == 0x80 && c.ins == 0x50 {
            self.session = None;
            self.status_cursor = None;
            self.card.restart_secure_channel(should_cancel)?;
            if c.p2 != 0 || !matches!(c.p1, 0 | 1) {
                return Err(Error::Format);
            }
            if c.data.len() != crate::scp03::CHALLENGE_BYTES {
                // Report the length itself rather than a generic failure. A host that
                // assumed the other challenge width learns which one to use, and
                // GlobalPlatformPro retries in S16 on exactly this status word.
                let mut wrong_length = Vec::new();
                wrong_length
                    .try_reserve_exact(2)
                    .map_err(|_| Error::Quota)?;
                wrong_length.extend([0x67, 0x00]);
                return Ok(wrong_length);
            }
            // A derived challenge spends a sequence counter value, so the counter is
            // taken before anything else can fail and the response carries it back.
            #[cfg_attr(not(feature = "scp03-pseudo-random"), allow(unused_mut))]
            let mut sequence = [0; crate::scp03::SEQUENCE_BYTES];
            #[cfg(feature = "scp03-pseudo-random")]
            let challenge = {
                let issued = match self.card.next_secure_channel_sequence() {
                    Ok(issued) => issued,
                    // The counter has no more values, so no further session can be opened
                    // without replacing the key set.
                    Err(_) => return fixed_response(&[0x69, 0x85]),
                };
                sequence.copy_from_slice(&issued.to_be_bytes()[1..]);
                crate::scp03::pseudo_random_challenge(
                    &self.keys,
                    sequence,
                    &globalplatform::ISD_AID,
                    self.card.crypto_provider(),
                )?
            };
            #[cfg(not(feature = "scp03-pseudo-random"))]
            let challenge = {
                let mut challenge = [0; crate::scp03::CHALLENGE_BYTES];
                self.card.random(&mut challenge)?;
                challenge
            };
            let (session, crypt) = Session::initiate_with(
                &self.keys,
                c.data[..].try_into().unwrap(),
                challenge,
                self.card.crypto_provider(),
            )?;
            self.session = Some(session);
            let mut r = Vec::new();
            // Ten key diversification bytes, three of key information, the challenge, the
            // card cryptogram, the sequence counter where the challenge is derived, then
            // the status word, SCP03 Table 7-3.
            let length =
                10 + 3 + 2 * crate::scp03::CHALLENGE_BYTES + crate::scp03::SEQUENCE_BYTES + 2;
            r.try_reserve_exact(length).map_err(|_| Error::Quota)?;
            r.resize(10, 0);
            // Key version, SCP identifier, then the i parameter this build implements.
            r.extend([1, 3, crate::scp03::SCP03_I]);
            r.extend(challenge);
            r.extend(crypt);
            r.extend(sequence);
            r.extend([0x90, 0]);
            return Ok(r);
        }
        let s = self.session.as_mut().ok_or(Error::Unauthorized)?;
        if c.cla == 0x84 && c.ins == 0x82 {
            s.authenticate_with(&c, self.card.crypto_provider())?;
            self.status_cursor = None;
            return fixed_response(&[0x90, 0]);
        }
        if !C::DIRECT_APDUS && c.cla != 0x84 {
            return Err(Error::Authentication);
        }
        let verified = s.unwrap_with(c, self.card.crypto_provider())?;
        let management_class = verified.command().cla == 0x80;
        if self.card.globalplatform_load_active()
            && !(management_class && verified.command().ins == 0xe8)
        {
            self.card.abort_staging();
        }
        let gp_management = management_class
            && (verified.command().ins == 0xe6 && matches!(verified.command().p1, 0x02 | 0x0c)
                || verified.command().ins == 0xe8 && self.card.globalplatform_load_active()
                || verified.command().ins == 0xe4
                    && verified.command().data.first().copied() == Some(0x4f));
        if gp_management {
            self.status_cursor = None;
            let (mut data, status) = match self.card.manage_globalplatform_with_cancel(verified, should_cancel) {
                Ok(data) => (data, 0x9000u16),
                Err(error) => (Vec::new(), globalplatform_management_status(&error)),
            };
            if self.card.take_security_reset() {
                self.session = None;
                data.try_reserve_exact(2).map_err(|_| Error::Quota)?;
                data.extend_from_slice(&status.to_be_bytes());
                return Ok(data);
            }
            return s.response_with(&data, status, self.card.crypto_provider());
        }
        if management_class && verified.command().ins == 0xca {
            self.status_cursor = None;
            let data = globalplatform::get_data(verified.command())?;
            return s.response_with(
                data.as_deref().unwrap_or_default(),
                if data.is_some() { 0x9000 } else { 0x6a88 },
                self.card.crypto_provider(),
            );
        }
        if management_class && verified.command().ins == ENTER_BOOTLOADER_APDU[1] {
            let command = verified.command();
            if verified.level() & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
                return s.response_with(&[], 0x6985, self.card.crypto_provider());
            }
            if command.p1 != ENTER_BOOTLOADER_APDU[2]
                || command.p2 != ENTER_BOOTLOADER_APDU[3]
                || !command.data.is_empty()
                || command.le.is_some()
            {
                return s.response_with(&[], 0x6a80, self.card.crypto_provider());
            }
            let response = s.response_with(&[], 0x9000, self.card.crypto_provider())?;
            self.bootloader_requested = true;
            return Ok(response);
        }
        if management_class && verified.command().ins == 0xf2 {
            let command = verified.command();
            if verified.level() & crate::scp03::MANAGEMENT_SECURITY_LEVEL == 0 {
                return s.response_with(&[], 0x6985, self.card.crypto_provider());
            }
            if command.p1 == 0x80 && command.p2 == 0x03 {
                self.status_cursor = None;
                return s.response_with(&[], 0x6a80, self.card.crypto_provider());
            }
            let cursor_result = if command.p2 == 0x02 {
                StatusCursor::first(command.p1, command.p2, &command.data)
            } else {
                self.status_cursor
                    .take()
                    .filter(|cursor| cursor.matches_next(command.p1, command.p2, &command.data))
                    .ok_or(Error::Format)
            };
            let mut cursor = match cursor_result {
                Ok(cursor) => cursor,
                Err(_) => {
                    self.status_cursor = None;
                    return s.response_with(&[], 0x6a80, self.card.crypto_provider());
                }
            };
            match self
                .card
                .get_status_record(cursor.p1, cursor.next, cursor.filter())
            {
                Ok((record, more)) => {
                    cursor.next += 1;
                    self.status_cursor = more.then_some(cursor);
                    return s.response_with(
                        &record,
                        if more { 0x6310 } else { 0x9000 },
                        self.card.crypto_provider(),
                    );
                }
                Err(Error::Missing) => {
                    self.status_cursor = None;
                    return s.response_with(&[], 0x6a88, self.card.crypto_provider());
                }
                Err(_) => {
                    self.status_cursor = None;
                    return s.response_with(&[], 0x6a80, self.card.crypto_provider());
                }
            }
        }
        self.status_cursor = None;
        if self.card.is_application_command(verified.command()) {
            let r = if verified.command().ins == 0xa4 {
                match self
                    .card
                    .select_verified_with_cancel(verified, should_cancel)
                {
                    Ok(response) => response,
                    Err(_) => return s.response_with(&[], 0x6985, self.card.crypto_provider()),
                }
            } else {
                self.card
                    .process_verified_with_cancel(verified, should_cancel)?
            };
            if self.card.take_security_reset() {
                self.session = None;
                self.status_cursor = None;
                return Ok(r);
            }
            let n = r.len();
            if n < 2 {
                return Err(Error::Format);
            }
            return s.response_with(
                &r[..n - 2],
                u16::from_be_bytes([r[n - 2], r[n - 1]]),
                self.card.crypto_provider(),
            );
        }
        let result = self.card.manage_with_cancel(verified, should_cancel);
        match result {
            Ok(data) => s.response_with(&data, 0x9000, self.card.crypto_provider()),
            Err(_) => s.response_with(&[], 0x6985, self.card.crypto_provider()),
        }
    }
}

fn globalplatform_management_status(error: &Error) -> u16 {
    match error {
        Error::Unauthorized | Error::KeyMismatch | Error::Signature => 0x6982,
        Error::Missing | Error::Domain => 0x6a88,
        Error::Quota => 0x6a84,
        Error::Format | Error::Bounds | Error::Unsupported => 0x6a80,
        _ => 0x6985,
    }
}

#[cfg(all(test, feature = "mc04"))]
mod tests {
    use super::*;
    use crate::{domains::Mc04Engine, journal::MemoryFlash};
    use alloc::vec;

    struct TestPlatform;
    impl crate::crypto::CryptoProvider for TestPlatform {}
    impl crate::hal::Entropy for TestPlatform {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
            output.fill(0x5a);
            Ok(())
        }
    }
    impl crate::hal::LogicalGpio for TestPlatform {
        fn write_gpio(&mut self, _: i32, _: i32) -> Result<()> {
            Err(Error::Unauthorized)
        }
    }

    fn endpoint() -> Endpoint<Mc04Engine<MemoryFlash, TestPlatform>> {
        Endpoint::new(
            Mc04Engine::open(MemoryFlash::new(16384), TestPlatform, [0x33; 16]).unwrap(),
            Keys {
                enc: [0x11; 16],
                mac: [0x22; 16],
            },
        )
    }

    #[test]
    fn default_isd_select_is_available_before_scp03() {
        let mut endpoint = endpoint();
        assert_eq!(
            endpoint.exchange(&[0x00, 0xa4, 0x04, 0x00, 0x00]),
            globalplatform::isd_fci().unwrap()
        );
        let mut command = vec![0x00, 0xa4, 0x04, 0x00, 8];
        command.extend_from_slice(&globalplatform::ISD_AID);
        assert_eq!(
            endpoint.exchange(&command),
            globalplatform::isd_fci().unwrap()
        );

        let mut card_data = globalplatform::card_recognition_data().unwrap();
        card_data.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(
            endpoint.exchange(&[0x80, 0xca, 0x00, 0x66, 0x00]),
            card_data
        );
        assert_eq!(
            endpoint.exchange(&[0x80, 0xca, 0x9f, 0x7f, 0x00]),
            [0x6a, 0x88]
        );

        assert_eq!(endpoint.exchange(&ENTER_BOOTLOADER_APDU), [0x69, 0x82]);
        assert!(!endpoint.take_bootloader_request());

        command[12] ^= 1;
        assert_eq!(endpoint.exchange(&command), [0x6a, 0x82]);
    }

    #[cfg(feature = "scp03-pseudo-random")]
    #[test]
    fn the_sequence_counter_advances_and_never_repeats_across_a_restart() {
        use crate::scp03::{CHALLENGE_BYTES, SEQUENCE_BYTES};
        let offset = 13 + 2 * CHALLENGE_BYTES;
        let initialize_update = |endpoint: &mut Endpoint<Mc04Engine<MemoryFlash, TestPlatform>>| {
            let mut command = vec![0x80, 0x50, 0, 0, CHALLENGE_BYTES as u8];
            command.extend(core::iter::repeat_n(0x77, CHALLENGE_BYTES));
            command.push(0);
            let response = endpoint.exchange(&command);
            assert_eq!(response.len(), offset + SEQUENCE_BYTES + 2);
            assert_eq!(&response[response.len() - 2..], &[0x90, 0x00]);
            (
                response[offset..offset + SEQUENCE_BYTES].to_vec(),
                response[13..13 + CHALLENGE_BYTES].to_vec(),
            )
        };

        // The card keeps its flash, which is what a power cycle leaves behind.
        let mut flash = MemoryFlash::new(16384);
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..3 {
            let mut endpoint = Endpoint::new(
                Mc04Engine::open(flash, TestPlatform, [0x33; 16]).unwrap(),
                Keys {
                    enc: [0x11; 16],
                    mac: [0x22; 16],
                },
            );
            for _ in 0..4 {
                let (sequence, challenge) = initialize_update(&mut endpoint);
                // Every counter value is new, and the challenge moves with it even though
                // the platform entropy source is a constant.
                assert!(
                    !seen.iter().any(|(s, _)| s == &sequence),
                    "counter repeated"
                );
                assert!(
                    !seen.iter().any(|(_, c)| c == &challenge),
                    "challenge repeated"
                );
                seen.push((sequence, challenge));
            }
            flash = endpoint.card.into_flash();
        }
    }
}
