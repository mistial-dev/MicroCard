use microcard_core::{
    crypto::CryptoProvider,
    hal::{Entropy, LogicalGpio},
    Error, Result,
};

pub struct Hardware;
impl CryptoProvider for Hardware {}
impl Entropy for Hardware {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
        output.fill(0);
        let result = getrandom::getrandom(output).map_err(|_| Error::Native);
        microcard_core::crypto::clear_output_on_error(output, result)
    }
}
impl LogicalGpio for Hardware {
    fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()> {
        if resource != 0 || !(0..=1).contains(&value) {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod deterministic {
    use super::*;
    use microcard_core::{
        framing::Decoder,
        hal::{
            conformance::{self, Control},
            ApduTransport, DeviceIdentity, MonotonicClock, ResetReason, ResetReport, StagingFlash,
            Watchdog,
        },
    };
    use std::collections::VecDeque;

    pub struct DeterministicHardware {
        state: u64,
        fail_entropy: bool,
        allow_gpio: bool,
    }
    impl DeterministicHardware {
        pub fn new(seed: u64) -> Self {
            Self {
                state: seed,
                fail_entropy: false,
                allow_gpio: true,
            }
        }

        pub fn fail_entropy(&mut self) {
            self.fail_entropy = true;
        }

        pub fn deny_gpio(&mut self) {
            self.allow_gpio = false;
        }
    }
    impl CryptoProvider for DeterministicHardware {}
    impl Entropy for DeterministicHardware {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
            if self.fail_entropy {
                output.fill(0);
                return Err(Error::Native);
            }
            for byte in output {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                *byte = self.state as u8;
            }
            Ok(())
        }
    }
    impl LogicalGpio for DeterministicHardware {
        fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()> {
            if !self.allow_gpio {
                return Err(Error::Unauthorized);
            }
            if resource != 0 || !(0..=1).contains(&value) {
                return Err(Error::Bounds);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct DeterministicClock {
        now: u64,
    }
    impl DeterministicClock {
        pub fn advance(&mut self, ticks: u64) {
            self.now = self.now.saturating_add(ticks);
        }
    }
    impl MonotonicClock for DeterministicClock {
        fn ticks(&mut self) -> u64 {
            self.now
        }

        fn ticks_per_second(&self) -> u32 {
            1_000_000
        }
    }

    #[derive(Default)]
    pub struct DeterministicWatchdog {
        now: u64,
        timeout: Option<u64>,
        deadline: Option<u64>,
    }
    impl DeterministicWatchdog {
        pub fn advance(&mut self, ticks: u64) {
            self.now = self.now.saturating_add(ticks);
        }
    }
    impl Watchdog for DeterministicWatchdog {
        fn arm(&mut self, timeout_ticks: u64) -> Result<()> {
            if timeout_ticks == 0 {
                return Err(Error::Bounds);
            }
            self.timeout = Some(timeout_ticks);
            self.deadline = Some(self.now.saturating_add(timeout_ticks));
            Ok(())
        }

        fn feed(&mut self) -> Result<()> {
            let timeout = self.timeout.ok_or(Error::Native)?;
            if self.now >= self.deadline.ok_or(Error::Native)? {
                return Err(Error::Native);
            }
            self.deadline = Some(self.now.saturating_add(timeout));
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct FragmentTransport {
        decoder: Decoder,
        input: VecDeque<u8>,
        now: u32,
        sent: Vec<u8>,
    }
    impl FragmentTransport {
        pub fn queue(&mut self, fragment: &[u8]) {
            self.input.extend(fragment.iter().copied());
        }
    }
    impl ApduTransport for FragmentTransport {
        fn receive(&mut self, output: &mut [u8], deadline_ticks: u64) -> Result<usize> {
            while let Some(byte) = self.input.pop_front() {
                self.now = self.now.wrapping_add(1);
                if let Some(frame) = self.decoder.push(byte, self.now) {
                    if frame.len() > output.len() {
                        return Err(Error::Bounds);
                    }
                    output[..frame.len()].copy_from_slice(frame);
                    return Ok(frame.len());
                }
            }
            self.now = deadline_ticks as u32;
            self.decoder.expire(self.now);
            Err(Error::Native)
        }

        fn send(&mut self, input: &[u8], _: u64) -> Result<()> {
            self.sent.extend_from_slice(input);
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct DeterministicStaging {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
    }
    impl DeterministicStaging {
        pub fn new(capacity: usize) -> Self {
            Self {
                bytes: vec![0xff; capacity],
                fail_after: None,
            }
        }

        pub fn fail_after(&mut self, bytes: usize) {
            self.fail_after = Some(bytes);
        }
    }
    impl StagingFlash for DeterministicStaging {
        fn capacity(&self) -> usize {
            self.bytes.len()
        }

        fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
            let source = self
                .bytes
                .get(offset..offset.checked_add(output.len()).ok_or(Error::Bounds)?)
                .ok_or(Error::Bounds)?;
            output.copy_from_slice(source);
            Ok(())
        }

        fn erase(&mut self) -> Result<()> {
            self.bytes.fill(0xff);
            Ok(())
        }

        fn program(&mut self, offset: usize, input: &[u8]) -> Result<()> {
            let end = offset.checked_add(input.len()).ok_or(Error::Bounds)?;
            let target = self.bytes.get_mut(offset..end).ok_or(Error::Bounds)?;
            if target
                .iter()
                .zip(input)
                .any(|(current, next)| current & next != *next)
            {
                return Err(Error::Storage);
            }
            let written = self
                .fail_after
                .take()
                .unwrap_or(input.len())
                .min(input.len());
            for (target, next) in target.iter_mut().zip(input).take(written) {
                *target &= *next;
            }
            if written != input.len() {
                return Err(Error::Native);
            }
            Ok(())
        }
    }

    pub struct DeterministicHal {
        hardware: DeterministicHardware,
        clock: DeterministicClock,
        watchdog: DeterministicWatchdog,
        transport: FragmentTransport,
        staging: DeterministicStaging,
        reset_reason: ResetReason,
    }
    impl DeterministicHal {
        fn new() -> Self {
            Self {
                hardware: DeterministicHardware::new(0),
                clock: DeterministicClock::default(),
                watchdog: DeterministicWatchdog::default(),
                transport: FragmentTransport::default(),
                staging: DeterministicStaging::new(16),
                reset_reason: ResetReason::PowerOn,
            }
        }
    }
    impl CryptoProvider for DeterministicHal {}
    impl Entropy for DeterministicHal {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<()> {
            self.hardware.fill_entropy(output)
        }
    }
    impl LogicalGpio for DeterministicHal {
        fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()> {
            self.hardware.write_gpio(resource, value)
        }
    }
    impl MonotonicClock for DeterministicHal {
        fn ticks(&mut self) -> u64 {
            self.clock.ticks()
        }

        fn ticks_per_second(&self) -> u32 {
            self.clock.ticks_per_second()
        }
    }
    impl Watchdog for DeterministicHal {
        fn arm(&mut self, timeout_ticks: u64) -> Result<()> {
            self.watchdog.arm(timeout_ticks)
        }

        fn feed(&mut self) -> Result<()> {
            self.watchdog.feed()
        }
    }
    impl ApduTransport for DeterministicHal {
        fn receive(&mut self, output: &mut [u8], deadline_ticks: u64) -> Result<usize> {
            self.transport.receive(output, deadline_ticks)
        }

        fn send(&mut self, input: &[u8], deadline_ticks: u64) -> Result<()> {
            self.transport.send(input, deadline_ticks)
        }
    }
    impl StagingFlash for DeterministicHal {
        fn capacity(&self) -> usize {
            self.staging.capacity()
        }

        fn read(&self, offset: usize, output: &mut [u8]) -> Result<()> {
            self.staging.read(offset, output)
        }

        fn erase(&mut self) -> Result<()> {
            self.staging.erase()
        }

        fn program(&mut self, offset: usize, input: &[u8]) -> Result<()> {
            self.staging.program(offset, input)
        }
    }
    impl DeviceIdentity for DeterministicHal {
        fn read_identity(&self, output: &mut [u8]) -> Result<usize> {
            const IDENTITY: [u8; 8] = *b"MCRDSIM1";
            let destination = output.get_mut(..IDENTITY.len()).ok_or(Error::Bounds)?;
            destination.copy_from_slice(&IDENTITY);
            Ok(IDENTITY.len())
        }
    }
    impl ResetReport for DeterministicHal {
        fn reset_reason(&self) -> ResetReason {
            self.reset_reason
        }
    }
    impl Control for DeterministicHal {
        fn reset_entropy(&mut self, seed: u64) {
            self.hardware = DeterministicHardware::new(seed);
        }

        fn fail_entropy(&mut self) {
            self.hardware.fail_entropy();
        }

        fn deny_gpio(&mut self) {
            self.hardware.deny_gpio();
        }

        fn set_reset_reason(&mut self, reason: ResetReason) {
            self.reset_reason = reason;
        }

        fn advance_clock(&mut self, ticks: u64) {
            self.clock.advance(ticks);
        }

        fn advance_watchdog(&mut self, ticks: u64) {
            self.watchdog.advance(ticks);
        }

        fn queue_transport(&mut self, fragment: &[u8]) {
            self.transport.queue(fragment);
        }

        fn sent_response(&self) -> &[u8] {
            &self.transport.sent
        }

        fn fail_staging_after(&mut self, bytes: usize) {
            self.staging.fail_after(bytes);
        }

        fn power_cycle_staging(&mut self) {
            self.staging = self.staging.clone();
            self.staging.fail_after = None;
        }
    }

    #[test]
    fn simulator_hal_conformance() {
        conformance::run(&mut DeterministicHal::new()).unwrap();
    }
}
