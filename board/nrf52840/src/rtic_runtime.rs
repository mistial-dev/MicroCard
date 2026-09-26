//! USB runs above the VM. Flash maintenance and APDUs share one lower-priority card owner.

#[cfg(feature = "dongle-layout")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicBool, Ordering};

use super::*;

static RESET_PENDING: AtomicBool = AtomicBool::new(false);
static WORK_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "dongle-layout")]
static UF2_AT: AtomicU32 = AtomicU32::new(0);

// RTIC moves local resources from init into their owning task. The endpoint
// stays exclusively in worker on this single-core MCU; its Rc image leases
// are never accessed by an interrupt task.
struct WorkerEndpoint(Endpoint<BoardCard>);
unsafe impl Send for WorkerEndpoint {}

#[rtic::app(device = nrf52840_pac, dispatchers = [SWI0_EGU0])]
mod app {
    use super::*;

    #[shared]
    struct Shared {}

    #[local]
    struct Local {
        endpoint: WorkerEndpoint,
        responder: usb_ccid::ApduResponder<'static>,
        maintenance_at: Option<u32>,
        usb_parts: Option<(pac::CLOCK, pac::USBD, usb_ccid::ApduRequester<'static>)>,
        usb_stack: Option<(BoardUsbDevice, BoardCcidClass)>,
        usb_started: bool,
        extension_at: Option<u32>,
        configuration_at: Option<u32>,
        ticks: u32,
    }

    #[init]
    fn init(cx: init::Context) -> (Shared, Local) {
        let (card, keys) = initialize_card();
        let (requester, responder) = APDU_CHANNEL.split().unwrap_or_else(|| {
            let mut watchdog = BoardWatchdog;
            halt_with_diagnostic(&mut watchdog, 0x0a)
        });
        let timer = cx.device.TIMER1;
        timer.mode.write(|w| w.mode().timer());
        timer.bitmode.write(|w| w.bitmode()._32bit());
        timer.prescaler.write(|w| unsafe { w.prescaler().bits(4) });
        timer.cc[0].write(|w| unsafe { w.cc().bits(1_000) });
        timer.shorts.write(|w| w.compare0_clear().enabled());
        timer.intenset.write(|w| w.compare0().set());
        timer.tasks_start.write(|w| unsafe { w.bits(1) });
        cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD);
        (
            Shared {},
            Local {
                endpoint: WorkerEndpoint(Endpoint::new(card, keys)),
                responder,
                maintenance_at: None,
                usb_parts: Some((cx.device.CLOCK, cx.device.USBD, requester)),
                usb_stack: None,
                usb_started: false,
                extension_at: None,
                configuration_at: None,
                ticks: 0,
            },
        )
    }

    #[task(binds = TIMER1, priority = 2, local = [ticks])]
    fn tick(cx: tick::Context) {
        let timer = unsafe { &*pac::TIMER1::ptr() };
        timer.events_compare[0].write(|w| w);
        feed();
        *cx.local.ticks = cx.local.ticks.wrapping_add(1);
        cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD);
        if WORK_PENDING.load(Ordering::Acquire) || (*cx.local.ticks).is_multiple_of(250) {
            let _ = worker::spawn();
        }
        #[cfg(feature = "dongle-layout")]
        {
            let deadline = UF2_AT.load(Ordering::Relaxed);
            if deadline != 0 && now().wrapping_sub(deadline) < 0x8000_0000 {
                enter_uf2();
            }
        }
    }

    #[task(binds = USBD, priority = 3, local = [usb_parts, usb_stack, usb_started, extension_at, configuration_at])]
    fn usb(cx: usb::Context) {
        let powered = usb_ccid::power_ready();
        if powered && cx.local.usb_stack.is_none() {
            if let Some((clock, usbd, requester)) = cx.local.usb_parts.take() {
                *cx.local.usb_stack = initialize_usb(clock, usbd, requester);
                if cx.local.usb_stack.is_none() {
                    let mut watchdog = BoardWatchdog;
                    halt_with_diagnostic(&mut watchdog, 0x0b);
                }
                *cx.local.usb_started = true;
                #[cfg(feature = "latency-trace")]
                trace::record(trace::event::USB_READY, 0);
                #[cfg(feature = "dongle-layout")]
                {
                    *cx.local.configuration_at = Some(now().wrapping_add(5_000_000));
                }
            }
        }
        let Some((device, class)) = cx.local.usb_stack.as_mut() else {
            return;
        };
        if !powered {
            if *cx.local.usb_started {
                if !device.bus().vbus_removed() {
                    let mut watchdog = BoardWatchdog;
                    halt_with_diagnostic(&mut watchdog, 0x0c);
                }
                *cx.local.usb_started = false;
                *cx.local.extension_at = None;
                RESET_PENDING.store(true, Ordering::Release);
                let _ = worker::spawn();
                #[cfg(feature = "latency-trace")]
                trace::record(trace::event::USB_POWER_LOST, 0);
                #[cfg(feature = "dongle-layout")]
                led_color(LedColor::Blue);
            }
            return;
        }
        if !*cx.local.usb_started {
            #[cfg(all(feature = "development-recovery", feature = "dongle-layout"))]
            set_uf2_recovery_marker(0x57);
            if !device.bus().vbus_present() {
                let mut watchdog = BoardWatchdog;
                halt_with_diagnostic(&mut watchdog, 0x0d);
            }
            *cx.local.usb_started = true;
            #[cfg(feature = "dongle-layout")]
            {
                led_color(LedColor::Blue);
                *cx.local.configuration_at = Some(now().wrapping_add(5_000_000));
            }
        }
        class.check_for_app_response();
        #[cfg(feature = "latency-trace")]
        trace::usb_poll();
        let _ = device.poll(&mut [class]);
        #[cfg(feature = "dongle-layout")]
        match device.state() {
            UsbDeviceState::Configured => {
                if cx.local.configuration_at.take().is_some() {
                    #[cfg(feature = "development-recovery")]
                    set_uf2_recovery_marker(0);
                    led_color(LedColor::Green);
                }
            }
            state => {
                if cx
                    .local
                    .configuration_at
                    .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
                {
                    report_usb_failure(if state == UsbDeviceState::Addressed {
                        6
                    } else {
                        5
                    });
                }
            }
        }
        if matches!(
            class.did_start_processing(),
            usbd_ccid::Status::ReceivedData(_)
        ) {
            *cx.local.extension_at = Some(now().wrapping_add(750_000));
            WORK_PENDING.store(true, Ordering::Release);
            let _ = worker::spawn();
        }
        if cx
            .local
            .extension_at
            .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
        {
            *cx.local.extension_at = match class.send_wait_extension() {
                usbd_ccid::Status::ReceivedData(_) => {
                    #[cfg(feature = "latency-trace")]
                    trace::wait_extension();
                    Some(now().wrapping_add(750_000))
                }
                usbd_ccid::Status::Idle => None,
            };
        }
        class.check_for_app_response();
    }

    #[task(priority = 1, local = [endpoint, responder, maintenance_at])]
    async fn worker(cx: worker::Context) {
        let endpoint = &mut cx.local.endpoint.0;
        let responder = cx.local.responder;
        loop {
            if RESET_PENDING.swap(false, Ordering::AcqRel) {
                endpoint.reset();
                *cx.local.maintenance_at = None;
            }
            if let Some(request) = responder.take_request() {
                WORK_PENDING.store(false, Ordering::Release);
                #[cfg(feature = "latency-trace")]
                {
                    trace::apdu_start();
                    let header = request
                        .get(0..4)
                        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
                        .unwrap_or(0);
                    trace::record(trace::event::REQUEST, header);
                }
                let reply = Nvm::with_flash_yield(
                    &mut || cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD),
                    || {
                        Ok(endpoint.exchange_with_cancel(&request, &mut || {
                            #[cfg(feature = "latency-trace")]
                            trace::cancel_poll();
                            feed();
                            cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD);
                            !usb_ccid::power_ready()
                        }))
                    },
                )
                .unwrap_or_else(|_| alloc::vec![0x69, 0x85]);
                #[cfg(feature = "latency-trace")]
                {
                    trace::apdu_end();
                    let status = reply
                        .get(reply.len().saturating_sub(2)..)
                        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                        .map(u16::from_be_bytes)
                        .unwrap_or(0);
                    trace::record(
                        trace::event::EXECUTION_DONE,
                        ((reply.len() as u32) << 16) | u32::from(status),
                    );
                }
                let mut outgoing = heapless::Vec::new();
                if outgoing.extend_from_slice(&reply).is_ok() && responder.respond(outgoing).is_ok()
                {
                    #[cfg(feature = "latency-trace")]
                    trace::record(trace::event::RESPONSE_QUEUED, 0);
                    if cx.local.maintenance_at.is_none() {
                        *cx.local.maintenance_at = Some(now().wrapping_add(250_000));
                    }
                }
                cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD);
                #[cfg(feature = "dongle-layout")]
                if endpoint.take_bootloader_request() {
                    UF2_AT.store(now().wrapping_add(250_000), Ordering::Release);
                }
                continue;
            }
            if cx
                .local
                .maintenance_at
                .is_some_and(|deadline| now().wrapping_sub(deadline) < 0x8000_0000)
            {
                #[cfg(feature = "latency-trace")]
                let started = now();
                #[cfg(feature = "latency-trace")]
                trace::record(trace::event::MAINTENANCE_START, 0);
                let result = Nvm::with_flash_yield(
                    &mut || cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD),
                    || {
                        endpoint.maintenance_with_cancel(&mut || {
                            feed();
                            cortex_m::peripheral::NVIC::pend(pac::Interrupt::USBD);
                            !usb_ccid::power_ready()
                        })
                    },
                );
                #[cfg(feature = "latency-trace")]
                {
                    trace::maintenance(started, result.is_err());
                    trace::record(trace::event::MAINTENANCE_DONE, result.is_err() as u32);
                }
                if result.is_err() {
                    cortex_m::peripheral::SCB::sys_reset();
                }
                *cx.local.maintenance_at = None;
                continue;
            }
            break;
        }
    }

    #[idle]
    fn idle(_: idle::Context) -> ! {
        loop {
            cortex_m::asm::wfi();
        }
    }
}
