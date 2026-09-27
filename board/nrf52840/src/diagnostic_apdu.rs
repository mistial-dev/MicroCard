//! Small retained, non-secret diagnostic record for development firmware.
use core::{ptr, sync::atomic::{AtomicU32, Ordering}};
use microcard_core::Error;

const MAGIC: u32 = 0x4d43_4447;
const VERSION: u32 = 1;
pub(crate) const COMMAND: [u8; 5] = [0x80, 0xf3, 0, 0, 0];
pub(crate) const APDU: u32 = 1;
pub(crate) const MAINTENANCE: u32 = 2;
pub(crate) const STARTUP: u32 = 3;

pub(crate) const PREPARE: u32 = 1;
pub(crate) const PUBLISH: u32 = 3;
pub(crate) const RESPOND: u32 = 4;
pub(crate) const MAINTAIN: u32 = 5;
pub(crate) const DRAINED: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy)]
struct Record {
    magic: u32,
    checksum: u32,
    version: u32,
    attempt: u32,
    scope: u32,
    phase: u32,
    decision: u32,
    generation_lo: u32,
    generation_hi: u32,
    erased_pages: u32,
    programmed_words: u32,
    started_us: u32,
    phase_started_us: u32,
    elapsed_us: u32,
    reset_reason: u32,
    error: u32,
    last_failure_attempt: u32,
    last_failure_phase: u32,
    last_failure_error: u32,
    phase_us: [u32; 6],
    last_apdu: [u32; 8],
    last_maintenance: [u32; 8],
    last_apdu_phase_us: [u32; 6],
    last_maintenance_phase_us: [u32; 6],
    publication_count: u32,
    publication_active: u32,
    publication_started_us: u32,
    publication_start_erases: u32,
    publication_start_words: u32,
    publications: [[u32; 6]; 4],
    last_apdu_publication_count: u32,
    last_apdu_publications: [[u32; 6]; 4],
    last_maintenance_publication_count: u32,
    last_maintenance_publications: [[u32; 6]; 4],
    retained_from_previous_boot: u32,
}

impl Record {
    const EMPTY: Self = Self {
        magic: MAGIC, checksum: 0, version: VERSION, attempt: 0, scope: 0, phase: 0,
        decision: 0, generation_lo: 0, generation_hi: 0, erased_pages: 0,
        programmed_words: 0, started_us: 0, phase_started_us: 0, elapsed_us: 0,
        reset_reason: 0, error: 0, last_failure_attempt: 0,
        last_failure_phase: 0, last_failure_error: 0, phase_us: [0; 6],
        last_apdu: [0; 8], last_maintenance: [0; 8],
        last_apdu_phase_us: [0; 6], last_maintenance_phase_us: [0; 6],
        publication_count: 0, publication_active: 0, publication_started_us: 0,
        publication_start_erases: 0, publication_start_words: 0,
        publications: [[0; 6]; 4],
        last_apdu_publication_count: 0, last_apdu_publications: [[0; 6]; 4],
        last_maintenance_publication_count: 0,
        last_maintenance_publications: [[0; 6]; 4],
        retained_from_previous_boot: 0,
    };

    fn checksum(&self) -> u32 {
        let mut value = 0x79b9_25a7u32;
        for word in [self.version, self.attempt, self.scope, self.phase, self.decision,
            self.generation_lo, self.generation_hi, self.erased_pages,
            self.programmed_words, self.started_us, self.phase_started_us,
            self.elapsed_us, self.reset_reason, self.error, self.last_failure_attempt,
            self.last_failure_phase, self.last_failure_error]
            .into_iter().chain(self.phase_us).chain(self.last_apdu)
            .chain(self.last_maintenance).chain(self.last_apdu_phase_us)
            .chain(self.last_maintenance_phase_us)
            .chain([self.publication_count, self.publication_active,
                self.publication_started_us, self.publication_start_erases,
                self.publication_start_words])
            .chain(self.publications.into_iter().flatten())
            .chain([self.last_apdu_publication_count])
            .chain(self.last_apdu_publications.into_iter().flatten())
            .chain([self.last_maintenance_publication_count])
            .chain(self.last_maintenance_publications.into_iter().flatten())
            .chain([self.retained_from_previous_boot]) {
            value = value.rotate_left(5) ^ word.wrapping_mul(0x9e37_79b1);
        }
        value
    }

    fn valid(&self) -> bool {
        self.magic == MAGIC && self.version == VERSION && self.checksum == self.checksum()
    }
}

// cortex-m-rt does not clear .uninit. A checksum invalidates a torn or corrupted
// record after reset; the record has no key or APDU contents.
#[link_section = ".uninit.microcard_diagnostic"]
static mut RETAINED: Record = Record::EMPTY;
static ERASED_PAGES: AtomicU32 = AtomicU32::new(0);
static PROGRAMMED_WORDS: AtomicU32 = AtomicU32::new(0);

fn read() -> Record {
    let value = unsafe { ptr::read_volatile(ptr::addr_of!(RETAINED)) };
    if value.valid() { value } else { Record::EMPTY }
}

fn update(change: impl FnOnce(&mut Record)) {
    cortex_m::interrupt::free(|_| {
        let mut value = read();
        change(&mut value);
        value.magic = 0;
        value.checksum = value.checksum();
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(RETAINED), value) };
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(RETAINED).cast::<u32>(), MAGIC) };
    });
}

pub(crate) fn boot(reset_reason: u32) {
    // RESETREAS bit 2 is SREQ. Other sources can corrupt retained RAM; a
    // checksum alone cannot make a stale record trustworthy after those resets.
    let previous = reset_reason == (1 << 2)
        && unsafe { ptr::read_volatile(ptr::addr_of!(RETAINED)) }.valid();
    if !previous {
        // Force update() to start from EMPTY, without trusting the old fields.
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(RETAINED).cast::<u32>(), 0) };
    }
    update(|record| {
        record.reset_reason = reset_reason;
        record.retained_from_previous_boot = u32::from(previous);
    });
}

pub(crate) fn startup_failure(code: u8) {
    update(|record| {
        record.scope = STARTUP;
        record.error = 0x100 | u32::from(code);
        record.last_failure_attempt = record.attempt;
        record.last_failure_phase = record.phase;
        record.last_failure_error = record.error;
    });
}

pub(crate) fn begin(scope: u32, phase: u32) {
    let at = crate::platform::now();
    ERASED_PAGES.store(0, Ordering::Relaxed);
    PROGRAMMED_WORDS.store(0, Ordering::Relaxed);
    update(|record| {
        record.attempt = record.attempt.wrapping_add(1);
        record.scope = scope;
        record.phase = phase;
        record.decision = 0;
        record.erased_pages = 0;
        record.programmed_words = 0;
        record.started_us = at;
        record.phase_started_us = at;
        record.elapsed_us = 0;
        record.error = 0;
        record.phase_us = [0; 6];
        record.publication_count = 0;
        record.publication_active = 0;
        record.publications = [[0; 6]; 4];
    });
}

pub(crate) fn phase(next: u32) {
    let at = crate::platform::now();
    update(|record| {
        if let Some(elapsed) = record.phase_us.get_mut(record.phase.saturating_sub(1) as usize) {
            *elapsed = elapsed.wrapping_add(at.wrapping_sub(record.phase_started_us));
        }
        record.phase = next;
        record.phase_started_us = at;
    });
}

pub(crate) fn journal(kind: u32, generation: u64, completed: bool) {
    let at = crate::platform::now();
    if !completed { phase(PUBLISH); }
    update(|record| {
        record.decision = kind;
        record.generation_lo = generation as u32;
        record.generation_hi = (generation >> 32) as u32;
        if !completed {
            record.publication_active = 1;
            record.publication_started_us = at;
            record.publication_start_erases = ERASED_PAGES.load(Ordering::Relaxed);
            record.publication_start_words = PROGRAMMED_WORDS.load(Ordering::Relaxed);
        } else if record.publication_active != 0 {
            record.publication_active = 0;
            let index = record.publication_count as usize % record.publications.len();
            record.publications[index] = [kind, (generation >> 32) as u32,
                generation as u32,
                ERASED_PAGES.load(Ordering::Relaxed)
                    .wrapping_sub(record.publication_start_erases),
                PROGRAMMED_WORDS.load(Ordering::Relaxed)
                    .wrapping_sub(record.publication_start_words),
                at.wrapping_sub(record.publication_started_us)];
            record.publication_count = record.publication_count.wrapping_add(1);
        }
    });
}

pub(crate) fn erased_page() {
    ERASED_PAGES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn programmed_word() {
    PROGRAMMED_WORDS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn finish(error: Option<Error>) {
    let at = crate::platform::now();
    update(|record| {
        record.erased_pages = ERASED_PAGES.load(Ordering::Relaxed);
        record.programmed_words = PROGRAMMED_WORDS.load(Ordering::Relaxed);
        if record.publication_active != 0 {
            record.publication_active = 0;
            let index = record.publication_count as usize % record.publications.len();
            record.publications[index] = [record.decision | 0x8000_0000,
                record.generation_hi, record.generation_lo,
                record.erased_pages.wrapping_sub(record.publication_start_erases),
                record.programmed_words.wrapping_sub(record.publication_start_words),
                at.wrapping_sub(record.publication_started_us)];
            record.publication_count = record.publication_count.wrapping_add(1);
        }
        if let Some(elapsed) = record.phase_us.get_mut(record.phase.saturating_sub(1) as usize) {
            *elapsed = elapsed.wrapping_add(at.wrapping_sub(record.phase_started_us));
        }
        record.phase_started_us = at;
        record.elapsed_us = at.wrapping_sub(record.started_us);
        if let Some(error) = error {
            record.error = microcard_core::diagnostic_error_code(&error);
            record.last_failure_attempt = record.attempt;
            record.last_failure_phase = record.phase;
            record.last_failure_error = record.error;
        }
        let summary = [record.attempt, record.elapsed_us, record.erased_pages,
            record.programmed_words, record.decision, record.error,
            record.generation_hi, record.generation_lo];
        match record.scope {
            APDU => {
                record.last_apdu = summary;
                record.last_apdu_phase_us = record.phase_us;
                record.last_apdu_publication_count = record.publication_count;
                record.last_apdu_publications = record.publications;
            }
            MAINTENANCE => {
                record.last_maintenance = summary;
                record.last_maintenance_phase_us = record.phase_us;
                record.last_maintenance_publication_count = record.publication_count;
                record.last_maintenance_publications = record.publications;
            }
            _ => {}
        }
    });
}

pub(crate) fn response(command: &[u8])
    -> Option<heapless::Vec<u8, { crate::usb_ccid::APDU_BYTES }>> {
    if command != COMMAND { return None; }
    let record = read();
    let mut result = heapless::Vec::new();
    for word in [record.version, record.attempt, record.scope, record.phase,
        record.decision, record.generation_hi, record.generation_lo,
        record.erased_pages, record.programmed_words, record.elapsed_us,
        record.reset_reason, record.error, record.last_failure_attempt,
        record.last_failure_phase, record.last_failure_error]
        .into_iter().chain(record.phase_us).chain(record.last_apdu)
        .chain(record.last_maintenance).chain(record.last_apdu_phase_us)
        .chain(record.last_maintenance_phase_us)
        .chain([record.last_apdu_publication_count])
        .chain(record.last_apdu_publications.into_iter().flatten())
        .chain([record.last_maintenance_publication_count])
        .chain(record.last_maintenance_publications.into_iter().flatten())
        .chain([record.retained_from_previous_boot]) {
        result.extend_from_slice(&word.to_be_bytes()).ok()?;
    }
    result.extend_from_slice(&[0x90, 0x00]).ok()?;
    Some(result)
}

#[no_mangle]
pub extern "C" fn microcard_diagnostic_journal(kind: u32, generation: u64, completed: u32) {
    journal(kind, generation, completed != 0);
}

#[no_mangle]
pub extern "C" fn microcard_diagnostic_phase(kind: u32) {
    phase(kind);
}

#[no_mangle]
pub extern "C" fn microcard_diagnostic_maintenance_recovered(error_code: u32) {
    update(|record| {
        record.error = 10;
        record.last_failure_attempt = record.attempt;
        record.last_failure_phase = record.phase;
        record.last_failure_error = error_code;
    });
}
