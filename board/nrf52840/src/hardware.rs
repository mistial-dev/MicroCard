mod crypto;
mod entropy;
mod gpio;

pub(crate) struct Hardware {
    #[cfg(feature = "cc310-sha256")]
    cc310_initialized: bool,
    pub(crate) self_test_stage: u8,
}

impl Hardware {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "cc310-sha256")]
            cc310_initialized: false,
            self_test_stage: 0,
        }
    }
}
