use super::Hardware;
use microcard_core::{hal::Entropy, Result};
#[cfg(feature = "cc310-entropy")]
use microcard_core::Error;
#[cfg(feature = "cc310-entropy")]
use crate::cc310;
#[cfg(not(feature = "cc310-entropy"))]
use crate::platform::{read, wait, write, RNG};

impl Entropy for Hardware {
    fn fill_entropy(&mut self, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        #[cfg(feature = "cc310-entropy")]
        {
            self.ensure_cc310()?;
            let result = if cc310::fill_entropy(out) {
                Ok(())
            } else {
                Err(Error::Native)
            };
            microcard_core::crypto::clear_output_on_error(out, result)
        }
        #[cfg(not(feature = "cc310-entropy"))]
        unsafe {
            write(RNG + 0x504, 1);
            write(RNG, 1);
        }
        #[cfg(not(feature = "cc310-entropy"))]
        for index in 0..out.len() {
            unsafe {
                write(RNG + 0x100, 0);
            }
            if let Err(error) = wait(RNG + 0x100) {
                out.fill(0);
                unsafe {
                    write(RNG + 0x004, 1);
                }
                return Err(error);
            }
            out[index] = unsafe { read(RNG + 0x508) } as u8;
        }
        #[cfg(not(feature = "cc310-entropy"))]
        unsafe {
            write(RNG + 0x004, 1);
        }
        #[cfg(not(feature = "cc310-entropy"))]
        Ok(())
    }
}
