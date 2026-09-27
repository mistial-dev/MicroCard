use super::Hardware;
use microcard_core::{hal::LogicalGpio, Error, Result};
use crate::platform::write;

impl LogicalGpio for Hardware {
    fn write_gpio(&mut self, resource: i32, value: i32) -> Result<()> {
        if resource != 0 || !(0..=1).contains(&value) {
            return Err(Error::Bounds);
        }
        unsafe {
            write(0x50000518, 1 << 13);
            write(if value == 0 { 0x50000508 } else { 0x5000050C }, 1 << 13);
        }
        Ok(())
    }
}
