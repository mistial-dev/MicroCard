use crate::Error;

extern "C" {
    fn mc_tc_aes128_ctr(key: *const u8, counter: *const u8,
        buffer: *mut u8, length: usize) -> i32;
}

/// AES-128 CTR with the library's big-endian counter and wrap rejection.
/// Failure clears the caller's in-place buffer.
pub fn crypt(key: &[u8; 16], counter: &[u8; 16], buffer: &mut [u8]) -> Result<(), Error> {
    let status = unsafe {
        mc_tc_aes128_ctr(key.as_ptr(), counter.as_ptr(), buffer.as_mut_ptr(), buffer.len())
    };
    if status == 0 { Ok(()) } else {
        buffer.fill(0);
        Err(Error::OperationFailed)
    }
}
