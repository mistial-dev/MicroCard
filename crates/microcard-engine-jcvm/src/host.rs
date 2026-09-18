//! What the engine asks the card for, JCRE §5.
//!
//! Algorithms are not the virtual machine's business. A card has accelerators, key storage
//! and an entropy source, and which of those exist differs between one card and the next.
//! The engine asks through this trait, so key material never has to pass through the Java
//! heap and a card can answer with hardware where it has it.
use crate::{Error, Result};

/// The services an applet's cryptography needs.
pub trait Host {
    /// Fill a buffer with random bytes.
    fn random(&mut self, output: &mut [u8]) -> Result<()> {
        let _ = output;
        Err(Error::Unsupported)
    }

    /// Hash a message, answering how many bytes the digest occupies.
    ///
    /// The algorithm is the code `javacard.security.MessageDigest` uses.
    fn digest(&mut self, algorithm: u8, message: &[u8], output: &mut [u8]) -> Result<usize> {
        let _ = (algorithm, message, output);
        Err(Error::Unsupported)
    }
}

/// A card that provides no algorithms, which is what a build with nothing wired up has.
///
/// Every operation refuses rather than answering with something predictable, because a
/// predictable answer from a random source is worse than no answer at all.
pub struct NoHost;

impl Host for NoHost {}
