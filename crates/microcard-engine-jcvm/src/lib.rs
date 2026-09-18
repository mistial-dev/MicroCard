//! Java Card execution engine, per [docs/JCVM_PROFILE.md](../../../docs/JCVM_PROFILE.md).
//!
//! The CAP container and the bytecode decoder are implemented. There is no linker or
//! interpreter yet, and nothing on the card reaches this crate.
#![no_std]
extern crate alloc;
pub mod cap;
pub mod code;
#[allow(dead_code)]
mod jcvm_opcodes;
pub mod verify;
pub mod vm;
#[cfg(test)]
mod test_support;

/// Why a Java Card structure was refused.
///
/// Local to this crate while it stands alone. It folds into the shared error type when the
/// workspace gains one, which is why the variants stay coarse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A length, offset or index reached outside the bytes it was given.
    Bounds,
    /// A field held a value the format does not allow.
    Format,
    /// Two fields that describe the same thing disagreed.
    Inconsistent,
    /// The structure is well formed and this build does not implement it.
    Unsupported,
    /// Verifying or running it needs more memory than the card offered.
    Quota,
    /// A word was used as the wrong kind of value, such as a number as a reference.
    Type,
    /// An arithmetic operation the language defines as a thrown exception, such as a
    /// division by zero.
    Arithmetic,
}

pub type Result<T> = core::result::Result<T, Error>;
