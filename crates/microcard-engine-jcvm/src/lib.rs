//! Java Card execution engine, per [docs/JCVM_PROFILE.md](../../../docs/JCVM_PROFILE.md).
//!
//! Only the CAP container is implemented. There is no verifier, linker or interpreter yet,
//! and nothing on the card reaches this crate.
#![no_std]
pub mod cap;

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
}

pub type Result<T> = core::result::Result<T, Error>;
