//! The interpreter.
//!
//! Nothing here allocates. Frames are carved out of an arena the caller owns, which is how
//! a card bounds what one invocation can use before it starts rather than after.
pub mod exec;
pub mod frame;

pub use exec::{Outcome, run};
pub use frame::{Frame, NULL, Reference};
