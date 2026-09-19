//! The interpreter.
//!
//! Frames and objects use caller-owned arenas. Heap transactions allocate a bounded
//! before-image log; admission precedes each conditional payload write.
pub mod exec;
pub mod frame;
pub mod heap;

pub use exec::{Outcome, run};
pub use frame::{Frame, NULL, Reference};
pub use heap::{Context, Heap, Info};
