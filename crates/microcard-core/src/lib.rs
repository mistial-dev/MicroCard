#![no_std]
extern crate alloc;
pub mod apdu;
pub mod assembly;
pub mod crypto;
mod credential_store;
pub mod domains;
mod fallible_clone;
pub mod journal;
pub mod mc04_imports;
#[allow(dead_code)]
mod mc04_opcodes;
#[allow(dead_code)]
mod mc04_schema;
pub mod mc04_vm;
pub mod native_abi;
pub mod package;
pub mod provisioning;
pub mod scp03;
pub mod staging;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Format,
    Bounds,
    Unsupported,
    Signature,
    Domain,
    KeyMismatch,
    Rollback,
    Busy,
    Quota,
    Unauthorized,
    Missing,
    Budget,
    Stack,
    Arithmetic,
    Native,
    Storage,
    Authentication,
    Cancelled,
}
pub type Result<T> = core::result::Result<T, Error>;

pub mod transport;

pub mod key_store;

pub mod framing;

pub mod ccid;
pub mod ccid_usb;

pub mod globalplatform;

pub mod hal;
