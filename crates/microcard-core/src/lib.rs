#![no_std]
extern crate alloc;
pub mod apdu;
pub mod cbor;
#[cfg(feature = "mc04")]
pub mod assembly;
pub mod crypto;
#[cfg(feature = "mc04")]
mod credential_store;
#[cfg(feature = "mc04")]
pub mod domains;
#[cfg(feature = "mc04")]
mod fallible_clone;
pub mod journal;
pub mod image_store;
#[cfg(feature = "mc04")]
pub mod mc04_imports;
#[allow(dead_code)]
#[cfg(feature = "mc04")]
mod mc04_opcodes;
#[allow(dead_code)]
#[cfg(feature = "mc04")]
mod mc04_schema;
#[cfg(feature = "mc04")]
pub mod mc04_vm;
#[cfg(feature = "mc04")]
pub mod native_abi;
#[cfg(feature = "mc04")]
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
    IncompatibleState,
    Authentication,
    Cancelled,
}
pub type Result<T> = core::result::Result<T, Error>;

pub mod transport;
pub mod engine;
#[cfg(feature = "jcvm")]
pub mod jcvm_services;
#[cfg(feature = "jcvm")]
pub mod jcvm_storage;

pub mod key_store;

pub mod framing;

pub mod ccid;
pub mod ccid_usb;

pub mod globalplatform;

pub mod hal;
