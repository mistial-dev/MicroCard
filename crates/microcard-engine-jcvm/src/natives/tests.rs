extern crate alloc;
use super::*;
use alloc::vec;

fn framework(class: ClassId, method: MethodId, static_token: bool) -> ApiTarget {
    framework_token(class, method, static_token, None)
}

fn framework_token(class: ClassId, method: MethodId, static_token: bool,
    token: Option<u8>) -> ApiTarget {
    for package in PACKAGES.iter() {
        for entry in package.classes.iter() {
            if entry.id != class {
                continue;
            }
            for candidate in entry.methods.iter() {
                if candidate.id == method && candidate.static_token == static_token
                    && token.is_none_or(|token| candidate.token == token) {
                    return ApiTarget {
                        package,
                        class: entry,
                        method: candidate,
                    };
                }
            }
        }
    }
    panic!("no {class:?}.{method:?}");
}

fn setup(words: usize) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u16>, alloc::vec::Vec<u8>) {
    (vec![0; 1024], vec![0; words + 16], vec![0; 8])
}

/// A runtime with no command in flight, for the methods that do not read one.
fn idle() -> Jcre {
    Jcre::new(0, 0)
}

mod reference_tests;
mod runtime_tests;
mod random_tests;
mod pin_tests;
mod apdu_tests;
mod key_tests;
mod crypto_tests;
mod exception_tests;
mod util_tests;

fn invoke_security(class: ClassId, method: MethodId, args: &[(bool, u16)], heap: &mut Heap,
        frame: &mut Frame, host: &mut dyn crate::host::Host) -> Result<Native> {
        for &(reference, value) in args {
            if reference { frame.push_reference(value)?; } else { frame.push_short(value as i16)?; }
        }
        let target = framework(class, method, matches!(method, MethodId::getInstance | MethodId::Constructor));
        let signature = if method == MethodId::init {
            target.class.methods.iter().find(|entry| entry.id == method && entry.signature.init_vector() == (args.len() == 6)).unwrap().signature
        } else { target.method.signature };
        security::call(class, method, signature,
            heap, host, frame, 1, &mut Jcre { installing: true, ..idle() }, &mut { u32::MAX }, &[])
    }
