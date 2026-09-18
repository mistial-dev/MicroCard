//! Structural verification of a whole package, in one pass at load.
//!
//! With no signature on a Java Card package, this and the secure channel are the whole
//! safety boundary. Everything checked here is something a later pass is then allowed to
//! assume, so each check is stated once and relied on everywhere.
//!
//! What this pass does not do is track types across the dataflow. That is deferred, and
//! the runtime carries a reference tag per stack and local slot in its place, per
//! docs/JCVM_PROFILE.md.
use crate::cap::{LoadFile, MethodHeader, Tag};
use crate::code::{Boundaries, Limits, constant_pool_index, instruction_length, verify_targets};
use crate::{Error, Result};
use alloc::vec::Vec;

/// What a package looked like once it verified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Methods whose bytecode was decoded. Abstract methods have none.
    pub methods: usize,
    /// Words the static field image needs.
    pub static_image_bytes: u16,
    /// The largest frame any verified method asks for, in words.
    pub max_frame_words: u16,
    /// The largest operand stack any verified method asks for, in words.
    pub max_stack_words: u8,
}

/// Every offset in the Method component that the package names as a method.
///
/// Three components between them name methods, and none is sufficient alone. The class
/// method tables hold virtual methods, the constant pool holds static methods and
/// constructors, and the Applet component holds install entry points. Even together they
/// miss a method nothing references, which is why a method is decoded by reachability
/// rather than swept from one named offset to the next.
fn method_offsets(file: &LoadFile) -> Result<Vec<usize>> {
    let mut offsets = Vec::new();
    let mut push = |offset: usize, offsets: &mut Vec<usize>| -> Result<()> {
        offsets.try_reserve(1).map_err(|_| Error::Quota)?;
        offsets.push(offset);
        Ok(())
    };
    for class in file.classes()?.iter() {
        for offset in class.method_offsets() {
            push(offset as usize, &mut offsets)?;
        }
    }
    for entry in file.constants()?.iter() {
        if let Some(offset) = entry.internal_static_method() {
            push(offset as usize, &mut offsets)?;
        }
    }
    for applet in file.applets()?.iter() {
        push(applet.install_method_offset as usize, &mut offsets)?;
    }
    offsets.sort_unstable();
    offsets.dedup();
    Ok(offsets)
}

/// Verify a Load File Data Block.
///
/// `scratch` holds the instruction boundary map of one method at a time. Two bits per byte
/// of the largest method is enough, and a method larger than the scratch is refused rather
/// than verified partially.
pub fn verify(file: &LoadFile, scratch: &mut [u8]) -> Result<Report> {
    let header = file.header()?;
    header.supported()?;
    let directory = file.directory()?;
    let constants = file.constants()?;
    let methods = file.methods()?;
    let applets = file.applets()?;
    let classes = file.classes()?;

    // The static field image is described twice over, and a disagreement means a field
    // would read initial bytes belonging to another field.
    let statics = file.static_fields()?;
    if statics.image_size != directory.image_size
        || statics.array_init_count() != directory.array_init_count as usize
    {
        return Err(Error::Inconsistent);
    }

    // The applet count is likewise stated in two places.
    if applets.count() != directory.applet_count as usize {
        return Err(Error::Inconsistent);
    }
    if file.imports()?.count() != directory.import_count as usize {
        return Err(Error::Inconsistent);
    }

    // A handler names the class it catches, unless it catches everything.
    for handler in methods.handlers() {
        if handler.catch_type_index != 0
            && handler.catch_type_index as usize >= constants.count()
        {
            return Err(Error::Bounds);
        }
    }

    // A class may not inherit from itself, directly or in a cycle. The walk is bounded by
    // the number of classes, so a cycle is found rather than followed.
    let class_count = classes.iter().count();
    for class in classes.iter() {
        let mut super_class = class.super_class;
        for _ in 0..=class_count {
            let crate::cap::ClassRef::Internal(offset) = super_class else {
                break;
            };
            super_class = classes.at(offset)?.super_class;
        }
        if let crate::cap::ClassRef::Internal(_) = super_class {
            return Err(Error::Format);
        }
    }

    let limits = Limits {
        int: header.int(),
        ..Limits::IMPLEMENTED
    };
    let offsets = method_offsets(file)?;
    let mut report = Report {
        static_image_bytes: statics.image_size,
        ..Report::default()
    };
    for (index, &offset) in offsets.iter().enumerate() {
        // A method ends where the next named one begins. That bound is what stops a branch
        // from entering another method's body while running on this method's frame.
        let end = offsets
            .get(index + 1)
            .copied()
            .unwrap_or(methods.bytes().len());
        let (method, code) = methods.method(offset, end)?;
        if method.abstract_method() {
            continue;
        }
        report.max_frame_words = report.max_frame_words.max(method.frame_words());
        report.max_stack_words = report.max_stack_words.max(method.max_stack);
        let body = offset + method.length;
        verify_method(&methods, code, body, end, scratch, limits, &constants)?;
        report.methods += 1;
    }
    // A package with no code is not one this engine can be asked to run.
    if report.methods == 0 || file.component(Tag::Method).is_none() {
        return Err(Error::Format);
    }
    Ok(report)
}

/// Verify one method's bytecode and return its boundary map.
fn verify_method(
    methods: &crate::cap::Method,
    code: &[u8],
    body: usize,
    end: usize,
    scratch: &mut [u8],
    limits: Limits,
    constants: &crate::cap::ConstantPool,
) -> Result<()> {
    // Control enters at the first instruction, and at any handler covering this method.
    let mut entries = Vec::new();
    entries.try_reserve(1).map_err(|_| Error::Quota)?;
    entries.push(0usize);
    for handler in methods.handlers() {
        let target = handler.handler_offset as usize;
        if target >= body && target < end {
            entries.try_reserve(1).map_err(|_| Error::Quota)?;
            entries.push(target - body);
        }
    }
    let boundaries = Boundaries::reachable(code, scratch, limits, &entries)?;
    verify_targets(code, &boundaries)?;
    // Every constant pool index an instruction names has to be in range, or resolution
    // would read whatever followed the pool.
    let mut at = 0;
    while at < code.len() {
        if !boundaries.is_boundary(at) {
            at += 1;
            continue;
        }
        if let Some((_, index)) = constant_pool_index(code, at)? {
            if index as usize >= constants.count() {
                return Err(Error::Bounds);
            }
        }
        at += instruction_length(code, at)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::LoadFile;
    use alloc::vec;

    use crate::test_support::Package;

    #[test]
    fn a_minimal_package_verifies_and_reports_what_it_holds() {
        let bytes = Package::default().build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut scratch = vec![0; 64];
        let report = verify(&file, &mut scratch).unwrap();
        assert_eq!(report.methods, 1);
        assert_eq!(report.max_stack_words, 2);
    }

    fn refuse(package: Package) -> Error {
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut scratch = vec![0; 256];
        verify(&file, &mut scratch).expect_err("package should have been refused")
    }

    #[test]
    fn a_branch_outside_the_method_is_refused() {
        // goto with an offset that leaves the method would run whatever followed it.
        let package = Package {
            code: vec![0x70, 0x40, 0x7a],
            ..Package::default()
        };
        assert_eq!(refuse(package), Error::Bounds);
    }

    #[test]
    fn a_constant_pool_index_past_the_end_is_refused() {
        // getstatic_a naming entry 9 of an empty pool. Resolution would read past the pool.
        let package = Package {
            code: vec![0x7b, 0x00, 0x09, 0x7a],
            ..Package::default()
        };
        assert_eq!(refuse(package), Error::Bounds);
        // The same instruction naming an entry that exists verifies.
        let package = Package {
            code: vec![0x7b, 0x00, 0x00, 0x7a],
            constants: vec![[5, 0, 0, 0]],
            ..Package::default()
        };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        verify(&file, &mut vec![0; 256]).unwrap();
    }

    #[test]
    fn an_undefined_opcode_is_refused() {
        let package = Package {
            code: vec![0xc0, 0x7a],
            ..Package::default()
        };
        assert_eq!(refuse(package), Error::Format);
    }

    #[test]
    fn an_int_instruction_in_a_package_that_declared_no_int_is_refused() {
        // iadd, in a package whose header leaves ACC_INT clear.
        let package = Package {
            code: vec![0x42, 0x7a],
            ..Package::default()
        };
        assert_eq!(refuse(package), Error::Unsupported);
        // The same package declaring int support verifies.
        let package = Package {
            flags: 0x04 | 0x01,
            code: vec![0x42, 0x7a],
            ..Package::default()
        };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        verify(&file, &mut vec![0; 256]).unwrap();
    }

    #[test]
    fn a_handler_catching_a_class_that_is_not_in_the_pool_is_refused() {
        // start 0, length 1, target 9, catch type 3, with an empty constant pool.
        let package = Package {
            handlers: vec![[0, 0, 0x80, 0x01, 0, 9, 0, 3]],
            ..Package::default()
        };
        assert_eq!(refuse(package), Error::Bounds);
    }

    #[test]
    fn a_scratch_buffer_too_small_for_a_method_refuses_rather_than_verifying_part() {
        let bytes = Package::default().build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut scratch = vec![0; 0];
        assert_eq!(verify(&file, &mut scratch), Err(Error::Bounds));
    }
}
