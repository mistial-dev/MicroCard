extern crate alloc;
use super::*;
use alloc::vec;
use alloc::vec::Vec;

use crate::cap::LoadFile;
use crate::link::Linked;
use crate::test_support::Package;

/// Run one package's first method, which is what the applet entry point is.
fn execute_package(package: &Package) -> Result<Outcome> {
    execute_package_with_cancel(package, &mut || false)
}

fn execute_package_with_cancel(package: &Package, cancel: &mut dyn FnMut() -> bool) -> Result<Outcome> {
    let bytes = package.build();
    let file = LoadFile::parse(&bytes)?;
    let linked = Linked::new(&file)?;
    let methods = file.methods()?;
    let mut slab = vec![0u8; 1024];
    let mut heap = Heap::new(&mut slab)?;
    natives::reserve_runtime_exceptions(&mut heap, 1)?;
    let mut statics = vec![0u8; package.static_bytes as usize + 8];
    let mut host = crate::host::NoHost;
    let mut machine = Machine::new(
        &mut heap,
        &mut host,
        &linked,
        methods,
        &mut statics,
        1,
        Limits::IMPLEMENTED,
        Jcre::new(0, 0),
    ).with_cancel(cancel);
    let mut words = vec![0u16; 256];
    let mut tags = vec![0u8; 32];
    let mut arena = Arena {
        words: &mut words,
        tags: &mut tags,
    };
    let mut budget = 10_000;
    // A frame with nothing in it, so the entry point is invoked like any other method.
    let mut outer_words = [0u16; 8];
    let mut outer_tags = [0u8; 1];
    let mut outer = Frame::new(&mut outer_words, &mut outer_tags, 0, 8)?;
    if let Some(exception) = invoke(
        &mut machine,
        package.install_offset(),
        &mut outer,
        &mut arena,
        &mut budget,
    )? {
        // Nothing caught it, which is what the runtime environment would see.
        return Ok(Outcome::Thrown(exception));
    }
    // What the method returned, read back off the frame that called it.
    Ok(match outer.depth() {
        0 => Outcome::Void,
        _ => {
            let (value, reference) = outer.pop_raw()?;
            if reference {
                Outcome::Reference(value)
            } else {
                Outcome::Short(value as i16)
            }
        }
    })
}

fn execute(code: &[u8], locals: usize) -> Result<Outcome> {
    execute_package(&Package {
        code: Vec::from(code),
        max_stack: 15,
        nargs: 0,
        max_locals: locals as u8,
        ..Package::default()
    })
}

fn short(code: &[u8]) -> i16 {
    match execute(code, 4).unwrap() {
        Outcome::Short(value) => value,
        other => panic!("{other:?}"),
    }
}

fn integer(code: &[u8]) -> i32 {
    let package = Package {
        code: Vec::from(code),
        max_stack: 15,
        nargs: 0,
        max_locals: 8,
        ..Package::default()
    };
    let bytes = package.build();
    let file = LoadFile::parse(&bytes).unwrap();
    let linked = Linked::new(&file).unwrap();
    let methods = file.methods().unwrap();
    let mut slab = vec![0u8; 1024];
    let mut heap = Heap::new(&mut slab).unwrap();
    let mut statics = vec![0u8; 8];
    let mut host = crate::host::NoHost;
    let mut machine = Machine::new(
        &mut heap,
        &mut host,
        &linked,
        methods,
        &mut statics,
        1,
        Limits::IMPLEMENTED,
        Jcre::new(0, 0),
    );
    let mut words = vec![0u16; 64];
    let mut tags = vec![0u8; 8];
    let mut frame = Frame::new(&mut words, &mut tags, 8, 15).unwrap();
    let mut budget = 10_000;
    let code = &methods.bytes()[package.install_offset() as usize + 2..];
    match run(&mut machine, code, &mut frame, &mut budget).unwrap() {
        Outcome::Int(value) => value,
        other => panic!("{other:?}"),
    }
}

#[test]
fn constants_and_returns() {
    assert_eq!(execute(&[op::RETURN], 0).unwrap(), Outcome::Void);
    assert_eq!(short(&[op::SCONST_M1, op::SRETURN]), -1);
    assert_eq!(short(&[8, op::SRETURN]), 5);
    assert_eq!(short(&[op::BSPUSH, 0xff, op::SRETURN]), -1);
    assert_eq!(short(&[op::SSPUSH, 0x12, 0x34, op::SRETURN]), 0x1234);
    assert_eq!(integer(&[op::ICONST_M1, op::IRETURN]), -1);
    assert_eq!(integer(&[op::IIPUSH, 0xff, 0xff, 0xff, 0xfe, op::IRETURN]), -2);
    assert_eq!(
        execute(&[op::ACONST_NULL, op::ARETURN], 0).unwrap(),
        Outcome::Reference(NULL)
    );
}

fn catch_java_fault(code: &[u8], locals: u8, class: ClassId) -> Result<Outcome> {
    use crate::cap::CONSTANT_CLASSREF;
    let api = crate::jcvm_api::PACKAGES.iter()
        .find(|package| package.classes.iter().any(|entry| entry.id == class)).unwrap();
    let token = api.classes.iter().find(|entry| entry.id == class).unwrap().token;
    let mut package = Package {
        imports: vec![(vec![0xa0, 0, 0, 0, 0x62, 0, 1], 1, 0)],
        handlers: vec![[0; 8]], nargs: 0, max_stack: 15,
        ..Package::default()
    };
    package.max_locals = locals;
    package.constants = vec![[CONSTANT_CLASSREF, 0x80, 0, 0],
        [CONSTANT_CLASSREF, 0x80, token, 0]];
    let body = package.install_offset() + 2;
    package.code = code.to_vec();
    let end = package.code.len() as u16;
    package.code.extend([op::POP, op::SCONST_1, op::SRETURN]);
    package.handlers = vec![handler(body, end, body + end, 1, true)];
    execute_package(&package)
}

#[test]
fn arithmetic_wraps_where_java_card_says_it_does() {
    // 32767 + 1, which is the case that would panic on a checked add.
    assert_eq!(
        short(&[op::SSPUSH, 0x7f, 0xff, 4, op::SADD, op::SRETURN]),
        -32768
    );
    // The most negative short divided by minus one overflows and wraps to itself.
    assert_eq!(
        short(&[op::SSPUSH, 0x80, 0x00, op::SCONST_M1, op::SDIV, op::SRETURN]),
        -32768
    );
    assert_eq!(
        short(&[op::SSPUSH, 0x80, 0x00, op::SCONST_M1, op::SREM, op::SRETURN]),
        0
    );
    // Both widths and both division operations report the Java exception.
    for code in [
        [op::SCONST_1, op::SCONST_0, op::SDIV, op::SRETURN],
        [op::SCONST_1, op::SCONST_0, op::SREM, op::SRETURN],
        [op::ICONST_M1 + 2, op::ICONST_M1 + 1, op::IDIV, op::IRETURN],
        [op::ICONST_M1 + 2, op::ICONST_M1 + 1, op::IREM, op::IRETURN],
    ] {
        assert_eq!(catch_java_fault(&code, 0, ClassId::ArithmeticException),
            Ok(Outcome::Short(1)));
    }
}

#[test]
fn an_unsigned_shift_masks_before_it_shifts() {
    // Minus one shifted right by one, unsigned. The value has to be masked to 16 bits
    // first, or the sign bits of the wider register shift in and the answer stays
    // negative.
    assert_eq!(
        short(&[op::SCONST_M1, 4, op::SUSHR, op::SRETURN]) as u16,
        0x7fff
    );
    assert_eq!(short(&[op::SCONST_M1, 4, op::SSHR, op::SRETURN]), -1);
    // A distance is taken modulo the width, so shifting by 16 is shifting by zero.
    assert_eq!(
        short(&[op::SCONST_M1, op::SSPUSH, 0, 16, op::SSHL, op::SRETURN]),
        -1
    );
    assert_eq!(integer(&[op::ICONST_M1, 4, op::IUSHR, op::IRETURN]), 0x7fff_ffff);
}

#[test]
fn conversions_truncate_the_way_a_field_round_trip_does() {
    // 0x1234 stored into a byte and read back is 0x34, which is positive.
    assert_eq!(short(&[op::SSPUSH, 0x12, 0x34, op::S2B, op::SRETURN]), 0x34);
    // 0x80 is negative once it has been through a byte.
    assert_eq!(short(&[op::SSPUSH, 0x00, 0x80, op::S2B, op::SRETURN]), -128);
    assert_eq!(integer(&[op::SCONST_M1, op::S2I, op::IRETURN]), -1);
    assert_eq!(
        short(&[op::IIPUSH, 0x00, 0x01, 0x12, 0x34, op::I2S, op::SRETURN]),
        0x1234
    );
}

#[test]
fn locals_keep_references_and_numbers_apart() {
    // astore_1 then sload_1 asks for a number where a reference was stored.
    let code = [op::ACONST_NULL, op::ASTORE_0 + 1, op::SLOAD_0 + 1, op::SRETURN];
    assert_eq!(execute(&code, 4), Err(Error::Type));
    // The right form of the load works.
    let code = [op::ACONST_NULL, op::ASTORE_0 + 1, op::ALOAD_0 + 1, op::ARETURN];
    assert_eq!(execute(&code, 4).unwrap(), Outcome::Reference(NULL));
}

#[test]
fn increments_apply_to_the_local_in_place() {
    let code = [
        op::SSPUSH, 0x00, 0x05, op::SSTORE_0, op::SINC, 0, 0xfe, op::SLOAD_0, op::SRETURN,
    ];
    assert_eq!(short(&code), 3);
    let code = [op::SINC_W, 0, 0x01, 0x00, op::SLOAD_0, op::SRETURN];
    assert_eq!(short(&code), 256);
}

#[test]
fn branches_go_where_the_offset_points() {
    // if_scmpeq over two equal values jumps past the sconst_1.
    let code = [
        4, 4, op::IF_SCMPEQ, 4, 3, op::SRETURN, 8, op::SRETURN,
    ];
    assert_eq!(short(&code), 5);
    // The same shape with unequal values falls through.
    let code = [
        4, 5, op::IF_SCMPEQ, 4, 3, op::SRETURN, 8, op::SRETURN,
    ];
    assert_eq!(short(&code), 0);
    // goto backwards, with a counter to end the loop.
    let code = [
        op::SSPUSH, 0x00, 0x03, op::SSTORE_0, op::SINC, 0, 0xff, op::SLOAD_0,
        op::IFEQ, 4, op::GOTO, 0xfa, op::SLOAD_0, op::SRETURN,
    ];
    assert_eq!(short(&code), 0);
}

#[test]
fn a_switch_picks_its_entry_and_falls_back_to_the_default() {
    // stableswitch over 0 to 1, default returning 9.
    let build = |key: i16| {
        let mut code: Vec<u8> = vec![op::SSPUSH];
        code.extend_from_slice(&key.to_be_bytes());
        code.push(op::STABLESWITCH);
        code.extend_from_slice(&15i16.to_be_bytes());
        code.extend_from_slice(&0i16.to_be_bytes());
        code.extend_from_slice(&1i16.to_be_bytes());
        code.extend_from_slice(&11i16.to_be_bytes());
        code.extend_from_slice(&13i16.to_be_bytes());
        code.extend_from_slice(&[4, op::SRETURN, 5, op::SRETURN, 8, op::SRETURN]);
        code
    };
    assert_eq!(short(&build(0)), 1);
    assert_eq!(short(&build(1)), 2);
    assert_eq!(short(&build(7)), 5);
}

#[test]
fn a_lookup_switch_matches_on_the_key() {
    let mut code: Vec<u8> = vec![op::SSPUSH, 0x01, 0x00, op::SLOOKUPSWITCH];
    code.extend_from_slice(&17i16.to_be_bytes());
    code.extend_from_slice(&2i16.to_be_bytes());
    code.extend_from_slice(&[0x00, 0x05]);
    code.extend_from_slice(&13i16.to_be_bytes());
    code.extend_from_slice(&[0x01, 0x00]);
    code.extend_from_slice(&15i16.to_be_bytes());
    code.extend_from_slice(&[4, op::SRETURN, 5, op::SRETURN, 8, op::SRETURN]);
    assert_eq!(short(&code), 2);
}

#[test]
fn an_instruction_this_loop_cannot_run_yet_says_so() {
    // jsr, which the verifier refuses and the loop therefore never runs.
    assert_eq!(
        execute(&[0x71, 0x00, 0x00, op::RETURN], 1),
        Err(Error::Unsupported)
    );
}

#[test]
fn the_opcode_constants_match_the_generated_table() {
    // These are written out by name for readability, and the wide and this forms of
    // the field instructions run in the opposite order to what the mnemonics suggest.
    // Getting one wrong sends an instruction to another instruction's arm, which is
    // how a field read once ran the code for a field write.
    for (value, name) in [
        (op::GETFIELD_A, "getfield_a"),
        (op::PUTFIELD_A, "putfield_a"),
        (op::GETFIELD_A_W, "getfield_a_w"),
        (op::GETFIELD_A_THIS, "getfield_a_this"),
        (op::PUTFIELD_A_W, "putfield_a_w"),
        (op::PUTFIELD_A_THIS, "putfield_a_this"),
        (op::GETSTATIC_A, "getstatic_a"),
        (op::PUTSTATIC_A, "putstatic_a"),
        (op::INVOKEVIRTUAL, "invokevirtual"),
        (op::INVOKESPECIAL, "invokespecial"),
        (op::INVOKESTATIC, "invokestatic"),
        (op::INVOKEINTERFACE, "invokeinterface"),
        (op::NEW, "new"),
        (op::NEWARRAY, "newarray"),
        (op::ANEWARRAY, "anewarray"),
        (op::ARRAYLENGTH, "arraylength"),
        (op::ATHROW, "athrow"),
        (op::CHECKCAST, "checkcast"),
        (op::INSTANCEOF, "instanceof"),
    ] {
        assert_eq!(crate::jcvm_opcodes::NAME[value as usize], name);
    }
}

#[test]
fn an_interface_call_changes_namespace_and_then_dispatches() {
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_VIRTUAL_METHODREF};
    use crate::test_support::ClassSpec;
    // An interface with one method, and a class implementing it. The interface token
    // is zero, and the class maps it to its own virtual token one, so a mapping that
    // was ignored would call the wrong body.
    let mut package = Package {
        extra: vec![
            (1, 0, vec![op::BSPUSH, 1, op::SRETURN]),
            (1, 0, vec![op::BSPUSH, 2, op::SRETURN]),
        ],
        code: vec![
            op::NEW, 0x00, 0x01, op::ASTORE_0,
            op::ALOAD_0, op::INVOKEINTERFACE, 1, 0x00, 0x00, 0x00, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 2,
        ..Package::default()
    };
    let bodies = package.extra_offsets();
    package.classes = vec![
        // The interface itself, which carries no method table.
        ClassSpec {
            interface: true,
            ..ClassSpec::default()
        },
        ClassSpec {
            public: vec![bodies[0], bodies[1]],
            implements: vec![(0, vec![1])],
            ..ClassSpec::default()
        },
    ];
    let offsets = package.class_offsets();
    package.constants = vec![
        [CONSTANT_CLASSREF, 0x00, offsets[0] as u8, 0],
        [
            CONSTANT_CLASSREF,
            (offsets[1] >> 8) as u8,
            offsets[1] as u8,
            0,
        ],
        [CONSTANT_VIRTUAL_METHODREF, 0x00, offsets[1] as u8, 0],
    ];
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(2));
}

#[test]
fn throwing_null_raises_a_catchable_null_pointer_exception() {
    assert_eq!(
        catch_java_fault(&[op::ACONST_NULL, op::ATHROW, op::SRETURN], 1, ClassId::NullPointerException),
        Ok(Outcome::Short(1))
    );
}

#[test]
fn an_array_round_trips_through_the_heap() {
    // newarray byte[5], store 7 at index 1, read it back.
    let code = [
        op::SCONST_5, op::NEWARRAY, 11, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_1, op::BSPUSH, 7, op::BASTORE,
        op::ALOAD_0, op::SCONST_1, op::BALOAD, op::SRETURN,
    ];
    assert_eq!(short(&code), 7);
    // arraylength reads the header rather than trusting the caller.
    let code = [op::SCONST_5, op::NEWARRAY, 12, op::ARRAYLENGTH, op::SRETURN];
    assert_eq!(short(&code), 5);
}

#[test]
fn an_index_outside_the_array_is_refused_in_both_directions() {
    let code = [
        op::SCONST_1, op::NEWARRAY, 11, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_1, op::BALOAD, op::SRETURN,
    ];
    assert_eq!(catch_java_fault(&code, 2, ClassId::ArrayIndexOutOfBoundsException), Ok(Outcome::Short(1)));
    // A negative index is out of bounds rather than a large positive one.
    let code = [
        op::SCONST_1, op::NEWARRAY, 11, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_M1, op::BALOAD, op::SRETURN,
    ];
    assert_eq!(catch_java_fault(&code, 2, ClassId::ArrayIndexOutOfBoundsException), Ok(Outcome::Short(1)));
}

#[test]
fn the_instruction_and_the_array_have_to_agree_on_the_element_type() {
    // saload on a byte array would read two bytes as one short.
    let code = [
        op::SCONST_5, op::NEWARRAY, 11, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_0, op::SALOAD, op::SRETURN,
    ];
    assert_eq!(execute(&code, 2), Err(Error::Type));
    // aaload on a short array would turn a number into a reference.
    let code = [
        op::SCONST_5, op::NEWARRAY, 12, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_0, op::AALOAD, op::ARETURN,
    ];
    assert_eq!(execute(&code, 2), Err(Error::Type));
}

#[test]
fn a_reference_array_holds_references_and_says_so() {
    let code = vec![
        op::SCONST_5, op::ANEWARRAY, 0x00, 0x00, op::ASTORE_0,
        op::ALOAD_0, op::SCONST_0, op::ALOAD_0, op::AASTORE,
        op::ALOAD_0, op::SCONST_0, op::AALOAD, op::ARETURN,
    ];
    let package = Package {
        code,
        max_stack: 15,
        nargs: 0,
        max_locals: 2,
        constants: vec![[crate::cap::CONSTANT_CLASSREF, 0x80, 0, 0]],
        imports: vec![(vec![0xa0, 0, 0, 0, 0x62, 0, 1], 1, 0)],
        ..Package::default()
    };
    // The array holds itself, and what comes back is tagged as a reference, which
    // areturn requires.
    assert!(matches!(execute_package(&package), Ok(Outcome::Reference(_))));
}

#[test]
fn reference_array_stores_enforce_the_declared_component_type() {
    use crate::cap::CONSTANT_CLASSREF;
    use crate::test_support::ClassSpec;

    let mut package = Package {
        max_stack: 4,
        nargs: 0,
        max_locals: 2,
        classes: vec![ClassSpec::default(), ClassSpec::default()],
        imports: vec![(vec![0xa0, 0, 0, 0, 0x62, 0, 1], 1, 0)],
        ..Package::default()
    };
    let offsets = package.class_offsets();
    package.classes[1].super_class = offsets[0];
    package.constants = vec![
        [CONSTANT_CLASSREF, (offsets[0] >> 8) as u8, offsets[0] as u8, 0],
        [CONSTANT_CLASSREF, (offsets[1] >> 8) as u8, offsets[1] as u8, 0],
        [CONSTANT_CLASSREF, 0x80, 11, 0], // ArrayStoreException
    ];

    // A subclass is valid in an array declared for its superclass.
    package.code = vec![
        op::SCONST_1, op::ANEWARRAY, 0, 0, op::ASTORE_0,
        op::NEW, 0, 1, op::ASTORE_0 + 1,
        op::ALOAD_0, op::SCONST_0, op::ALOAD_0 + 1, op::AASTORE,
        op::ALOAD_0 + 1, op::ARETURN,
    ];
    assert!(matches!(execute_package(&package), Ok(Outcome::Reference(_))));

    // The inverse store throws ArrayStoreException before mutating the array.
    package.code = vec![
        op::SCONST_1, op::ANEWARRAY, 0, 1, op::ASTORE_0,
        op::NEW, 0, 0, op::ASTORE_0 + 1,
        op::ALOAD_0, op::SCONST_0, op::ALOAD_0 + 1, op::AASTORE,
        op::SCONST_0, op::SRETURN,
    ];
    package.handlers = vec![[0; 8]];
    let body = package.install_offset() + 2;
    let protected = package.code.len() as u16;
    package.code.extend([op::POP, op::SCONST_1, op::SRETURN]);
    package.handlers = vec![handler(body, protected, body + protected, 2, true)];
    assert_eq!(execute_package(&package), Ok(Outcome::Short(1)));
}

#[test]
fn an_array_on_a_null_reference_is_refused_before_it_reads_anything() {
    let code = [op::ACONST_NULL, op::ARRAYLENGTH, op::SRETURN];
    assert_eq!(catch_java_fault(&code, 0, ClassId::NullPointerException), Ok(Outcome::Short(1)));
    // Operand-stack underflow remains a malformed program, not a Java fault.
    assert_eq!(catch_java_fault(&[op::BALOAD, op::SRETURN], 0, ClassId::ArrayIndexOutOfBoundsException), Err(Error::Bounds));
}

#[test]
fn allocations_report_catchable_java_failures() {
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_VIRTUAL_METHODREF};
    use crate::test_support::ClassSpec;
    for allocation in [vec![op::NEWARRAY, 11], vec![op::ANEWARRAY, 0, 0], vec![op::NEW, 0, 0]] {
        let object = allocation[0] == op::NEW;
        let mut package = Package {
            imports: vec![(vec![0xa0, 0, 0, 0, 0x62, 0, 1], 1, 0),
                (vec![0xa0, 0, 0, 0, 0x62, 1, 1], 1, 6)],
            classes: vec![ClassSpec::default()],
            handlers: vec![[0; 8]], nargs: 0, max_stack: 3,
            ..Package::default()
        };
        let body = package.install_offset() + 2;
        let class = package.class_offsets()[0];
        package.constants = vec![
            [CONSTANT_CLASSREF, (class >> 8) as u8, class as u8, 0],
            [CONSTANT_CLASSREF, 0x80, 6, 0], // NegativeArraySizeException
            [CONSTANT_VIRTUAL_METHODREF, 0x81, 13, 1], // SystemException.getReason
        ];
        if !object {
            package.code = vec![op::SCONST_M1];
            package.code.extend_from_slice(&allocation);
            package.code.push(op::ARETURN);
            let end = package.code.len() as u16;
            package.code.extend([op::POP, op::SCONST_1, op::SRETURN]);
            package.handlers = vec![handler(body, end, body + end, 1, true)];
            assert_eq!(execute_package(&package), Ok(Outcome::Short(1)));
        }
        // Discard each reference and allocate until the slab is full. The reserved
        // SystemException must still be usable, without allocating another object.
        package.code = if object { vec![] } else { vec![op::SCONST_1] };
        package.code.extend_from_slice(&allocation);
        package.code.push(op::POP);
        let back = -(package.code.len() as i8);
        package.code.extend([op::GOTO, back as u8]);
        let end = package.code.len() as u16;
        package.code.extend([op::INVOKEVIRTUAL, 0, 2, op::SRETURN]);
        package.constants[1] = [CONSTANT_CLASSREF, 0x81, 13, 0]; // SystemException
        package.handlers = vec![handler(body, end, body + end, 1, true)];
        assert_eq!(execute_package(&package), Ok(Outcome::Short(5))); // NO_RESOURCE
    }
}

#[test]
fn reference_stores_reject_temporary_runtime_objects_before_mutation() {
    use crate::cap::{CONSTANT_INSTANCE_FIELDREF, CONSTANT_STATIC_FIELDREF};
    use crate::test_support::ClassSpec;
    let native = |name| crate::jcvm_api::PACKAGES.iter().enumerate().find_map(|(index, package)|
        package.classes.iter().find(|class| class.id == name)
            .map(|class| natives::native_class(index, class.token))).unwrap();
    for (opcode, transient) in [(op::AASTORE, false), (op::AASTORE, true),
        (op::PUTFIELD_A, false), (op::PUTFIELD_A_W, false),
        (op::PUTFIELD_A_THIS, false), (op::PUTSTATIC_A, false)] {
        let code = match opcode {
            op::AASTORE => vec![op::ALOAD_0, op::SCONST_0, op::ALOAD_0 + 1, opcode, op::RETURN],
            op::PUTFIELD_A_THIS => vec![op::ALOAD_0 + 1, opcode, 0, op::RETURN],
            op::PUTSTATIC_A => vec![op::ALOAD_0 + 1, opcode, 0, 0, op::RETURN],
            op::PUTFIELD_A_W => vec![op::ALOAD_0, op::ALOAD_0 + 1, opcode, 0, 0, op::RETURN],
            _ => vec![op::ALOAD_0, op::ALOAD_0 + 1, opcode, 0, op::RETURN],
        };
        let package = Package { code, nargs: 2, max_locals: 0, max_stack: 3, static_bytes: 2,
            classes: vec![ClassSpec { declared_size: 1, ..ClassSpec::default() }],
            constants: vec![[if opcode == op::PUTSTATIC_A { CONSTANT_STATIC_FIELDREF }
                else { CONSTANT_INSTANCE_FIELDREF }, 0, 0, 0]], ..Package::default() };
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let linked = Linked::new(&file).unwrap();
        let methods = file.methods().unwrap();
        let mut slab = [0; 1024];
        let mut heap = Heap::new(&mut slab).unwrap();
        let buffer = heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        let apdu = heap.new_object(native(ClassId::APDU), 1, 1).unwrap();
        let runtime = natives::new_exception(&mut heap, ClassId::CryptoException, 1).unwrap();
        let explicit = heap.new_object(native(ClassId::CryptoException), 6, 1).unwrap();
        let security = natives::new_exception(&mut heap, ClassId::SecurityException, 1).unwrap();
        let object = heap.new_object(0, 1, 1).unwrap();
        let foreign = heap.new_object(0, 1, 2).unwrap();
        let array = if transient {
            heap.new_transient_array(heap::KIND_REFERENCE, 1, 1, heap::CLEAR_ON_RESET).unwrap()
        } else { heap.new_array(heap::KIND_REFERENCE, 1, 1).unwrap() };
        let mut statics = [0; 2];
        let mut host = crate::host::NoHost;
        let mut machine = Machine::new(&mut heap, &mut host, &linked, methods,
            &mut statics, 1, Limits::IMPLEMENTED, Jcre::new(apdu, buffer));
        for (value, allowed) in [(NULL, true), (object, true), (explicit, true),
            (foreign, false), (buffer, false), (apdu, false), (runtime, false)] {
            machine.heap.put_word(object, 0, 0).unwrap();
            machine.heap.array_put_reference(array, 0, NULL).unwrap();
            machine.statics.fill(0);
            machine.heap.begin_transaction(if allowed { 8 } else { 0 }).unwrap();
            let mut words = [0; 12];
            let mut tags = [0; 2];
            let mut frame = Frame::new(&mut words, &mut tags, 2, 4).unwrap();
            frame.store_reference(0, if opcode == op::AASTORE { array } else { object }).unwrap();
            frame.store_reference(1, value).unwrap();
            let result = run(&mut machine, &package.code, &mut frame, &mut 100).unwrap();
            if allowed { assert_eq!(result, Outcome::Void); }
            else {
                assert_eq!(result, Outcome::Thrown(security));
                assert_eq!(machine.heap.transaction_remaining(), Some(0));
            }
            let stored = match opcode {
                op::AASTORE => machine.heap.array_get(array, 0).unwrap() as u16,
                op::PUTSTATIC_A => u16::from_be_bytes(machine.statics[..2].try_into().unwrap()),
                _ => machine.heap.get_word(object, 0).unwrap(),
            };
            assert_eq!(stored, if allowed { value } else { NULL });
            machine.heap.commit_transaction().unwrap();
        }
    }
}

#[test]
fn an_object_field_round_trips_through_new_and_putfield() {
    use crate::cap::CONSTANT_INSTANCE_FIELDREF;
    use crate::test_support::ClassSpec;
    // A class with two field words. new it, put 9 in field 1, read it back.
    let package = Package {
        classes: vec![ClassSpec {
            declared_size: 2,
            ..ClassSpec::default()
        }],
        constants: vec![
            [crate::cap::CONSTANT_CLASSREF, 0x00, 0x00, 0],
            [CONSTANT_INSTANCE_FIELDREF, 0x00, 0x00, 1],
        ],
        code: vec![
            op::NEW, 0x00, 0x00, op::ASTORE_0,
            op::ALOAD_0, op::BSPUSH, 9, 0x89, 0x01,
            op::ALOAD_0, 0x85, 0x01, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 2,
        ..Package::default()
    };
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(9));
}

#[test]
fn a_static_field_round_trips_through_the_image() {
    use crate::cap::CONSTANT_STATIC_FIELDREF;
    let package = Package {
        static_bytes: 4,
        constants: vec![[CONSTANT_STATIC_FIELDREF, 0x00, 0x00, 0x02]],
        // putstatic_s then getstatic_s, at image offset 2.
        code: vec![
            op::SSPUSH, 0x12, 0x34, 0x81, 0x00, 0x00,
            0x7d, 0x00, 0x00, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(0x1234));
}

#[test]
fn a_static_call_runs_the_callee_and_brings_its_answer_back() {
    use crate::cap::CONSTANT_STATIC_METHODREF;
    let mut package = Package {
        // The callee doubles its argument.
        extra: vec![(1, 0, vec![op::SLOAD_0, op::SLOAD_0, op::SADD, op::SRETURN])],
        code: vec![op::BSPUSH, 21, 0x8d, 0x00, 0x00, op::SRETURN],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    // The offsets follow the first method's bytecode, so the code has to be final
    // before they are asked for.
    let callee = package.extra_offsets()[0];
    package.constants = vec![[
        CONSTANT_STATIC_METHODREF,
        0x00,
        (callee >> 8) as u8,
        callee as u8,
    ]];
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(42));
}

#[test]
fn a_virtual_call_runs_the_body_the_receiver_class_names() {
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_VIRTUAL_METHODREF};
    use crate::test_support::ClassSpec;
    // Two classes, the subclass overriding token 0. Calling through the superclass
    // reference has to reach the subclass body.
    let mut package = Package {
        extra: vec![
            (1, 0, vec![op::BSPUSH, 1, op::SRETURN]),
            (1, 0, vec![op::BSPUSH, 2, op::SRETURN]),
        ],
        // new the subclass, then invokevirtual the token the superclass declares.
        code: vec![
            op::NEW, 0x00, 0x00, op::ASTORE_0,
            op::ALOAD_0, 0x8b, 0x00, 0x01, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 2,
        ..Package::default()
    };
    let bodies = package.extra_offsets();
    package.classes = vec![
        ClassSpec {
            public: vec![bodies[0]],
            ..ClassSpec::default()
        },
        ClassSpec {
            super_class: 0,
            public: vec![bodies[1]],
            ..ClassSpec::default()
        },
    ];
    let subclass = package.class_offsets()[1];
    package.constants = vec![
        [CONSTANT_CLASSREF, (subclass >> 8) as u8, subclass as u8, 0],
        [CONSTANT_VIRTUAL_METHODREF, 0x00, 0x00, 0],
    ];
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(2));
}

#[test]
fn a_call_deeper_than_the_arena_allows_is_refused() {
    use crate::cap::CONSTANT_STATIC_METHODREF;
    // A method that calls itself, which without a bound would recurse until the card
    // ran out of native stack.
    let mut package = Package {
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    package.code = vec![0x8d, 0x00, 0x00, op::RETURN];
    let here = package.install_offset();
    package.constants = vec![[
        CONSTANT_STATIC_METHODREF,
        0x00,
        (here >> 8) as u8,
        here as u8,
    ]];
    assert_eq!(execute_package(&package), Err(Error::Quota));
}

/// A handler entry, with the offsets a built package puts things at.
fn handler(start: u16, length: u16, target: u16, catch: u16, stop: bool) -> [u8; 8] {
    let bits = length | if stop { 0x8000 } else { 0 };
    [
        (start >> 8) as u8, start as u8,
        (bits >> 8) as u8, bits as u8,
        (target >> 8) as u8, target as u8,
        (catch >> 8) as u8, catch as u8,
    ]
}

#[test]
fn a_thrown_exception_lands_in_the_handler_that_covers_it() {
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_STATIC_METHODREF};
    use crate::test_support::ClassSpec;
    // The callee throws. The caller has a handler over the call, so control arrives at
    // the handler with the exception on an otherwise empty stack.
    let mut package = Package {
        classes: vec![ClassSpec::default()],
        extra: vec![(0, 1, vec![op::NEW, 0x00, 0x00, op::ATHROW])],
        code: vec![
            // The call, then the handler at the end returning 7.
            op::BSPUSH, 1, 0x8d, 0x00, 0x01, op::SRETURN,
            op::POP, op::BSPUSH, 7, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 1,
        ..Package::default()
    };
    let callee = package.extra_offsets()[0];
    package.constants = vec![
        [CONSTANT_CLASSREF, 0x00, 0x00, 0],
        [CONSTANT_STATIC_METHODREF, 0x00, (callee >> 8) as u8, callee as u8],
    ];
    // Adding a handler moves every method along, so the try range and the call target
    // are both computed after the table is in place.
    package.handlers = vec![[0; 8]];
    let callee = package.extra_offsets()[0];
    package.constants[1] =
        [CONSTANT_STATIC_METHODREF, 0x00, (callee >> 8) as u8, callee as u8];
    // The try range covers the call, and the handler sits after the normal return.
    let body = package.install_offset() + 2;
    package.handlers = vec![handler(body, 6, body + 6, 0, true)];
    assert_eq!(execute_package(&package).unwrap(), Outcome::Short(7));
}

#[test]
fn an_exception_no_handler_covers_leaves_the_method() {
    use crate::cap::CONSTANT_CLASSREF;
    use crate::test_support::ClassSpec;
    let package = Package {
        classes: vec![ClassSpec::default()],
        constants: vec![[CONSTANT_CLASSREF, 0x00, 0x00, 0]],
        code: vec![op::NEW, 0x00, 0x00, op::ATHROW],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    // It reaches the caller, which here is the test itself.
    assert!(matches!(
        execute_package(&package).unwrap(),
        Outcome::Thrown(_)
    ));
}

#[test]
fn the_stop_bit_keeps_an_exception_from_escaping_one_scope_too_far() {
    use crate::cap::CONSTANT_CLASSREF;
    use crate::test_support::ClassSpec;
    // Two handlers over the same range. The first catches a class the exception is
    // not, and carries the stop bit, so the second must never be reached even though
    // it covers the same code and catches everything.
    let other = 10u16;
    let mut package = Package {
        classes: vec![
            ClassSpec::default(),
            ClassSpec {
                super_class: 0xffff,
                ..ClassSpec::default()
            },
        ],
        code: vec![
            op::NEW, 0x00, 0x00, op::ATHROW,
            op::POP, op::BSPUSH, 7, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    // Two handlers in the table, so the method sits after both of them.
    package.handlers = vec![[0; 8]; 2];
    let body = package.install_offset() + 2;
    // The first catches constant pool entry one, which names the other class, and
    // carries the stop bit. The second catches everything and must stay unreachable.
    package.handlers = vec![
        handler(body, 4, body + 4, 1, true),
        handler(body, 4, body + 4, 0, true),
    ];
    let second = package.class_offsets()[1];
    assert_eq!(second, other);
    package.constants = vec![
        [CONSTANT_CLASSREF, 0x00, 0x00, 0],
        [CONSTANT_CLASSREF, (second >> 8) as u8, second as u8, 0],
    ];
    assert!(matches!(
        execute_package(&package).unwrap(),
        Outcome::Thrown(_)
    ));
}

#[test]
fn bytecode_can_call_the_api_and_catch_what_it_throws() {
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_STATIC_METHODREF};
    // sspush 0x6a80, invokestatic ISOException.throwIt, which must not return. The
    // handler catches it and reads the reason back out through getReason.
    let mut package = Package {
        imports: vec![(
            vec![0xa0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01],
            1,
            6,
        )],
        code: vec![
            op::SSPUSH, 0x6a, 0x80, 0x8d, 0x00, 0x00, op::RETURN,
            // The handler: the exception is on the stack, so ask it its reason.
            0x8b, 0x00, 0x02, op::SRETURN,
        ],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    package.handlers = vec![[0; 8]];
    let body = package.install_offset() + 2;
    package.handlers = vec![handler(body, 7, body + 7, 1, true)];
    package.constants = vec![
        // ISOException.throwIt, static token 1 of class token 7.
        [CONSTANT_STATIC_METHODREF, 0x80, 7, 1],
        // The same class, named as a catch type.
        [CONSTANT_CLASSREF, 0x80, 7, 0],
        // ISOException.getReason, virtual token 1 of the same class.
        [crate::cap::CONSTANT_VIRTUAL_METHODREF, 0x80, 7, 1],
    ];
    assert_eq!(
        execute_package(&package).unwrap(),
        Outcome::Short(0x6a80u16 as i16)
    );

    // Invalid framework arguments must enter the matching typed Java handler.
    package.imports.push((vec![0xa0, 0x00, 0x00, 0x00, 0x62, 0x00, 0x01], 1, 0));
    for (input, argument, class, method, return_op, exception_token) in [
        (vec![op::ACONST_NULL], op::SCONST_0, 16, 4, op::SRETURN, 7), // Util.getShort
        (vec![op::SCONST_0, op::NEWARRAY, 11], op::SCONST_0, 16, 4, op::SRETURN, 5),
        (vec![op::BSPUSH, 0xff], op::SCONST_1, 8, 13, op::ARETURN, 6), // makeTransientByteArray
    ] {
        package.code = input;
        package.code.extend([argument, 0x8d, 0, 0, return_op]);
        let end = package.code.len() as u16;
        package.code.extend([op::POP, op::BSPUSH, 7, op::SRETURN]);
        package.handlers = vec![handler(body, end, body + end, 1, true)];
        package.constants = vec![
            [CONSTANT_STATIC_METHODREF, 0x80, class, method],
            [CONSTANT_CLASSREF, 0x81, exception_token, 0],
        ];
        assert_eq!(execute_package(&package).unwrap(), Outcome::Short(7));
    }
}

#[test]
fn an_api_method_the_card_does_not_provide_is_refused_by_name() {
    use crate::cap::CONSTANT_STATIC_METHODREF;
    // A method that resolves to a real API entry this build has not implemented. The
    // refusal is unsupported rather than missing.
    let package = Package {
        imports: vec![(vec![0xa0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01], 1, 6)],
        // JCSystem token 8, static token 4 is getAppletShareableInterfaceObject,
        // which is a real API entry this build has nothing behind.
        constants: vec![[CONSTANT_STATIC_METHODREF, 0x80, 8, 4]],
        code: vec![0x8d, 0x00, 0x00, op::RETURN],
        max_stack: 15,
        nargs: 0,
        max_locals: 0,
        ..Package::default()
    };
    assert_eq!(execute_package(&package), Err(Error::Unsupported));
}

#[test]
fn a_budget_bounds_a_loop_in_the_bytecode() {
    // goto to itself, which without a budget would never return.
    let code = [op::GOTO, 0, op::RETURN];
    assert_eq!(execute(&code, 0), Err(Error::Quota));
    let mut package = Package { code: code.to_vec(), nargs: 0, handlers: vec![[0; 8]], ..Package::default() };
    let body = package.install_offset() + 2;
    package.code.extend([op::POP, op::SCONST_1, op::SRETURN]);
    package.handlers = vec![handler(body, code.len() as u16, body + code.len() as u16, 0, true)];
    assert_eq!(execute_package(&package), Err(Error::Quota));
    let mut polls = 0;
    assert_eq!(execute_package_with_cancel(&package, &mut || {
        polls += 1;
        polls == 3
    }), Err(Error::Cancelled));
    assert_eq!(polls, 3);
}
