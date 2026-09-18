//! Parse Load File Data Blocks produced from real CAP files.
//!
//! The synthetic cases in the crate pin each rejection. This pins the opposite direction,
//! that a package a real converter emits is accepted, which a hand-built fixture cannot
//! prove. CAP files are third-party build outputs and stay out of this repository, so the
//! blocks are supplied through `MICROCARD_JCVM_LOAD_FILES` and the test reports that it
//! found nothing when the variable is unset.
//!
//! Produce the blocks with `scripts/jcvm_cap_inventory.py <cap directory> --load-file <out>`.
use microcard_engine_jcvm::cap::{LoadFile, MethodHeader, Tag};
use microcard_engine_jcvm::code::instruction_length;
use std::collections::BTreeSet;
use microcard_engine_jcvm::code::{Boundaries, Limits, constant_pool_index, verify_targets};

/// The six packages docs/JCVM_PROFILE.md commits to, with the versions it names.
const PROFILE: [(&[u8], u8, u8); 6] = [
    (&[0xa0, 0, 0, 0, 0x62, 0, 1], 1, 0),
    (&[0xa0, 0, 0, 0, 0x62, 1, 1], 1, 6),
    (&[0xa0, 0, 0, 0, 0x62, 1, 2], 1, 6),
    (&[0xa0, 0, 0, 0, 0x62, 2, 1], 1, 6),
    (&[0xa0, 0, 0, 0, 0x62, 2, 9], 1, 0),
    (&[0xa0, 0, 0, 1, 0x51, 0], 1, 5),
];

#[test]
fn every_supplied_load_file_parses_as_a_supported_package() {
    let Ok(directory) = std::env::var("MICROCARD_JCVM_LOAD_FILES") else {
        eprintln!("MICROCARD_JCVM_LOAD_FILES is unset, so no real package was parsed");
        return;
    };
    let mut parsed = 0;
    for entry in std::fs::read_dir(&directory).expect("load file directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().is_none_or(|extension| extension != "lfdb") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("load file");
        let file = LoadFile::parse(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        let header = file.header().expect("header");
        header
            .supported()
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        // What the profile says every target variant carries.
        assert_eq!((header.cap_major, header.cap_minor), (2, 1));
        assert_eq!(header.package_aid.len(), 9);
        let directory = file.directory().expect("directory");
        assert_eq!(directory.applet_count, 1);
        // The Directory count and the Applet component have to agree, and the AID is the
        // one a PIV host selects.
        let applets = file.applets().expect("applets");
        assert_eq!(applets.count(), directory.applet_count as usize);
        let applet = applets.iter().next().expect("one applet");
        assert_eq!(applet.aid, &[0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0]);
        assert!(applets.find(applet.aid).is_some());

        // The install offset has to land on a real method header inside the method area,
        // because a card calls it at instantiation with nothing else to check it against.
        let methods = file.methods().expect("methods");
        let offset = applet.install_method_offset as usize;
        assert!(offset >= methods.methods_start(), "{}: {offset}", path.display());
        let header = MethodHeader::parse(methods.bytes(), offset)
            .unwrap_or_else(|error| panic!("{}: install header {error:?}", path.display()));
        assert!(!header.abstract_method(), "{}", path.display());
        // install is static and takes the byte array, its offset and its length, so three
        // words of parameter. max_locals counts only what the method declares on top.
        assert_eq!(header.nargs, 3, "{}", path.display());
        assert!(header.frame_words() >= header.nargs as u16, "{}", path.display());

        // Every handler in the package points inside the component, which Method::parse
        // established, and the table is small enough to walk here.
        for handler in methods.handlers() {
            assert!(handler.handler_offset as usize >= methods.methods_start());
        }
        assert_eq!(directory.import_count, 6);
        assert!(file.component(Tag::Method).is_some());

        // The profile says six packages and no others, and it names the version of each.
        // A card exporting anything less cannot link this package, which is what makes the
        // target version real rather than a label.
        let imports = file.imports().expect("imports");
        assert_eq!(imports.count(), PROFILE.len());
        for package in imports.iter() {
            let (_, major, minor) = PROFILE
                .iter()
                .find(|(aid, _, _)| *aid == package.aid)
                .unwrap_or_else(|| panic!("{}: unexpected import {:02x?}", path.display(), package.aid));
            assert_eq!(
                (package.major, package.minor),
                (*major, *minor),
                "{}: {:02x?}",
                path.display(),
                package.aid
            );
            assert!(package.satisfied_by(*major, *minor));
        }
        // Descriptor and Debug are excluded from a Load File Data Block, and their absence
        // is why the block is a third of the archive that carried it.
        assert!(file.component(Tag::Descriptor).is_none());
        assert!(file.component(Tag::Debug).is_none());
        // The Directory and the Static Field component describe the same image, so they
        // have to agree before anything allocates it.
        let statics = file.static_fields().expect("static fields");
        assert_eq!(statics.image_size, directory.image_size, "{}", path.display());
        assert_eq!(
            statics.array_init_count(),
            directory.array_init_count as usize,
            "{}",
            path.display()
        );
        let initialised: usize = statics.array_inits().map(|array| array.values.len()).sum();
        assert_eq!(initialised, directory.array_init_size as usize, "{}", path.display());

        // Every method the package declares, from the class method tables and the applet
        // install offsets. A method records no length, so the next offset is its bound.
        let classes = file.classes().expect("classes");
        let mut offsets: Vec<usize> = classes
            .iter()
            .flat_map(|class| class.method_offsets().collect::<Vec<u16>>())
            .map(usize::from)
            .chain(applets.iter().map(|a| a.install_method_offset as usize))
            // Static methods and constructors appear in no class method table. Their only
            // offsets are the internal static references in the constant pool, and without
            // them a method's extent swallows whatever follows it.
            .chain(
                file.constants()
                    .expect("constants")
                    .iter()
                    .filter_map(|entry| entry.internal_static_method())
                    .map(usize::from),
            )
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert!(offsets.len() > 100, "{}: {} methods", path.display(), offsets.len());

        // The package declares no 32-bit integers, and subroutines have not been emitted by
        // a converter for many years, so this is the policy every method is walked under.
        let limits = Limits {
            int: header.flags & 0x01 != 0,
            ..Limits::IMPLEMENTED
        };
        let mut scratch = vec![0u8; 4096];
        let mut walked = 0;
        let constants = file.constants().expect("constants");
        // Offsets into the Method component where this walk found a constant pool index.
        let mut named: BTreeSet<usize> = BTreeSet::new();
        // A handler's catch type is a constant pool index too, and it sits in the handler
        // table rather than in any method, so the lists cover it as well.
        for (index, handler) in methods.handlers().enumerate() {
            assert!(
                (handler.catch_type_index as usize) < constants.count()
                    || handler.catch_type_index == 0,
                "{}: catch type {}",
                path.display(),
                handler.catch_type_index
            );
            // A zero catch type is a finally block, which names no class and so appears
            // in no list.
            if handler.catch_type_index != 0 {
                named.insert(1 + index * 8 + 6);
            }
        }
        for (index, &offset) in offsets.iter().enumerate() {
            let end = offsets.get(index + 1).copied().unwrap_or(methods.bytes().len());
            let (method_header, code) = methods
                .method(offset, end)
                .unwrap_or_else(|error| panic!("{}: method at {offset} {error:?}", path.display()));
            if method_header.abstract_method() {
                continue;
            }
            if scratch.len() < Boundaries::scratch_for(code.len()) {
                scratch.resize(Boundaries::scratch_for(code.len()), 0);
            }
            // Entry points are the first instruction and every handler that lands inside
            // this method. A method's extent is bounded above by the next offset the
            // package names, and a package can carry a method nothing names, so decoding
            // everything in between would decode the next method's header as code.
            let body = offset + method_header.length;
            let mut entries = vec![0usize];
            entries.extend(methods.handlers().filter_map(|handler| {
                let target = handler.handler_offset as usize;
                (target >= body && target < end).then(|| target - body)
            }));
            let boundaries = Boundaries::reachable(code, &mut scratch, limits, &entries)
                .unwrap_or_else(|error| panic!("{}: decode at {offset} {error:?}", path.display()));
            verify_targets(code, &boundaries)
                .unwrap_or_else(|error| panic!("{}: targets at {offset} {error:?}", path.display()));
            // Every constant pool index this method names has to be in range, and every
            // one has to be listed in the Reference Location component. Both directions are
            // collected here and checked against that component once the walk is done.
            let mut at = 0;
            while at < code.len() {
                if !boundaries.is_boundary(at) {
                    at += 1;
                    continue;
                }
                if let Some((operand, index)) = constant_pool_index(code, at).expect("index") {
                    assert!(
                        (index as usize) < constants.count(),
                        "{}: pool index {index} of {}",
                        path.display(),
                        constants.count()
                    );
                    named.insert(body + operand);
                }
                at += instruction_length(code, at).expect("length");
            }

            walked += 1;
        }
        assert!(walked > 100, "{}: walked {walked}", path.display());

        // The Reference Location component lists every constant pool index in the bytecode.
        // Nothing here rewrites those indices, so the lists are read as a claim and checked
        // against what the decode found. A listed offset that is not the operand of an
        // instruction taking a pool index means the two disagree about where the code is.
        let locations = file.ref_locations().expect("ref locations");
        let listed: BTreeSet<usize> = locations
            .one_byte_indices()
            .chain(locations.two_byte_indices())
            .map(|offset| offset.expect("offset"))
            .collect();
        // The lists cover the whole component, including the methods nothing references
        // and this walk therefore never decodes, so they hold offsets the decode does not
        // account for. What has to hold is the other direction.
        // Anything the decode reads as a pool index has to appear in the lists. A
        // disagreement here means the decode and the component disagree about where the
        // instructions are, which is the whole reason to check the lists rather than
        // follow them.
        let extra: Vec<usize> = named.difference(&listed).copied().take(5).collect();
        assert!(
            extra.is_empty(),
            "{}: decoded pool indices not listed: {extra:?}",
            path.display()
        );
        assert!(
            listed.len() > named.len(),
            "{}: {} listed against {} decoded",
            path.display(),
            listed.len(),
            named.len()
        );
        assert!(listed.len() > 500, "{}: {} listed", path.display(), listed.len());

        parsed += 1;
    }
    assert!(parsed > 0, "no .lfdb file in {directory}");
}
