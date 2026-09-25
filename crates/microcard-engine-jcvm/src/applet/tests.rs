    use super::*;
    use crate::cap::{CONSTANT_CLASSREF, CONSTANT_STATIC_FIELDREF, CONSTANT_STATIC_METHODREF, CONSTANT_VIRTUAL_METHODREF};
    use crate::test_support::{ClassSpec, Package};
    use alloc::vec;

    /// Opcodes this test spells out, so the bytecode reads like the applet it stands for.
    mod op {
        #[allow(dead_code)]
        pub const ACONST_NULL: u8 = 1;
        pub const SCONST_0: u8 = 3;
        #[allow(dead_code)]
        pub const SCONST_1: u8 = 4;
        pub const SSPUSH: u8 = 17;
        pub const ALOAD_0: u8 = 24;
        #[allow(dead_code)]
        pub const SLOAD_1: u8 = 29;
        pub const ASTORE_0: u8 = 43;
        pub const DUP: u8 = 61;
        pub const SRETURN: u8 = 120;
        pub const RETURN: u8 = 122;
        pub const PUTSTATIC_A: u8 = 127;
        pub const INVOKEVIRTUAL: u8 = 139;
        pub const INVOKESPECIAL: u8 = 140;
        pub const INVOKESTATIC: u8 = 141;
        pub const NEW: u8 = 143;
    }

    const FRAMEWORK_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01];
    const JAVA_LANG_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x00, 0x62, 0x00, 0x01];

    /// An applet that registers itself, accepts selection and answers one command.
    ///
    /// The shape is the smallest thing that is still an applet: a static install that
    /// constructs the class and registers it, a select that agrees, and a process that
    /// writes into the APDU buffer and sends it.
    fn applet(process: Vec<u8>, process_stack: u8) -> Package {
        applet_registration(process, process_stack, false)
    }

    fn applet_registration(process: Vec<u8>, process_stack: u8, explicit: bool) -> Package {
        let mut package = Package {
            imports: vec![
                (Vec::from(JAVA_LANG_AID), 1, 0),
                (Vec::from(FRAMEWORK_AID), 1, 6),
            ],
            // install: new Applet, dup, invokespecial <init>, invokevirtual register.
            code: vec![
                op::NEW, 0x00, 0x03,
                op::DUP,
                op::INVOKESPECIAL, 0x00, 0x04,
                op::INVOKEVIRTUAL, 0x00, 0x00,
                op::RETURN,
            ],
            max_stack: 8,
            nargs: 3,
            max_locals: 0,
            extra: vec![
                // The constructor, which just runs the superclass one.
                (1, 0, vec![op::ALOAD_0, op::INVOKESPECIAL, 0x00, 0x05, op::RETURN]),
                // select, which accepts.
                (1, 0, vec![op::SCONST_1, op::SRETURN]),
                // process, supplied by the caller.
                (2, 2, process),
            ],
            ..Package::default()
        };
        if explicit {
            package.code.splice(7..7, [op::ALOAD_0, op::SCONST_0, op::SLOAD_1 + 1]);
        }
        let bodies = package.extra_offsets();
        package.classes = vec![ClassSpec {
            // The applet class extends javacard.framework.Applet, which is external, and
            // its method table is indexed by the tokens that package assigned.
            super_class: 0x8103,
            public: {
                // Tokens zero to seven of Applet, with the three this class defines.
                let mut table = vec![0xffff; 8];
                table[applet_token(MethodId::select).unwrap() as usize] = bodies[1];
                table[applet_token(MethodId::process).unwrap() as usize] = bodies[2];
                table
            },
            ..ClassSpec::default()
        }];
        package.max_stack = 8;
        package.constants = vec![
            // Applet.register, virtual token 1 in the framework.
            [CONSTANT_VIRTUAL_METHODREF, 0x81, 3, if explicit { 2 } else { 1 }],
            [CONSTANT_CLASSREF, 0x81, 3, 0],
            [CONSTANT_CLASSREF, 0x81, 10, 0],
            // The applet's own class.
            [CONSTANT_CLASSREF, 0x00, 0x00, 0],
            // Its constructor, and the superclass constructor in the framework.
            [CONSTANT_STATIC_METHODREF, 0x00, (bodies[0] >> 8) as u8, bodies[0] as u8],
            [CONSTANT_STATIC_METHODREF, 0x81, 3, 0],
        ];
        let _ = process_stack;
        package
    }

    #[test]
    fn a_serviced_deletion_request_is_a_net_zero_persistent_write() {
        let mut bytes = vec![0; 128];
        let mut heap = Heap::new(&mut bytes).unwrap();
        heap.initialize_lifecycle();
        let buffer = heap.new_transient_array(heap::KIND_BYTE, 4, 1, heap::CLEAR_ON_RESET).unwrap();
        let instance = heap.new_object(1, 0, 1).unwrap();
        heap.mark_checkpointed();
        let before_length = heap.used();
        let before_header = heap.image()[0];
        heap.request_object_deletion().unwrap();
        heap.clear_object_deletion_request().unwrap();
        let view = PersistentView {
            heap: heap.image(), statics: &[], instance, buffer, projection: Some(&heap),
        };
        assert!(view.same_state_after_deletion_request(before_length, before_header).unwrap());
        assert!(!view.same_state_after_deletion_request(before_length, before_header | 0x80).unwrap());
        heap.new_object(1, 0, 1).unwrap();
        let grown = PersistentView {
            heap: heap.image(), statics: &[], instance, buffer, projection: Some(&heap),
        };
        assert!(!grown.same_state_after_deletion_request(before_length, before_header).unwrap());
    }

    #[test]
    fn deletion_runs_at_the_command_boundary_and_a_durable_request_survives_reboot() {
        struct Capture { snapshots: Vec<(Vec<u8>, Vec<u8>, Reference)> }
        impl crate::host::Host for Capture {
            fn checkpoint(&mut self, view: PersistentView<'_>, _: crate::host::CheckpointReason) -> Result<()> {
                let mut bytes = vec![0; view.heap_bytes()];
                let saved = view.save_into(&mut bytes)?;
                let statics = saved.statics.to_vec();
                let instance = saved.instance;
                self.snapshots.push((bytes, statics, instance));
                Ok(())
            }
        }
        let mut package = applet(vec![op::INVOKESTATIC, 0, 6, op::RETURN], 1);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 8, 18]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
        let before = card.heap_used;
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        card.pending_writes.merge(heap.pending_writes());
        card.heap_used = heap.used();
        let mut host = Capture { snapshots: Vec::new() };
        assert_eq!(card.process(&file, &mut host, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, SW_SUCCESS);
        assert_eq!(host.snapshots.len(), 1);
        assert!(card.heap_used < before + heap::HEADER + 16);
        assert_eq!(host.snapshots[0].0[0], 3, "the request is serviced before publication");

        // A previously checkpointed request, for example at a PIN boundary,
        // must still be honored before the next process after power loss.
        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        heap.new_array(heap::KIND_BYTE, 16, 1).unwrap();
        heap.request_object_deletion().unwrap();
        card.pending_writes.merge(heap.pending_writes());
        card.heap_used = heap.used();
        let mut committed = vec![0; card.heap_used];
        let state = card.save_into(&mut committed).unwrap();
        assert_eq!(state.heap[0], 0x83);
        let mut restored = AppletInstance::restore(&file, Sizes::default(), state).unwrap();
        let before = restored.heap_used;
        assert_eq!(restored.process(&file, &mut host, &[0, 1, 0, 0, 0], false).unwrap().sw, SW_SUCCESS);
        assert!(restored.heap_used < before);
        assert_eq!(host.snapshots.len(), 2);
        assert_eq!(host.snapshots[1].0[0], 3);
    }

    #[test]
    fn an_applet_installs_registers_selects_and_answers_a_command() {
        // process: write 0x9000 worth of nothing, then send two bytes from the buffer.
        let process = vec![
            // apdu.getBuffer(), keeping it in local 0.
            op::ALOAD_0 + 1, op::INVOKEVIRTUAL, 0x00, 0x06, op::ASTORE_0,
            // Util.setShort(buffer, 0, 0x1234)
            op::ALOAD_0, op::SCONST_0, op::SSPUSH, 0x12, 0x34,
            op::INVOKESTATIC, 0x00, 0x07,
            // The answer of setShort is the next offset, which is also the length to send.
            op::ALOAD_0 + 1, op::SCONST_0, op::SSPUSH, 0x00, 0x02,
            op::INVOKEVIRTUAL, 0x00, 0x08,
            op::RETURN,
        ];
        let mut package = applet(process, 8);
        package.constants.push([CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 1]);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 16, 6]);
        package.constants.push([CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 8]);
        package.static_bytes = 2;
        package.constants.push([CONSTANT_STATIC_FIELDREF, 0, 0, 0]);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 7, 1]);
        let typed_component = 0x800b; // java.lang.ArrayStoreException
        // deselect records that it ran, then throws; JCRE must still clear its arrays.
        package.extra.push((1, 0, vec![op::SCONST_1, 129, 0, 9,
            op::SSPUSH, 0x6a, 0x82, op::INVOKESTATIC, 0, 10, op::RETURN]));
        package.classes[0].public[applet_token(MethodId::deselect).unwrap() as usize] = package.extra_offsets()[3];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();

        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        let initial_heap = card.heap_used;
        let module = file.applets().unwrap().iter().next().unwrap().aid;
        assert_eq!(card.install_module_with_cancel(&file, &mut crate::host::NoHost, module, &[], &mut || true), Err(Error::Cancelled));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, &[0; 5], &[]), Err(Error::Missing));
        assert_eq!(card.install_module(&file, &mut crate::host::NoHost, module, &[0; 256]), Err(Error::Bounds));
        assert_eq!(card.heap_used, initial_heap);
        assert!(!card.installed());
        {
            let mut interrupted = AppletInstance::new(&file, Sizes::default()).unwrap();
            let mut polls = 0;
            assert_eq!(interrupted.install_module_with_cancel(&file, &mut crate::host::NoHost, module, &[], &mut || {
                polls += 1;
                polls == 3
            }), Err(Error::Cancelled));
            assert_eq!(polls, 3);
        }
        card.install_module(&file, &mut crate::host::NoHost, module, &[]).unwrap();
        assert!(card.installed());
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[]), Err(Error::Inconsistent));
        assert_eq!(card.process_with_cancel(&file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true, &mut || true), Err(Error::Cancelled));

        // SELECT, which the applet accepts.
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0xa4, 0x04, 0x00, 0x00], true)
            .unwrap();
        assert_eq!(response.sw, SW_SUCCESS);
        assert_eq!(response.data, [0x12, 0x34]);
        assert!(card.selected());

        // Then an ordinary command, whose answer the applet wrote into the buffer.
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        assert_eq!(response.sw, SW_SUCCESS);
        assert_eq!(response.data, [0x12, 0x34]);

        let mut heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        let transient = heap.new_transient_array(heap::KIND_BYTE, 1, 1, heap::CLEAR_ON_RESET).unwrap();
        let on_deselect = heap.new_transient_array(heap::KIND_BYTE, 1, 1, heap::CLEAR_ON_DESELECT).unwrap();
        heap.array_put(on_deselect, 0, 8).unwrap();
        let persistent = heap.new_array(heap::KIND_BYTE, 64, 1).unwrap();
        let pin = heap.new_object(native_class_of(ClassId::OwnerPIN).unwrap(), 6, 1).unwrap();
        heap.array_put(transient, 0, 7).unwrap();
        heap.byte_slice_mut(persistent, 0, 64).unwrap().fill(9);
        heap.put_word(pin, 0, 3).unwrap();
        heap.put_word(pin, 1, 64).unwrap(); // PIN length is bounded by its configured material array.
        heap.put_word(pin, 2, persistent).unwrap();
        heap.put_word(pin, 3, 1).unwrap(); // Validated flag.
        heap.put_word(pin, 4, 2).unwrap(); // Remaining attempts are persistent.
        let key = heap.new_object(native_class_of(ClassId::AESKey).unwrap(), 6, 1).unwrap();
        let key_material = heap.new_transient_array(heap::KIND_BYTE, 17, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.byte_slice_mut(key_material, 0, 17).unwrap().fill(0x42);
        heap.array_put(key_material, 0, 1).unwrap(); // Initialization lives with transient bytes.
        heap.put_word(key, 0, 13).unwrap();
        heap.put_word(key, 1, 128).unwrap();
        heap.put_word(key, 2, key_material).unwrap();
        let cipher = heap.new_object(native_class_of(ClassId::Cipher).unwrap(), 6, 1).unwrap();
        let pending = heap.new_transient_array(heap::KIND_BYTE, 32, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.byte_slice_mut(pending, 0, 32).unwrap().fill(3);
        heap.put_word(cipher, 0, 13).unwrap();
        heap.put_word(cipher, 2, key).unwrap();
        heap.put_word(cipher, 3, 1).unwrap();
        heap.put_word(cipher, 4, 2).unwrap();
        heap.put_word(cipher, 5, pending).unwrap();
        let ec_public = heap.new_object(native_class_of(ClassId::ECPublicKey).unwrap(), 6, 1).unwrap();
        let ec_public_bytes = heap.new_array(heap::KIND_BYTE, 66, 1).unwrap();
        heap.array_put(ec_public_bytes, 0, 0x5f).unwrap();
        heap.put_word(ec_public, 0, 11).unwrap();
        heap.put_word(ec_public, 1, 256).unwrap();
        heap.put_word(ec_public, 2, ec_public_bytes).unwrap();
        let ec_private = heap.new_object(native_class_of(ClassId::ECPrivateKey).unwrap(), 6, 1).unwrap();
        let ec_private_bytes = heap.new_transient_array(heap::KIND_BYTE, 33, 1, heap::CLEAR_ON_RESET).unwrap();
        heap.array_put(ec_private_bytes, 0, 0x5f).unwrap();
        heap.array_put(ec_private_bytes, 32, 1).unwrap();
        heap.put_word(ec_private, 0, 30).unwrap();
        heap.put_word(ec_private, 1, 256).unwrap();
        heap.put_word(ec_private, 2, ec_private_bytes).unwrap();
        let agreement = heap.new_object(native_class_of(ClassId::KeyAgreement).unwrap(), 6, 1).unwrap();
        heap.put_word(agreement, 0, 3).unwrap();
        heap.put_word(agreement, 2, ec_private).unwrap();
        heap.put_word(agreement, 3, 1).unwrap();
        let pair = heap.new_object(native_class_of(ClassId::KeyPair).unwrap(), 6, 1).unwrap();
        heap.put_word(pair, 0, 5).unwrap();
        heap.put_word(pair, 1, 256).unwrap();
        heap.put_word(pair, 2, ec_public).unwrap();
        heap.put_word(pair, 5, ec_private).unwrap();
        let signature = heap.new_object(native_class_of(ClassId::Signature).unwrap(), 6, 1).unwrap();
        let hash_state = heap.new_transient_array(heap::KIND_BYTE, crate::host::SHA256_STATE_BYTES as u16,
            1, heap::CLEAR_ON_RESET).unwrap();
        heap.array_put(hash_state, 0, 1).unwrap();
        heap.put_word(signature, 0, 33).unwrap();
        heap.put_word(signature, 2, ec_private).unwrap();
        heap.put_word(signature, 3, 1).unwrap();
        heap.put_word(signature, 4, 1).unwrap();
        heap.put_word(signature, 5, hash_state).unwrap();
        let reserved_exception = natives::new_exception(&mut heap, ClassId::SystemException, 1).unwrap();
        heap.put_word_unconditional(reserved_exception, natives::REASON_FIELD, 2).unwrap();
        let runtime_exception = natives::new_exception(&mut heap, ClassId::CryptoException, 1).unwrap();
        let explicit_exception = heap.new_object(native_class_of(ClassId::CryptoException).unwrap(), 6, 1).unwrap();
        heap.put_word_unconditional(runtime_exception, natives::REASON_FIELD, 3).unwrap();
        heap.put_word_unconditional(explicit_exception, natives::REASON_FIELD, 4).unwrap();
        let retained_references = heap.new_array(heap::KIND_REFERENCE, 1, 1).unwrap();
        heap.array_put_reference(retained_references, 0, explicit_exception).unwrap();
        let typed_references = heap.new_reference_array(typed_component, 1, 1).unwrap();
        let pair_class = PACKAGES.iter().flat_map(|package| package.classes)
            .find(|class| class.id == ClassId::KeyPair).unwrap();
        // NEW checkpoints before invokespecial runs the constructor.
        let unconstructed_pair = natives::new_api_object(&mut heap, pair_class, 1).unwrap();
        assert_eq!(heap.set_lifecycle(0x0f), Ok(true));
        card.heap_used = heap.used();
        let mut saved_heap = vec![0; card.persistent_heap_bytes()];
        let saved = card.save_into(&mut saved_heap).unwrap();
        for width in [1, 3, 17, 127] {
            let mut windowed = vec![0xa5; saved.heap.len()];
            for (index, chunk) in windowed.chunks_mut(width).enumerate() {
                card.persistent_view().unwrap().save_range(index * width, chunk).unwrap();
            }
            assert_eq!(windowed, saved.heap);
        }
        let instance = saved.instance;
        let saved_statics = saved.statics.to_vec();
        let mut restored = AppletInstance::restore_without_frames(&file, Sizes::default(), saved).unwrap();
        assert_eq!((restored.words.capacity(), restored.tags.capacity()), (0, 0));
        let live_heap = restored.heap[..restored.heap_used].to_vec();
        restored.release_idle_memory();
        assert_eq!(restored.heap.len(), restored.heap_used);
        assert_eq!(restored.heap, live_heap);
        restored.restore_idle_memory().unwrap();
        assert_eq!(restored.heap.len(), Sizes::default().heap_bytes);
        assert_eq!(restored.heap[..restored.heap_used], live_heap);
        assert!(restored.heap[restored.heap_used..].iter().all(|byte| *byte == 0));
        assert!(restored.words.iter().all(|word| *word == 0));
        assert!(restored.tags.iter().all(|tag| *tag == 0));
        assert!(!restored.selected());
        let recovered = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(recovered.lifecycle(), Ok(0x0f));
        assert_eq!(recovered.array_get(transient, 0), Ok(0));
        assert_eq!(recovered.array_get(persistent, 0), Ok(9));
        assert_eq!(recovered.get_word(pin, 1), Ok(64));
        assert_eq!(recovered.byte_slice(persistent, 0, 64).unwrap(), &[9; 64]);
        assert_eq!(recovered.get_word(pin, 3), Ok(0));
        assert_eq!(recovered.get_word(pin, 4), Ok(2));
        assert_eq!(recovered.get_word(reserved_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(recovered.get_word(runtime_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(recovered.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        assert_eq!(recovered.info(typed_references).unwrap().class, typed_component);
        assert_eq!(recovered.byte_slice(key_material, 0, 17).unwrap(), &[0; 17]);
        assert_eq!(recovered.byte_slice(pending, 0, 32).unwrap(), &[0; 32]);
        assert_eq!(recovered.get_word(cipher, 2), Ok(key));
        assert_eq!(recovered.get_word(signature, 2), Ok(ec_private));
        assert_eq!(recovered.byte_slice(hash_state, 0, crate::host::SHA256_STATE_BYTES).unwrap(),
            &[0; crate::host::SHA256_STATE_BYTES]);
        assert_eq!(recovered.get_word(pair, 2), Ok(ec_public));
        assert_eq!(recovered.get_word(pair, 5), Ok(ec_private));
        assert_eq!(recovered.get_word(agreement, 2), Ok(ec_private));
        assert_eq!(recovered.get_word(agreement, 3), Ok(1));
        assert_eq!(recovered.array_get(ec_public_bytes, 0), Ok(0x5f));
        assert_eq!(recovered.byte_slice(ec_private_bytes, 0, 33).unwrap(), &[0; 33]);
        assert_eq!(restored.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0, 0], false).unwrap().data, [0x12, 0x34]);
        // Saving must not clear authorization or transient values in the live session.
        let live = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(live.array_get(transient, 0), Ok(7));
        assert_eq!(live.get_word(pin, 3), Ok(1));
        assert_eq!(live.get_word(reserved_exception, natives::REASON_FIELD), Ok(2));
        assert_eq!(live.get_word(runtime_exception, natives::REASON_FIELD), Ok(3));
        assert_eq!(live.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        let mut old_heap = saved_heap.clone();
        old_heap[0] = 1;
        assert!(matches!(
            AppletInstance::restore(
                &file,
                Sizes::default(),
                PersistentState {
                    heap: &old_heap,
                    statics: &saved_statics,
                    instance,
                },
            ),
            Err(Error::IncompatibleState)
        ));
        for case in 0..31 {
            let mut invalid = saved_heap.clone();
            let root = match case {
                0 => instance + 2, // A field is not an object handle.
                1 => { invalid[transient as usize + heap::HEADER] = 1; instance }
                2 => { invalid[pin as usize + heap::HEADER + 7] = 1; instance }
                3 => { invalid[persistent as usize + 5] = 2; instance }
                4 => { invalid[key_material as usize + 4] &= 0x0f; instance } // Old persistent-key layout.
                5 => { invalid[pending as usize + 4] &= 0x0f; instance }
                6 => { invalid[cipher as usize + heap::HEADER + 10..cipher as usize + heap::HEADER + 12].fill(0); instance }
                7 => { invalid[cipher as usize + heap::HEADER + 1] = 14; instance }
                8 => { invalid[ec_public_bytes as usize + heap::HEADER] = 0x80; instance }
                9 => { invalid[ec_private_bytes as usize + 4] &= 0x0f; instance }
                10 => { invalid[ec_public as usize + heap::HEADER + 1] = 12; instance }
                11 => { invalid[ec_public as usize + heap::HEADER + 7] = 1; instance }
                12 => { invalid[agreement as usize + heap::HEADER + 1] = 1; instance }
                13 => { invalid[agreement as usize + heap::HEADER + 4..agreement as usize + heap::HEADER + 6].copy_from_slice(&ec_public.to_be_bytes()); instance }
                14 => { invalid[pair as usize + heap::HEADER + 10..pair as usize + heap::HEADER + 12].copy_from_slice(&(ec_private + 2).to_be_bytes()); instance }
                15 => { invalid[pair as usize + heap::HEADER + 10..pair as usize + heap::HEADER + 12].copy_from_slice(&ec_public.to_be_bytes()); instance }
                16 => { invalid[hash_state as usize + 4] &= 0x0f; instance }
                17 => { invalid[signature as usize + heap::HEADER + 9] = 2; instance }
                18 => { invalid[signature as usize + heap::HEADER + 10..signature as usize + heap::HEADER + 12].copy_from_slice(&pending.to_be_bytes()); instance }
                19 => { invalid[runtime_exception as usize + heap::HEADER + 1] = 3; instance }
                20..=22 => {
                    let reference = match case { 20 => runtime_exception, 21 => card.apdu, _ => card.buffer };
                    let at = retained_references as usize + heap::HEADER;
                    invalid[at..at + 2].copy_from_slice(&reference.to_be_bytes());
                    instance
                }
                23 => { invalid[pin as usize + heap::HEADER + 3] = 65; instance } // Exceeds configured PIN capacity.
                24 => { invalid[unconstructed_pair as usize + heap::HEADER + 1] = 5; instance }
                25 => { invalid[..2].fill(0); instance } // Pre-lifecycle heap format.
                26 => { invalid[0] = 2; instance } // Previous heap version.
                27 => { invalid[1] = 0x80; instance } // Invalid application state.
                28 => { invalid.truncate(invalid.len() - 1); instance }
                30 => { invalid[0] = 4; instance } // Unknown header version.
                _ => {
                    let at = typed_references as usize + heap::HEADER;
                    invalid[at..at + 2].copy_from_slice(&explicit_exception.to_be_bytes());
                    instance
                }
            };
            assert!(AppletInstance::restore(&file, Sizes::default(), PersistentState { heap: &invalid, statics: &saved_statics, instance: root }).is_err());
        }
        card.deselect_with_cancel(&file, &mut crate::host::NoHost, &mut || false).unwrap();
        assert!(!card.selected());
        assert_eq!(card.statics, [0, 1]);
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(on_deselect, 0), Ok(0));
        assert_eq!(heap.array_get(transient, 0), Ok(7));
        assert!(matches!(card.retain_volatile(363), Err(Error::Quota)));
        let retained = card.retain_volatile(364).unwrap();
        assert_eq!(retained.bytes(), 364);
        // Runtime exceptions are reserved, so deselection preserves the heap layout.
        restored.restore_volatile(&retained).unwrap();
        let mut suspended_heap = vec![0; card.persistent_heap_bytes()];
        restored = AppletInstance::restore(&file, Sizes::default(), card.save_into(&mut suspended_heap).unwrap()).unwrap();
        restored.restore_volatile(&retained).unwrap();
        let resumed = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
        assert_eq!(resumed.array_get(transient, 0), Ok(7));
        assert_eq!(resumed.array_get(on_deselect, 0), Ok(0));
        assert_eq!(resumed.get_word(pin, 3), Ok(0));
        assert_eq!(resumed.array_get(key_material, 0), Ok(1));
        assert_eq!(resumed.array_get(hash_state, 0), Ok(1));
        assert_eq!(resumed.array_get(ec_private_bytes, 0), Ok(0x5f));
        assert_eq!(resumed.array_get(ec_private_bytes, 32), Ok(1));
        assert_eq!(resumed.byte_slice(key_material, 1, 16).unwrap(), &[0x42; 16]);
        card.reset().unwrap();
        assert!(card.installed());
        assert!(card.words.iter().all(|word| *word == 0));
        assert!(card.tags.iter().all(|tag| *tag == 0));
        let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
        assert_eq!(heap.array_get(transient, 0), Ok(0));
        assert_eq!(heap.array_get(persistent, 0), Ok(9));
        assert_eq!(heap.get_word(pin, 3), Ok(0));
        assert_eq!(heap.get_word(pin, 4), Ok(2));
        assert_eq!(heap.get_word(runtime_exception, natives::REASON_FIELD), Ok(0));
        assert_eq!(heap.get_word(explicit_exception, natives::REASON_FIELD), Ok(4));
        assert!(heap.byte_slice(card.buffer, 0, card.sizes.buffer_bytes as usize).unwrap().iter().all(|byte| *byte == 0));
        // Explicit registration may not change the instance management authorized.
        let bytes = applet_registration(vec![op::RETURN], 1, true).build();
        let file = LoadFile::parse(&bytes).unwrap();
        let module_aid = file.applets().unwrap().iter().next().unwrap().aid;
        let requested = [0xf0, 1, 2, 3, 4];
        for (parameters, expected) in [(&requested[..], Ok(())), (&[0xf0, 1, 2, 3, 5][..], Err(Error::Unauthorized)), (&[0xf0, 1, 2, 3][..], Err(Error::Bounds))] {
            let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
            assert_eq!(card.install_instance_with_cancel(&file, &mut crate::host::NoHost,
                Installation { module_aid, instance_aid: &requested, parameters }, &mut || false), expected);
        }
    }

    #[test]
    fn installation_parameters_cannot_escape_into_static_storage() {
        let mut package = applet(vec![op::RETURN], 1);
        package.static_bytes = 2;
        package.constants.push([crate::cap::CONSTANT_STATIC_FIELDREF, 0, 0, 0]);
        // Keep method offsets unchanged; this installation only attempts the store.
        package.code[..5].copy_from_slice(&[op::ALOAD_0, op::PUTSTATIC_A, 0, 6, op::RETURN]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[0x42]), Err(Error::Unauthorized));
        assert_eq!(card.statics, [0, 0]);
        assert!(!card.installed());
    }

    #[test]
    fn an_exception_the_applet_throws_becomes_the_status_word() {
        // process: ISOException.throwIt(0x6a82)
        let process = vec![
            op::SSPUSH, 0x6a, 0x82, op::INVOKESTATIC, 0x00, 0x06, op::RETURN,
        ];
        let mut package = applet(process, 8);
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 7, 1]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        // The word the applet chose, not a generic failure.
        assert_eq!(response.sw, 0x6a82);
        assert!(response.data.is_empty());
        let response = card.process(&file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap();
        assert_eq!(response.sw, 0x6a82);
        assert!(card.selected(), "a process status word does not undo accepted selection");
        package.extra[1].2[0] = op::SCONST_0;
        let declined_bytes = package.build();
        let declined_file = LoadFile::parse(&declined_bytes).unwrap();
        let mut declined = AppletInstance::new(&declined_file, Sizes::default()).unwrap();
        declined.install(&declined_file, &mut crate::host::NoHost, &[]).unwrap();
        assert_eq!(declined.process(&declined_file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x6999);
        assert!(!declined.selected());
        // Inherited Applet.select() accepts; process still chooses the response status.
        package.classes[0].public[applet_token(MethodId::select).unwrap() as usize] = 0xffff;
        let inherited_bytes = package.build();
        let inherited_file = LoadFile::parse(&inherited_bytes).unwrap();
        let mut inherited = AppletInstance::new(&inherited_file, Sizes::default()).unwrap();
        inherited.install(&inherited_file, &mut crate::host::NoHost, &[]).unwrap();
        assert_eq!(inherited.process(&inherited_file, &mut crate::host::NoHost, &[0, 0xa4, 4, 0, 0], true).unwrap().sw, 0x6a82);
        assert!(inherited.selected());
        let mut polls = 0;
        assert_eq!(card.process_with_cancel(&file, &mut crate::host::NoHost, &[0, 1, 0, 0, 0], false, &mut || {
            polls += 1;
            polls == 3
        }), Err(Error::Cancelled));
        assert_eq!(polls, 3);
    }

    #[test]
    fn explicit_transactions_and_ordinary_writes_follow_callback_boundaries() {
        #[derive(Default)]
        struct CheckpointHost { saved: Vec<(Vec<u8>, Vec<u8>, Reference)>, fail_at: Option<usize>, calls: usize }
        impl Host for CheckpointHost {
            fn checkpoint(&mut self, state: PersistentView<'_>, _: crate::host::CheckpointReason) -> Result<()> {
                self.calls += 1;
                if self.fail_at == Some(self.calls) { return Err(Error::Storage); }
                let mut heap = vec![0; state.heap_bytes()];
                let saved = state.save_into(&mut heap)?;
                self.saved.push((saved.heap.to_vec(), saved.statics.to_vec(), saved.instance));
                Ok(())
            }
        }
        for ending in ["commit", "commit-throw", "commit-cancel", "commit-fail", "abort", "return", "throw", "allocate-abort", "cancel", "plain-throw", "plain-cancel", "plain-store-fail", "full", "full-caught"] {
            // Constants 6..12: begin, commit, abort, static field, instance field,
            // ISOException.throwIt, Util.arrayCopy.
            let mut process = vec![
                op::SSPUSH, 0, 9, 0x81, 0, 9,
                op::ALOAD_0, op::SSPUSH, 0, 9, 0x89, 10,
            ];
            if ending.starts_with("full") {
                process.extend_from_slice(&[op::SSPUSH, 0x20, 0, 144, 11, op::ASTORE_0 + 2]);
            }
            if !ending.starts_with("plain-") { process.extend_from_slice(&[op::INVOKESTATIC, 0, 6]); }
            process.extend_from_slice(&[
                op::SSPUSH, 0, 12, 0x81, 0, 9,
                op::ALOAD_0, op::SSPUSH, 0, 12, 0x89, 10,
                op::ALOAD_0 + 1, op::INVOKEVIRTUAL, 0, 13,
                op::SCONST_0, op::SSPUSH, 0, 42, 56,
            ]);
            match ending {
                "commit" | "commit-fail" => process.extend_from_slice(&[op::INVOKESTATIC, 0, 7]),
                "commit-throw" | "commit-cancel" => {
                    process.extend_from_slice(&[
                        op::INVOKESTATIC, 0, 7, op::INVOKESTATIC, 0, 6,
                        op::SSPUSH, 0, 99, 0x81, 0, 9,
                        op::ALOAD_0, op::SSPUSH, 0, 99, 0x89, 10,
                    ]);
                    if ending == "commit-throw" {
                        process.extend_from_slice(&[op::SSPUSH, 0x6a, 0x80, op::INVOKESTATIC, 0, 11]);
                    } else { process.extend_from_slice(&[112, 0]); }
                },
                "abort" => process.extend_from_slice(&[op::INVOKESTATIC, 0, 8]),
                "throw" | "plain-throw" => process.extend_from_slice(&[op::SSPUSH, 0x6a, 0x80, op::INVOKESTATIC, 0, 11]),
                "allocate-abort" => process.extend_from_slice(&[op::NEW, 0, 3, op::ASTORE_0 + 2, op::INVOKESTATIC, 0, 8]),
                "cancel" | "plain-cancel" => process.extend_from_slice(&[112, 0]), // goto itself until cancellation
                "full" | "full-caught" => process.extend_from_slice(&[
                    op::ALOAD_0 + 2, op::SCONST_0, op::ALOAD_0 + 2, op::SCONST_0,
                    op::SSPUSH, 0x20, 0, op::INVOKESTATIC, 0, 12,
                ]),
                _ => {},
            }
            process.push(op::RETURN);
            let handler_offset = process.len() as u16;
            if ending == "full-caught" {
                process.extend_from_slice(&[op::INVOKEVIRTUAL, 0, 14, op::INVOKESTATIC, 0, 8, 0x81, 0, 9, op::RETURN]);
            }
            let mut package = applet(process, 8);
            package.static_bytes = 2;
            package.classes[0].declared_size = 1;
            package.constants.extend_from_slice(&[
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 1],
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 2],
                [CONSTANT_STATIC_METHODREF, 0x81, 8, 0],
                [CONSTANT_STATIC_FIELDREF, 0, 0, 0],
                [crate::cap::CONSTANT_INSTANCE_FIELDREF, 0, 0, 0],
                [CONSTANT_STATIC_METHODREF, 0x81, 7, 1],
                [CONSTANT_STATIC_METHODREF, 0x81, 16, 1],
                [CONSTANT_VIRTUAL_METHODREF, 0x81, 10, 1],
                [CONSTANT_VIRTUAL_METHODREF, 0x81, 14, 1],
            ]);
            if ending == "full-caught" {
                package.handlers.push([0; 8]);
                let bodies = package.extra_offsets();
                package.constants[4] = [CONSTANT_STATIC_METHODREF, 0, (bodies[0] >> 8) as u8, bodies[0] as u8];
                package.classes[0].public[applet_token(MethodId::select).unwrap() as usize] = bodies[1];
                package.classes[0].public[applet_token(MethodId::process).unwrap() as usize] = bodies[2];
                let start = bodies[2] + 2;
                let target = start + handler_offset;
                let length = handler_offset | 0x8000;
                package.handlers[0] = [(start >> 8) as u8, start as u8, (length >> 8) as u8, length as u8,
                    (target >> 8) as u8, target as u8, 0, 0];
            }
            let bytes = package.build();
            let file = LoadFile::parse(&bytes).unwrap();
            let mut card = AppletInstance::new(&file, Sizes { heap_bytes: 16384, ..Sizes::default() }).unwrap();
            card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
            let mut polls = 0;
            let mut host = CheckpointHost { fail_at: match ending { "commit-fail" | "plain-store-fail" => Some(1), _ => None }, ..Default::default() };
            let result = card.process_with_cancel(&file, &mut host, &[0, 1, 0, 0], false, &mut || {
                polls += 1;
                ending.ends_with("cancel") && polls == 100
            });
            if matches!(ending, "commit-fail" | "plain-store-fail") { assert_eq!(result, Err(Error::Storage), "{ending}"); }
            else if ending.ends_with("cancel") { assert_eq!(result, Err(Error::Cancelled)); }
            else {
                let expected_sw = match ending {
                    "commit" | "abort" | "full-caught" => SW_SUCCESS,
                    "plain-throw" => 0x6a80,
                    _ => SW_UNKNOWN,
                };
                assert_eq!(result.unwrap().sw, expected_sw, "{ending}");
            }
            let expected: u16 = if ending.starts_with("plain-") || ending.starts_with("commit") && ending != "commit-fail" { 12 } else { 9 };
            assert_eq!(card.statics, if ending == "full-caught" { 3u16 } else { expected }.to_be_bytes(), "{ending}");
            let heap = Heap::resume(&mut card.heap, card.heap_used).unwrap();
            assert_eq!(heap.get_word(card.instance.unwrap(), 0).unwrap(), expected, "{ending}");
            assert_eq!(heap.array_get(card.buffer, 0), Ok(42), "APDU bytes are transient: {ending}");
            if ending.ends_with("cancel") && ending != "commit-cancel"
                || matches!(ending, "commit-fail" | "plain-store-fail") {
                assert!(host.saved.is_empty(), "{ending}");
            } else {
                assert!(!host.saved.is_empty(), "{ending}");
            }
            for (heap, statics, instance) in &host.saved {
                let mut restored = AppletInstance::restore(&file, card.sizes, PersistentState { heap, statics, instance: *instance }).unwrap();
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.array_get(restored.buffer, 0), Ok(0));
            }
            if let Some((heap, statics, instance)) = host.saved.last() {
                let durable_field: u16 = if ending.starts_with("commit")
                    || ending.starts_with("plain-") { 12 } else { 9 };
                let durable_static = if ending == "full-caught" { 3 } else { durable_field };
                let mut restored = AppletInstance::restore(&file, card.sizes,
                    PersistentState { heap, statics, instance: *instance }).unwrap();
                assert_eq!(statics, &durable_static.to_be_bytes(), "{ending}");
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.get_word(*instance, 0), Ok(durable_field), "{ending}");
            }
            if let Some(failed) = host.fail_at { assert_eq!(host.calls, failed, "failed checkpoint must not retry"); }
            if !ending.ends_with("cancel") && ending != "commit-fail" {
                let mut saved = vec![0; card.persistent_heap_bytes()];
                let mut restored = AppletInstance::restore(&file, card.sizes, card.save_into(&mut saved).unwrap()).unwrap();
                assert_eq!(restored.statics, card.statics);
                let heap = Heap::resume(&mut restored.heap, restored.heap_used).unwrap();
                assert_eq!(heap.get_word(restored.instance.unwrap(), 0), Ok(expected));
                assert_eq!(heap.array_get(restored.buffer, 0), Ok(0));
            }
            if ending == "throw" {
                // Throwing a reserved exception must not invalidate applet references.
                assert!(!card.transaction_aborted);
                assert_eq!(card.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0], false).unwrap().sw, SW_UNKNOWN);
                assert!(!card.transaction_aborted);
            }
            if ending == "allocate-abort" {
                assert_eq!(card.process(&file, &mut crate::host::NoHost, &[0, 1, 0, 0], false), Err(Error::TransactionAborted));
                card.reset().unwrap();
                assert!(!card.transaction_aborted);
            }
        }
    }

    #[test]
    fn a_failure_the_applet_did_not_describe_answers_with_the_word_that_says_so() {
        // process: commit a transaction that was never begun, which the runtime refuses
        // with an exception that carries no status word of its own.
        let process = vec![op::INVOKESTATIC, 0x00, 0x06, op::RETURN];
        let mut package = applet(process, 8);
        // JCSystem.commitTransaction, static token 2 of class token 8.
        package.constants.push([CONSTANT_STATIC_METHODREF, 0x81, 8, 2]);
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        card.install(&file, &mut crate::host::NoHost, &[]).unwrap();
        let response = card
            .process(&file, &mut crate::host::NoHost, &[0x00, 0x01, 0x00, 0x00, 0x00], false)
            .unwrap();
        // Not a word the applet chose, so the card answers with the one that says exactly
        // that rather than inventing a plausible one.
        assert_eq!(response.sw, SW_UNKNOWN);
        assert!(response.data.is_empty());
    }

    #[test]
    fn short_apdu_lengths_distinguish_command_data_from_expected_response() {
        for (raw, incoming, expected) in [
            (&[0, 0xa4, 4, 0][..], 0, 0),
            (&[0, 0xa4, 4, 0, 0][..], 0, 256),
            (&[0, 0xa4, 4, 0, 7][..], 0, 7),
            (&[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7][..], 5, 0),
            (&[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0][..], 5, 256),
        ] {
            assert_eq!(incoming_length(raw), Ok(incoming));
            assert_eq!(expected_length(raw), Ok(expected));
        }
        for raw in [&[0, 0xa4, 4][..], &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3],
            &[0, 0xcb, 0x3f, 0xff, 1, 1, 2, 3, 4], &[0, 0xcb, 0, 0, 0, 0]] {
            assert_eq!(incoming_length(raw), Err(Error::Bounds));
        }
    }

    #[test]
    fn an_install_that_registers_nothing_leaves_nothing_to_select() {
        let mut package = applet(vec![op::RETURN], 8);
        package.code = vec![op::RETURN];
        let bytes = package.build();
        let file = LoadFile::parse(&bytes).unwrap();
        let mut card = AppletInstance::new(&file, Sizes::default()).unwrap();
        assert_eq!(card.install(&file, &mut crate::host::NoHost, &[]), Err(Error::Missing));
        assert!(!card.installed());
    }
