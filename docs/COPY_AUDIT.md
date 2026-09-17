# Buffer-copy audit

The fast host gate rejects any unreviewed `clone`, owned-slice conversion, or explicit slice-copy site in device package parsing, MC04 verification, linking, and execution. It also rejects reintroducing complete section or complete output copies in the managed MC04 writer.

The current Rust sites are bounded and required:

- Host-owned package verification makes one exact envelope copy. Device activation uses `PackageView` and borrows staged bytes.
- `Range::clone` copies two integer offsets and allocates nothing.
- CIL verification copies a bounded incoming stack state only when establishing or merging a control-flow state. The reusable work stack borrows that state afterward.
- Staged uploads retain each APDU chunk because later commands complete the package. Both upload paths reserve before copying.
- Managed memory-copy instructions and response writes copy into their explicit destination buffers after bounds and budget checks.
- Management command construction copies two already validated identifiers into one exact-size buffer, and fixed version/AID fields copy into stack arrays.
- Native byte results and the final status word copy once into the pre-reserved response buffer.
- Persistent storage declarations are shared across ordinary candidate states. Extending the immutable contract copies its bounded prior declarations once into an exactly reserved replacement during assembly activation.

The managed preprocessor keeps metadata ordering arrays and per-method transformed CIL because later offset calculation requires them. Final Tables, Strings, Blob, and Code buffers are exposed as `ReadOnlyMemory<byte>` and streamed directly into a same-directory temporary file. A successful atomic replacement publishes the complete output. Failure removes the temporary file.

Run `python3 scripts/copy_audit.py` after changing these paths. A changed site requires reviewing its lifetime, bound, reservation order, and whether borrowing or a validated offset can replace it.
