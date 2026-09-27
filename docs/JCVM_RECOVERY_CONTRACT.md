# JCVM recovery contract

The flash store authenticates a complete record before the JCVM sees it. The VM then
checks the saved heap as a Java Card heap: object boundaries, references, array
element types, ownership, firewall context, static references, and the installed
applet instance. It rejects malformed state before any applet bytecode runs. It does
not decide whether an applet's own fields represent a valid business transaction.

Native objects have private fields that Java bytecode cannot inspect. Their owning
native service checks those fields during recovery. In particular, cryptographic
services check their key and reset-scoped workspace references, and the PIN service
checks the material array and retry-counter bounds. A native service must handle
its own unsupported or uninitialized state with the specified Java Card exception;
the VM heap validator must not list cryptographic algorithm numbers.

Transient object identity and length survive reset while CLEAR_ON_RESET contents
are cleared. CLEAR_ON_DESELECT contents are cleared on deselection and reset.
Runtime-only values, including a PIN's validated flag and streaming crypto
workspace, are omitted or cleared in the persistence projection. An initialized
`Signature` resumes in its specified post-`init()` state; a cleared transient key
leaves it uninitialized. These rules follow the Java Card 3.0.5 Classic JCRE,
JCVM, and `javacard.security.Signature` API specifications in the Reference Library.

Ordinary applet working data remains in RAM and reaches authenticated flash at the
APDU boundary before the response is released. Explicit `JCSystem` transaction
commits and PIN retry changes retain their earlier synchronous checkpoints.
The nRF52840 has no hold-up capacitor, so a cut during a flash publication
must leave either the previous or the new authenticated record authoritative.
Recovery accepts a complete authenticated record or returns an error; it does
not silently reset the applet. DK cuts have exercised snapshot and PIN marker
boundaries plus staged heap-renewal recovery. Other publication boundaries
remain host fault-injection evidence until physically exercised.

Keep recovery checks off the APDU hot path. A new native object layout must define
its reference fields, transient fields, recovery checks, and specified reset behavior
beside its implementation. Host and board paths use the same validator.
