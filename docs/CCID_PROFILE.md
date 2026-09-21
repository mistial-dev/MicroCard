# USB CCID profile

MicroCard presents one permanently inserted virtual card through USB CCID 1.1. The USB transport carries the same short APDUs used by the simulator. It does not change authorization, SCP03, assembly verification, domain identity, or command semantics.

## Fixed profile

- One slot: `bMaxSlotIndex = 0`, `bMaxCCIDBusySlots = 1`.
- Short APDU exchange: `dwFeatures = 0x0002004A`, selecting short APDUs, ATR-based parameter configuration, automatic voltage selection, and automatic parameter negotiation.
- T=1 only: `dwProtocols = 0x00000002`.
- `dwMaxCCIDMessageLength = 271`: ten CCID header bytes plus the 261-byte maximum short command APDU.
- Stable ATR: `3B 80 01 81`, direct convention, T=1, no historical bytes, valid TCK.
- Bulk OUT accepts `IccPowerOn`, `IccPowerOff`, `GetSlotStatus`, `XfrBlock`, and the bulk half of `Abort`. Bulk IN emits `DataBlock` and `SlotStatus`. Interrupt IN can emit the two-byte one-slot `NotifySlotChange` message.
- One full-speed interface (`0B/00/00`) with 64-byte bulk OUT endpoint `01`, 64-byte bulk IN endpoint `81`, and two-byte interrupt IN endpoint `82`. The complete configuration descriptor is 93 bytes.
- USB vendor and product identifiers are required board inputs. MicroCard does not embed, reserve, or claim identifiers. Device and UTF-16 string descriptors are written into caller-owned buffers.

The portable `ccid` codec borrows an accepted transfer block from the USB receive buffer and writes replies into caller-owned buffers. It rejects a message before APDU dispatch when the ten-byte header is incomplete, `dwLength` differs from the received body, the message exceeds 271 bytes, `bSlot` is not zero, short-APDU reserved parameters are nonzero, a zero-data command carries data, or the command is outside this profile. The fixed header remains separately parseable so an endpoint can echo the received slot and `bSeq` in an error response.

The portable one-slot state machine begins powered off, returns the fixed ATR on power-on, and allows only one transfer to remain active. It preserves the active transfer when another command receives `CMD_SLOT_BUSY`, requires an exact sequence match before completion, and supports either arrival order for the matching control and bulk halves of an abort. Once the control half arrives, nonmatching bulk commands fail with `CMD_ABORTED` until the pair completes. USB reset, suspend, or disconnect clears the transfer and abort state and requires a fresh power-on. The APDU dispatcher receives only a validated, borrowed `XfrBlock` payload.

The portable USB layer reassembles bulk OUT packets into one fixed 271-byte buffer and refuses empty, oversized, overlong, or overlapping messages without retaining a partial message. A completed command remains borrowed until explicitly released. Bulk IN responses are exposed as borrowed 64-byte packet slices and add a terminal zero-length packet when a response is an exact packet multiple.

The portable controller maps a complete bulk message to an immediate CCID response, a borrowed APDU dispatch, or a pending abort pair. It produces inactive-card, invalid-slot, malformed-command, busy, successful completion, runtime-failure, and abort responses from the same slot state. An oversized or wrongly sequenced completion leaves the active command intact.

The control parser accepts only the host-to-device, class, interface `ABORT` request with zero data length, the configured interface index, slot zero, and the sequence encoded in the high byte of `wValue`. Other requests or malformed setup fields never reach slot state.

The nRF52840 endpoint layer services both USB pipes while a managed command runs. It copies the accepted short APDU once into the existing fixed command buffer so the USB receive buffer can accept the ten-byte abort message, then polls the interpreter's cancellation hook before execution and every 64 managed instructions. A single abort half leaves the transaction running. If execution finishes first, the slot waits for the other half without dispatching the APDU again. Only a completed matching control-and-bulk pair cancels it. Cancellation discards ordinary candidate-state writes, retains the established durable credential retry floor, tears down the now-unusable SCP03 session, and leaves the successful abort `SlotStatus` response queued. USB reset or power loss also cancels execution. Native operations remain bounded by their own work limits and are observed at the next managed-instruction poll.

The endpoint layer remains responsible for EasyDMA scheduling, timeouts and physical suspend/resume notification. Physical enumeration and abort timing remain board-acceptance work.

## Reference

USB-IF, *Device Class: Smart Card, CCID Specification for Integrated Circuit(s) Cards Interface Devices*, revision 1.1, April 22, 2005:

- §3.1.3 requires command/response pairing, one active command per slot, and response `bSeq` matching.
- §3.2.2 defines short APDU exchange.
- §4.3 defines the CCID interface. §5.1 defines the class descriptor, including the one selected exchange-level bit and maximum message length.
- §5.3.1 defines the matching control-plus-bulk abort pair and behavior while it remains incomplete.
- §§5.2.1-5.2.3 define the bulk and interrupt endpoint descriptors.
- §§6.1.1-6.1.4 and 6.1.13 define the supported bulk-OUT layouts.
- §§6.2.1-6.2.2 define the two bulk-IN layouts. §6.3.1 defines slot-change notification.

The unchanged official PDF is stored under ignored `references/downloads/`. Its digest and clause map are committed in `references.json`. The repository does not redistribute it.
