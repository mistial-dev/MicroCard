# usbd-ccid 0.5.0, local USB-ICC compatibility patch

This is the upstream [`usbd-ccid` 0.5.0](https://github.com/trussed-dev/usbd-ccid)
crate (Apache-2.0 OR MIT), retained as a local path dependency for the DK.
The source archive was copied from crates.io. Upstream CI and registry metadata
were omitted.

MicroCard adds the CCID `SetDataRateAndClockFrequency` request and its required
response with the fixed values advertised by the device descriptor. macOS sends
this request while opening a fresh PC/SC reader. The local patch also corrects
the message type used for a slot-status error. Keep changes in this crate rather
than adding another CCID implementation in board code.
