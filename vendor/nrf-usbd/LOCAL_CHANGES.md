# Local nrf-usbd patch

Source: `nrf-usbd` 0.3.0 from crates.io, checksum
`aedf862f941154442271ae9914777bd1c93f6d2e0dc9db4cafa160e55ffb9085`.
The original dual MIT/Apache-2.0 licenses are retained.

The board uses this pinned copy to wait for the PHY supply before connecting,
bound readiness waits, and disable/re-enable USBD across VBUS removal. The
`UsbPeripheral::phy_ready` hook lets the nRF52840 board supply the typed POWER
register status without duplicating the USB bus implementation. The CCID class
remains `usbd-ccid`.

The board also identifies affected nRF52840 QIAA/CKAA Fx0 silicon from FICR.
For those builds, the driver applies Nordic erratum 199 around each EasyDMA
transfer, clearing the workaround register after the transfer completes.

Keep local changes small and compare them with upstream before upgrading.
