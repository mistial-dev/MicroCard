/* Makerdiary nRF52840 MDK USB Dongle, Board-ID nRF52840-MDK-USB-DONGLE.
 *
 * The current UF2 bootloader reports no SoftDevice and starts applications at 0x1000.
 * It remains protected above 0xEA000. Keep persistent-region addresses stable while
 * allowing the application to use the previously reserved SoftDevice range.
 */
MEMORY {
 FLASH : ORIGIN = 0x00001000, LENGTH = 536K
 STAGING : ORIGIN = 0x00087000, LENGTH = 64K
 JOURNAL0 : ORIGIN = 0x00097000, LENGTH = 64K
 JOURNAL1 : ORIGIN = 0x000A7000, LENGTH = 64K
 JOURNAL2 : ORIGIN = 0x000B7000, LENGTH = 64K
 KEYS : ORIGIN = 0x000C7000, LENGTH = 4K
 MONOTONIC : ORIGIN = 0x000C8000, LENGTH = 4K
 IMAGES : ORIGIN = 0x000C9000, LENGTH = 128K
 NONCES : ORIGIN = 0x000E9000, LENGTH = 4K
 RAM : ORIGIN = 0x20000000, LENGTH = 256K
}

/* Defined only by a MicroCard memory map. The firmware references it, so a build that
 * picked up some other crate's memory.x fails to link instead of quietly using the
 * wrong flash layout. */
_microcard_flash_origin = ORIGIN(FLASH);
