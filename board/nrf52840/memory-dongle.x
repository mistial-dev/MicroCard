/* Makerdiary nRF52840 MDK USB Dongle, Board-ID nRF52840-MDK-USB-DONGLE.
 *
 * This board keeps a UF2 bootloader and an S140 SoftDevice that MicroCard does not use and
 * must not overwrite. Read from the bootloader's own CURRENT.UF2 readback:
 *
 *   0x000000 - 0x001000  MBR
 *   0x001000 - 0x027000  SoftDevice S140 7.2.0
 *   0x027000 - 0x0EA000  application, 780 KiB, which is everything below
 *   0x0EA000 - 0x100000  UF2 bootloader, MBR parameters and bootloader settings
 *
 * The application vector table the bootloader jumps to sits at 0x027000 with an initial
 * stack pointer of 0x20040000, which is the value scripts/prepare_first_flash.py already
 * requires. Regions below keep the sizes the DK layout uses, because a journal slot has to
 * hold a serialized State and that ceiling is independent of the board.
 */
MEMORY {
 FLASH : ORIGIN = 0x00027000, LENGTH = 384K
 STAGING : ORIGIN = 0x00087000, LENGTH = 64K
 JOURNAL0 : ORIGIN = 0x00097000, LENGTH = 64K
 JOURNAL1 : ORIGIN = 0x000A7000, LENGTH = 64K
 JOURNAL2 : ORIGIN = 0x000B7000, LENGTH = 64K
 KEYS : ORIGIN = 0x000C7000, LENGTH = 4K
 MONOTONIC : ORIGIN = 0x000C8000, LENGTH = 4K
 RAM : ORIGIN = 0x20000000, LENGTH = 256K
}

/* Defined only by a MicroCard memory map. The firmware references it, so a build that
 * picked up some other crate's memory.x fails to link instead of quietly using the
 * wrong flash layout. */
_microcard_flash_origin = ORIGIN(FLASH);
