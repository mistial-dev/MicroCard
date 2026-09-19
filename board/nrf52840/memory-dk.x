/* nRF52840: 1 MiB flash, 256 KiB SRAM. Development image, no bootloader. */
MEMORY {
 FLASH : ORIGIN = 0x00000000, LENGTH = 576K
 IMAGES : ORIGIN = 0x00090000, LENGTH = 128K
 STAGING : ORIGIN = 0x000B0000, LENGTH = 64K
 JOURNAL0 : ORIGIN = 0x000C0000, LENGTH = 64K
 JOURNAL1 : ORIGIN = 0x000D0000, LENGTH = 64K
 KEYS : ORIGIN = 0x000E0000, LENGTH = 4K
 MONOTONIC : ORIGIN = 0x000E1000, LENGTH = 4K
 JOURNAL2 : ORIGIN = 0x000E2000, LENGTH = 64K
 RAM : ORIGIN = 0x20000000, LENGTH = 256K
}

/* Defined only by a MicroCard memory map. The firmware references it, so a build that
 * picked up some other crate's memory.x fails to link instead of quietly using the
 * wrong flash layout. */
_microcard_flash_origin = ORIGIN(FLASH);
