/*
 * Desk-only K210 safe-idle sentinel layout.
 *
 * Kendryte's Apache-2.0 standalone SDK (commit
 * 02576ba67e8797444f3ee3f34c625b5ed048e707) establishes a fixed cached-RAM
 * execution base of 0x80000000 and a conservative 6 MiB linker region. This
 * script encodes only those public SoC facts. It contains no Avalon board map.
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 6M
}

SECTIONS
{
  . = ORIGIN(RAM);

  .text : ALIGN(8)
  {
    KEEP(*(.text.start))
    *(.text .text.*)
  } > RAM

  .rodata : ALIGN(8)
  {
    *(.rodata .rodata.*)
  } > RAM

  .data : ALIGN(8)
  {
    *(.sdata .sdata.*)
    *(.data .data.*)
  } > RAM

  .bss (NOLOAD) : ALIGN(8)
  {
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    *(COMMON)
  } > RAM

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame.*)
    *(.comment)
  }
}

ASSERT(ADDR(.text) == 0x80000000, "K210 sentinel entry moved from ROM load base")
ASSERT(SIZEOF(.text) + SIZEOF(.rodata) + SIZEOF(.data) + SIZEOF(.bss) <= LENGTH(RAM),
       "K210 sentinel exceeds conservative cached-RAM region")
