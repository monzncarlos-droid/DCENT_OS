/*
 * K210 Phase-A RAM runtime layout. Public Kendryte SoC facts only.
 * No Avalon flash offset, pin assignment, peripheral route, or actuator map.
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
    KEEP(*(.rodata.dcent_boundary))
    *(.rodata .rodata.*)
  } > RAM

  .data : ALIGN(8)
  {
    *(.sdata .sdata.*)
    *(.data .data.*)
  } > RAM

  .bss (NOLOAD) : ALIGN(8)
  {
    __bss_start = .;
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(8);
    __bss_end = .;
  } > RAM

  .stack (NOLOAD) : ALIGN(16)
  {
    __stack_bottom = .;
    . += 16K;
    __stack_top = .;
  } > RAM

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame.*)
    *(.comment)
  }
}

ASSERT(ADDR(.text) == 0x80000000, "K210 runtime entry moved from ROM load base")
ASSERT(__stack_top <= ORIGIN(RAM) + LENGTH(RAM), "K210 runtime exceeds cached RAM")
ASSERT((__stack_top & 15) == 0, "K210 stack is not 16-byte aligned")
