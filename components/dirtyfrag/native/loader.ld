OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS
{
  loader PT_LOAD FLAGS(5);
}

SECTIONS
{
  . = 0x10000 + SIZEOF_HEADERS;
  .loader : AT(ADDR(.loader) - 0x10000) {
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.*)
    *(COMMON)
  } :loader

  /DISCARD/ : {
    *(.comment)
    *(.note .note.*)
    *(.eh_frame .eh_frame_hdr)
    *(.rela .rela.*)
    *(.dynamic)
    *(.dynsym)
    *(.dynstr)
    *(.hash)
    *(.gnu.hash)
  }
}
