/* hello.ld — linker script for the embedded hello ELF.
 *
 * Layout requirement:
 *   The Bochs slot loader sets vaddr_base = min PT_LOAD vaddr, then
 *   injects stub/GDT/IDT at slab offsets 0x000..0x8ff. Code must NOT
 *   start until slab offset >= 0x900.
 *
 *   We anchor the PT_LOAD at 0x08001000 and pad with a .fill section
 *   so the first real instruction is at 0x08002000 (slab offset 0x1000).
 */

ENTRY(_start)

PHDRS { load PT_LOAD FLAGS(7); }

SECTIONS
{
    . = 0x08001000;

    /* 4 KiB of explicit zeros so the PT_LOAD *starts* at 0x08001000.
     * inject_slab_tables will overwrite part of this with its stub,
     * GDT, and IDT — that is intentional and correct.            */
    .slab_reserved (NOLOAD) : { . += 0x1000; } :load

    /* Actual code/data begins at 0x08002000 = slab offset 0x1000.  */
    . = 0x08002000;
    .text   : { *(.text._start) *(.text .text.*)   } :load
    .rodata : { *(.rodata .rodata.*)               } :load
    .data   : { *(.data .data.*)                   } :load
    .bss    : { *(.bss .bss.* COMMON)              } :load

    /DISCARD/ : {
        *(.note .note.*) *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.gnu.hash .hash .dynsym .dynstr .dynamic)
    }
}
