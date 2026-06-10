/* tcc_guest.ld — linker script for TCC-compiled 32-bit i386 guest ELFs.
 *
 * Differences from guest.ld
 * --------------------------
 * guest.ld places _start at 0x08001000, which is slab offset 0x000.
 * That overlaps the zone where inject_slab_tables writes the GDT/IDT/stub
 * (slab offsets 0x000..0x8ff).  When gcc compiles with -nostartfiles the
 * gap is filled by the toolchain's crt; TCC emits nothing there, so code
 * starts at exactly offset 0x000 and gets clobbered.
 *
 * This script inserts an explicit 4 KiB NOLOAD gap so the first real
 * instruction lands at 0x08002000 (slab offset 0x1000), safely after the
 * stub injection zone.
 *
 * Kernel ABI (guest side)
 * -----------------------
 * Write a character to the terminal  : outb(0xE9, ch)
 * Exit with code N (clean)           : outb(0xE8, N & 0xFF)
 *
 * Typical minimal _start:
 *
 *   static inline void outb(unsigned short port, unsigned char v) {
 *       __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(port));
 *   }
 *   static void puts_(const char *s) { while (*s) outb(0xE9,*s++); }
 *
 *   void _start(void) {
 *       puts_("Hello from TCC!\n");
 *       outb(0xE8, 0);
 *       for (;;) {}
 *   }
 *
 * Build (done automatically by `make cc SRC=foo.c`):
 *   i386-tcc -c -nostdlib -o foo.o foo.c
 *   ld -m elf_i386 -static -nostdlib -T tcc_guest.ld -o foo foo.o
 */

ENTRY(_start)

PHDRS { load PT_LOAD FLAGS(7); }

SECTIONS
{
    /* PT_LOAD begins here → vaddr_base = 0x08001000 for the slot loader. */
    . = 0x08001000;

    /* 4 KiB NOLOAD placeholder.
     * inject_slab_tables() writes GDT+IDT+stub into this region.
     * NOLOAD keeps the ELF file small (no 4 KiB of zeros on disk). */
    .slab_reserved (NOLOAD) : { . += 0x1000; } :load

    /* Code begins at 0x08002000 = slab offset 0x1000. */
    . = 0x08002000;
    .text   : { *(.text._start) *(.text .text.*)   } :load
    .rodata : { *(.rodata .rodata.*)               } :load
    .data   : { *(.data .data.*)                   } :load
    .bss    : { *(.bss .bss.* COMMON)              } :load

    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.gnu.hash .hash .dynsym .dynstr .dynamic)
        *(.interp)
        *(.got .got.plt)
        *(.plt)
    }
}
