/* guest.ld — linker script for the hotwired-`test` guest ELF.
 *
 * Why a custom script instead of plain -Ttext:
 *   With -Ttext alone, the GNU linker emits a separate read-only
 *   PT_LOAD for the ELF headers themselves, placed *below* the text
 *   base. For a guest based at 0x08001000 that header segment lands at
 *   0x08000000 — right on top of the GDT/IDT/stub tables the Bochs slot
 *   injects into the first GUEST_ENTRY_OFF (0x1000) bytes of the slab.
 *   test_module's loader then (correctly) rejects the image with
 *   "guest base too low".
 *
 * This script forces a single PT_LOAD that begins exactly at
 * 0x08001000 = SLAB_VADDR_BASE (0x08000000) + GUEST_ENTRY_OFF (0x1000),
 * with the ELF/program headers folded into that same segment. The
 * result is one clean loadable region the slab loader maps verbatim.
 *
 * Keep the whole image well under SLAB_VADDR_BASE + 1 MiB - 16; for a
 * tiny test guest that is never a concern.
 *
 * Build:
 *   gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
 *       -ffreestanding -fno-stack-protector \
 *       -Wl,--build-id=none -T guest.ld -o guest guest.c
 */

ENTRY(_start)

PHDRS
{
    /* One load segment, readable + writable + executable. The Bochs
     * slot runs with paging off and does not enforce per-page W^X, so
     * a single RWX segment is simplest and safe for a test guest. */
    load PT_LOAD FLAGS(7);   /* 7 = R(4) | W(2) | X(1) */
}

SECTIONS
{
    /* Start of the slot slab's usable region. */
    . = 0x08001000;

    /* Fold the ELF header + program headers into the segment so the
     * linker does not spin up a second PT_LOAD below this address. */
    .text : {
        *(.text._start)     /* _start first, purely for readability   */
        *(.text .text.*)
    } :load

    .rodata : {
        *(.rodata .rodata.*)
    } :load

    .data : {
        *(.data .data.*)
    } :load

    .bss : {
        *(.bss .bss.* COMMON)
    } :load

    /* Drop everything that would otherwise create extra segments or
     * pull in host-toolchain metadata the guest must not carry. */
    /DISCARD/ : {
        *(.note .note.*)
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.gnu.hash .hash .dynsym .dynstr .dynamic)
    }
}
