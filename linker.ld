/* linker.ld — 32-bit bare-metal kernel linker script
 *
 * Changes vs. the old version:
 *  1. .multiboot comes first inside .text so the header is within the first
 *     8 KB of the file (Multiboot 1 requirement).
 *  2. .bootstrap_stack is placed AFTER .bss (not inside it) so the ELF
 *     BSS segment size reported to GRUB does not include the stack.
 *     This prevents GRUB from having to zero an extra 64 KB on top of the
 *     already-large BSS, and keeps the stack at a known fixed address.
 *  3. __bss_start and __bss_end symbols are exported so boot.S can zero
 *     BSS explicitly and reliably.
 *  4. The kernel_end symbol is exported for future heap/memory-map use.
 *  5. .eh_frame and exception tables are discarded — we never unwind.
 *  6. .gnu.* and .comment noise is discarded.
 */

ENTRY(_start)

SECTIONS
{
    /* Load address: 1 MB, which is above the real-mode area and where
       GRUB places 32-bit multiboot payloads by default. */
    . = 0x100000;

    /* ── Text ─────────────────────────────────────────────────────── */
    .text BLOCK(4K) : ALIGN(4K)
    {
        /* Multiboot header MUST be within the first 8 KB of the image */
        *(.multiboot)
        *(.text)
        *(.text.*)
        *(.gnu.linkonce.t.*)
    }

    /* ── Read-only data ───────────────────────────────────────────── */
    .rodata BLOCK(4K) : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
        *(.gnu.linkonce.r.*)
    }

    /* ── Initialised data ─────────────────────────────────────────── */
    .data BLOCK(4K) : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
        *(.gnu.linkonce.d.*)
        *(.got)
        *(.got.plt)
        /* C++ static initialisers — run before kernel_main if needed.
           Currently we do not call them (no crt0), but keeping them here
           means the objects are at least present in the binary. */
        *(.init_array)
        *(.init_array.*)
        *(.data.rel.ro*)
    }

    /* ── Uninitialised data (BSS) ─────────────────────────────────── */
    /* boot.S zeros this region explicitly using __bss_start/__bss_end. */
    .bss BLOCK(4K) : ALIGN(4K)
    {
        __bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        *(.gnu.linkonce.b.*)
        . = ALIGN(4K);
        __bss_end = .;
    }

    /* ── Bootstrap stack (separate from BSS) ─────────────────────── */
    /* Placed outside the BSS segment so the ELF BSS p_memsz does not
       include it; GRUB only needs to zero BSS, not the stack region. */
    .bootstrap_stack BLOCK(4K) : ALIGN(16)
    {
        *(.bootstrap_stack)
    }

    /* ── End of kernel image ──────────────────────────────────────── */
    kernel_end = .;

    /* ── Discarded sections ───────────────────────────────────────── */
    /DISCARD/ :
    {
        /* C++ exception / unwind tables — we never unwind */
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.ARM.exidx*)
        /* Debug / metadata noise */
        *(.note.*)
        *(.gnu.*)
        *(.comment)
        *(.GCC.command.line)
    }
}
