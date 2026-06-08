/* kernel.ld — Linker script for the freestanding i386 Multiboot kernel.
 *
 * GRUB loads a Multiboot ELF kernel at the physical addresses specified
 * by the PT_LOAD segments.  We place everything at 1 MiB (0x100000),
 * well above the real-mode IVT/BIOS data area and safely within the
 * first 4 MiB that GRUB identity-maps before handing off to the kernel.
 *
 * Section layout
 * ──────────────
 *   .text      — code (kernel_main, all C++ functions)
 *   .rodata    — string literals, vtables, read-only data
 *   .data      — initialised globals
 *   .init_array— global constructor function pointers (C++ ctors)
 *   .bss       — zero-initialised globals (heap arrays, VGA buffers …)
 *
 * Symbols exported to kernel.cpp
 * ───────────────────────────────
 *   __init_array_start / __init_array_end  — walked by kernel_run_global_ctors_once()
 *   ramdisk_start / ramdisk_end            — embedded ramdisk (if any)
 *   hello_start   / hello_end             — embedded hello ELF (if any)
 *
 * The kernel uses a bump/free-list allocator in BSS, so _kernel_end
 * is exported to let the allocator know where BSS ends and usable
 * RAM begins.
 */

ENTRY(kernel_main)

SECTIONS
{
    /* ── Load address: 1 MiB ──────────────────────────────────────── */
    . = 0x00100000;

    /* ── Text ────────────────────────────────────────────────────── */
    .text ALIGN(4K) : {
		*(.multiboot)
        *(.text)
        *(.text.*)
        *(.gnu.linkonce.t.*)
    }

    /* ── Read-only data ──────────────────────────────────────────── */
    .rodata ALIGN(4K) : {
        *(.rodata)
        *(.rodata.*)
        *(.gnu.linkonce.r.*)
    }

    /* ── Global constructors (C++ static initialisers) ───────────── */
    .init_array ALIGN(4) : {
        __init_array_start = .;
        KEEP(*(.init_array))
        KEEP(*(.ctors))
        __init_array_end = .;
    }

    /* ── Initialised data ────────────────────────────────────────── */
    .data ALIGN(4K) : {
        *(.data)
        *(.data.*)
        *(.gnu.linkonce.d.*)
    }

    /* ── Embedded blobs (ramdisk, hello ELF) — optional ─────────── *
     * If your build embeds binary blobs via objcopy --add-section,
     * they land here.  The kernel accesses them via the symbols below.
     * Leave the sections empty if you do not embed any blobs; the
     * linker will simply produce zero-size stubs. */
    .ramdisk ALIGN(4K) : {
        ramdisk_start = .;
        KEEP(*(.ramdisk))
        ramdisk_end = .;
    }

    .hello ALIGN(4K) : {
        hello_start = .;
        KEEP(*(.hello))
        hello_end = .;
    }

    /* ── BSS — zero-initialised (GRUB zeroes it before kernel_main) */
    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        *(.gnu.linkonce.b.*)
        . = ALIGN(4K);
        __bss_end = .;
    }

    _kernel_end = .;

    /* ── Discard C++ exception tables (freestanding, no unwinding) ─ */
    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note.GNU-stack)
    }
}
