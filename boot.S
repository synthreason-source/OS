/* boot.S — Multiboot entry point
 *
 * Key fixes vs. the old version:
 *  1. FLAGS includes bit 2 (video mode request) so GRUB sets up a linear
 *     framebuffer and fills mbi->framebuffer_* before jumping to _start.
 *  2. The multiboot header is extended with the five video-mode fields
 *     that Multiboot 1 requires when bit 2 is set.
 *  3. BSS is NOT in the .bss section of boot.S — the stack lives in a
 *     dedicated .bootstrap_stack section so the linker can place it
 *     immediately after .bss without confusing the ELF BSS size calculation.
 *  4. We zero BSS ourselves in _start (GRUB zeroes it according to the ELF
 *     p_filesz/p_memsz gap, but doing it explicitly is safer and required
 *     when the BSS is very large and GRUB may skip it).
 *  5. A minimal protected-mode GDT is loaded before calling kernel_main.
 */

/* ─── Multiboot 1 header constants ───────────────────────────────────────── */
.set MB_MAGIC,   0x1BADB002
/* bit 0 = align modules on 4 K boundaries
   bit 1 = provide memory map
   bit 2 = request video mode information (fills mbi framebuffer fields) */
.set MB_FLAGS,   (1 << 0) | (1 << 1) | (1 << 2)
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

/* ─── Multiboot header ────────────────────────────────────────────────────── */
.section .multiboot, "a"
.align 4
    .long MB_MAGIC
    .long MB_FLAGS
    .long MB_CHECKSUM
    /* The next five fields are required when bit 2 (video mode) is set.
       Fields 4-7 are the address fields (set to 0 = use ELF header).
       Field 8 is the video mode type: 0 = linear framebuffer, 1 = EGA text. */
    .long 0          /* header_addr   (0 = use ELF) */
    .long 0          /* load_addr     (0 = use ELF) */
    .long 0          /* load_end_addr (0 = use ELF) */
    .long 0          /* bss_end_addr  (0 = use ELF) */
    .long 0          /* entry_addr    (0 = use ELF) */
    /* video mode: 0=linear FB, width=1024, height=768, depth=32 */
    .long 0          /* mode_type: 0 = linear framebuffer */
    .long 1024       /* width  */
    .long 768        /* height */
    .long 32         /* depth  */

/* ─── Bootstrap stack (separate section, NOT in .bss) ────────────────────── */
.section .bootstrap_stack, "aw", @nobits
.align 16
stack_bottom:
    .skip 65536      /* 64 KB — plenty for kernel_main setup */
stack_top:

/* ─── Minimal flat GDT ───────────────────────────────────────────────────── */
.section .data
.align 8
gdt_start:
    /* Descriptor 0: null */
    .quad 0x0000000000000000
    /* Descriptor 1: 32-bit code, base=0, limit=4GB, DPL=0 */
    .quad 0x00CF9A000000FFFF
    /* Descriptor 2: 32-bit data, base=0, limit=4GB, DPL=0 */
    .quad 0x00CF92000000FFFF
gdt_end:

gdt_ptr:
    .word gdt_end - gdt_start - 1   /* limit */
    .long gdt_start                  /* base  */

/* ─── Kernel entry point ─────────────────────────────────────────────────── */
.section .text
.global _start
.type _start, @function
_start:
    /* Interrupts off immediately */
    cli

    /* ── VGA heartbeat: 'B' at column 0 proves we reached _start ── */
    movl $0xB8000, %edi
    movw $0x1F42, (%edi)          /* 'B', blue bg + white fg */

    /* ── Load our own flat GDT (GRUB's may be minimal) ── */
    lgdt gdt_ptr
    /* Reload segment registers with our descriptors */
    movw $0x10, %ax               /* data segment = descriptor 2 */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    /* Far-jump to flush the code-segment cache with descriptor 1 */
    ljmp $0x08, $1f
1:
    /* ── Set up the bootstrap stack ── */
    movl $stack_top, %esp
    movw $0x1F53, 2(%edi)         /* 'S' = stack ready */

    /* ── Zero BSS explicitly ─────────────────────────────────────────
     * GRUB zeroes the BSS p_memsz-p_filesz gap, but with a 35+ MB BSS
     * some older GRUB builds skip it.  We do it ourselves to be safe.
     * __bss_start and __bss_end are provided by the linker script.
     */
    movl $__bss_start, %edi
    movl $__bss_end,   %ecx
    subl %edi, %ecx               /* byte count */
    xorl %eax, %eax
    /* rep stosb is fine for zeroing; speed doesn't matter here */
    cld
    rep stosb
    movw $0x1F5A, 6(%edi)         /* 'Z' = BSS zeroed (edi now at bss_end, harmless) */

    /* ── Restore VGA pointer and signal we are about to call C ── */
    movl $0xB8000, %edi
    movw $0x1F43, 4(%edi)         /* 'C' = calling kernel_main */

    /* ── Push multiboot arguments: eax=magic, ebx=mbi pointer ── */
    pushl %ebx                    /* arg 2: multiboot_addr */
    pushl %eax                    /* arg 1: magic */

    call kernel_main

    /* ── kernel_main should never return; halt if it does ── */
.hang:
    cli
    hlt
    jmp .hang
