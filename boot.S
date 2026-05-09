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

/* ─── Host-side IDT ──────────────────────────────────────────────────────────
 *
 * Without this, any host CPU fault (page fault, GP, UD, etc.) walks an
 * empty / zeroed IDT and triple-faults. Under QEMU that resets/freezes
 * the box silently — no VGA output, no heartbeat, nothing.
 *
 * This IDT has 256 entries, each pointing at an isr_stub_N stub that:
 *   - writes '!' + the vector number (in hex) to row 1 of VGA (red bg)
 *   - halts the CPU with cli;hlt forever
 *
 * The result: any host-side fault now leaves a visible breadcrumb at
 * VGA row 1 instead of vanishing into a triple-fault.
 *
 * Kernel size cost: 256 * 8 = 2 KB IDT + ~256 * 16 = 4 KB stubs = 6 KB.
 */
.align 16
idt_start:
    .skip 256 * 8       /* filled by _start at boot */
idt_end:

idt_ptr:
    .word 256 * 8 - 1    /* limit */
    .long idt_start       /* base  */

/* ─── Saved multiboot args ────────────────────────────────────────────────
 * _start stashes eax/ebx here before clobbering them, and reloads them
 * just before calling kernel_main. */
.align 4
mb_saved_magic:
    .long 0
mb_saved_mbi:
    .long 0

/* ─── Kernel entry point ─────────────────────────────────────────────────── */
.section .text

/* ── ISR stub generator ─────────────────────────────────────────────────────
 *
 * Each stub pushes its vector number then jumps to a single shared
 * handler `isr_common`. The handler writes "!XX" to row 1 of VGA where
 * XX is the vector in hex (red-on-white attribute), then halts.
 *
 * Stubs are 10 bytes each (forced) so the IDT-build loop below can
 * stride them uniformly.
 */
.global isr_common
.type   isr_common, @function
isr_common:
    /* Top of stack: vector number (pushed by stub).
     *
     * We first write the VGA text-mode breadcrumb directly so that even
     * if the C handler crashes we leave a forensic trail. Then we call
     * into the C handler which paints the same info into the framebuffer
     * (visible after graphics mode takes over). Finally halt forever.
     */
    movl 0(%esp), %eax            /* vector */
    movl $0xB80A0, %edi           /* VGA: row 1 col 0 */
    /* '!' at row 1 col 0 */
    movb $'!', (%edi)
    movb $0x4F, 1(%edi)           /* white-on-red */
    /* high nibble */
    movl %eax, %ecx
    shrl $4, %ecx
    andl $0xF, %ecx
    cmpl $10, %ecx
    jl   1f
    addl $7, %ecx                 /* 10 -> 'A' */
1:  addl $'0', %ecx
    movb %cl, 2(%edi)
    movb $0x4F, 3(%edi)
    /* low nibble */
    movl %eax, %ecx
    andl $0xF, %ecx
    cmpl $10, %ecx
    jl   2f
    addl $7, %ecx
2:  addl $'0', %ecx
    movb %cl, 4(%edi)
    movb $0x4F, 5(%edi)

    /* Call C handler with vector as arg. handler returns; we then halt. */
    pushl %eax
    call host_fault_handler
    addl $4, %esp

    /* Frozen — halt forever. We can't safely return because the fault
       is on the host kernel and we have no recovery. */
.host_halt:
    cli
    hlt
    jmp .host_halt
    .size isr_common, .-isr_common

/* Macro: emit one stub for vector N. Each stub is encoded by hand to
 * be exactly 10 bytes — GAS would otherwise shorten the jump and we
 * couldn't compute IDT entries by uniform stride.
 *
 * Encoding (10 bytes total):
 *   68 NN NN NN NN     pushl $N             (5 bytes)
 *   E9 dd dd dd dd     jmp   isr_common     (5 bytes, forced near rel32)
 */
.altmacro
.macro ISR_STUB n
    .byte 0x68                              /* opcode: pushl imm32 */
    .long \n                                /* imm32 = vector */
    .byte 0xE9                              /* opcode: jmp rel32  */
    .long isr_common - (. + 4)              /* rel32 displacement */
.endm

.align 16
.global isr_table
isr_table:
    /* 256 stubs * 10 bytes = 2560 bytes. */
    .set i, 0
    .rept 256
        ISR_STUB %i
        .set i, i + 1
    .endr
    .size isr_table, .-isr_table

.global _start
.type _start, @function
_start:
    /* Interrupts off immediately */
    cli

    /* ── Save the multiboot args BEFORE we touch anything ────────────────
     * GRUB invokes us with eax = MULTIBOOT_BOOTLOADER_MAGIC and ebx = mbi
     * pointer. We must hand both to kernel_main(magic, mbi) at the bottom
     * of this routine. The IDT-build loop below clobbers ebx, and the
     * data-segment reload + BSS-zero clobber eax. Stash them in dedicated
     * memory cells in .data so they survive everything. */
    movl %eax, mb_saved_magic
    movl %ebx, mb_saved_mbi

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
    /* ── Build IDT: 256 gates, each pointing at isr_table + N*10 ─────────
     *
     * Gate format (8 bytes):
     *   bytes 0-1: offset bits 15:0
     *   bytes 2-3: selector (0x08 = our flat code segment)
     *   byte  4:   reserved (0)
     *   byte  5:   type/attr (0x8E = present, DPL=0, 32-bit interrupt gate)
     *   bytes 6-7: offset bits 31:16
     */
    movl $idt_start, %edi          /* dest: IDT entry pointer */
    movl $isr_table, %ebx          /* src:  current ISR stub address */
    movl $256, %ecx                /* loop count */
0:
    /* offset 15:0 */
    movw %bx, (%edi)
    /* selector = 0x0008 */
    movw $0x08, 2(%edi)
    /* zero/attr/zero */
    movb $0,    4(%edi)
    movb $0x8E, 5(%edi)
    /* offset 31:16 */
    movl %ebx, %eax
    shrl $16, %eax
    movw %ax, 6(%edi)
    /* advance */
    addl $8, %edi
    addl $10, %ebx                  /* each ISR stub is 10 bytes */
    loop 0b

    /* Load IDTR */
    lidt idt_ptr

    /* ── Set up the bootstrap stack ── */
    movl $stack_top, %esp
    movl $0xB8000, %edi
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

    /* ── Reload the saved multiboot args ── */
    movl mb_saved_magic, %eax
    movl mb_saved_mbi,   %ebx

    /* ── Push multiboot arguments: eax=magic, ebx=mbi pointer ── */
    pushl %ebx                    /* arg 2: multiboot_addr */
    pushl %eax                    /* arg 1: magic */

    call kernel_main

    /* ── kernel_main should never return; halt if it does ── */
.hang:
    cli
    hlt
    jmp .hang
