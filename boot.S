/* boot.S — Multiboot entry, PIC remap, minimal IDT */

.set MB_ALIGN,    1 << 0
.set MB_MEMINFO,  1 << 1
.set MB_VIDMODE,  1 << 2
.set MB_FLAGS,    MB_ALIGN | MB_MEMINFO | MB_VIDMODE
.set MB_MAGIC,    0x1BADB002
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

/* ── Multiboot header ── */
.section .multiboot
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM
.long 0, 0, 0, 0, 0     /* address fields (bit-16 not set, ignored) */
.long 0, 1024, 768, 32   /* mode_type=linear, width, height, depth */

/* ── BSS ── */
.section .bss
.align 16
stack_bottom:
    .skip 65536
stack_top:

.align 8
idt_table:
    .skip 2048

/* ── IDT pointer ── */
.section .data
.align 4
idt_ptr:
    .word 2047
    .long idt_table

/* ── Multiboot args (stored in .bss so write_gate can use %edi freely) ── */
.section .bss
saved_magic:   .skip 4
saved_mbi:     .skip 4

/* ── ISR stubs ── */
.section .text

.global isr_no_err
isr_no_err:
    pusha
    movb  $0x20, %al
    outb  %al, $0xA0
    outb  %al, $0x20
    popa
    iret

.global isr_err
isr_err:
    addl  $4, %esp        /* discard CPU-pushed error code */
    pusha
    movb  $0x20, %al
    outb  %al, $0xA0
    outb  %al, $0x20
    popa
    iret

/* write_gate: fill idt_table[%ecx] with 32-bit int gate to handler in %edi */
write_gate:
    leal  idt_table(,%ecx,8), %edx
    movl  %edi, %eax
    movw  %ax,   (%edx)
    movw  $0x08, 2(%edx)
    movb  $0x00, 4(%edx)
    movb  $0x8E, 5(%edx)
    shrl  $16,   %eax
    movw  %ax,   6(%edx)
    ret

.global _start
.type  _start, @function
_start:
    movl $stack_top, %esp

    /* Save multiboot registers to .bss variables (avoids register conflicts) */
    movl %eax, saved_magic
    movl %ebx, saved_mbi

    /* ── Remap 8259 PIC ── */
    movb  $0x11, %al; outb %al, $0x20; outb %al, $0x80
                      outb %al, $0xA0; outb %al, $0x80
    movb  $0x20, %al; outb %al, $0x21; outb %al, $0x80
    movb  $0x28, %al; outb %al, $0xA1; outb %al, $0x80
    movb  $0x04, %al; outb %al, $0x21; outb %al, $0x80
    movb  $0x02, %al; outb %al, $0xA1; outb %al, $0x80
    movb  $0x01, %al; outb %al, $0x21; outb %al, $0x80
                      outb %al, $0xA1; outb %al, $0x80
    movb  $0xFF, %al; outb %al, $0x21; outb %al, $0x80
                      outb %al, $0xA1; outb %al, $0x80

    /* ── Build IDT ── */
    movl  $isr_no_err, %edi
    movl  $0, %ecx
.Lfill:
    call  write_gate
    incl  %ecx
    cmpl  $256, %ecx
    jl    .Lfill

    movl  $isr_err, %edi
    movl   $8, %ecx; call write_gate
    movl  $10, %ecx; call write_gate
    movl  $11, %ecx; call write_gate
    movl  $12, %ecx; call write_gate
    movl  $13, %ecx; call write_gate
    movl  $14, %ecx; call write_gate
    movl  $17, %ecx; call write_gate
    movl  $21, %ecx; call write_gate

    lidt  idt_ptr

    /* ── Call kernel_main(magic, mbi_addr) ──
       16-byte align esp before the call (ABI requirement).
       esp = stack_top now. Align: (stack_top - 8) & ~15, then push args. */
    andl  $-16, %esp        /* 16-byte align */
    subl  $8,   %esp        /* make room for 2 x 4-byte args + keep align */
    pushl saved_mbi         /* arg1: multiboot info ptr */
    pushl saved_magic       /* arg0: magic number */
    call  kernel_main

    cli
.Lhalt:
    hlt
    jmp .Lhalt
