/* =========================================================
   boot.S
   Working Multiboot + IDT + ISR Bootloader
   GAS / GNU AS syntax
   ========================================================= */

/* =========================================================
   MULTIBOOT
   ========================================================= */

.set ALIGN,      1<<0
.set MEMINFO,    1<<1
.set FLAGS,      ALIGN | MEMINFO
.set MAGIC,      0x1BADB002
.set CHECKSUM,   -(MAGIC + FLAGS)

/* =========================================================
   MULTIBOOT HEADER
   ========================================================= */

.section .multiboot
.align 4

.long MAGIC
.long FLAGS
.long CHECKSUM

/* =========================================================
   BSS
   ========================================================= */

.section .bss
.align 16

stack_bottom:
.skip 16384

stack_top:

.align 16

idt_start:
.skip 256 * 8

idt_end:

/* =========================================================
   DATA
   ========================================================= */

.section .data

mb_saved_magic:
.long 0

mb_saved_mbi:
.long 0

idt_ptr:
.word idt_end - idt_start - 1
.long idt_start

/* =========================================================
   TEXT
   ========================================================= */

.section .text
.code32

.global _start

.extern kernel_main
.extern host_fault_handler

/* =========================================================
   BOOT ENTRY
   ========================================================= */

_start:
    cli

    /* Save multiboot registers */
    mov %eax, mb_saved_magic
    mov %ebx, mb_saved_mbi

    /* Setup stack */
    mov $stack_top, %esp

    /* ── FPU + CR0 initialisation ────────────────────────────────────────
       Bochs' bx_pc_system_c::initialize() does:
           m_ips = double(ips) / 1000000.0L;
       The 80-bit `long double` divide forces the i386 backend to emit
       x87 FPU instructions (fldt / fdivr / fstpl). If the FPU is left
       in whatever state the BIOS / GRUB handed us — possibly with
       pending unmasked exceptions, or with CR0.EM=1 (no FPU emulation
       allowed) or CR0.TS=1 (task switched) — the first FPU instruction
       hangs the host: either the CPU stalls waiting for FERR# on the
       legacy IRQ13 path (no NE bit), or it raises #NM/#MF into our
       ISR 7/16 that just halts forever. Either way: the kernel appears
       frozen at  bx_pc_system.initialize(50000000u) .

       Fix: clear CR0.EM and CR0.TS, set CR0.MP (so #NM is precise) and
       CR0.NE (so x87 errors come in via #MF, not the IRQ13 chipset
       loop), then  fninit  to drop any pending exception state and
       set the control word to a known masked-all configuration.    */

    mov  %cr0, %eax
    and  $0xFFFFFFFB, %eax     /* clear EM (bit 2) — FPU is real, not emulated */
    or   $0x00000022, %eax     /* set MP (bit 1) and NE (bit 5)               */
    and  $0xFFFFFFF7, %eax     /* clear TS (bit 3)                            */
    mov  %eax, %cr0
    fninit                      /* clear FPU state, mask all exceptions       */

    /* Build IDT */
    call build_idt

    /* Load IDT */
    lidt idt_ptr

    /* Restore registers */
    mov mb_saved_magic, %eax
    mov mb_saved_mbi, %ebx

    /* Push kernel args */
    push %ebx
    push %eax

    /* Enter kernel */
    call kernel_main

/* =========================================================
   HALT
   ========================================================= */

halt:
    cli

1:
    hlt
    jmp 1b

/* =========================================================
   SET IDT ENTRY MACRO
   ========================================================= */

.macro SET_IDT num, handler

    lea \handler, %eax

    mov $idt_start + (\num * 8), %edi

    /* offset low */
    movw %ax, (%edi)

    /* selector */
    movw $0x08, 2(%edi)

    /* zero */
    movb $0, 4(%edi)

    /* interrupt gate */
    movb $0x8E, 5(%edi)

    /* offset high */
    mov %eax, %edx
    shr $16, %edx

    movw %dx, 6(%edi)

.endm

/* =========================================================
   BUILD IDT
   ========================================================= */

build_idt:
    pusha

    SET_IDT 0,  isr_0
    SET_IDT 1,  isr_1
    SET_IDT 2,  isr_2
    SET_IDT 3,  isr_3
    SET_IDT 4,  isr_4
    SET_IDT 5,  isr_5
    SET_IDT 6,  isr_6
    SET_IDT 7,  isr_7
    SET_IDT 8,  isr_8
    SET_IDT 9,  isr_9
    SET_IDT 10, isr_10
    SET_IDT 11, isr_11
    SET_IDT 12, isr_12
    SET_IDT 13, isr_13
    SET_IDT 14, isr_14
    SET_IDT 15, isr_15
    SET_IDT 16, isr_16
    SET_IDT 17, isr_17
    SET_IDT 18, isr_18
    SET_IDT 19, isr_19
    SET_IDT 20, isr_20
    SET_IDT 21, isr_21
    SET_IDT 22, isr_22
    SET_IDT 23, isr_23
    SET_IDT 24, isr_24
    SET_IDT 25, isr_25
    SET_IDT 26, isr_26
    SET_IDT 27, isr_27
    SET_IDT 28, isr_28
    SET_IDT 29, isr_29
    SET_IDT 30, isr_30
    SET_IDT 31, isr_31

    popa
    ret

/* =========================================================
   ISR MACRO
   ========================================================= */

.macro ISR num

.global isr_\num

isr_\num:
    cli

    pushl $\num

    call host_fault_handler

1:
    hlt
    jmp 1b

.endm

/* =========================================================
   ISR DEFINITIONS
   ========================================================= */

ISR 0
ISR 1
ISR 2
ISR 3
ISR 4
ISR 5
ISR 6
ISR 7
ISR 8
ISR 9
ISR 10
ISR 11
ISR 12
ISR 13
ISR 14
ISR 15
ISR 16
ISR 17
ISR 18
ISR 19
ISR 20
ISR 21
ISR 22
ISR 23
ISR 24
ISR 25
ISR 26
ISR 27
ISR 28
ISR 29
ISR 30
ISR 31