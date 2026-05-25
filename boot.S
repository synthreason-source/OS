/* =========================================================
   boot.S
   Multiboot + IDT + ISR Bootloader  (fixed: GDT selector + PIC remap)
   GAS / GNU AS syntax
   ========================================================= */

.set ALIGN,      1<<0
.set MEMINFO,    1<<1
.set VIDINFO,    1<<2          /* ask GRUB to set up a linear framebuffer */
.set FLAGS,      ALIGN | MEMINFO | VIDINFO
.set MAGIC,      0x1BADB002
.set CHECKSUM,   -(MAGIC + FLAGS)

/* ───── Kernel code selector in the kernel's *own* GDT.
   The triple-fault chain in the QEMU log proved that by the time IRQs
   are serviced, CS=0x10 / SS=0x18 (see "IP=0010:... SP=0018:..." in the
   -d int trace).  IDT entries built with the old GRUB selector 0x08
   triggered #GP on every exception/IRQ delivery → #DF → triple fault.
   Keep this in sync with whatever the kernel reloads into CS.        */
.set KCS_SEL,    0x10

/* =========================================================
   MULTIBOOT HEADER
   ========================================================= */

.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM
/* Address fields (bit 16 not set in FLAGS — zero-fill so the video
   fields below land at the offsets the Multiboot 1 spec requires).
   header_addr / load_addr / load_end_addr / bss_end_addr / entry_addr. */
.long 0
.long 0
.long 0
.long 0
.long 0
/* Video mode request (FLAGS bit 2):
     mode_type = 0 (linear graphics — RGB framebuffer; 1 = EGA text)
     width  = 1024
     height = 768
     depth  = 32 bpp
   GRUB treats 0 as "no preference" for any field; the kernel clamps
   anything larger anyway. Asking for 1024x768x32 means GRUB-BIOS will
   pick the closest VBE mode and GRUB-EFI will pick the closest GOP
   mode, then pass back the live framebuffer address in the multiboot
   info struct (mbi->flags bit 12, mbi->framebuffer_* fields). */
.long 0
.long 1024
.long 768
.long 32

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

mb_saved_magic: .long 0
mb_saved_mbi:   .long 0

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

_start:
    cli

    /* Save multiboot registers before we clobber eax/ebx */
    mov %eax, mb_saved_magic
    mov %ebx, mb_saved_mbi

    /* Stack */
    mov $stack_top, %esp

    /* ── FPU + CR0 init (unchanged from prior version) ────────────── */
    mov  %cr0, %eax
    and  $0xFFFFFFFB, %eax     /* clear EM */
    or   $0x00000022, %eax     /* set MP, NE */
    and  $0xFFFFFFF7, %eax     /* clear TS */
    mov  %eax, %cr0
    fninit

    /* ── FIX B: Remap 8259 PIC ─────────────────────────────────────────
       Default BIOS PIC mapping puts IRQ 0 (timer) at vector 8 — exactly
       the #DF slot.  Every timer tick was therefore taking the #DF
       path through isr_8.  Remap master → 0x20..0x27, slave → 0x28..0x2F,
       then mask everything so no IRQ fires until the kernel chooses to
       unmask.                                                         */
    movb $0x11, %al
    outb %al, $0x20           /* master ICW1 */
    outb %al, $0xA0           /* slave  ICW1 */
    movb $0x20, %al
    outb %al, $0x21           /* master ICW2: vector base 0x20 */
    movb $0x28, %al
    outb %al, $0xA1           /* slave  ICW2: vector base 0x28 */
    movb $0x04, %al
    outb %al, $0x21           /* master ICW3: slave on IRQ2 */
    movb $0x02, %al
    outb %al, $0xA1           /* slave  ICW3: cascade id 2 */
    movb $0x01, %al
    outb %al, $0x21           /* master ICW4: 8086 mode */
    outb %al, $0xA1           /* slave  ICW4 */
    movb $0xFF, %al
    outb %al, $0x21           /* mask all master IRQs */
    outb %al, $0xA1           /* mask all slave  IRQs */

    /* Build & load IDT */
    call build_idt
    lidt idt_ptr

    /* Restore multiboot regs and jump into C */
    mov mb_saved_magic, %eax
    mov mb_saved_mbi,   %ebx
    push %ebx
    push %eax
    call kernel_main

halt:
    cli
1:  hlt
    jmp 1b

/* =========================================================
   SET IDT ENTRY MACRO
   ── FIX A: selector now KCS_SEL (0x10), matching the kernel's GDT.
   ========================================================= */

.macro SET_IDT num, handler
    lea  \handler, %eax
    mov  $idt_start + (\num * 8), %edi
    movw %ax, (%edi)                /* offset 0-15 */
    movw $KCS_SEL, 2(%edi)          /* selector (was 0x08) */
    movb $0, 4(%edi)                /* zero / IST */
    movb $0x8E, 5(%edi)             /* P=1 DPL=0 32-bit interrupt gate */
    mov  %eax, %edx
    shr  $16, %edx
    movw %dx, 6(%edi)               /* offset 16-31 */
.endm

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
1:  hlt
    jmp 1b
.endm

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
