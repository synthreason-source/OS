/* boot.S - Multiboot entry point */
.set ALIGN,    1<<0
.set MEMINFO,  1<<1
.set VIDMODE,  1<<2
.set FLAGS,    ALIGN | MEMINFO | VIDMODE
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM
/* Multiboot video fields (used when VIDMODE flag set) */
.long 0   /* header_addr */
.long 0   /* load_addr */
.long 0   /* load_end_addr */
.long 0   /* bss_end_addr */
.long 0   /* entry_addr */
.long 0   /* mode_type: 0=linear */
.long 1024 /* width */
.long 768  /* height */
.long 32   /* depth */

.section .bss
.align 16
stack_bottom:
.skip 65536
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp
    push %ebx   /* multiboot info pointer */
    push %eax   /* multiboot magic */
    call kernel_main
    cli
1:  hlt
    jmp 1b
