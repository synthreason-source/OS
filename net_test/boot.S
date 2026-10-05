.set MAGIC, 0x1BADB002
.set FLAGS, 0
.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long -(MAGIC+FLAGS)
.section .bss
.align 16
stack_bottom: .skip 65536
stack_top:
.section .text
.global _start
_start:
    mov $stack_top, %esp
    call kmain
1:  hlt
    jmp 1b
