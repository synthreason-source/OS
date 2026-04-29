.section .multiboot
.align 4
.long 0x1BADB002
.long 0x00010000  /* FLAGS: meminfo+align */
.long -(0x1BADB002 + 0x00010000)  /* CHECKSUM */

.section .text
.global start
.code32
start:
    mov $stack_top, %esp
    push %ebx
    push %eax
    call kernel_main  /* Matches kernel.cpp */
hang: hlt; jmp hang

.bss
stack_bottom: .skip 16384
stack_top:


# The kernel's entry point.
.section .text
.global _start
.type _start, @function
_start:
	# Disable interrupts initially.
	cli

	# Set up the stack pointer.
	movl $stack_top, %esp

	# The bootloader places the magic number in EAX and a pointer to the 
	# Multiboot info structure in EBX. We pass them as arguments to kernel_main.
	# Arguments are pushed in reverse order (right to left).
	pushl %ebx # Push multiboot_addr
	pushl %eax # Push magic

	# Call the C++ part of our kernel.
	call kernel_main

	# If kernel_main returns, halt the system.
.Lhang:
	hlt
	jmp .Lhang

.size _start, . - _start

