# Declare constants for the Multiboot 1 header.
.set ALIGN,    1<<0             # align loaded modules on page boundaries
.set MEMINFO,  1<<1             # provide memory map
.set GFX,      1<<2             # request graphics mode
.set FLAGS,    ALIGN | MEMINFO | GFX
.set MAGIC,    0x1BADB002       # 'magic number' lets bootloader find the header
.set CHECKSUM, -(MAGIC + FLAGS) # checksum of above

# Declare a multiboot header that marks the program as a kernel.
.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

# These fields are required by the Multiboot 1 graphics specification.
.long 0  # header_addr (optional)
.long 0  # load_addr (optional)
.long 0  # load_end_addr (optional)
.long 0  # bss_end_addr (optional)
.long _start # entry_addr (optional, but good practice)

.long 0  # mode_type: 0 for linear framebuffer graphics
.long 1024 # width
.long 768  # height
.long 32   # depth

# Reserve space for a temporary stack.
.section .bootstrap_stack, "aw", @nobits
stack_bottom:
.skip 16384 # 16 KiB stack
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

