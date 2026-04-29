.section .multiboot
.align 4

/* Multiboot magic */
.long 0x1BADB002
/* FLAGS: bit0=align, bit1=meminfo, bit2=request video mode */
.long 0x00000007
/* CHECKSUM */
.long -(0x1BADB002 + 0x00000007)
/* Address fields (unused when bit16=0, but space required by spec for video) */
.long 0, 0, 0, 0, 0
/* Video mode: type=0 (linear graphics), width=1024, height=768, depth=32 */
.long 0        /* mode_type: 0=linear framebuffer */
.long 1024     /* width */
.long 768      /* height */
.long 32       /* depth */

.section .text
.global _start
.type _start, @function
_start:
    cli
    movl $stack_top, %esp
    pushl %ebx            /* multiboot_info pointer */
    pushl %eax            /* multiboot magic */
    call kernel_main
.Lhang:
    hlt
    jmp .Lhang
.size _start, . - _start

.section .bss
.align 16
stack_bottom:
    .skip 16384
stack_top:
