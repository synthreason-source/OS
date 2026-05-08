/* setjmp.S - real i386 setjmp/longjmp for the freestanding kernel.
 *
 * Glibc's i386 jmp_buf layout (which is what libcpu.a's setjmp/longjmp
 * calls expect, since libcpu.a was compiled against system <setjmp.h>):
 *
 *   offset  0: ebx
 *   offset  4: esi
 *   offset  8: edi
 *   offset 12: ebp
 *   offset 16: esp (at point of call, i.e. esp+4 inside the callee)
 *   offset 20: eip (return address)
 *
 * We provide _setjmp, setjmp, longjmp, and __longjmp_chk. They all share
 * this layout. These are written in pure asm (no C frame) so no compiler
 * choices about prologues/locals can corrupt the stack reads.
 *
 * Calling convention (cdecl): jmp_buf pointer is the first argument at
 * 4(%esp); int val (for longjmp) is the second at 8(%esp). Return address
 * is at 0(%esp) on entry.
 */

    .text

    .globl _setjmp
    .type  _setjmp, @function
_setjmp:
    movl    4(%esp), %eax       /* eax = jmp_buf* */
    movl    %ebx,  0(%eax)
    movl    %esi,  4(%eax)
    movl    %edi,  8(%eax)
    movl    %ebp, 12(%eax)
    leal    4(%esp), %ecx       /* esp at caller frame */
    movl    %ecx, 16(%eax)
    movl    (%esp), %ecx        /* return address */
    movl    %ecx, 20(%eax)
    xorl    %eax, %eax          /* return 0 */
    ret
    .size  _setjmp, .-_setjmp

    .globl setjmp
    .type  setjmp, @function
setjmp:
    jmp _setjmp
    .size  setjmp, .-setjmp

    .globl longjmp
    .type  longjmp, @function
longjmp:
    movl    4(%esp), %edx       /* edx = jmp_buf* */
    movl    8(%esp), %eax       /* eax = val */
    testl   %eax, %eax
    jnz     1f
    incl    %eax                /* if val==0, return 1 */
1:
    movl     0(%edx), %ebx
    movl     4(%edx), %esi
    movl     8(%edx), %edi
    movl    12(%edx), %ebp
    movl    16(%edx), %esp      /* restore caller's esp */
    jmp    *20(%edx)            /* jump to saved eip with val in eax */
    .size  longjmp, .-longjmp

    .globl __longjmp_chk
    .type  __longjmp_chk, @function
__longjmp_chk:
    jmp longjmp
    .size  __longjmp_chk, .-__longjmp_chk

    .section .note.GNU-stack,"",@progbits
