/* hello.c — minimal test ELF for the Bochs slot.
 *
 * Build:
 *   gcc -m32 -nostdlib -static -fno-pie -no-pie -Ttext=0x08048000 \
 *       -o hello hello.c -nostartfiles
 *
 * Then copy `hello` into the FAT32 image alongside busybox, and from
 * the kernel terminal type:  hello
 *
 * If the GDT/IDT setup and port-0xE9 routing are working, you should
 * see "HELLO\n" printed in the terminal window.
 */

static inline void out_byte(unsigned short port, unsigned char val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void put_ch(char c) { out_byte(0xE9, (unsigned char)c); }
static void put_str(const char* s) { while (*s) put_ch(*s++); }

void _start(void) {
    put_str("HELLO\n");
    /* End by deliberately faulting. The injected IDT vector points back
       to a stub that re-faults, which triple-faults Bochs. The host
       catches the panic via setjmp and kills the slot cleanly. The
       kernel keeps running. */
    __asm__ volatile("ud2");
    for (;;) {}
}
