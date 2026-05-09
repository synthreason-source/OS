/* busybox_stub.c — minimal i386 ELF used as a stand-in for the real
 * BusyBox binary when the BusyBox download URL is not reachable from
 * the build environment. Has a valid ELF header so the kernel's ramdisk
 * extraction does NOT reject it; just prints a short message and halts.
 *
 * Build (matches Makefile's hello target):
 *   gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
 *       -Wl,-Ttext=0x08048000 -o busybox busybox_stub.c
 */

static inline void out_byte(unsigned short port, unsigned char val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}
static void put_str(const char* s) {
    while (*s) out_byte(0xE9, (unsigned char)*s++);
}

void _start(void) {
    put_str("[busybox stub: real binary not bundled in this build]\n");
    __asm__ volatile("ud2");
    for (;;) {}
}
