/* guest.c — freestanding guest ELF for the hotwired `test` command.
 *
 * Build (see the `guest` rule in the Makefile, or by hand):
 *   gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
 *       -ffreestanding -fno-stack-protector \
 *       -Wl,--build-id=none -T guest.ld -o guest guest.c
 *
 * Put `guest` on the FAT32 disk (the kernel's `cp`, or mkfat32 +
 * mtools), then from a terminal window run:
 *
 *     test guest
 *
 * test_module_run_elf() parses this ELF, copies its PT_LOAD segment
 * into slot 0's 1 MiB slab at its own address, points EIP at _start,
 * and ticks the Bochs CPU. A correct run prints the lines below into
 * the terminal's GUEST row and then exits cleanly, so `test` reports:
 *
 *     === self-test PASSED ===
 *     test: PASSED (cpu init + guest tick OK)
 *
 * -- Why this is "freestanding" -----------------------------------------
 * There is no libc, no Linux kernel, and no syscalls under the guest.
 * It may only touch the two ports the Bochs slot understands:
 *
 *     out 0xE9, al   putc  — emit one byte to the terminal
 *     out 0xE8, al   exit  — terminate the guest; AL is the exit code
 *
 * Everything else (printing numbers, strings) is built from those two
 * primitives.
 *
 * -- Link address --------------------------------------------------------
 * This guest is loaded by test_module_run_elf() at its OWN absolute
 * addresses (the loader does NOT relocate it — a compiled C program has
 * absolute pointers baked in). The slot slab is mapped at SLAB_VADDR_BASE
 * (0x08000000) and the injected GDT/IDT/stub tables occupy the first
 * GUEST_ENTRY_OFF (0x1000) bytes. So the guest must be linked to start
 * at 0x08001000 = SLAB_VADDR_BASE + GUEST_ENTRY_OFF, and stay under
 * SLAB_VADDR_BASE + 1 MiB - 16. That is what guest.ld (passed via
 * -T guest.ld in the build line above) arranges: a single PT_LOAD
 * starting at 0x08001000. Linking it anywhere else makes
 * tm_load_elf_into_slab() reject it with a clear message.
 */

/* ── Port primitives ──────────────────────────────────────────────── */

static inline void out_byte(unsigned short port, unsigned char val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void put_ch(char c) { out_byte(0xE9, (unsigned char)c); }

static void put_str(const char* s) {
    while (*s) put_ch(*s++);
}

/* Print an unsigned 32-bit value in decimal. Done without division by
 * a runtime variable beyond what the compiler lowers for /10 and %10;
 * no libc, no buffers larger than needed for 2^32-1 ("4294967295"). */
static void put_u32(unsigned int v) {
    char buf[10];
    int  n = 0;
    if (v == 0) { put_ch('0'); return; }
    while (v && n < 10) { buf[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n) put_ch(buf[--n]);
}

/* Clean exit: AL = code, `out 0xE8`, then park on hlt so the host has a
 * harmless instruction to find the guest on while it tears the slot
 * down. The test module counts this 0xE8 write as the guest-exit
 * sentinel — without it `test` reports INCOMPLETE. */
static void guest_exit(unsigned char code) {
    out_byte(0xE8, code);
    for (;;) { __asm__ volatile("hlt"); }
}

/* ── A little computation, so the run proves the CPU emulator is
 *    actually executing instructions and not just echoing rodata. ─── */

static unsigned int sum_to(unsigned int n) {
    unsigned int s = 0;
    for (unsigned int i = 1; i <= n; ++i) s += i;
    return s;
}

static unsigned int fib(unsigned int n) {
    unsigned int a = 0, b = 1;
    while (n--) { unsigned int t = a + b; a = b; b = t; }
    return a;
}

/* ── Entry point ──────────────────────────────────────────────────── */

/* _start goes in its own section so guest.ld can place it first in the
 * image. The kernel loader honours e_entry regardless, so this is only
 * for a tidy, easy-to-read layout. */
__attribute__((section(".text._start")))
void _start(void) {
    put_str("guest: hello from a hotwired ELF\n");

    /* arithmetic check: 1+2+...+10 == 55 */
    put_str("guest: sum(1..10)  = ");
    put_u32(sum_to(10));
    put_ch('\n');

    /* loop / state check: fib(10) == 55 */
    put_str("guest: fib(10)     = ");
    put_u32(fib(10));
    put_ch('\n');

    put_str("guest: done, exiting cleanly\n");

    /* Exit code 0 -> terminal shows `code=0`, test reports PASSED. */
    guest_exit(0);
}
