/* hello_tcc.c — example guest program compiled with the TCC glue.
 *
 * Build (on the host, before or after booting the OS):
 *   make cc SRC=hello_tcc.c
 *
 * Run (inside the OS terminal, bochs mode):
 *   bochs hello_tcc        — opens a dedicated Bochs emulator window
 *   hello_tcc              — if already in bochs mode
 *
 * Kernel ABI
 * ----------
 *  outb(0xE9, ch)   → write character ch to the terminal
 *  outb(0xE8, n)    → exit with code n  (n & 0xFF)
 *
 * No libc, no startup files, no dynamic linking.  _start is the entry
 * point (set by tcc_guest.ld).  Code lands at 0x08002000 so it is safe
 * from the Bochs slot's GDT/IDT/stub injection zone (0x08001000..0x08001FFF).
 */

/* ── port I/O helpers ──────────────────────────────────────────────── */
static inline void outb(unsigned short port, unsigned char val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void kputc(char c)   { outb(0xE9, (unsigned char)c); }
static void kexit(int code) { outb(0xE8, (unsigned char)code); }

static void kputs(const char *s)
{
    while (*s) kputc(*s++);
}

/* ── tiny integer formatter ───────────────────────────────────────── */
static void kputu(unsigned int n)
{
    if (n == 0) { kputc('0'); return; }
    char buf[12];
    int i = 0;
    while (n) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i--) kputc(buf[i]);
}

/* ── entry point ──────────────────────────────────────────────────── */
void _start(void)
{
    kputs("==============================\n");
    kputs("  Hello from TCC-compiled C!\n");
    kputs("==============================\n\n");

    kputs("This ELF was built by tcc_glue:\n");
    kputs("  i386-tcc -c hello_tcc.c -o hello_tcc.o\n");
    kputs("  ld -m elf_i386 -T tcc_guest.ld -o hello_tcc hello_tcc.o\n\n");

    kputs("Kernel ABI:\n");
    kputs("  outb(0xE9, ch)  -> write character to terminal\n");
    kputs("  outb(0xE8, n)   -> exit with code n\n\n");

    /* Simple loop to show integer output works */
    kputs("Counting: ");
    for (unsigned int i = 1; i <= 10; i++) {
        kputu(i);
        if (i < 10) kputc(' ');
    }
    kputc('\n');

    kputs("\nDone. Exiting with code 0.\n");
    kexit(0);
    for (;;) {}   /* should not reach here */
}
