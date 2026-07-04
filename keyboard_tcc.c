/* keyboard_tcc.c — example guest program showing keyboard input.
 *
 * Build (on the host, before or after booting the OS):
 *   make cc SRC=keyboard_tcc.c
 *
 * Run (inside the OS terminal, bochs mode):
 *   bochs keyboard_tcc     — opens a dedicated Bochs emulator window
 *   keyboard_tcc           — if already in bochs mode
 *
 * Kernel ABI
 * ----------
 *  outb(0xE9, ch)   -> write character ch to the terminal
 *  outb(0xE8, n)    -> exit with code n  (n & 0xFF)
 *  inb (0xE7)       -> next queued keystroke, or 0 if none waiting yet
 *
 * No libc, no startup files, no dynamic linking. _start is the entry
 * point (set by tcc_guest.ld). Code lands at 0x08002000 so it is safe
 * from the Bochs slot's GDT/IDT/stub injection zone (0x08001000..0x08001FFF).
 */

/* ── port I/O helpers ──────────────────────────────────────────────── */
static inline void outb(unsigned short port, unsigned char val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline unsigned char inb(unsigned short port)
{
    unsigned char v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static void kputc(char c)   { outb(0xE9, (unsigned char)c); }
static void kexit(int code) { outb(0xE8, (unsigned char)code); }

static void kputs(const char *s)
{
    while (*s) kputc(*s++);
}

/* Non-blocking read of the guest's stdin queue. Returns 0 if nothing
 * is waiting yet — spin on it to make a blocking getch(). */
static char getch(void)
{
    unsigned char c;
    while ((c = inb(0xE7)) == 0) { /* wait for a keystroke */ }
    return c;
}

/* ── entry point ──────────────────────────────────────────────────── */
void _start(void)
{
    kputs("==================================\n");
    kputs("  Keyboard test (TCC-compiled C)\n");
    kputs("==================================\n\n");

    kputs("Kernel ABI:\n");
    kputs("  outb(0xE9, ch)  -> write character to terminal\n");
    kputs("  outb(0xE8, n)   -> exit with code n\n");
    kputs("  inb (0xE7)      -> next keystroke, or 0 if none yet\n\n");

    kputs("Type some characters, ENTER to finish, 'q' to quit early.\n\n> ");

    char line[64];
    int  n = 0;

    for (;;) {
        char c = getch();

        if (c == 'q') {
            kputs("\n\nQuit key pressed. Bye!\n");
            kexit(0);
        }

        if (c == '\r' || c == '\n') {
            kputc('\n');
            break;
        }

        if (n < (int)sizeof(line) - 1) line[n++] = c;
        kputc(c);   /* local echo */
    }
    line[n] = 0;

    kputs("\nYou typed (");
    /* tiny integer formatter for the length */
    {
        unsigned int v = (unsigned int)n;
        char buf[12];
        int  i = 0;
        if (v == 0) { kputc('0'); }
        else { while (v) { buf[i++] = '0' + (v % 10); v /= 10; }
               while (i--) kputc(buf[i]); }
    }
    kputs(" chars): \"");
    kputs(line);
    kputs("\"\n\nDone. Exiting with code 0.\n");

    kexit(0);
    for (;;) {}   /* should not reach here */
}
