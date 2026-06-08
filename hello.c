/* hello.c — minimal test ELF for the Bochs slot, with keyboard input.
 *
 * Build:
 *   gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
 *       -Wl,-Ttext=0x08048000 -o hello hello.c
 *
 * I/O ports used:
 *   0xE9  write — debug-console putc (host sees it on debugcon stdout)
 *   0xE8  write — clean exit sentinel (code in AL)
 *   0xEA  read  — keyboard getc: returns next queued byte, or spins
 *                 (the glue rewinds EIP and yields when no byte is
 *                 ready, so the IN re-executes on the next tick)
 *
 * Behaviour:
 *   1. Print "HELLO WORLD\n".
 *   2. Print "Type something (Enter to finish):\n".
 *   3. Echo every character the user types until '\n' is received;
 *      prefix each echoed char with "> " so terminal output is clear.
 *   4. Print "You typed: " followed by the line, then "\n".
 *   5. Exit cleanly via port 0xE8.
 */

static inline void out_byte(unsigned short port, unsigned char val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline unsigned char in_byte(unsigned short port) {
    unsigned char val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

static void put_ch (char c)        { out_byte(0xE9, (unsigned char)c); }
static void put_str(const char* s) { while (*s) put_ch(*s++); }

/* Read one character from the keyboard via port 0xEA.
 * The Bochs glue backs this up:
 *   - If a byte is queued in read_cb, return it immediately.
 *   - If no byte is ready, the glue rewinds EIP by 2 (the size of
 *     IN AL, imm8) and yields cpu_loop. The kernel then feeds a byte
 *     and re-ticks, causing this IN instruction to re-execute. From
 *     the guest's perspective this call simply blocks until a char
 *     is available. */
static char get_ch(void) {
    return (char)in_byte(0xEA);
}

void _start(void) {
    /* --- greeting --- */
    put_str("HELLO WORLD\n");
    put_str("Type something (Enter to finish):\n");

    /* --- collect a line of input, echo each char --- */
    static char buf[64];
    int len = 0;

    while (len < 63) {
        char c = get_ch();
        if (c == '\r') c = '\n';   /* normalise CR -> LF */
        if (c == '\n') break;

        /* Echo with "> " prefix so it's visible in the terminal window */
        put_str("> ");
        put_ch(c);
        put_ch('\n');

        buf[len++] = c;
    }
    buf[len] = '\0';

    /* --- playback --- */
    put_str("You typed: ");
    put_str(buf);
    put_ch('\n');

    out_byte(0xE8, 0);                  /* clean exit, code 0 */
    for (;;) { __asm__ volatile("cli; hlt"); }
}
