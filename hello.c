/* hello.c — minimal test ELF for the Bochs slot.
 *
 * Build:
 *   gcc -m32 -nostdlib -nostartfiles -static -fno-pie -no-pie \
 *       -Wl,-Ttext=0x08048000 -o hello hello.c
 *
 * The kernel embeds this binary via hello_blob.o, so `make` will
 * regenerate it whenever hello.c changes.
 *
 * Exit path: clean — write 0 to port 0xE8. The kernel's exit_cb
 * (elf_io_exit) fires and tears the slot down. Do NOT use `ud2`:
 * the injected IDT can't always place its exit stub at slab offset
 * 0 (the first PT_LOAD often occupies it), so a fault may route
 * the IDT vector back into program code and produce a visible loop
 * like "HELLO WOHELLO WOHELLO WO...". Port-0xE8 exit is direct and
 * doesn't depend on the IDT-stub fallback working.
 */

static inline void out_byte(unsigned short port, unsigned char val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static void put_ch (char c)        { out_byte(0xE9, (unsigned char)c); }
static void put_str(const char* s) { while (*s) put_ch(*s++); }

void _start(void) {
    put_str("HELLO\n");
    out_byte(0xE8, 0);                  /* clean exit, code 0 */
    for (;;) { __asm__ volatile("cli; hlt"); }
}