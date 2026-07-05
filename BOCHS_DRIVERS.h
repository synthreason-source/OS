/* BOCHS_DRIVERS.h — guest ABI for in-kernel TCC programs */
 
/* port I/O helpers */
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

static inline void kputc(char c)   { outb(0xE9, (unsigned char)c); }
static inline void kexit(int code) { outb(0xE8, (unsigned char)code); }

static inline void kputs(const char *s)
{
    while (*s) kputc(*s++);
}

/* Blocking read of one keystroke from the guest's stdin queue — spins
 * on port 0xE7 until a non-zero byte is queued. Safe: the kernel yields
 * control back to the scheduler on every empty read instead of burning
 * the guest's instruction budget spinning (see bochs_guest_getc()). */
static inline char getch(void)
{
    unsigned char c;
    while ((c = inb(0xE7)) == 0) { /* wait for a keystroke */ }
    return c;
}
