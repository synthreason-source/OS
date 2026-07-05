a simple GUI interface OS with terminal windows, TCC compiler & bochs emulator.


CTRL-Q saves and exits text editor...


SATA port selection with 'disk_select'


TODO: add TCC include functionality.

TODO: add ethernet, Lynx_(web_browser) & busybox

# Build Instructions

## Prerequisites (one-time apt installs)

```bash
sudo apt update
sudo apt install make gcc g++ gcc-multilib g++-multilib gcc-13-multilib \
    binutils binutils-multiarch grub-common grub-pc-bin \
    xorriso mtools qemu-system-x86 build-essential nasm \
    libncurses-dev bison flex git bc libssl-dev \
    xorg-dev libx11-dev
```

> **Note:** `binutils-multiarch` is required for `ld -m elf_i386` used by
> the TCC guest linker step.  TCC itself is built from source automatically
> (see below) — no `apt install tcc` needed.

---

## TCC: download and build (one-time, automatic)

TCC (Tiny C Compiler) is fetched from GitHub and built locally into
`tcc-local/`.  This gives you `i386-tcc` (cross-compiler targeting 32-bit
i386) and `libtcc.a` (for `tcc_tool`).

```bash
make setup-tcc        # downloads source, builds, installs into tcc-local/
```

To remove the local TCC build and start fresh:

```bash
make tcc-clean        # removes tcc-local/, tcc-src/, tcc-mob.tar.gz
```

---

## Bochs test

```bash
sudo make test_main
qemu-system-i386 -cdrom test_main.iso -m 256 -debugcon stdio -no-reboot -no-shutdown
```

---

## Full kernel build

```bash
make clean
rm -rf bochs-2.0 bochs-2.0-src.tar.gz tcc-src tcc-local i386-libtcc-kern.a i386-libtcc.a
make world
```

Run in QEMU:

```bash
qemu-system-i386 -M q35 -m 2048M -vga std \
    -drive id=cd0,file=main.iso,format=raw,if=none,media=cdrom \
    -drive id=disk0,file=disk.img,format=raw,if=none \
    -device ahci,id=ahci \
    -device ide-cd,drive=cd0,bus=ahci.0 \
    -device ide-hd,drive=disk0,bus=ahci.1 \
    -boot d
```

---

## Compile a C program for the guest kernel

Compiles a `.c` file on the **host** into a 32-bit ELF and writes it into
`disk.img`.  Boot (or restart) the OS and run it by typing its name in the
shell.

```bash
# One-time setup (if not already done):
make setup-tcc

# Compile:
make cc SRC=hello_tcc.c           # output name derived from filename
make cc SRC=hello_tcc.c OUT=hello # explicit output name

# Inside the OS shell, type:
hello
```

### What happens under the hood

1. `i386-tcc -c -nostdlib foo.c` → `foo.o`  (relocatable i386 object)
2. `ld -m elf_i386 -T tcc_guest.ld -static -nostdlib` → `foo` (ELF32, code at 0x08002000)
3. `mtools mcopy foo → disk.img::/foo`

The linker script `tcc_guest.ld` places code at `0x08002000`, safely past
the Bochs GDT/IDT/stub injection zone (`0x08001000–0x08001fff`).

### Guest kernel ABI

```c
static inline void outb(unsigned short port, unsigned char v) {
    __asm__ volatile("outb %0,%1" :: "a"(v), "Nd"(port));
}

static inline unsigned char inb(unsigned short port) {
    unsigned char v;
    __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(port));
    return v;
}

void _start(void) {
    const char *s = "Hello from TCC!\n";
    while (*s) outb(0xE9, *s++);   // print to terminal
    outb(0xE8, 0);                  // exit(0)
    for (;;) {}
}
```

### Keyboard input

`inb(0xE7)` returns the next queued keystroke from the terminal, or `0`
if none is waiting yet. It's non-blocking, so poll it in a loop:

```c
/* keyboard_tcc.c â€” example guest program showing keyboard input.
 *
 * Build (on the host, before or after booting the OS):
 *   make cc SRC=keyboard_tcc.c
 *
 * Run (inside the OS terminal, bochs mode):
 *   bochs keyboard_tcc     â€” opens a dedicated Bochs emulator window
 *   keyboard_tcc           â€” if already in bochs mode
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
/* tcc.h â€” guest ABI for in-kernel TCC programs */
#ifndef TCC_H
#define TCC_H
/* port I/O helpers
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
 * is waiting yet â€” spin on it to make a blocking getch(). */
static char getch(void)
{
    unsigned char c;
    while ((c = inb(0xE7)) == 0) { /* wait for a keystroke */ }
    return c;
}
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
```

While a guest is polling an empty queue, the kernel notices (via
`bochs_process_wants_input`) and pauses that slot until the next
keypress arrives instead of burning its whole instruction budget —
see `bochs_guest_getc()` in `bochs_glue.cpp`.
