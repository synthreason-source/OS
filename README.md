a simple GUI interface OS with terminal windows, TCC compiler & bochs emulator.


CTRL-Q saves and exits text editor...


SATA port selection with 'disk_select'


TODO: elf's print/memory/tick algorithm glitch free

TODO: bochs keyboard input working and test elf functionality via bochs CPU emulator

TODO: add ethernet, Lynx_(web_browser)

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
make clean && make BOCHS=1
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

void _start(void) {
    const char *s = "Hello from TCC!\n";
    while (*s) outb(0xE9, *s++);   // print to terminal
    outb(0xE8, 0);                  // exit(0)
    for (;;) {}
}
```
