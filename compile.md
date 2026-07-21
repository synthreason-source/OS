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

### Graphics: drawing into the terminal window

`bochs_drivers.h` also gives guest programs a small graphics ABI so a
program isn't limited to scrolling text — it can take over its
terminal window and draw pixels instead:

```c
#include "bochs_drivers.h"

void _start(void) {
    gfx_clear(0x000000);                 // black background
    gfx_set_pixel(160, 100, 0xFF0000);   // one red pixel, centre-ish
    gfx_present();                       // blit gfx_framebuffer to the window

    for (;;) { /* keep drawing frames here */ }
}
```

- The canvas is fixed at `GFX_WIDTH x GFX_HEIGHT` (320x200), 32-bit
  `0xRRGGBB` pixels, addressed row-major via `gfx_set_pixel(x, y, rgb)`
  or by writing directly into the `gfx_framebuffer[]` array.
- `gfx_present()` blits the current `gfx_framebuffer` into this
  program's own terminal window, replacing the scrolling text view for
  as long as graphics mode stays active. It's synchronous, so it's
  always safe to start drawing the next frame immediately afterward.
- `gfx_exit()` drops back to plain text mode (`kputs`/`kputc`); it's
  also called automatically when the program exits, so a crashed or
  killed graphics program never leaves a stale frame behind.
- Build and run it exactly like any other guest program (see
  `gfx_demo.c` for a complete example):
  ```bash
  make cc SRC=gfx_demo.c
  # in the OS shell:
  gfx_demo
  ```

**Using the in-kernel `cc` command instead of `make cc`:** the shell's
own `cc <file.c>` compiles straight from the OS's FAT32 disk, and any
`#include "local_header.h"` has to resolve to a *file already on that
same disk*. This used to fail for `bochs_drivers.h` specifically: the
function backing that lookup (`fat32_read_file_as_string`) only ever
compared against a naive first-8-characters short name it computed
itself, ignoring the real long-filename (VFAT LFN) entries mtools
writes for a 13-character base name like `bochs_drivers` — so the
header could come back "not on disk" even when it genuinely was. Fixed
by making that lookup reuse the same long-name-aware matching
`cd`/`ls`/the File Explorer already rely on
(`kernel_parts/06_fat32_filesystem_and_explorer.h`'s
`fat32_find_entry`), and by having `make cc` always `mcopy` a current
copy of `bochs_drivers.h` onto `disk.img` before compiling, so it's
never missing in the first place. `#include "bochs_drivers.h"` now
just works from the in-kernel `cc` command:
```
cc gfx_demo.c
gfx_demo
```
(`gfx_demo_standalone.c` — the same demo with those few lines inlined
instead of `#include`d — is still there if you ever want a single
self-contained file with no local include at all, but it's no longer
necessary to work around this.)

**If a frame doesn't show up right away:** a program computing a full
320x200 frame does tens of thousands of `gfx_set_pixel` calls with no
port I/O in between, unlike a `kputs`-based program that naturally
yields every ~10-15 instructions. Give it a moment — the demo prints a
"starting..." message via `kputs` immediately, before it ever touches
graphics, so you can confirm it launched even before the first frame
appears.

### Mouse: reading the compositor's cursor into your gfx canvas

A gfx-mode program can also poll the desktop's one shared mouse
cursor — but only while its own window is the FOCUSED one. Click a
titlebar, another window, the desktop, or the taskbar and that's
handled entirely by the window manager (the "compositor") as normal;
none of it ever reaches a guest program, with or without this ABI.

```c
#include "bochs_drivers.h"

void _start(void) {
    for (;;) {
        mouse_state_t ms;
        mouse_poll(&ms);          // synchronous, always safe to call every frame

        gfx_clear(0x202020);
        if (ms.in_window) {
            gfx_set_pixel(ms.x, ms.y, 0xFFFFFF);   // draw a dot at the cursor
            if (ms.left_clicked) { /* ... */ }
        }
        gfx_present();
    }
}
```

- `mouse_state_t.x`/`.y` are in the SAME coordinate space as
  `gfx_set_pixel()` — 0..319, 0..199 — already converted from screen
  coordinates, already accounting for however the window is
  positioned/sized/centred on screen.
- `.left_clicked`/`.right_clicked` are one-shot edges: true only on
  the very next `mouse_poll()` after the button went down, even if
  that poll happens on a later frame than the actual click (the
  kernel latches it so a fast click between two frames is never
  dropped).
- `.in_window` is 0 whenever this window isn't focused, or the cursor
  is simply outside the canvas — check it before trusting `.x`/`.y`.
- `key_poll()` is `getch()`'s non-blocking sibling: returns 0
  immediately if nothing's queued (instead of spinning), which is
  what a per-frame GUI loop needs alongside `mouse_poll()`.

### compositor.h: buttons, a scrollbar, and a text box

`compositor.h` is a small GUI widget library built on top of the gfx +
mouse ABI above — buttons, a vertical scrollbar, and a single-line
text box, all driven by `mouse_poll()`/`key_poll()` under the hood so
individual programs don't have to hand-roll hit-testing and drag
state themselves. See `gui_demo.c` for a complete example:

```bash
make cc SRC=gui_demo.c
# in the OS shell:
gui_demo
```

```c
#include "bochs_drivers.h"
#include "compositor.h"

static ui_button_t quit_btn = { 10, 10, 60, 20, "Quit" };

void _start(void) {
    for (;;) {
        ui_frame_t f;
        ui_frame_begin(&f, UI_COLOR_BG);   // polls mouse+key, clears the canvas

        if (ui_button(&f, &quit_btn)) break;

        ui_frame_end();                    // gfx_present()
    }
    gfx_exit();
    kexit(0);
}
```

Widget state (scrollbar drag, text box contents/focus) lives in plain
structs the caller owns — usually file-scope `static` — the same
"no hidden state" style as the rest of this ABI. `compositor.h`
`#include`s `bochs_drivers.h` and `font.h` itself, so a program only
needs both headers present (`make cc` syncs all three onto `disk.img`
automatically, the same way it already does for `bochs_drivers.h`
alone).
