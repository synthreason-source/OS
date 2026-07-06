# Guest disk wrapper (FAT32 file access for TCC guest programs)

Adds file-level FAT32 access to the guest ABI (the same ABI `keyboard_tcc.c`
uses for `outb(0xE9,...)`/`outb(0xE8,...)`/`inb(0xE7)`). Guest programs can
now `kfread`/`kfwrite`/`kfstat`/`kfremove` files on the **same** `disk.img`
FAT32 volume the host kernel's own shell/file-explorer use — no separate
cache, no shadow copy, nothing to keep "in sync" after the fact, because
there's only ever one copy of the data.

## Files touched

- `drivers.h` / `bochs_drivers.h` — new guest-side API: `kfread`, `kfwrite`,
  `kfremove`, `kfstat`, the `disk_mailbox_t` struct, and the `DISK_*` port/
  command/error constants.
- `bochs_infra.cpp` — `bx_devices_c::outp` now latches ports `0xE0`-`0xE3`
  (a little-endian guest-physical address) and dispatches on `0xE4`
  (command byte) to `bochs_guest_disk_cmd()`.
- `bochs_glue.cpp` — `bochs_guest_disk_cmd()`: translates the guest
  address to a host pointer (reusing the same `mem_base`/`vaddr_base` math
  `mapping_register()` uses for CPU memory), then calls straight into
  kernel.cpp's existing `fat32_write_file` / `fat32_read_file_as_string` /
  `fat32_remove_file` / `fat32_stat_file`.
- `kernel.cpp` — added `fat32_stat_file()`, a thin wrapper around the
  existing `fat32_find_entry()` that returns just a file's size (used for
  the `STAT` command and, internally, to fail fast on `READ` if the
  guest's buffer is too small instead of paying for a full read first).
- `disk_tcc.c` — new example guest program exercising all four calls
  (write → stat → read back → delete), in the same style as
  `keyboard_tcc.c`.

## Protocol

The guest fills in a `disk_mailbox_t { name[64]; buf_addr; buf_len; status; }`,
then submits it by writing the little-endian bytes of *its own address* to
ports `0xE0`-`0xE3`, followed by a command byte (`DISK_CMD_READ` /
`_WRITE` / `_DELETE` / `_STAT`) to `0xE4`. That final `outb()` does not
return until the kernel has finished the whole file operation and written
the result back into the same struct — synchronous, like a real blocking
disk transaction, so there's no polling loop on the guest side.

```c
#include "drivers.h"

kfwrite("hello.txt", "hi!\n", 4);           // create/overwrite
unsigned int size;
kfstat("hello.txt", &size);                 // size without reading
char buf[64];
int n = kfread("hello.txt", buf, sizeof buf);
kfremove("hello.txt");                      // delete
```

Error codes (`DISK_ERR_NOTFOUND`, `DISK_ERR_IO`, `DISK_ERR_TOOBIG`,
`DISK_ERR_BADCMD`, `DISK_ERR_BADNAME`) are all negative; success is `0`
(`kfread` returns the byte count instead, so check `>= 0`).

## Build/run

Same as any other guest program:

```bash
make cc SRC=disk_tcc.c
# boot the OS, then in its shell:
disk_tcc
```

## Note on testing

I wasn't able to build or boot this sandboxed — the toolchain needs
`gcc-multilib`/`nasm`/`qemu-system-i386`/a locally-built `i386-tcc`, and
this environment's network allowlist doesn't reach the package mirrors or
`download.savannah.gnu.org`. I did syntax-check `drivers.h` and
`disk_tcc.c` against host gcc (`-fsyntax-only -std=c99`), and traced the
new `bochs_glue.cpp`/`bochs_infra.cpp`/`kernel.cpp` code by hand against
the existing `SlotState`/`mapping_register`/`fat32_*` definitions already
in the tree, but please build it with `make clean && make BOCHS=1` and
run `disk_tcc` before relying on it.
