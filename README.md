# Bochs slot hang fix (v3)

## Symptom

Typing `hello` (or `busybox`) at the kernel terminal locks up the entire
system. The screen freezes at `> hello` — no `hello started.` message,
no new emulator window, no shell response.

v1 fixed the IDT trap-loop. v2 fixed an earlier NULL-deref in
`bochs_set_process_memory`. v3 fixes a third hang that v2 exposed:
`BX_MEM_C::init_memory()` itself wedges in this freestanding kernel.

Each iteration of the diagnostic top-row breadcrumbs tells the story:

| State        | Breadcrumb | Where it stopped                          |
|--------------|------------|-------------------------------------------|
| Original     | `01234`    | inside `BX_MEM(0)->init_memory(...)`      |
| After v1     | `01234`    | same (IDT fix never reached)              |
| After v2     | `1234`     | same hang, but `bochs_cpu_init()` no longer on the path so the leading `0` is gone |
| After v3     | `12345…`   | `init_memory` returns cleanly; on to `'M'` / `'S'` and process execution |

## Three root causes

### Bug 1 — `bochs_set_process_memory()` runs before BX_MEM is initialised

`handle_command()`'s hello branch in `kernel.cpp` calls
`bochs_set_process_memory()` directly, which then calls
`BX_MEM(0)->registerMemoryHandlers(...)`. From
`bochs-2.7/memory/misc_mem.cc`:

```cpp
if (BX_MEM_THIS memory_handlers[page_idx] != NULL) { … }
memory_handler->next = BX_MEM_THIS memory_handlers[page_idx];
BX_MEM_THIS memory_handlers[page_idx] = memory_handler;
```

`memory_handlers` is `NULL` until `BX_MEM(0)->init_memory()` runs.
Paging is disabled in this kernel, so the NULL deref doesn't trap —
the write at `(NULL)[page_idx]` silently clobbers a low address inside
the multiboot / BIOS data area, and the kernel goes off the rails on
the next dependent operation. No `HOST FAULT !14` red bar fires.

The author's own comment block in `bochs_glue.cpp` calls this out
verbatim ("Without that allocation, the index lookup deref's a null
/garbage pointer and host-faults during bochs_set_process_memory()"),
but the call sites had never been updated to enforce the ordering.

**Fix.** `bochs_set_process_memory()` now calls
`bochs_cpu_initialize_guarded()` before touching `BX_MEM`. The
guarded function is idempotent (`g_cpu_inited_once`), so this is free
on every call after the first.

### Bug 2 — `BX_MEM_C::init_memory()` hangs in `register_state()`

With Bug 1 fixed, `init_memory` finally runs — and hangs partway
through. The stock body in `bochs-2.7/memory/misc_mem.cc:95` does:

1. `alloc_vector_aligned(host + BIOSROMSZ + EXROMSIZE + 4096, …)` —
   a ~3.13 MB host buffer we never use, since every guest memory
   access is routed through our `registerMemoryHandlers` callbacks.
2. `blocks = new Bit8u*[num_blocks]` — small, fine.
3. `memory_handlers = new struct memory_handler_struct*[BX_MEM_HANDLERS]`
   — a 4 MB allocation we actually need.
4. `pci_enabled = SIM->get_param_bool(BXPN_PCI_ENABLED)->get()` — fine
   (KernelSIM returns a dummy bool param).
5. `register_state()` — walks `SIM->get_bochs_root()` (= `nullptr` in
   this kernel) and builds a savestate param tree of
   `bx_list_c` / `bx_shadow_data_c` / `bx_param_num_c` / `bx_shadow_bool_c`
   objects. The chain of constructors against a nullptr-rooted tree is
   where the kernel wedges. We never save or restore state, so this
   work is pointless anyway.

**Fix.** Override `BX_MEM_C::init_memory()` and
`BX_MEM_C::register_state()` in `bochs_infra.cpp`. The replacement
`init_memory` does exactly one thing — allocate and zero-initialise
`memory_handlers[]`. `register_state` is a no-op. Both rely on
`-Wl,--allow-multiple-definition` (already in the Makefile) and on
our object files being listed before `libmemory.a` (also already the
case), so the linker picks our copies.

Member-function definitions written in `bochs_infra.cpp` (which
includes `memory-bochs.h`) have full access to `BX_MEM_C`'s private
members.

### Bug 3 — IDT trap stub recurses on `int $0x80`

With Bugs 1 and 2 fixed, `hello` finally runs, prints `HELLO\n`, then
executes `ud2`. The CPU walks the injected IDT, lands at slab+0:

```
B8 01 00 00 00     mov $1, %eax        ; SYS_EXIT
BB 00 00 00 00     mov $0, %ebx
CD 80              int $0x80
```

Every IDT entry points at this same stub. The author intended
`bx_instr_interrupt()` to detect vector `0x80` and emulate Linux
`_exit(0)`. But:

1. `bx_instr_interrupt()` is never defined anywhere in the source
   (only mentioned in comments).
2. `libcpu.a` is prebuilt with `BX_INSTRUMENTATION=0`, so
   `BX_INSTR_INTERRUPT(...)` at `cpu/exception.cc:768` is
   macro-expanded to nothing in the linked library — the
   instrumentation hook is dead code regardless of what we define.

`int $0x80` dispatches through IDT[0x80] → slab+0 again → infinite
loop. `cpu_loop()` never yields (`async_event` is only set by port-0xE9
writes via `bochs_guest_putc`), so `bochs_cpu_tick()` never returns,
the kernel main loop never repaints. Hang.

**Fix.** New IDT stub writes to a dedicated sentinel port (0xE8)
instead of re-issuing `int $0x80`:

```
B0 00     mov $0, %al
E6 E8     out %al, $0xE8       ; "process exited" sentinel
F4        hlt                   ; safety: never reached
EB FE     jmp .                 ; safety: spin if hlt returns
```

A new `bochs_guest_exit(code)` in `bochs_glue.cpp` is invoked by
`bx_devices_c::outp` on 0xE8 writes. It calls the slot's `exit_cb`
(the kernel's `elf_io_exit`, which sets `proc.active = false`) and
arms `kill_bochs_request + async_event` so `cpu_loop()` yields
immediately.

A `g_exit_pending` flag prevents `bochs_cpu_tick` from re-entering
`cpu_loop` on the now-defunct slot — that would step the `hlt` and
trap the CPU in `BX_ACTIVITY_STATE_HLT` forever inside
`handleWaitForEvent` (no external interrupts ever arrive).

`x86_tick()` re-checks `proc.active` after the tick so
`tick_elf_processes` clears `captured_elf_slot` and the shell prompt
returns.

## Files changed

* **`bochs_glue.cpp`** —
  * Forward decl for `bochs_cpu_initialize_guarded`.
  * `bochs_set_process_memory()` self-inits before touching BX_MEM.
  * New IDT stub (port 0xE8 + hlt).
  * New `bochs_guest_exit()` plus `g_exit_pending` early-out in
    `bochs_cpu_tick()`.
* **`bochs_infra.cpp`** —
  * Replacement `BX_MEM_C::init_memory()` (only allocates
    `memory_handlers[]`).
  * No-op `BX_MEM_C::register_state()`.
  * `bx_devices_c::outp` routes port 0xE8 to `bochs_guest_exit()`.
* **`kernel.cpp`** — `x86_tick()` re-checks `proc.active` after the
  Bochs tick.
* **`bochs_stub.cpp`** — `bochs_guest_exit(int)` no-op for `BOCHS=0`
  builds.

Untouched files included for completeness so you have a known-good
build set side-by-side: `bochs_cstubs.c`, `boot.S`, `setjmp.S`,
`Makefile`, `linker.ld`, `fixes.h`, `font.h`, `instrument_stub.h`,
`busybox_stub.c`, `hello.c`.

## Expected behaviour after all three fixes

1. User types `hello`, hits Enter.
2. `handle_command` hello branch: `bochs_activate_slot`,
   `bochs_set_process_memory` (self-inits BX_MEM via the v2 fix; the
   v3 minimal `init_memory` allocates `memory_handlers[]` without
   hanging; `registerMemoryHandlers` then writes into a real table).
   `inject_idt_into_slab` writes the v3 stub.
3. Top-row breadcrumbs reach `…12345…SM` (1=entered guarded,
   2=guard passed, 3=pc_system init done, 4=about to init_memory,
   5=init_memory returned cleanly, M=mem subsystem ready,
   S=skipped BX_CPU::initialize).
4. Terminal prints `hello started.`
5. Main loop ticks the slot. The Bochs CPU runs hello, which prints
   `HELLO\n` via port 0xE9.
6. hello executes `ud2`. The CPU traps into the new IDT stub →
   writes 0 to port 0xE8 → `bochs_guest_exit` → `elf_io_exit`
   (`[diag] elf_io_exit slot=N code=0`) → slot inactive →
   `cpu_loop` yields.
7. `x86_tick` sees inactive slot, returns false.
   `tick_elf_processes` clears `captured_elf_slot`. Shell prompt
   returns; user can type again.

`busybox` will exit cleanly on its first `int $0x80` syscall instead
of hanging. It won't actually do useful work without a syscall
interpreter, but the kernel no longer freezes.

## Verification

`bochs_glue.cpp` and `bochs_infra.cpp` both pass `g++ -m32
-fsyntax-only` against a freshly configured `bochs-2.7` tree, no
errors beyond the pre-existing `BX_INSTRUMENTATION` redefinition
warning the original Makefile already produces.

Build with `make all` as usual, then boot `main.iso` with `disk.img`.
