# RTOS++ — QEMU Hang Fix (Round 2: with diagnostic overlay)

## Symptoms timeline

**Round 1 (original)**: Under QEMU, typing `hello` printed `"hello started."`
to the terminal, then the kernel froze completely — no VGA breadcrumbs at
columns 70/72/73, the green heartbeat at column 79 stopped spinning. Under
real Bochs the same flow worked.

**Round 1 patch attempt**: I (a) installed a host-side IDT in `boot.S` to
turn silent triple-faults into visible breadcrumbs, (b) made
`bochs_cpu_init()` idempotent so `BX_CPU::initialize()` runs at most once,
and (c) called `bochs_cpu_prewarm()` from `init_elf_system()` at boot to
surface init-time bugs early. *Result*: fixed the silent freeze on QEMU
in theory, but **broke VMware** — the early `BX_CPU::initialize()` triggered
a known PCI/SVGA path documented in the existing code at line 7576, where
VMware briefly unmaps SVGA BAR1 and a subsequent framebuffer write crashes
with `"execute an invalid part of memory"`.

**Round 2 (current)**: revert the prewarm call (it was unnecessary anyway —
the host IDT means we no longer need to "trip the bug at a known time").
Add a diagnostic overlay so VGA breadcrumbs are visible in graphics mode,
since the framebuffer otherwise hides VGA text. Add fine-grained
breadcrumbs in `x86_tick`'s lazy-init path so we can see exactly which
`bochs_*` call wedges. Add a host-fault visual: any host CPU fault now
paints a red bar at the top of the framebuffer with `"HOST FAULT !XX"`.

## What's in this drop

### Diagnostic infrastructure (always-on, additive)

#### `boot.S`
- 256-entry host-side IDT before calling `kernel_main`. Each vector
  pushes its number and jumps to a shared `isr_common` that:
  1. Writes `'!' + hex(vector)` to VGA text-mode row 1 cols 0-2 (red bg)
     — forensic, readable via QEMU `pmemsave 0xb8000 4096 vga.bin`.
  2. Calls C handler `host_fault_handler(vector)` which paints a bright
     red bar with `"HOST FAULT !XX"` at the top of the framebuffer.
  3. Halts forever (`cli; hlt`) — no resume.
- Multiboot `eax`/`ebx` saved to `.data` cells before being clobbered, so
  they survive the IDT-build / BSS-zero clobber and reach `kernel_main`.

#### `kernel.cpp`
- `host_fault_handler(unsigned vector)` — paints red bar +
  `"HOST FAULT !XX"`. Called from `boot.S isr_common`.
- `draw_vga_overlay()` — every frame, copies VGA text rows 0/1/2 onto the
  top 24 px of the framebuffer. Called just before `swap_buffers()`.
  Includes attribute-aware coloring: white-on-red attributes (panic,
  IDT) render as bright red.
- `x86_breadcrumb(col, char)` — writes both VGA text row 2 AND the live
  framebuffer (bypassing the back buffer so it survives a hang). 8
  breadcrumbs in `x86_tick`'s lazy-init: `L M I S E B T t`.
  - `L` = entered lazy init
  - `M` = `bochs_set_process_memory` returned
  - `I` = `bochs_cpu_init` returned
  - `S` = `bochs_cpu_set_esp` returned
  - `E` = `bochs_cpu_set_eip` returned
  - `B` = `bochs_set_brk` returned
  - `T` = about to call `bochs_cpu_tick`
  - `t` = `bochs_cpu_tick` returned
- Main loop reordered: `tick_elf_processes(100)` now runs **before** the
  paint+swap, so any breadcrumbs from this frame's tick are reflected in
  the paint that follows. (Old order was paint→swap→tick, which meant
  breadcrumbs trailed by one frame and were invisible if the *first*
  tick wedged.)

### Behaviour fix

#### `bochs_glue.cpp`
- `bochs_cpu_init()` is now **idempotent**: `BX_CPU::initialize()` runs
  at most once per boot, guarded by `g_cpu_inited_once`. Subsequent
  calls only do `reset(BX_RESET_HARDWARE)` + `enter_protected_mode()`.
  This prevents libcpu.a's CPUID parameter-tree registration from
  re-walking nullptr-rooted lists every launch.
- New exported `bochs_cpu_prewarm()` (currently unused but available
  if you want to force the one-shot init at a chosen time).

#### `bochs_stub.cpp`
- Added matching `bochs_cpu_prewarm()` no-op for `BOCHS=0` builds.

#### `kernel.cpp`
- `init_elf_system()` does **not** call prewarm (avoids the VMware
  regression). Lazy init in `x86_tick` is unchanged in shape.

## What you should see when you boot the new ISO

### Best case (everything works)
- Desktop comes up. Top-left of the framebuffer shows a thin black
  strip with the boot trail (`B S Z C` etc.) and the spinning heartbeat
  on the right edge.
- Type `hello`. Watch row 2 of the overlay — you should see
  `LMISEBTt` flash through. Then `'P'` or `'X'` should appear at row 0
  col 70 (red bg) when the guest's `ud2` triple-faults inside Bochs.
  `"HELLO\n"` prints to the terminal.
- Heartbeat keeps spinning. Kernel is alive.

### Diagnostic case 1: host fault
- Top of framebuffer goes solid red with `"HOST FAULT !XX"`.
- `XX` tells you the vector:
  - `!0E` = `#PF` (page fault) — most likely, suggests a null deref
    inside libcpu.a code.
  - `!0D` = `#GP` (general protection) — bad segment access.
  - `!06` = `#UD` (undefined opcode) — corrupted instruction stream.
  - `!08` = `#DF` (double fault) — chained faults; very bad.
- The kernel halts after this. **You won't see any further desktop
  updates** but the red bar is durable and pinpoints exactly what
  faulted.

### Diagnostic case 2: silent hang
- Heartbeat dies, no red bar, but the row-2 overlay shows partial
  letters of `LMISEBTt`. The **last letter visible** tells you which
  call is hanging.
  - `L` only → `bochs_set_process_memory` is hanging (maybe a slab
    allocation issue).
  - `LM` → `bochs_cpu_init` is hanging — most likely `BX_CPU::initialize`
    (first call) or `BX_CPU::reset`.
  - `LMIS` → `bochs_cpu_set_eip` hangs (rare).
  - `LMISEB` → first frame paints fine but `bochs_cpu_tick` hangs in
    `cpu_loop`.
  - All of `LMISEBT` but no `t` → guest is running but `cpu_loop`
    never returns.

### Diagnostic case 3: silent freeze (no breadcrumbs)
- Heartbeat dies, no red bar, no row-2 letters at all.
- Means the hang happened inside the main paint loop itself, before
  `tick_elf_processes` was reached. Possibly inside `swap_buffers` or
  elsewhere. Less likely.

## How to build

```bash
# Prerequisites (Ubuntu/Debian):
apt-get install -y \
    build-essential gcc-multilib g++-multilib \
    grub-pc-bin grub-common xorriso mtools \
    qemu-system-x86 wget python3

make -j$(nproc) iso     # produces main.iso
make run                # boots it under QEMU
```

The first build downloads `bochs-2.7.tar.gz` and the busybox i686 binary.
Subsequent builds skip the download.

## Files changed

- `boot.S`            — IDT, ISR stubs, host_fault_handler call, multiboot save
- `bochs_glue.cpp`    — split `bochs_cpu_init` into one-shot + per-launch
- `bochs_stub.cpp`    — added `bochs_cpu_prewarm` no-op
- `kernel.cpp`        — host_fault_handler, draw_vga_overlay, x86_breadcrumb,
                        main-loop reorder; **no** prewarm at boot

## What to send me next

Boot the patched ISO under QEMU, type `hello`, and tell me what you see.
The new diagnostics will pinpoint the failure precisely:

- "Red bar with HOST FAULT !XX" → tell me XX, that's a CPU vector
  number I can map back to the libcpu.a call site.
- "Letters L M I S E B T t at row 2-ish" → tell me how far they got.
  The last letter visible names the failing function.
- "Nothing visible, heartbeat dead" → likely outside Bochs entirely.
