# OS-main-full — patches already applied

This is a **drop-in replacement** for your `OS-main/` source tree:

- `kernel.cpp` — patched (matrix store, recurse, hello, desktop launchers, help text)
- `matrix_array.h` — header-only persistent array store (NumPy-style + GEMM)
- `desktop_suite/` — Clock, Calculator, Paint, Snake, Minesweeper, System
  Monitor, Matrix Inspector, About apps + launcher
- `Makefile` — unchanged

## To use

1. Backup your existing `OS-main/`.
2. Copy these files over the top — `kernel.cpp`, `matrix_array.h`,
   and `desktop_suite/` (folder) all sit in the `OS-main/` root.
3. Build:

   ```
   make clean && make BOCHS=1
   qemu-system-i386 -M q35 -m 2048M -vga std \
     -drive id=cd0,file=main.iso,format=raw,if=none,media=cdrom \
     -drive id=disk0,file=disk.img,format=raw,if=none \
     -device ahci,id=ahci \
     -device ide-cd,drive=cd0,bus=ahci.0 \
     -device ide-hd,drive=disk0,bus=ahci.1 \
     -boot d
   ```

4. From the terminal:

   ```
   help                 # full command list
   clock                # analog + digital clock window
   calc                 # calculator
   paint                # pixel paint (Tab = brush size, c = clear)
   snake                # space to start, arrows or WASD
   mines                # left-click reveal, right-click flag, n=new
   monitor              # CPU/RAM/uptime dashboard
   inspector            # visual matrix inspector
   about                # about dialog window
   launch <app>         # generic launcher

   hello                # bochs hello (one word)
   recurse 6            # the recursive-Bochs gag from the screenshot

   matrix create A 8 8  # create persistent array A.npa
   matrix create B 8 8
   matrix gemm A B C    # blocked GEMM into C.npa
   matrix show C        # print the result grid
   matrix perms C r---  # strip W → next gemm to C is denied
   ```

## What changed inside kernel.cpp

Search for "MATRIX ARRAY STORE + DESKTOP SUITE" to find the include
block (just before `class TerminalWindow`). Search for "PATCH: matrix
array store + desktop suite commands" to find the new `else if`
handlers inside `handle_command()`. Search for "NpaPrint adapter" to
find the small helper function after `class TerminalWindow` closes.

## Caveats / further work

- `SystemMonitorWindow::read_cpu_load_pct()` and friends are synthetic
  stubs — swap to your real scheduler/heap counters when convenient.
- `MinesweeperWindow` uses your existing `on_mouse_right_click` route
  for flags; press `F` to toggle flag-mode for left clicks if right-
  click isn't wired in your input loop.
- `matrix list` probes a fixed name set (A..F.npa). Lift your `ls`
  command's FAT32 dir iterator into a helper for a true listing.
- `recurse` is capped at 10 to keep room under `MAX_ELF_PROCESSES`.
