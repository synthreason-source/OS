#pragma once
// 11_kernel_main.h
// Hardware bring-up, the framebuffer probe, and kernel_main() --
// the kernel's actual entry point.
// Extracted from kernel.cpp (original lines 9360-10540) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.


// =============================================================================
// KERNEL MAIN - ATOMIC FRAME RENDERING
// =============================================================================



struct BochsCPURegs {
    uint32_t eax, ebx, ecx, edx, esi, edi, esp, ebp;
};

// Forward decls for I/O callback adapters defined just below.
static int  elf_io_read (int slot);
static void elf_io_write(int slot, char c);
static void elf_io_exit (int slot, int code);

// Replace init_elf_system() call in kernel_main with:
void init_elf_system() {
    for (auto& p : elf_processes) {
        p.active          = false;
        p.cpu_initialized = false;
        p.in_head  = p.in_tail  = 0;
        p.out_head = p.out_tail = 0;
    }
    // Register IO callbacks for every slot. These are what make
    // port-0xE9 writes from the guest reach the terminal: the chain is
    //   guest: out 0xE9, al
    //   -> bx_devices_c::outp (bochs_infra.cpp)
    //   -> bochs_guest_putc   (bochs_glue.cpp)
    //   -> write_cb = elf_io_write
    //   -> push_output(slot, c)
    //   -> tick_elf_processes drains it to terminal->console_print
    for (int s = 0; s < MAX_ELF_PROCESSES; ++s) {
        bochs_register_io_callbacks(s, elf_io_read, elf_io_write, elf_io_exit);
    }
    // NOTE: bochs_cpu_init() is NOT called here.
    //
    // We tried calling bochs_cpu_prewarm() (a guarded BX_CPU::initialize)
    // here to surface init-time bugs early, but it triggered the VMware
    // BAR1-unmap path documented at the top of vmware_svga_init(), causing
    // VMware to die with "execute an invalid part of memory". The early
    // call was unnecessary anyway: the host IDT installed in boot.S means
    // a host fault inside BX_CPU::initialize() during lazy init now
    // produces a visible "!XX" breadcrumb at VGA row 1 instead of a
    // silent triple fault.
    //
    // Init runs lazily on the first ELF launch via x86_tick. The
    // bochs_cpu_init() guard added in bochs_glue.cpp ensures
    // BX_CPU::initialize() runs at most once per boot regardless of how
    // many times the kernel calls bochs_cpu_init().
}
// I/O callback adapters
static int  elf_io_read (int slot) { return pop_input(slot); }
static void elf_io_write(int slot, char c) { push_output(slot, c); }
static void elf_io_exit (int slot, int code) {
    if (slot >= 0 && slot < MAX_ELF_PROCESSES) {
        // DIAGNOSTIC: report the exit code (now the real fault vector
        // number, per the per-vector stub change in inject_slab_tables).
        // The buffer is zero-initialized this time, unlike the old
        // disabled version this comment used to warn about.
        char buf[64] = {0};
        snprintf(buf, sizeof(buf), "\n[guest exit, code=%d]\n", code);
        console_print(buf);

        elf_processes[slot].completed = true;
        elf_processes[slot].active    = false;
    }
}static void dbg(const char* s) { /* write to VGA or terminal */ }
// Minimal ELF execution path for Bochs-backed processes.
// Assumes your existing kernel includes/types/helpers are already present.


static inline unsigned int align_down(unsigned int v, unsigned int a) {
    return v & ~(a - 1);
}

static inline unsigned int align_up(unsigned int v, unsigned int a) {
    return (v + a - 1) & ~(a - 1);
}

static bool load_elf_image_to_slab(
    int slot,
    const unsigned char* elf,
    unsigned int elf_size,
    unsigned int& entry_out)
{
    if (elf_size < 52) return false;
    if (!(elf[0] == 0x7f && elf[1] == 'E' && elf[2] == 'L' && elf[3] == 'F')) return false;
    if (elf[4] != 1 || elf[5] != 1) return false;

    auto rd16 = [&](unsigned int off) -> unsigned short {
        return (unsigned short)(elf[off] | (elf[off + 1] << 8));
    };
    auto rd32 = [&](unsigned int off) -> unsigned int {
        return (unsigned int)(elf[off] |
                              (elf[off + 1] << 8) |
                              (elf[off + 2] << 16) |
                              (elf[off + 3] << 24));
    };

    unsigned short phoff = rd32(28);
    unsigned short phentsize = rd16(42);
    unsigned short phnum = rd16(44);
    unsigned int entry = rd32(24);

    if (phoff == 0 || phentsize < 32 || phnum == 0) return false;

    unsigned int min_vaddr = 0xFFFFFFFFu;
    unsigned int max_vaddr = 0;

    for (unsigned int i = 0; i < phnum; ++i) {
        unsigned int p = phoff + i * phentsize;
        if (p + 32 > elf_size) return false;

        unsigned int p_type = rd32(p + 0);
        if (p_type != 1) continue; // PT_LOAD

        unsigned int p_vaddr = rd32(p + 8);
        unsigned int p_memsz = rd32(p + 20);

        if (p_memsz == 0) continue;

        if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
        if (p_vaddr + p_memsz > max_vaddr) max_vaddr = p_vaddr + p_memsz;
    }

    if (min_vaddr == 0xFFFFFFFFu || max_vaddr <= min_vaddr) return false;

    unsigned int vaddr_base = align_down(min_vaddr, 0x1000);
    unsigned int vaddr_top = align_up(max_vaddr + ELF_STACK_SIZE + ELF_HEAP_SIZE, 0x1000);
    unsigned int slab_size = vaddr_top - vaddr_base;

    unsigned char* slab = elf_alloc_bytes(slab_size);
    if (!slab) return false;
    memset(slab, 0, slab_size);

    for (unsigned int i = 0; i < phnum; ++i) {
        unsigned int p = phoff + i * phentsize;
        if (p + 32 > elf_size) continue;

        unsigned int p_type = rd32(p + 0);
        if (p_type != 1) continue;

        unsigned int p_offset = rd32(p + 4);
        unsigned int p_vaddr  = rd32(p + 8);
        unsigned int p_filesz  = rd32(p + 16);
        unsigned int p_memsz   = rd32(p + 20);

        if (p_offset + p_filesz > elf_size) {
            elf_free_bytes(slab);
            return false;
        }

        unsigned int dest = p_vaddr - vaddr_base;
        if (dest + p_memsz > slab_size) {
            elf_free_bytes(slab);
            return false;
        }

        memcpy(slab + dest, elf + p_offset, p_filesz);
        if (p_memsz > p_filesz) {
            memset(slab + dest + p_filesz, 0, p_memsz - p_filesz);
        }
    }

    entry_out = entry;
    bochs_activate_slot(slot);
    bochs_set_process_memory(slab, slab_size, vaddr_base);
    bochs_finalize_process_memory();

    // Populate ElfProcess so that start_elf_process (and kill_elf_process)
    // can track and free this slab correctly.
    ElfProcess& proc = elf_processes[slot];
    proc.memory_base = slab;
    proc.memory_size = slab_size;
    proc.vaddr_base  = vaddr_base;
    proc.vaddr_end   = vaddr_top;

    return true;
}

static bool start_elf_process(int slot, const unsigned char* elf, unsigned int elf_size) {
    ElfProcess& proc = elf_processes[slot];
    unsigned int entry = 0;

    // load_elf_image_to_slab calls bochs_activate_slot + bochs_set_process_memory
    // and populates proc.memory_base / proc.memory_size / proc.vaddr_base.
    if (!load_elf_image_to_slab(slot, elf, elf_size, entry)) return false;

    proc.active = true;
    proc.completed = false;
    proc.entry_point = entry;

    // vaddr_base was set by load_elf_image_to_slab; don't clobber it with a
    // page-aligned guess derived from the entry point (those can differ for
    // PIE or non-zero-based binaries).
    unsigned int stack_top = proc.vaddr_base + proc.memory_size;
    proc.esp = stack_top - 16;
    proc.brk_addr = proc.vaddr_base + proc.memory_size - ELF_HEAP_SIZE;

    // Finish CPU wiring: init once, then point at entry.
    bochs_cpu_init();
    bochs_cpu_set_esp(proc.esp);
    bochs_cpu_set_eip(proc.entry_point);
    bochs_set_brk(slot, proc.brk_addr);

    // Mark cpu_initialized so x86_tick skips the lazy-init path and goes
    // straight to bochs_cpu_tick (we've done the full setup just above).
    proc.cpu_initialized = true;

    return true;
}

extern "C" volatile unsigned char bx_panic_breadcrumbs[64];
// ── Diagnostic breadcrumb at VGA row 2 ────────────────────────────────────
// Each x86_tick lazy-init step writes a tag char to row 2 columns 0..N.
// Tags are:
//   col 0: 'L'  — entered lazy init
//   col 1: 'M'  — set_process_memory returned
//   col 2: 'I'  — bochs_cpu_init returned
//   col 3: 'S'  — set_esp returned
//   col 4: 'E'  — set_eip returned
//   col 5: 'B'  — set_brk returned
//   col 6: 'T'  — about to call bochs_cpu_tick
//   col 7: 't'  — bochs_cpu_tick returned
// If lazy init wedges, the last tag visible tells you which call did it.
//
// We write to BOTH the VGA text-mode plane (forensic for pmemsave) AND
// directly to the live framebuffer (visible to the user even if the
// kernel never reaches swap_buffers again). Direct framebuffer writes
// bypass the back buffer and use fb_info.ptr; that means they survive
// a hang inside x86_tick that prevents the next paint cycle.
static inline void x86_breadcrumb(int col, char c) {
    if (col < 0 || col >= 80) return;

    // 1. VGA text-mode plane (forensic).
    {
        volatile unsigned short* p =
            (volatile unsigned short*)(0xB8000 + 2 * 80 + 2 * col);
        *p = (unsigned short)(0x0E00u | (unsigned char)c);
    }

    // 2. Live framebuffer (visible). 8x8 yellow glyph at row 2 of overlay.
    if (!fb_info.ptr) return;
    if ((unsigned char)c > 127) return;
    const uint8_t* glyph = font + (int)c * 8;
    int x0 = col * 8;
    int y0 = 16;          // row 2 of overlay (rows 0,1,2 each 8px tall)
    if (x0 + 8 > (int)fb_info.width)  return;
    if (y0 + 8 > (int)fb_info.height) return;

    uint32_t color = 0xFFFF55u;   // bright yellow
    uint32_t bg    = 0x000000u;
    for (int yy = 0; yy < 8; ++yy) {
        uint32_t* row = &fb_info.ptr[(y0 + yy) * (fb_info.pitch / 4) + x0];
        uint8_t bits = glyph[yy];
        for (int xx = 0; xx < 8; ++xx) {
            row[xx] = (bits & (0x80 >> xx)) ? color : bg;
        }
    }
}

static bool x86_tick(int slot, int steps) {
    ElfProcess& proc = elf_processes[slot];
    // Tick a process that is alive: active and NOT yet completed.
    // The previous form (`!proc.active || !proc.completed`) was inverted —
    // it returned for every live process, so the guest never advanced and
    // its port-0xE9 output never reached the terminal display.
    if (!proc.active || proc.completed) return false;

    if (!proc.cpu_initialized) {
        if (!proc.memory_base || proc.memory_size == 0) {
            proc.active    = false;
            proc.completed = true;
            return false;
        }
        // Correct init order:
        //   1. bochs_cpu_init()          -- global Bochs one-time init (idempotent)
        //   2. bochs_activate_slot()     -- select which slot g_active_slot points at
        //   3. bochs_set_process_memory  -- resets CPU to clean state, injects GDT/IDT/
        //                                   stub tables, then restores to protected mode
        //   4. set_esp / set_eip         -- point the protected-mode CPU at guest entry
        //
        // The previous order was: activate → set_memory → cpu_init.
        // bochs_set_process_memory does BX_CPU::reset() + slot_restore_cpu() to
        // arrive at protected mode. bochs_cpu_init() called *after* does another
        // BX_CPU::reset() — wiping that protected mode state back to real mode.
        // The guest then runs (or tries to) in real mode at a 32-bit EIP, which
        // either executes garbage or hangs inside cpu_loop with no visible output.
        x86_breadcrumb(0, 'L');
        bochs_cpu_init();
        x86_breadcrumb(1, 'I');
        bochs_activate_slot(slot);
        bochs_set_process_memory(proc.memory_base, proc.memory_size,
                                 proc.vaddr_base);
        x86_breadcrumb(2, 'M');
        bochs_cpu_set_esp(proc.esp);
        x86_breadcrumb(3, 'S');
        bochs_cpu_set_eip(proc.entry_point);
        x86_breadcrumb(4, 'E');
        bochs_set_brk(slot, proc.vaddr_base + proc.memory_size - ELFHEAPSIZE);
        x86_breadcrumb(5, 'B');
        proc.cpu_initialized = true;
    } else {
        bochs_activate_slot(slot);
    }

    x86_breadcrumb(6, 'T');

    // Diagnostic: snapshot EIP BEFORE tick so we can detect an unexpected
    // jump back to entry after the tick. (Don't enable unconditionally —
    // gated on the very-recent-restart condition below so normal output
    // isn't polluted.)
    uint32_t eip_before = bochs_cpu_get_eip();

bochs_cpu_tick(steps);
x86_breadcrumb(7, 't');

bool just_started_waiting =
    bochs_process_wants_input(slot) && in_empty(slot);

if (just_started_waiting) {
    proc.waiting_for_input = true;
    // The guest yielded mid-`IN` on port 0xE7. EIP isn't reliably
    // retired across that abort, so don't trust it this tick —
    // skip the exit/EIP-range checks below entirely and pick back
    // up cleanly next tick once real input has been pushed.
    return true;
}

// ─── FIX: detect clean guest-exit signal ──────────────────────────────
if (!proc.active || proc.completed) return false;

unsigned int eip = bochs_cpu_get_eip();
if (eip == 0 || eip < proc.vaddr_base || eip >= proc.vaddr_base + proc.memory_size) {
    proc.completed = true;
    proc.active    = false;
    return false;
}

return true;

    return true;
}
// And definition without default:
//
// FIX (focused app + mouse starved by background processes): this used
// to run x86_tick() for every active slot every single call, uniformly
// -- with only one guest program running (the common case) that's
// fine, but with two or more active at once (e.g. a background
// terminal still finishing a `run` while the user is actively using a
// different, focused window), every slot's CPU-emulation work and its
// bochs_activate_slot() context switch happened on EVERY iteration
// regardless of which window the user is actually looking at. That
// makes each iteration take longer in wall time, which in turn slows
// down how often the mouse gets polled/redrawn AND how often the
// focused app's own next frame lands -- both by exactly the same
// mechanism, since neither has a dedicated fast path independent of
// how long the shared main-loop iteration takes.
//
// `focus_slot` (the window manager's get_focused_elf_slot(), or -1 if
// nothing's focused) lets the caller say which slot the user is
// actually watching. The focused slot always executes, every call, in
// full -- it never gets deprioritized. Non-focused active slots take
// turns round-robin, at most one of them executing per call, so a
// background process still makes forward progress (just not at the
// cost of competing with the focused app on every single iteration).
// Passing -1 (or leaving it at the default) restores the original
// "tick everyone every call" behavior, which is also what happens
// naturally whenever 0 or 1 slots are active anyway.
//
// Deliberately NOT touched: output draining and exit/teardown handling
// below still run unconditionally for every active slot every call,
// same as before this fix. Only the x86_tick() call itself -- the
// actual CPU-emulation step -- is what gets skipped for a deprioritized
// slot this round. That keeps this change additive on top of logic
// this function's own comments describe as fragile, rather than
// touching it.
void tick_elf_processes(int steps, int focus_slot = -1) {
    bool any_exited_this_frame = false;

    // Pick this call's one "extra" (non-focused) slot to actually run,
    // round-robin across whichever active slots aren't the focused one.
    static int rr_cursor = 0;
    int chosen_background_slot = -1;
    if (focus_slot >= 0) {
        for (int k = 1; k <= MAX_ELF_PROCESSES; ++k) {
            int cand = (rr_cursor + k) % MAX_ELF_PROCESSES;
            if (cand == focus_slot) continue;
            if (elf_processes[cand].active && !elf_processes[cand].completed) {
                chosen_background_slot = cand;
                rr_cursor = cand;
                break;
            }
        }
    }

    for (int i = 0; i < MAX_ELF_PROCESSES; ++i) {
        ElfProcess& proc = elf_processes[i];
        // Drain output and step a process that is alive: active and not
        // completed. Inverting this gate (the old `!active || !completed`)
        // skipped every live process, leaving the terminal display silent
        // even though the Bochs guest had written bytes to port 0xE9.
        if (!proc.active || proc.completed) continue;

        while (!out_empty(i)) {
            char tmp[256];
            int n = 0;
            while (!out_empty(i) && n < 255) tmp[n++] = pop_output(i);
            tmp[n] = 0;
            if (proc.terminal && n) {
                proc.terminal->console_print(tmp);
                // Guest produced output. Flag the frame dirty so the main
                // loop actually repaints. Without this the repaint is
                // gated on g_evt_dirty / hasNewInput — both only set by
                // user input — so guest output sat invisibly in the
                // terminal buffer until the next keypress ("need to press
                // enter to print the last lot").
                g_evt_dirty = true;
            }
        }

        if (proc.waiting_for_input && in_empty(i)) continue;

        // Priority gate: skip the actual CPU-emulation step (but nothing
        // else -- output above and exit handling below still run) for a
        // non-focused, non-chosen-this-round slot. See the function
        // comment above for the full rationale.
        bool should_execute = (focus_slot < 0) || (i == focus_slot) || (i == chosen_background_slot);
        if (!should_execute) continue;

        bool running = x86_tick(i, steps);

        while (!out_empty(i)) {
            char tmp[256];
            int n = 0;
            while (!out_empty(i) && n < 255) tmp[n++] = pop_output(i);
            tmp[n] = 0;
            if (proc.terminal && n) {
                proc.terminal->console_print(tmp);
                g_evt_dirty = true;   // see note above
            }
        }

        if (!running) {
            proc.active = false;
            proc.completed = true;
            if (proc.terminal) proc.terminal->captured_elf_slot = -1;
            // A process just finished — the prompt needs to come back and
            // any final output needs to show. Repaint this frame.
            g_evt_dirty = true;

            // ── Per-slot kernel-side teardown ────────────────────────
            // Free the slab and stack we allocated in load_and_execute_elf,
            // and clear cpu_initialized so the NEXT process that lands in
            // this slot re-runs the lazy-init path from scratch.
            //
            // We do NOT touch the Bochs glue here. The glue side gets a
            // single heavy `bochs_reset_all_slots()` call at the end of
            // this function (see below) — that wipes every per-slot
            // mapping AND hardware-resets BX_CPU(0), so launch N starts
            // from the same state as launch 1. Trying to keep the glue
            // "incrementally consistent" with surgical per-slot updates
            // had a long history of subtle bugs (the second `bochs hello`
            // looping "HELLO WOHELLO WO..." because some untracked CPU
            // field survived across slot reuse). The big-hammer reset
            // is cheap and unambiguous.
            //
            // EXCEPTION (added for concurrent processes): if any OTHER
            // slot is still active, bochs_reset_all_slots() below will
            // be SKIPPED (resetting the live CPU would clobber that
            // peer's mid-execution state). In that case we still need
            // to clear THIS slot's mapping and dangling mem_base pointer
            // before freeing the slab — otherwise the glue carries
            // forward a dangling pointer that could be dereferenced on
            // a future activate_slot. bochs_release_slot does that
            // surgically without touching peer slots or BX_CPU(0).
            // It's safe to call unconditionally: when the all-slots
            // reset path also fires below, release_slot's wipe is
            // simply overwritten by the same values via reset_all_slots.
            bochs_release_slot(i);
            if (proc.memory_base) { elf_free_bytes(proc.memory_base); proc.memory_base = nullptr; }
            if (proc.stack)       { elf_free_bytes(proc.stack);       proc.stack       = nullptr; }
            proc.memory_size     = 0;
            proc.cpu_initialized = false;

            // ── Wipe per-slot I/O ring buffers and transient flags ──
            // Belt-and-braces companion to the scrub in
            // load_and_execute_elf: cleared HERE on the exit edge so
            // the slot is left in a strictly-empty state the instant
            // the process becomes inactive. If any code path on the
            // next frame reads from inbuf/outbuf before the next
            // load_and_execute_elf runs (e.g. a stray
            // tick_elf_processes pass on a slot whose `completed`
            // flag flipped but whose `active` flag hasn't been
            // re-set yet), it sees a clean empty queue rather than
            // stale bytes from the run that just ended.
            //
            // Without this, the third in-place run of `hello` in the
            // same emulator window produced "HELLO WOHELLO WO..."
            // loops with leftover keystrokes from previous runs
            // bleeding into the new guest's stdin and the previous
            // guest's tail-end output bleeding into the new
            // terminal display.
            for (int _b = 0; _b < INBUFSIZE;  ++_b) proc.inbuf[_b]  = 0;
            for (int _b = 0; _b < OUTBUFSIZE; ++_b) proc.outbuf[_b] = 0;
            proc.in_head           = 0;
            proc.in_tail           = 0;
            proc.out_head          = 0;
            proc.out_tail          = 0;
            proc.waiting_for_input = false;
            proc.exit_code         = 0;
            proc.input_pos         = 0;

            any_exited_this_frame = true;
        }
    }

    // ── Deferred glue-wide reset ────────────────────────────────────
    // If any process exited this frame AND no other Bochs-emulated
    // process is still running, wipe Bochs's glue state back to its
    // post-boot baseline. The next launch will then start from the
    // same state as launch #1.
    //
    // CRITICAL: do NOT reset while another slot is still running.
    // bochs_reset_all_slots() unmaps every slab and hardware-resets
    // BX_CPU(0); doing that to a live slot drops its EIP/CRs/segments
    // back to the post-reset state. On the very next frame, x86_tick
    // would re-enter the lazy-init path and bochs_cpu_set_eip would
    // restart the guest from _start. The visible symptom is a runaway
    // window spamming "HELLO WOHELLO WO..." for as long as another
    // window is finishing — exactly because every frame's exit on
    // window B triggered a reset that restarted window A from the top.
    if (any_exited_this_frame) {
        // Only wipe the Bochs glue when ALL slots are done AND all
        // output has been drained. Use two separate loops: the old
        // single-loop version broke out early on the first active slot,
        // so any_output_pending was never checked for remaining slots.
        bool any_still_active   = false;
        bool any_output_pending = false;
        for (int j = 0; j < MAX_ELF_PROCESSES; ++j) {
            if (elf_processes[j].active) { any_still_active = true; break; }
        }
        if (!any_still_active) {
            for (int j = 0; j < MAX_ELF_PROCESSES; ++j) {
                if (!out_empty(j)) { any_output_pending = true; break; }
            }
        }
        if (!any_still_active && !any_output_pending) {
            bochs_reset_all_slots();
        }
    }
     
}

extern "C" void cmd_exec(const char* code_text) {
    if (!code_text) return;
    TCompiler C;
    int ok = C.compile(code_text);
    if (ok < 0) return;
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (!exec_contexts[i].active) {
            exec_contexts[i].active = true;
            exec_contexts[i].exec_id = i;
            exec_contexts[i].prog = C.pr;
            const char* av[] = {"exec", nullptr};
            exec_contexts[i].vm.start_execution(exec_contexts[i].prog,1,av,0,0,nullptr);
            return;
        }
    }
}
// =============================================================================
// Helper: write a short status string to VGA text mode row 1 (safe at any
// point in kernel_main, before framebuffer is initialised).
// =============================================================================
// Write msg to VGA text row (0-based)
static void vga_dbg_row(int row, const char* msg, uint8_t attr = 0x0F) {
    volatile uint16_t* vga = (volatile uint16_t*)0xB8000 + row * 80;
    int i = 0;
    for (; i < 79 && msg[i]; i++)
        vga[i] = (uint16_t)((uint16_t)(attr << 8) | (uint8_t)msg[i]);
    for (; i < 79; i++)
        vga[i] = (uint16_t)((uint16_t)(attr << 8) | ' ');
}

static void vga_status(const char* msg, uint8_t attr = 0x0F) {
    vga_dbg_row(1, msg, attr);
}

// Write a 32-bit hex value into buf[11] and return it
static char* hex32(uint32_t v, char* buf) {
    const char* h = "0123456789ABCDEF";
    buf[0]='0'; buf[1]='x';
    for (int i = 7; i >= 0; i--) { buf[2+i] = h[v & 0xF]; v >>= 4; }
    buf[10] = 0;
    return buf;
}

// Concatenate up to 6 strings into dst[128]
static char* vga_cat(char* dst, const char* a, const char* b="",
                      const char* c="", const char* d="") {
    char* p = dst;
    auto app = [&](const char* s){ while(*s && p < dst+127) *p++=*s++; };
    app(a); app(b); app(c); app(d);
    *p = 0; return dst;
}

// =============================================================================
// Framebuffer probe — four strategies, always returns something safe.
// =============================================================================
static void probe_framebuffer(multiboot_info* mbi,
                              uint32_t& fb_phys,
                              uint32_t& fb_w,
                              uint32_t& fb_h,
                              uint32_t& fb_pitch)
{
    fb_phys  = 0;
    fb_w     = 1024;
    fb_h     = 768;
    fb_pitch = 1024 * 4;

    // Diagnostic: show multiboot flags and framebuffer fields on VGA rows 2-4
    {
        char dbuf[128]; char hb[11];
        vga_dbg_row(2, vga_cat(dbuf, "MB flags=", hex32(mbi->flags, hb)), 0x0E);
        uint32_t raw_fb = (uint32_t)(uintptr_t)mbi->framebuffer_addr;
        char hb2[11];
        vga_dbg_row(3, vga_cat(dbuf, "FB addr=", hex32(raw_fb, hb),
                           " type=", hex32(mbi->framebuffer_type, hb2)), 0x0E);
        vga_dbg_row(4, vga_cat(dbuf, "FB w=", hex32(mbi->framebuffer_width, hb),
                           " h=", hex32(mbi->framebuffer_height, hb2)), 0x0E);
    }

    // Strategy 1: GRUB filled framebuffer fields (our boot.S requests this
    // via MB_FLAGS bit 2).  This is the normal path on QEMU + GRUB 2.
    // framebuffer_type: 0=indexed, 1=RGB/direct, 2=EGA text — only accept 1.
    if (mbi->flags & (1u << 12)) {
        uint32_t addr = (uint32_t)(uintptr_t)mbi->framebuffer_addr;
        char dbuf[128]; char hb[11];
        vga_dbg_row(5, vga_cat(dbuf, "S1: addr=", hex32(addr, hb),
                           " type=", hex32(mbi->framebuffer_type, hb)), 0x0A);
        // Accept type 1 (RGB direct) or type 0 (indexed/paletted reported by
        // some VMware GRUB configs). Reject type 2 (EGA text mode).
        if (addr >= 0x1000000u && mbi->framebuffer_type != 2) {
            fb_phys  = addr;
            fb_w     = mbi->framebuffer_width;
            fb_h     = mbi->framebuffer_height;
            fb_pitch = mbi->framebuffer_pitch;
            if (fb_w  > 1024) { fb_w  = 1024; fb_pitch = 1024*4; }
            if (fb_h  > 768)  { fb_h  = 768; }
            vga_dbg_row(5, "S1: SUCCESS - using GRUB framebuffer", 0x0A);
            return;
        }
        vga_dbg_row(5, "S1: SKIPPED (bad addr or type!=1)", 0x0E);
    } else {
        vga_dbg_row(5, "S1: SKIPPED (bit12 not set in flags)", 0x0E);
    }

    // Strategy 2: Bochs VBE ports (QEMU -vga std).
    {
        auto vbe_out = [](uint16_t idx, uint16_t val) {
            asm volatile("outw %0,%1" :: "a"(idx), "d"((uint16_t)0x01CE));
            asm volatile("outw %0,%1" :: "a"(val), "d"((uint16_t)0x01CF));
        };
        auto vbe_in = [](uint16_t idx) -> uint16_t {
            uint16_t v;
            asm volatile("outw %0,%1" :: "a"(idx), "d"((uint16_t)0x01CE));
            asm volatile("inw %1,%0"  : "=a"(v)   : "d"((uint16_t)0x01CF));
            return v;
        };
        vbe_out(0x04, 0x00);
        uint16_t id = vbe_in(0x00);
        if (id >= 0xB0C0) {
            vbe_out(0x01, 1024);
            vbe_out(0x02, 768);
            vbe_out(0x03, 32);
            vbe_out(0x05, 1024);
            vbe_out(0x06, 768);
            vbe_out(0x07, 0);
            vbe_out(0x08, 0);
            vbe_out(0x04, 0x41); // ENABLE | LFB_ENABLED
            for (uint16_t bus = 0; bus < 8 && !fb_phys; bus++) {
                for (uint8_t dev = 0; dev < 32 && !fb_phys; dev++) {
                    uint32_t vd = pci_read_config_dword(bus, dev, 0, 0x00);
                    if ((vd & 0xFFFF) == 0xFFFF) continue;
                    bool is_bochs   = (vd == 0x11111234u);
                    uint32_t cc     = pci_read_config_dword(bus, dev, 0, 0x08) >> 16;
                    bool is_display = (cc == 0x0300 || cc == 0x0380);
                    if (!is_bochs && !is_display) continue;
                    for (int b = 0; b < 3 && !fb_phys; b++) {
                        uint32_t bar = pci_read_config_dword(bus, dev, 0, 0x10 + b*4);
                        if (bar & 1) continue;
                        uint32_t addr = bar & 0xFFFFFFF0u;
                        if (addr >= 0x1000000u) fb_phys = addr;
                    }
                }
            }
            if (fb_phys) return;
        }
    }

    // Strategy 3: VMware SVGA II (vendor 0x15AD, device 0x0405).
    // The SVGA II adapter uses an I/O BAR (BAR0) for its index/value register
    // pair and a memory BAR (BAR1) for the linear framebuffer.  It must be
    // programmed via I/O ports to set the resolution and enable the FB;
    // simply reading BAR1 is not enough — the FB is not live until ENABLE=1.
    //
    // SVGA II register map (index written to io_base+0, value at io_base+1):
    //   SVGA_REG_ID       = 0   write SVGA_MAGIC|2 to negotiate version
    //   SVGA_REG_ENABLE   = 1   write 1 to enable SVGA mode
    //   SVGA_REG_WIDTH    = 2
    //   SVGA_REG_HEIGHT   = 3
    //   SVGA_REG_BPP      = 7   (bits per pixel)
    //   SVGA_REG_FB_START = 13  returns the physical FB base address
    //   SVGA_REG_PITCH    = 24  returns bytes per scan line
    {
        // Locate the SVGA II PCI device
        uint16_t svga_io = 0;
        uint32_t svga_fb_bar = 0;
        for (uint16_t bus = 0; bus < 8 && !svga_io; bus++) {
            for (uint8_t dev = 0; dev < 32 && !svga_io; dev++) {
                uint32_t vd = pci_read_config_dword(bus, dev, 0, 0x00);
                // VMware vendor 0x15AD, SVGA II device 0x0405
                if (vd != 0x040515ADu) continue;
                // BAR0 = I/O port base (bit 0 set = I/O space)
                uint32_t bar0 = pci_read_config_dword(bus, dev, 0, 0x10);
                if (bar0 & 1) svga_io = (uint16_t)(bar0 & 0xFFFE);
                // BAR1 = framebuffer memory base
                svga_fb_bar = pci_read_config_dword(bus, dev, 0, 0x14) & 0xFFFFFFF0u;

                // Enable PCI memory + I/O decode (command register, offset 4)
                uint32_t cmd = pci_read_config_dword(bus, dev, 0, 0x04);
                cmd |= 0x03; // I/O + Memory enable
                // pci_write_config_dword not available, use outl directly
                uint32_t addr_reg = 0x80000000u | ((uint32_t)bus << 16) |
                                    ((uint32_t)dev << 11) | 0x04u;
                outl(0xCF8, addr_reg);
                outl(0xCFC, cmd);
            }
        }

        {
            char dbuf[128]; char hb[11]; char hb2[11];
            vga_dbg_row(6, vga_cat(dbuf, "S3: io=", hex32(svga_io, hb),
                               " bar1=", hex32(svga_fb_bar, hb2)), 0x0A);
        }

        if (svga_io) {
            // Helper lambdas for SVGA II register access
            auto svga_write = [&](uint32_t reg, uint32_t val) {
                outl((uint16_t)(svga_io + 0), reg); // index port
                outl((uint16_t)(svga_io + 4), val); // value port
            };
            auto svga_read = [&](uint32_t reg) -> uint32_t {
                outl((uint16_t)(svga_io + 0), reg);
                return inl((uint16_t)(svga_io + 4));
            };

            // Negotiate SVGA II version (SVGA_ID_2 = 0x90000002)
            svga_write(0 /*SVGA_REG_ID*/, 0x90000002u);
            uint32_t id = svga_read(0);
            { char dbuf[128]; char hb[11];
              vga_dbg_row(7, vga_cat(dbuf, "S3: SVGA_ID=", hex32(id, hb)), 0x0A); }

            if (id == 0x90000002u) {
                // Set 1024x768x32
                svga_write(2 /*SVGA_REG_WIDTH*/,  1024);
                svga_write(3 /*SVGA_REG_HEIGHT*/,  768);
                svga_write(7 /*SVGA_REG_BITS_PER_PIXEL*/, 32);
                svga_write(1 /*SVGA_REG_ENABLE*/,  1);

                // Read back actual FB address and pitch
                uint32_t reported_fb = svga_read(13 /*SVGA_REG_FB_START*/);
                uint32_t pitch       = svga_read(24 /*SVGA_REG_BYTES_PER_LINE*/);

                { char dbuf[128]; char hb[11]; char hb2[11];
                  vga_dbg_row(8, vga_cat(dbuf, "S3: fb=", hex32(reported_fb, hb),
                                     " pitch=", hex32(pitch, hb2)), 0x0A); }

                // Use the reported address if valid, fall back to BAR1
                fb_phys  = (reported_fb >= 0x1000000u) ? reported_fb : svga_fb_bar;
                fb_w     = 1024;
                fb_h     = 768;
                fb_pitch = (pitch >= 1024*4) ? pitch : 1024*4;
                if (fb_phys >= 0x1000000u) {
                    vga_dbg_row(9, "S3: SUCCESS - VMware SVGA II programmed", 0x0A);
                    return;
                }
                vga_dbg_row(9, "S3: FAILED - fb addr still bad", 0x4F);
            } else {
                vga_dbg_row(7, "S3: FAILED - wrong SVGA_ID (not VMware?)", 0x4F);
            }
        } else {
            vga_dbg_row(6, "S3: SKIPPED - no SVGA II device found on PCI", 0x0E);
        }
    }

    // Strategy 4: hardcoded fallback.
    // 0xFD000000 = Bochs/QEMU default.
    // 0xE8000000 = VMware Workstation SVGA II BAR1 (confirmed from vmware.log).
    // vmware_svga_init() runs before probe_framebuffer and will override this
    // with the correct BAR1 address, so this fallback is only for QEMU/Bochs.
    fb_phys = 0xFD000000u;
}

// =============================================================================
// kernel_main
// =============================================================================
// ─────────────────────────────────────────────────────────────────────────────
// VMware SVGA II initialisation.
// Must run BEFORE any framebuffer access.  Returns the live FB base address,
// or 0 if no SVGA II device is found.
//
// The SVGA II I/O port pair lives at BAR0 (an I/O BAR):
//   index port = BAR0 + 0
//   value port = BAR0 + 4        (NOT +1 — the value port is 32-bit wide)
// Register indices used here:
//   0  SVGA_REG_ID              write 0x90000002 to negotiate SVGA2
//   1  SVGA_REG_ENABLE          write 1 to enable linear framebuffer
//   2  SVGA_REG_WIDTH
//   3  SVGA_REG_HEIGHT
//   7  SVGA_REG_BITS_PER_PIXEL
//  13  SVGA_REG_FB_START        read to get physical FB address
//  24  SVGA_REG_BYTES_PER_LINE  read to get pitch in bytes
// ─────────────────────────────────────────────────────────────────────────────
struct SVGAResult { uint32_t fb; uint32_t pitch; bool ok; };

// ── VMware SVGA II: full PCI scan + I/O programming ──────────────────────────
// Scans ALL 256 PCI buses (some VMware configs place SVGA on bus > 7),
// all 32 devices, all 8 functions.  Tries both device IDs 0x0405 and 0x0710.
// The I/O BAR may be at BAR0 or BAR2 depending on SVGA revision.
static SVGAResult vmware_svga_init(uint32_t w, uint32_t h) {
    SVGAResult r = {0, w*4, false};

    uint16_t io   = 0;
    uint32_t bar1 = 0;

    // Full PCI scan — VMware may put the SVGA on any bus
    for (uint32_t bus = 0; bus < 256 && !io; bus++) {
        for (uint32_t dev = 0; dev < 32 && !io; dev++) {
            for (uint32_t fn = 0; fn < 8 && !io; fn++) {
                uint32_t id = pci_read_config_dword(
                    (uint16_t)bus, (uint8_t)dev, (uint8_t)fn, 0x00);
                if ((id & 0xFFFFu) != 0x15ADu) continue; // not VMware vendor
                uint32_t did = (id >> 16) & 0xFFFFu;
                if (did != 0x0405u && did != 0x0710u) continue; // not SVGA

                // DO NOT touch the PCI command register.
                // The BIOS has already enabled I/O + Memory decode for SVGA.
                // Re-writing the command register causes VMware to briefly
                // unmap BAR1 (0xe8000000), creating a window where pixel
                // writes crash with "execute an invalid part of memory".

                // Read all 6 BARs — find the I/O BAR and the memory BAR
                for (int b = 0; b < 6; b++) {
                    uint32_t bar = pci_read_config_dword(
                        (uint16_t)bus, (uint8_t)dev, (uint8_t)fn,
                        (uint8_t)(0x10 + b*4));
                    if ((bar & 1u) && !io) {
                        io = (uint16_t)(bar & 0xFFFCu); // I/O BAR
                    } else if (!(bar & 1u) && !bar1) {
                        uint32_t addr = bar & 0xFFFFFFF0u;
                        if (addr >= 0x1000000u) bar1 = addr; // memory BAR
                    }
                }
            }
        }
    }

    // Also try the fixed legacy SVGA I/O port (0x4560) used by very old VMware
    if (!io) io = 0x4560u;

    // I/O helpers
    auto wr = [&](uint32_t reg, uint32_t val) {
        outl(io,     reg);
        outl(io + 4, val);
    };
    auto rd = [&](uint32_t reg) -> uint32_t {
        outl(io, reg);
        return inl(io + 4);
    };

    // Negotiate SVGA2 — try SVGA_ID_2, fall back to SVGA_ID_1
    wr(0, 0x90000002u);
    uint32_t svga_id = rd(0);
    if (svga_id != 0x90000002u) {
        wr(0, 0x90000001u);
        svga_id = rd(0);
        if (svga_id != 0x90000001u) return r; // not responding
    }

    // Program resolution
    wr(2, w);
    wr(3, h);
    wr(7, 32);

    // Enable
    wr(1, 1);

    // Read FB address and pitch.
    // VMware Workstation 14+ returns 0 from SVGA_REG_FB_START (reg 13) —
    // the physical framebuffer is always at BAR1. Prefer BAR1 when valid.
    uint32_t fb    = rd(13);
    uint32_t pitch = rd(24);

    if (bar1 >= 0x1000000u) fb = bar1;  // BAR1 is authoritative on VMware
    else if (fb < 0x1000000u) fb = bar1;
    if (pitch < w * 4) pitch = w * 4;

    r.fb    = fb;
    r.pitch = pitch;
    r.ok    = (fb >= 0x1000000u);
    return r;
}


// Sticky click-edge latches for the guest mouse ABI (bochs_drivers.h's
// mouse_poll()). Set in the main loop below whenever mouse_left_down /
// mouse_right_down transitions from up to down; cleared only once
// kernel_gfx_mouse_poll() (defined further down, called from
// bochs_glue.cpp's bochs_guest_mouse_poll()) has actually reported the
// click to whichever guest program is the focused window's own ELF
// process. File scope (not a kernel_main local) because
// kernel_gfx_mouse_poll() needs to reach them from outside the loop.
static bool g_gfx_click_left_pending  = false;
static bool g_gfx_click_right_pending = false;

extern "C" void kernel_main(uint32_t magic, uint32_t multiboot_addr) {

    // ── Verify Multiboot 1 magic FIRST, before any hardware probing ───────────
    // If GRUB (or whatever bootloader) didn't pass 0x2BADB002, we are running
    // under something that doesn't honour the contract — bail out cleanly
    // instead of poking PCI / FB hardware on bad assumptions.
    if (magic != 0x2BADB002) {
        volatile uint16_t* vga = (volatile uint16_t*)0xB8000;
        vga[0] = 0x4F45; // 'E' on red — "bad magic"
        for (;;)
            asm volatile("hlt");
    }

    // ── Initialise heap ───────────────────────────────────────────────────────
    g_allocator.init(kernel_heap, sizeof(kernel_heap));

    // ── Step 1: unconditionally try VMware SVGA II first. ─────────────────────
    // This MUST happen before reading any framebuffer address because the
    // linear FB is not live until ENABLE=1 is written.
    SVGAResult svga = vmware_svga_init(1024, 768);

    // ── Step 2: determine framebuffer address ────────────────────────────────
    multiboot_info* mbi = (multiboot_info*)multiboot_addr;

    if (svga.ok) {
        // VMware SVGA II programmed successfully — use its reported address.
        // Wait for VMware to complete the MemSpace re-registration after ENABLE=1.
        // The log shows VMware briefly unmaps/remaps 0xe8000000 during SVGA init;
        // a short spin ensures the mapping is live before we write pixels.
        for (volatile uint32_t i = 0; i < 5000000u; i++);
		
        fb_info = { (uint32_t*)svga.fb, 1024, 768, svga.pitch };
    } else {
        // Not VMware (or SVGA II failed) — use GRUB multiboot info directly.
        // Accept any type except 2 (EGA text). If bit 12 not set, fall back
        // to probing Bochs VBE ports, then hardcoded candidates.
        uint32_t fb_phys = 0, fb_w = 1024, fb_h = 768, fb_pitch = 1024*4;

        if ((mbi->flags & (1u << 12)) && mbi->framebuffer_type != 2) {
            // GRUB filled the framebuffer fields (because boot.S requested
            // video mode via Multiboot1 FLAGS bit 2). Take its values
            // verbatim; this is the normal path on real BIOS + VMware-BIOS
            // and on UEFI through GRUB-EFI (which sets it up via GOP).
            fb_phys  = (uint32_t)(uintptr_t)mbi->framebuffer_addr;
            fb_w     = mbi->framebuffer_width  ? mbi->framebuffer_width  : 1024;
            fb_h     = mbi->framebuffer_height ? mbi->framebuffer_height : 768;
            fb_pitch = mbi->framebuffer_pitch  ? mbi->framebuffer_pitch  : fb_w*4;
        }

        if (fb_phys < 0x1000000u) {
            // GRUB gave nothing useful — try Bochs VBE then hardcoded
            probe_framebuffer(mbi, fb_phys, fb_w, fb_h, fb_pitch);
        }

        fb_info = { (uint32_t*)(uintptr_t)fb_phys, fb_w, fb_h, fb_pitch };
    }

    if (fb_info.width  == 0 || fb_info.width  > 1920) fb_info.width  = 1024;
    if (fb_info.height == 0 || fb_info.height > 1200) fb_info.height = 768;
    if (fb_info.pitch  < fb_info.width * 4) fb_info.pitch = fb_info.width * 4;

    // Real-hardware-only perf fix: mark the linear framebuffer's physical
    // range Write-Combining via MTRR if at all possible (see the big
    // comment above setup_framebuffer_write_combining() in
    // 02_boot_info_and_graphics_driver.h for why this matters -- in short,
    // it's what makes every-frame swap_buffers() blits, and therefore
    // mouse tracking, not feel sluggish on real silicon). No-op under
    // VMware/emulation, where this was never the bottleneck.
    const char* g_fb_wc_status = setup_framebuffer_write_combining();

    // ── Step 3: commit and paint ──────────────────────────────────────────────
    backbuffer = backbuffer_storage;
    g_gfx.init(false);

    g_gfx.clear_screen(ColorPalette::DESKTOP_GRAY );
    swap_buffers();

    // ── Open first terminal window ────────────────────────────────────────────
    launch_new_terminal();

    // Report whether the WC fix above actually took effect. This used to
    // fail silently, so "everything on real hardware is slow -- typing,
    // opening windows, all of it" had no visible cause: every one of
    // those triggers a full swap_buffers() blit, and if the framebuffer
    // is still stuck Uncacheable (no free MTRR slot is the common real-
    // hardware case -- firmware often claims all of them), that blit
    // stays 20-100x slower no matter what else gets optimized.
    {
        char wcmsg[128];
        vga_cat(wcmsg, "Framebuffer write-combining: ", g_fb_wc_status, "\n");
        wm.print_to_focused(wcmsg);
    }

    // ── PS/2 mouse ────────────────────────────────────────────────────────────
    ps2_flush_output_buffer();
    if (initialize_universal_mouse()) {
        wm.print_to_focused("Mouse: initialised.\n");
    } else {
        wm.print_to_focused("Mouse: init failed (keyboard-only mode).\n");
    }

    // ── AHCI disk + FAT32 ─────────────────────────────────────────────────────
    disk_init();
    // Don't hardcode a port selection here — disk_init() already
    // auto-selected the first port with an attached device. Hardcoding
    // "1" only worked on the QEMU command line in compile.md (which puts
    // the hard disk on ahci.1); bare-metal and VMware almost always have
    // the boot disk on port 0 and would have silently fallen back to no
    // selection. Pass "" to just list the detected ports for the user.
    cmd_list_and_select_disk("");

    if (ahci_base) {
        fat32_init();
        wm.print_to_focused("Disk: AHCI found.\n");
    } else {
        wm.print_to_focused("Disk: no AHCI controller.\n");
    }
    if (current_directory_cluster) {
        wm.load_desktop_items();
        if (extract_busybox_to_filesystem())
            wm.print_to_focused("BusyBox: saved to FAT32.\n");
        else
            wm.print_to_focused("BusyBox: ramdisk empty or write failed.\n");
        if (extract_hello_to_filesystem())
            wm.print_to_focused("hello: saved to FAT32.\n");

        // Write the TCC guest ABI header so user programs can #include "tcc.h"
        // to get outb / kprint / kexit without redefining them.
        {
            fat_dir_entry_t tcc_hdr_entry;
            uint32_t th_sec = 0, th_off = 0;
            if (fat32_find_entry("tcc.h", &tcc_hdr_entry, &th_sec, &th_off) != 0) {
                static const char tcc_h[] =
                    "/* tcc.h — guest ABI for in-kernel TCC programs */\n"
                    "#ifndef TCC_H\n#define TCC_H\n"
                    "static inline void outb(unsigned short p, unsigned char v) {\n"
                    "    __asm__ volatile(\"outb %0,%1\"::\"a\"(v),\"Nd\"(p)); }\n"
                    "static inline void kprint(const char* s) {\n"
                    "    while (*s) outb(0xE9, *s++); }\n"
                    "static inline void kexit(int c) {\n"
                    "    outb(0xE8, (unsigned char)c); }\n"
                    "#endif\n";
                fat32_write_file("tcc.h", tcc_h, (uint32_t)(sizeof(tcc_h) - 1));
            }
        }
    } else {
        wm.print_to_focused("FAT32: not initialised.\n");
    }

    // ── Bochs CPU / ELF subsystem ─────────────────────────────────────────────
    //
    // Run the file-scope C++ constructors NOW, before init_elf_system()
    // and before any code can reach a Bochs entry point. boot.S does not
    // walk __init_array, so without this the Bochs core objects (bx_cpu,
    // bx_mem, the CPUID param objects, icache's pageWriteStampTable, ...)
    // stay as zero-filled BSS with null vtables. The first ELF launched
    // in the Bochs emulator window would then call bochs_cpu_init() ->
    // BX_CPU(0)->initialize() against those null vtables and fault out on
    // its very first tick — the "first-time crash / autoclose" symptom.
    kernel_run_global_ctors_once();

    // The constructors have now run exactly once. Tell the test module so
    // its own run_init_array_once() inside test_module_run() becomes a
    // no-op — otherwise the first `test` command would re-run every ctor
    // a second time, re-constructing bx_cpu / bx_mem on top of live
    // (already-initialised) Bochs state.
    test_module_mark_ctors_done();

    init_elf_system();

    vga_status("Init complete - entering main loop", 0x0A);

    // ── Main loop ─────────────────────────────────────────────────────────────
    const uint32_t TICKS_PER_FRAME = 1;
    // Seeded so that (g_timer_ticks - last_tick_tick) >= TICKS_PER_FRAME is
    // already true on the very first loop iteration (0 - (uint32_t)-1
    // wraps around to 1). With last_tick_tick starting at 0 (matching
    // g_timer_ticks' own starting value of 0), that gating check read
    // (0 - 0) >= 1, i.e. false — so despite the g_evt_timer/g_evt_dirty
    // flags being forced below, the paint block a few lines down was
    // still skipped on frame one and the desktop (icons, taskbar, clock)
    // stayed blank until the software timer's poll_counter first ticked
    // over, rather than appearing immediately as the comment intended.
    // (Was a wait of up to 500 iterations with the original threshold;
    // the fix below stands regardless of what that threshold is.)
    uint32_t last_tick_tick = (uint32_t)0 - TICKS_PER_FRAME;
    int prev_mouse_x = mouse_x;
    int prev_mouse_y = mouse_y;

    // Force an immediate first render — don't wait for the software
    // timer to tick over before the desktop appears.
    g_evt_timer = true;
    g_evt_dirty = true;

    // Spinning heartbeat at VGA column 79, row 0 (green)
    volatile uint16_t* vga_hb = (volatile uint16_t*)(0xB8000 + 2*79);
    uint32_t hb_counter = 0;
    const char hb_chars[] = "|/-\\";
    static uint32_t poll_counter = 0;
    // Power-saving idle backoff -- see the big comment at the bottom of
    // the loop body for why this uses `pause` and not `hlt`.
    uint32_t idle_streak = 0;

    for (;;) {
        bool did_anything_this_iteration = false;
        if (++hb_counter % 10000 == 0) {
            *vga_hb = (uint16_t)(0x0A00u | (uint8_t)hb_chars[(hb_counter/10000)%4]);

		}


        bool prev_left  = mouse_left_down;
        bool prev_right = mouse_right_down;
        poll_input_universal();

        bool leftClickedThisFrame  = (mouse_left_down  && !prev_left);
        bool rightClickedThisFrame = (mouse_right_down && !prev_right);

        // Latch click edges for the guest mouse ABI (bochs_drivers.h's
        // mouse_poll(), via kernel_gfx_mouse_poll() below). This loop
        // runs every iteration, but tick_elf_processes() -- where a
        // guest actually gets to poll -- only runs once every
        // TICKS_PER_FRAME iterations, so a plain "clicked this frame"
        // bool would often be gone again before any guest ever saw it.
        // Sticky-until-consumed fixes that: set here, cleared only by
        // kernel_gfx_mouse_poll() once it's actually been reported.
        if (leftClickedThisFrame)  g_gfx_click_left_pending  = true;
        if (rightClickedThisFrame) g_gfx_click_right_pending = true;
        bool mouse_moved = (mouse_x != prev_mouse_x || mouse_y != prev_mouse_y);
        bool key_pressed = (last_key_press != 0);

        // Anything that can actually change what's on screen beyond the
        // cursor's own position: a key, a fresh click edge, or a button
        // being held (drag/resize/paint-canvas in progress). A plain
        // hover-move with nothing held is deliberately NOT included here
        // -- see the cursor-only fast path further down for why forcing
        // a full repaint for that case is what made mouse movement feel
        // heavy.
        bool input_needs_full_repaint = key_pressed || leftClickedThisFrame ||
                                         rightClickedThisFrame || mouse_left_down ||
                                         mouse_right_down;

        if (key_pressed || mouse_moved || leftClickedThisFrame || rightClickedThisFrame) {
            g_evt_input = true;
            if (input_needs_full_repaint) g_input_state.hasNewInput = true;
            prev_mouse_x = mouse_x;
            prev_mouse_y = mouse_y;
        }

        // Route keypresses to any active ELF guest process
        //
        // FIX (focus ignored on click): this used to scan every slot
        // and hand the keystroke to the FIRST one that was active &&
        // waiting_for_input, regardless of which terminal window was
        // actually focused/clicked. With two terminals each running
        // a program that reads stdin, typing while Terminal B was
        // focused would silently feed Terminal A instead (whichever
        // slot happened to be waiting), and last_key_press got
        // zeroed here before wm.handle_input ever saw it — so B's
        // own captured_elf_slot path (kernel.cpp's BUSYBOX CAPTURE
        // block) never even ran.
        //
        // Fix: only steal the keystroke for the ELF slot owned by
        // the currently FOCUSED window. If that slot isn't waiting
        // for input (or no window is focused, or the focused window
        // isn't capturing a slot), fall through and let the normal
        // g_evt_input / wm.handle_input path below handle the key —
        // which is what already correctly threads input to whichever
        // terminal's captured_elf_slot the user clicked into.
        if (last_key_press != 0) {
            int fs = wm.get_focused_elf_slot();
            if (fs >= 0 && fs < MAX_ELF_PROCESSES &&
                elf_processes[fs].active && elf_processes[fs].waiting_for_input) {
                push_input(fs, last_key_press);
                elf_processes[fs].waiting_for_input = false;
                last_key_press = 0;
            }
        }

        // Software timer (no PIT — IRQ0 would fire into an unhandled vector)
        //
        // FIX (guest programs still felt sluggish after the 500->20
        // change): 20 was still an arbitrary gap, not a real interval.
        // Since g_evt_timer has no consumer besides gating guest
        // ticking (see above) and unconditionally marking the frame
        // dirty (right below), there's no reason to gate it at all --
        // firing it every single iteration removes the last bit of
        // artificial latency between "guest produced a new frame" and
        // "that frame gets ticked/shown" while leaving every other
        // per-iteration cost (PS/2 polling, the idle pause-ramp)
        // exactly as it was. Kept as a counter rather than an
        // unconditional `g_evt_timer = true` purely so this stays a
        // one-line tweak if a real interval is ever wanted again.
        if (++poll_counter >= 1) {
            poll_counter  = 0;
            g_evt_timer   = true;
			g_evt_dirty = true;
            g_timer_ticks++;
        }


        if (g_evt_input) {
            g_evt_input = false;
            wm.handle_input(last_key_press, mouse_x, mouse_y,
                            mouse_left_down,
                            leftClickedThisFrame,
                            rightClickedThisFrame);
            if (last_key_press != 0) last_key_press = 0;
            // Only force the expensive full-desktop repaint for input
            // that can actually change what's drawn. handle_input()
            // early-returns doing nothing at all for a plain hover-move
            // (no button down, no click edge), so there's nothing here
            // for a full repaint to pick up in that case anyway.
            if (input_needs_full_repaint) g_evt_dirty = true;
        }

        wm.cleanup_closed_windows();

        // Guest-process ticking stays paced by the software timer (as
        // before) — this is what governs how much CPU-emulation work a
        // running ELF guest gets per iteration, and shouldn't speed up
        // or slow down just because the mouse is being moved.
        if (g_evt_timer && (g_timer_ticks - last_tick_tick) >= TICKS_PER_FRAME) {
            // Tick ELF processes BEFORE the paint so any breadcrumbs they
            // write (x86_breadcrumb at row 2, glue's tick markers at row 0
            // col 72/73, panic tags at col 70) are reflected in the next
            // swap_buffers. Otherwise a hang inside tick_elf_processes
            // would leave the last painted frame without the breadcrumbs
            // pointing at where the hang happened.
            //
            // (Historical note: this call used to be split into several
            // "sub-ticks" with a mouse poll/redraw between each one, to
            // keep the cursor responsive across the long gap the old
            // 500-iteration software timer left between guest ticks.
            // That gap is gone now that the timer fires every iteration,
            // so a single tick_elf_processes() call per iteration is
            // both simpler and, if the guest never yields, no worse
            // than before: the main loop's own poll_input_universal()/
            // redraw at the top of the next iteration takes over that
            // job instead. The old code also divided a GUEST_SUBTICKS
            // round count across however many processes were active so
            // no single interval's total budget scaled with process
            // count -- with exactly one round now instead of up to 8,
            // that division always resolved to 1 anyway, so it's gone
            // too rather than left in as dead arithmetic.)
            int active_count = 0;
            for (int i = 0; i < MAX_ELF_PROCESSES; i++) {
                if (elf_processes[i].active && !elf_processes[i].completed) active_count++;
            }

            // Pass the focused window's ELF slot (-1 if none) so a
            // background process can't compete with the one the user
            // is actually watching -- see tick_elf_processes' own
            // comment for the full rationale.
            tick_elf_processes(1, wm.get_focused_elf_slot());

            poll_input_universal();
            bool tick_mouse_moved = (mouse_x != prev_mouse_x || mouse_y != prev_mouse_y);
            if (tick_mouse_moved) {
                prev_mouse_x = mouse_x;
                prev_mouse_y = mouse_y;
                // Only the cheap cursor-only redraw here -- if a button
                // is down (drag/resize/paint in progress) or the
                // backbuffer isn't in a known-clean state, leave it for
                // the normal full-repaint path below instead of risking
                // a partial/stale-looking mid-tick frame.
                if (g_backbuffer_is_clean_on_screen &&
                    !mouse_left_down && !mouse_right_down) {
                    erase_cursor_from_screen();
                    draw_cursor_to_screen(mouse_x, mouse_y, ColorPalette::CURSOR_WHITE);
                }
            }
            if (active_count > 0) did_anything_this_iteration = true;

            last_tick_tick = g_timer_ticks;
            g_evt_timer     = false;
        }

        // Repaint is intentionally NOT gated on g_evt_timer above — only
        // on whether anything actually changed (g_evt_dirty /
        // hasNewInput). It used to require BOTH the timer *and* a dirty
        // flag, and the software timer here originally only fired once
        // every 500 raw loop iterations (poll_counter, further up --
        // there's no real PIT/IRQ0 to drive it; it now fires every
        // iteration instead, see the fix note there). Mouse movement/
        // clicks and keystrokes are polled and flagged dirty on EVERY
        // iteration regardless (see poll_input_universal() + the
        // g_evt_input block above), so gating the actual repaint behind
        // a slower timer made the on-screen cursor visibly lag behind
        // the real, continuously-updated mouse_x/mouse_y — i.e. the
        // mouse felt "slow"/laggy even though input was being read
        // promptly. Repainting as soon as something is dirty fixes
        // that; the timer above still exists to pace guest ticking and
        // to cover the "nothing moved, but a guest changed its own
        // frame" case via g_evt_timer's own g_evt_dirty = true (set
        // further up, now every iteration rather than every 500th).
        // timer above still exists to pace guest ticking and to cover
        // the "nothing moved, but a guest changed its own frame"
        // periodic case via g_evt_timer's own g_evt_dirty = true (set
        // where poll_counter last ticked over, further up).
        if (g_evt_dirty || g_input_state.hasNewInput) {
            g_evt_dirty               = false;
            g_input_state.hasNewInput = false;
            g_gfx.clear_screen(ColorPalette::DESKTOP_GRAY );
            wm.update_all();
            // Diagnostic overlay: paint VGA text-mode rows 0/1/2
            // (boot/panic/tick breadcrumbs, host-IDT fault tags,
            // x86_tick lazy-init progress) onto the framebuffer so
            // they are visible in graphics mode. Drawn last so it
            // overlays everything.
            draw_vga_overlay();
            swap_buffers();
            // The backbuffer just pushed to the screen has no cursor in
            // it (draw_cursor() is intentionally not called here any
            // more -- see the cursor-only fast path comment below), so
            // draw the cursor glyph straight onto the framebuffer now
            // and remember where. That's what lets the *next* frame, if
            // it's just a plain pointer move, skip the full repaint
            // entirely.
            erase_cursor_from_screen(); // no-op the first time through
            draw_cursor_to_screen(mouse_x, mouse_y, ColorPalette::CURSOR_WHITE);
            g_backbuffer_is_clean_on_screen = true;
            did_anything_this_iteration = true;
        } else if (mouse_moved && g_backbuffer_is_clean_on_screen) {
            // Cursor-only fast path: nothing but the pointer position
            // changed this frame (no key, no click, no button held --
            // handle_input() already established there's nothing else
            // to redraw). Move just the ~8x12px cursor glyph directly
            // on the framebuffer instead of clearing and redrawing the
            // entire desktop/every window/the taskbar clock and doing a
            // full 1024x768 blit for a one-pixel pointer nudge.
            erase_cursor_from_screen();
            draw_cursor_to_screen(mouse_x, mouse_y, ColorPalette::CURSOR_WHITE);
            did_anything_this_iteration = true;
        }

        // ── Power saving: back off the busy-poll spin when idle ────────────
        // This kernel has no working periodic hardware interrupt (see the
        // "Software timer (no PIT...)" comment above) and mouse/keyboard
        // input is polled, not interrupt-driven -- so `hlt` is NOT safe
        // here. Nothing would ever fire to wake the CPU back up once
        // halted, and the very first genuinely idle moment would hang the
        // machine solid. `pause` is the safe alternative: it's a hint to
        // the CPU that this is a spin-wait rather than real work, which on
        // real hardware measurably cuts power draw and heat in a busy-poll
        // loop like this one without changing behavior -- the very next
        // instruction still executes immediately afterward, so it can
        // never cause a missed input or a delayed guest tick.
        //
        // Back off adaptively: the longer nothing has happened, the more
        // pauses this iteration spends (capped), which lowers the
        // polling loop's CPU floor further the longer the system sits
        // genuinely idle. Any real input, redraw, or active guest process
        // resets it to full responsiveness immediately -- this never adds
        // latency to anything, it only spends idle cycles more cheaply.
        if (did_anything_this_iteration) {
            idle_streak = 0;
        } else if (idle_streak < 0xFFFFFFFFu) {
            idle_streak++;
        }
        {
            uint32_t pause_count = 1 + (idle_streak >> 6); // ramps 1 -> 64
            if (pause_count > 64) pause_count = 64;
            for (uint32_t p = 0; p < pause_count; p++) asm volatile("pause");
        }
    }
}
// =============================================================================
// extern "C" bridges for tcc_kernel.cpp
// =============================================================================
// tcc_kernel.cpp is compiled as freestanding C++ and cannot include the full
// kernel headers. These thin wrappers expose the symbols it needs with plain
// C linkage so the linker resolves them without name-mangling.

extern "C" {

// Bridge for bochs_glue.cpp's bochs_guest_mouse_poll() (guest port
// 0xEF, see bochs_drivers.h's mouse_poll()). Reports the compositor's
// cursor to ELF slot `slot` ONLY if that slot's window is BOTH the
// currently focused window AND showing a live gfx canvas the cursor
// happens to be over — everything else (titlebar drags, clicks on
// other windows, the desktop, the taskbar) is handled entirely by
// WindowManager::handle_input() above and never touches this path at
// all, which is what keeps those clicks going to the compositor only.
// On any "no" (wrong/no slot, not focused, no window, not in gfx
// mode, cursor outside the canvas) this leaves *out_x/*out_y/
// *out_buttons at their caller-supplied zero and returns false — a
// clean "cursor absent" snapshot rather than stale or foreign data.
bool kernel_gfx_mouse_poll(int slot, int* out_x, int* out_y,
                            unsigned char* out_buttons) {
    if (slot < 0 || wm.get_focused_elf_slot() != slot) return false;

    Window* win = wm.find_window_by_elf_slot(slot);
    if (!win) return false;

    int lx = 0, ly = 0;
    bool in_win = win->gfx_hit_test(mouse_x, mouse_y, &lx, &ly);
    if (in_win) {
        *out_x = lx;
        *out_y = ly;
        *out_buttons |= 0x10; // MOUSE_BIT_IN_WINDOW (bochs_drivers.h)
    }
    if (mouse_left_down)  *out_buttons |= 0x01; // MOUSE_BIT_LEFT_DOWN
    if (mouse_right_down) *out_buttons |= 0x02; // MOUSE_BIT_RIGHT_DOWN
    if (g_gfx_click_left_pending) {
        *out_buttons |= 0x04; // MOUSE_BIT_LEFT_CLICKED
        g_gfx_click_left_pending = false;
    }
    if (g_gfx_click_right_pending) {
        *out_buttons |= 0x08; // MOUSE_BIT_RIGHT_CLICKED
        g_gfx_click_right_pending = false;
    }
    return true;
}

void tcc_bridge_console_print(const char* s) {
    console_print(s);
}
static inline bool is_cc_safe_char(unsigned char c) {
    return c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c != 127);
}

char* tcc_bridge_fat32_read(const char* filename) {
    // Path-aware: fat32_read_file_as_string() only ever looks in the
    // current directory and treats any '/' as part of a garbage flat
    // name. fat32_read_file_as_string_path() falls back to that exact
    // behavior when there's no '/' in filename, and otherwise resolves
    // the directory part first -- needed both for `cc sub/foo.c` and for
    // #include "sub/foo.h" (this same function is what TCC's open()
    // shim calls for every #include, via the fat32_read_file_as_string
    // macro alias in tcc_kernel.cpp).
    char *data = fat32_read_file_as_string_path(filename);

    if (!data) {
        return NULL;
    }

    for (char *p = data; *p; ++p) {
        if (!is_cc_safe_char((unsigned char)*p)) {
            // FIX: this used to return NULL here without freeing `data`,
            // leaking the whole file's buffer every time a source file
            // or header contained a byte outside the "safe" set.
            delete[] data;
            return NULL;
        }
    }

    return data;
}

int tcc_bridge_fat32_write(const char* filename, const void* data, unsigned int size) {
    return fat32_write_file(filename, data, (uint32_t)size);
}

int tcc_bridge_exec_elf(void* terminal, const char* filename, const char* args) {
    TerminalWindow* tw = (TerminalWindow*)terminal;
    return tw->exec_elf(filename, args);
}

} // extern "C"
