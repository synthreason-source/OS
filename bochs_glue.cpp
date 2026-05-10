#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/pc_system.h"
#include <setjmp.h>

// Forward decls for the panic-rescue jmp_buf defined later in this TU.
// We need them visible up here so bochs_cpu_init() can guard the
// BX_CPU::initialize() call (see fix at bochs_cpu_init).
extern "C" jmp_buf bx_panic_jmpbuf;
extern "C" int     bx_panic_jmpbuf_armed;
extern "C" volatile int bx_last_panic_code;

// ─── Live framebuffer breadcrumb (provided by kernel.cpp) ──────────────────
// Writes directly to the visible framebuffer so it shows up even if the
// kernel main loop never gets to paint another frame. Use to localise
// freezes inside the bochs glue init path.
//
// Slot map (col along VGA top row):
//   30 = entered bochs_cpu_init
//   31 = entered bochs_cpu_initialize_guarded
//   32 = guard-flag check passed (about to call pc_system.initialize)
//   33 = pc_system.initialize returned
//   34 = about to call BX_MEM(0)->init_memory
//   35 = init_memory returned
//   36 = guarded() returning to bochs_cpu_init
//   37 = about to call bochs_cpu_reset_for_launch
//   38 = reset_for_launch returned (full bochs_cpu_init done)
extern "C" void live_breadcrumb(int slot, char ch);

// __dso_handle: defined here for the C++ static destructor machinery.
// Use weak linkage so bochs_infra.cpp's identical definition coexists.
__attribute__((weak)) void* __dso_handle = nullptr;
extern "C" int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void __cxa_finalize(void*) {}

#define MAX_BOCHS_SLOTS 4

struct SlotState {
    Bit8u* mem_base = nullptr;
    Bit32u mem_size = 0;
    Bit32u vaddr_base = 0;
    Bit32u brk_ptr = 0;
    int slot_id = -1;
    bool wants_input = false;
    int (*read_cb)(int) = nullptr;
    void (*write_cb)(int, char) = nullptr;
    void (*exit_cb)(int, int) = nullptr;
};

static SlotState g_slots[MAX_BOCHS_SLOTS];
static int g_active_slot = -1;
static bool g_cpu_ready = false;

static void setup_flat_segment(bx_segment_reg_t& seg, Bit16u sel, bool code) {
    seg.selector.value = sel;
    seg.selector.rpl = 0;
    seg.selector.ti = 0;
    seg.selector.index = sel >> 3;

    bx_descriptor_t& d = seg.cache;
    d.valid = 1;
    d.p = 1;
    d.dpl = 0;
    d.segment = 1;
    d.type = code ? 0x0B : 0x03;
    d.u.segment.base = 0x00000000u;
    d.u.segment.limit_scaled = 0xFFFFFFFFu;
    d.u.segment.g = 1;
    d.u.segment.d_b = 1;
    d.u.segment.avl = 0;
}

static void bochs_cpu_enter_protected_mode() {
    BX_CPU_C* cpu = BX_CPU(0);
    cpu->cr0.val32 |= 0x00000001u;

    setup_flat_segment(cpu->sregs[BX_SEG_REG_CS], 0x08, true);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_SS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_DS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_ES], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_FS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_GS], 0x10, false);

    // ── Re-arm GDTR/IDTR from the active slot's injected tables ────────────
    // BX_CPU_C::reset(BX_RESET_HARDWARE) zeros gdtr/idtr; bochs_cpu_init() is
    // generally called AFTER bochs_set_process_memory() (which had injected
    // those tables and set the registers). Re-pointing them here ensures the
    // first guest instruction that touches a segment register or raises an
    // exception sees the correct tables.
    if (g_active_slot >= 0 && g_active_slot < MAX_BOCHS_SLOTS) {
        SlotState& s = g_slots[g_active_slot];
        if (s.mem_base && s.mem_size) {
            cpu->gdtr.base  = s.vaddr_base + 0x80;
            cpu->gdtr.limit = 24 - 1;
            cpu->idtr.base  = s.vaddr_base + 0x100;
            cpu->idtr.limit = 256 * 8 - 1;
        }
    }

    cpu->invalidate_prefetch_q();
}

static bool mem_read_handler(bx_phy_address addr, unsigned len, void* data, void*) {
    if (g_active_slot < 0) {
        __builtin_memset(data, 0, len);
        return true;
    }

    SlotState& s = g_slots[g_active_slot];
    Bit32u off = (Bit32u)addr;

    if (s.mem_base && off >= s.vaddr_base) {
        off -= s.vaddr_base;
        if (off + len <= s.mem_size) {
            __builtin_memcpy(data, s.mem_base + off, len);
            return true;
        }
    }

    __builtin_memset(data, 0, len);
    return true;
}

static bool mem_write_handler(bx_phy_address addr, unsigned len, void* data, void*) {
    if (g_active_slot < 0) return true;

    SlotState& s = g_slots[g_active_slot];
    Bit32u off = (Bit32u)addr;

    if (s.mem_base && off >= s.vaddr_base) {
        off -= s.vaddr_base;
        if (off + len <= s.mem_size) {
            __builtin_memcpy(s.mem_base + off, data, len);
        }
    }

    return true;
}

static void inject_idt_into_slab(SlotState& s) {
    if (!s.mem_base || s.mem_size < 0x1000) return;

    static const Bit8u stub[12] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xBB, 0x00, 0x00, 0x00, 0x00,
        0xCD, 0x80
    };

    __builtin_memcpy(s.mem_base + 0x000, stub, sizeof(stub));
    s.mem_base[sizeof(stub)] = 0xF4;

    // ── GDT at slab offset 0x80 ──────────────────────────────────────────
    // Three flat descriptors matching the segment selectors used by
    // bochs_cpu_enter_protected_mode():
    //   selector 0x00 — null
    //   selector 0x08 — ring-0 code, base=0, limit=4G, 32-bit, executable
    //   selector 0x10 — ring-0 data, base=0, limit=4G, 32-bit, writable
    //
    // Without a real GDT loaded into gdtr, any guest segment-register
    // reload (e.g. busybox's "mov $0x10, %ds") triggers Bochs to walk an
    // empty GDT and raise #GP, which then triple-faults via our IDT stub.
    Bit8u* gdt_base = s.mem_base + 0x80;
    __builtin_memset(gdt_base, 0, 8);                  // null descriptor

    // Code segment (selector 0x08): type=0x9A, S=1, P=1, DPL=0,
    // G=1 (4K granularity), D=1 (32-bit), limit=0xFFFFF.
    Bit8u code_desc[8] = {
        0xFF, 0xFF,        /* limit 15:0 = 0xFFFF */
        0x00, 0x00, 0x00,  /* base 23:0 = 0 */
        0x9A,              /* access: P=1 DPL=0 S=1 type=execute/read */
        0xCF,              /* flags: G=1 D=1 limit 19:16 = 0xF */
        0x00               /* base 31:24 = 0 */
    };
    __builtin_memcpy(gdt_base + 8, code_desc, 8);

    // Data segment (selector 0x10): type=0x92 (read/write).
    Bit8u data_desc[8] = {
        0xFF, 0xFF,
        0x00, 0x00, 0x00,
        0x92,
        0xCF,
        0x00
    };
    __builtin_memcpy(gdt_base + 16, data_desc, 8);

    Bit32u gdt_va = s.vaddr_base + 0x80;
    BX_CPU(0)->gdtr.base  = gdt_va;
    BX_CPU(0)->gdtr.limit = 24 - 1;   // 3 descriptors

    // ── IDT at slab offset 0x100 (unchanged) ─────────────────────────────
    Bit32u handler_va = s.vaddr_base + 0x000;
    Bit8u* idt_base = s.mem_base + 0x100;
    Bit32u idt_va = s.vaddr_base + 0x100;

    Bit8u gate[8];
    gate[0] = (Bit8u)(handler_va & 0xFF);
    gate[1] = (Bit8u)((handler_va >> 8) & 0xFF);
    gate[2] = 0x08;
    gate[3] = 0x00;
    gate[4] = 0x00;
    gate[5] = 0x8E;
    gate[6] = (Bit8u)((handler_va >> 16) & 0xFF);
    gate[7] = (Bit8u)((handler_va >> 24) & 0xFF);

    for (int i = 0; i < 256; i++) {
        __builtin_memcpy(idt_base + i * 8, gate, 8);
    }

    BX_CPU(0)->idtr.base = idt_va;
    BX_CPU(0)->idtr.limit = 256 * 8 - 1;
}

// Called from bx_devices_c::outp when the guest writes port 0xE9.
// Forwards the byte to the active slot's output ring buffer via the
// kernel-supplied write_cb, then asks cpu_loop to yield back to the host
// so the kernel main loop can drain output / poll input / redraw.
//
// cpu_loop only checks for a yield at the top of each iteration, gated on
// BX_CPU_THIS_PTR async_event being non-zero. Inside handleAsyncEvent,
// kill_bochs_request causes a return-1 → cpu_loop returns to caller.
// Setting both here guarantees a clean yield after each emitted character.
extern "C" void bochs_guest_putc(char c) {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return;
    SlotState& s = g_slots[g_active_slot];
    if (s.write_cb) s.write_cb(g_active_slot, c);

    bx_pc_system.kill_bochs_request = 1;
    BX_CPU(0)->async_event = 1;
}

extern "C" void bochs_register_io_callbacks(
    int slot,
    int (*read_cb)(int),
    void (*write_cb)(int, char),
    void (*exit_cb)(int, int))
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].slot_id = slot;
    g_slots[slot].read_cb = read_cb;
    g_slots[slot].write_cb = write_cb;
    g_slots[slot].exit_cb = exit_cb;
}

extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size, Bit32u vaddr_base) {
    if (g_active_slot < 0) return;

    SlotState& s = g_slots[g_active_slot];

    if (s.mem_base && s.mem_size) {
        BX_MEM(0)->unregisterMemoryHandlers(nullptr,
            (bx_phy_address)s.vaddr_base,
            (bx_phy_address)(s.vaddr_base + s.mem_size - 1));
    }

    s.mem_base = base;
    s.mem_size = size;
    s.vaddr_base = vaddr_base;

    if (base && size) {
        BX_MEM(0)->registerMemoryHandlers(
            nullptr,
            mem_read_handler, mem_write_handler,
            (bx_phy_address)vaddr_base,
            (bx_phy_address)(vaddr_base + size - 1));

        inject_idt_into_slab(s);
    }
}

extern "C" void bochs_finalize_process_memory() {
}

extern "C" void bochs_set_brk(int slot, Bit32u brk_addr) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].brk_ptr = brk_addr;
}

extern "C" void bochs_activate_slot(int slot) {
    g_active_slot = slot;
}

// ── Initialisation split ─────────────────────────────────────────────────
// bochs_cpu_init() must run EXACTLY ONCE per boot. The libcpu.a path
// BX_CPU::initialize() registers CPUID parameters via SIM->get_param_*
// which our stub returns nullptr for; calling it a second time on a
// fully-initialised CPU re-walks those registration paths and on QEMU
// has been observed to host-fault (no host IDT present, so the box
// triple-faults silently with the kernel heartbeat frozen).
//
// Per-launch we now only need to:
//   1. reset the CPU to a known state (BX_RESET_HARDWARE)
//   2. re-enter protected mode with the active slot's GDT/IDT
//
// bochs_cpu_init() remains exposed for backward compatibility with
// kernel.cpp, but is now an idempotent guarded one-shot. Subsequent
// calls fall through to bochs_cpu_reset_for_launch().
static bool g_cpu_inited_once = false;
static bool g_cpu_init_failed  = false;   // set if BX_CPU::initialize() panicked

static void bochs_cpu_reset_for_launch() {
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    bochs_cpu_enter_protected_mode();
}

// VGA breadcrumb at row 0, col 68 — distinct from the cpu_loop tags at
// columns 70/72/73. 'i' = entered initialize(), 'I' = returned cleanly,
// '!' = panicked through setjmp during initialize().
static inline void glue_init_crumb(char c) {
    volatile unsigned short* p = (volatile unsigned short*)(0xB8000 + 2*68);
    *p = (unsigned short)(0x2F00 | (unsigned char)c);   // white-on-green
}

// ─── FIX v2: BX_CPU(0)->initialize() rescue path ─────────────────────────
// initialize() walks the bochs param tree (SIM->get_param_*). Our KernelSIM
// returns nullptr for every get_param query. Empirically, calling it from
// a freestanding kernel either:
//   (a) hangs in an infinite loop walking the tree,
//   (b) host-faults dereferencing a nullptr (caught by the boot.S host
//       IDT, painting a red HOST FAULT bar), or
//   (c) panics through BX_PANIC / fatal / quit_sim.
//
// Only (c) is recoverable via setjmp. (a) and (b) are not — a running
// kernel just stops with no breadcrumb past 'L'/'M'.
//
// The good news: we don't need initialize() for anything. The
// reset(BX_RESET_HARDWARE) call alone produces a CPU sufficient to run
// our guests (it sets GPRs, segment registers, EFLAGS, MSRs, and the
// CPUID feature bits that have static defaults from BX_CPU_C's ctor).
// initialize() exists to register the CPUID feature *parameters* with
// the param tree for runtime configuration — something we never use.
//
// Default (BX_GLUE_SKIP_INITIALIZE=1, the safe path): never call
// BX_CPU::initialize(). Skip straight to reset(). This is what fixes
// the "stops at LM" hang.
//
// Opt-in (BX_GLUE_SKIP_INITIALIZE=0): try initialize() once, guarded by
// setjmp so the (c)-class panic path is recoverable. Kept for anyone
// who wants to investigate further without ripping the call out.
#ifndef BX_GLUE_SKIP_INITIALIZE
#define BX_GLUE_SKIP_INITIALIZE 1
#endif

static void bochs_cpu_initialize_guarded() {
    live_breadcrumb(31, '1');
    if (g_cpu_inited_once || g_cpu_init_failed) return;
    live_breadcrumb(32, '2');

    // ─── FIX v3: bx_pc_system.initialize(ips) ─────────────────────────────
    // Several timing helpers in pc_system.cc (time_from_ticks, time_useconds,
    // time_to_ticks) divide or multiply by m_ips. m_ips is initialised by
    // bx_pc_system_c::initialize(Bit32u ips) which we never called before,
    // leaving it at 0.0. Anything inside cpu_loop that touches the timer
    // path then divides by zero and host-faults (vector 0 = #DE, caught by
    // boot.S host IDT, paints a red HOST FAULT !00 bar).
    //
    // initialize() itself just zeroes a handful of fields and stores
    // m_ips = ips/1e6 — no SIM-> calls, no allocation. Safe to call.
    // 50 MIPS is the bochs default for a "modern" CPU.
    //
    // ─── FIX v5: FPU init in boot.S ───────────────────────────────────────
    // The body of initialize() looks trivial but the assignment
    //   m_ips = double(ips) / 1000000.0L;
    // forces the i386 backend to emit 80-bit x87 (long double divide).
    // With the FPU in an indeterminate post-GRUB state the first fldt
    // hangs the host — symptom: kernel freezes here, no 'P' breadcrumb
    // ever appears at VGA col 68. boot.S now does fninit and clears
    // CR0.EM/TS before kernel_main, which prevents the hang.
    //
    // The lowercase 'p' below is the *entered* breadcrumb. If you see
    // 'p' but no 'P' the call hung inside initialize() — that points
    // back at FPU state. If you don't see 'p' at all, control never
    // reached this point.
    glue_init_crumb('p');                 // 'p' = about to call initialize
    bx_pc_system.initialize(50000000u);
    live_breadcrumb(33, '3');
    glue_init_crumb('P');                 // 'P' = pc_system initialized

    // ─── FIX v4: BX_MEM(0)->init_memory(guest, host) ───────────────────────
    // BX_MEM_C::registerMemoryHandlers indexes BX_MEM_THIS memory_handlers[]
    // which is allocated by init_memory(). Without that allocation, the
    // index lookup deref's a null/garbage pointer and host-faults during
    // bochs_set_process_memory().
    //
    // init_memory itself does:
    //   - alloc the vector / blocks / memory_handlers / rom / bogus
    //   - sets pci_enabled = SIM->get_param_bool(BXPN_PCI_ENABLED)->get()
    //
    // The SIM->get_param_bool path is now safe: KernelSIM returns a dummy
    // bx_param_bool_c (value=0) instead of nullptr. See bochs_infra.cpp.
    //
    // ─── FIX v6: shrink host vector from 16 MiB to 1 MiB ──────────────────
    // The kernel heap (kernel.cpp:kernel_heap) is 10 MiB. Asking init_memory
    // for a 16 MiB host vector blows past that and the kernel's operator
    // new() drops into oom_halt(), which writes "OOM HALT 16777216" to VGA
    // text mode and `cli; hlt`s. In graphics mode, VGA text is invisible
    // unless draw_vga_overlay() mirrors it — but the main loop is wedged
    // inside the failing tick, so the user just sees a freeze with the
    // last live breadcrumb still showing '4' (= about-to-call-init_memory).
    //
    // The host vector itself is mostly bookkeeping in our setup. Real
    // guest memory is owned by the ElfProcess slabs; we route every
    // physical access via registerMemoryHandlers' read_handler /
    // write_handler callbacks (mem_read_handler, mem_write_handler above)
    // and never touch BX_MEM's vector. So the smallest legal value is
    // fine: 1 MiB satisfies the BX_ASSERT((host & 0xfffff) == 0) check
    // and leaves the heap with plenty of room for everything else
    // init_memory itself wants to new[] (blocks table, memory_handlers
    // table, rom, bogus).
    live_breadcrumb(34, '4');
    BX_MEM(0)->init_memory(1u * 1024u * 1024u, 1u * 1024u * 1024u);
    live_breadcrumb(35, '5');
    glue_init_crumb('M');                 // 'M' = mem subsystem initialized

#if BX_GLUE_SKIP_INITIALIZE
    // Default path: skip initialize() entirely. The static ctor of
    // BX_CPU_C plus reset(BX_RESET_HARDWARE) is enough.
    glue_init_crumb('S');                // 'S' = Skipped initialize()
    g_cpu_inited_once = true;
    return;
#else
    glue_init_crumb('i');
    bx_panic_jmpbuf_armed = 1;
    if (setjmp(bx_panic_jmpbuf) != 0) {
        // initialize() panicked. Mark it failed so we don't retry on the
        // next launch, and let the caller fall through to reset().
        bx_panic_jmpbuf_armed = 0;
        g_cpu_init_failed = true;
        glue_init_crumb('!');
        return;
    }
    BX_CPU(0)->initialize();
    bx_panic_jmpbuf_armed = 0;
    g_cpu_inited_once = true;
    glue_init_crumb('I');
#endif
}

extern "C" void bochs_cpu_init() {
    live_breadcrumb(30, '0');
    bochs_cpu_initialize_guarded();
    live_breadcrumb(36, '6');
    bochs_cpu_reset_for_launch();
    live_breadcrumb(38, '8');
    // Note: do NOT clear g_cpu_ready here. bochs_cpu_set_eip() will set
    // it to true when the kernel hands us an entry point. Clearing it
    // means a relaunch that calls reset->set_esp->set_eip is fine; but
    // a stray reset that doesn't follow up with set_eip would also be
    // fine (the next set_eip arms it). Leaving the prior value alone
    // is the more conservative choice.
}

// Optional explicit one-shot prewarm. kernel.cpp can call this from
// kernel_main before any ELF launches; it does the same work as the
// first call to bochs_cpu_init() but is named for clarity at the
// startup site. Safe to call zero or many times.
extern "C" void bochs_cpu_prewarm() {
    bochs_cpu_initialize_guarded();
}

// ─── DIAGNOSTIC: panic recovery state ────────────────────────────────────────
// bochs_infra.cpp's panic/fatal/quit_sim/Unwind handlers longjmp here instead
// of halting the whole kernel. bochs_cpu_tick() arms the buffer before each
// cpu_loop call so a Bochs internal panic returns control to the kernel
// main loop with a VGA breadcrumb identifying which path fired:
//   P = logfunctions::panic   F = fatal1   X = fatal
//   Q = quit_sim              U = _Unwind_Resume
//
// Breadcrumb columns on VGA row 0:
//   col 70: panic tag          (red BG, set by infra recover handler)
//   col 72: 'B' = entered cpu_loop, 'A' = returned cleanly
//   col 73: rotating digit so we can see ticks happening
//   col 79: kernel main-loop spinner (set by kernel.cpp)

// (setjmp.h already included at top of file; jmp_buf forward-declared there.)
extern "C" {
    jmp_buf bx_panic_jmpbuf;
    int     bx_panic_jmpbuf_armed = 0;
    volatile int bx_last_panic_code = 0;
    // Symbol-resolved panic-diag buffer. Readable from the host (e.g. via
    // QEMU monitor `pmemsave`) when the kernel is in graphics mode and
    // VGA text-mode breadcrumbs aren't visible. Written by vga_breadcrumb()
    // in bochs_infra.cpp on every Bochs panic/fatal path.
    //   [0]  last tag char ('P' panic, 'F' fatal1, 'X' fatal, 'Q' quit_sim,
    //                       'U' unwind)
    //   [1]  total recovery count (uint8 wraps)
    //   [2..63] ring of last 62 tags
    volatile unsigned char bx_panic_breadcrumbs[64] = {0};
}

static void glue_breadcrumb(int col, char c) {
    volatile unsigned short* p = (volatile unsigned short*)(0xB8000 + 2*col);
    *p = (unsigned short)(0x2F00 | (unsigned char)c);  // white-on-green
}

extern "C" int bochs_cpu_tick(int n) {
    if (!g_cpu_ready || g_active_slot < 0) return 0;
    if (!g_slots[g_active_slot].mem_base) return 0;

    g_slots[g_active_slot].wants_input = false;

    // Cooperative budget: cpu_loop() only returns through handleAsyncEvent().
    // handleAsyncEvent() is only entered when async_event != 0. So we set
    // both async_event and kill_bochs_request before each call so the very
    // first iteration of cpu_loop's outer while() returns to us.
    if (n < 1) n = 1;
    if (n > 4) n = 4;

    static unsigned tick_seq = 0;
    glue_breadcrumb(73, '0' + (char)((tick_seq++) % 10));

    for (int i = 0; i < n; ++i) {
        // Arm panic recovery: any BX_PANIC/BX_FATAL/_Unwind_Resume inside
        // cpu_loop will longjmp back here instead of halting the host.
        bx_panic_jmpbuf_armed = 1;
        if (setjmp(bx_panic_jmpbuf) != 0) {
            // Came back via longjmp from a Bochs panic. The breadcrumb is
            // already on screen at column 70. Stop ticking this slot so we
            // don't keep re-entering the same panic path every frame.
            bx_panic_jmpbuf_armed = 0;
            if (g_active_slot >= 0 && g_active_slot < MAX_BOCHS_SLOTS) {
                SlotState& s = g_slots[g_active_slot];
                if (s.exit_cb) s.exit_cb(g_active_slot, -1);
            }
            return 0;
        }

        glue_breadcrumb(72, 'B');               // before cpu_loop
        // Make sure both yield flags are CLEAR so cpu_loop actually runs
        // instructions. The yield is requested from bochs_guest_putc when
        // the guest writes a byte to port 0xE9 (or other I/O paths). If we
        // pre-armed them here, the very first iteration of cpu_loop's
        // while(1) would call handleAsyncEvent and bail out without
        // executing a single guest instruction.
        bx_pc_system.kill_bochs_request = 0;
        BX_CPU(0)->cpu_loop();
        bx_pc_system.kill_bochs_request = 0;
        glue_breadcrumb(72, 'A');               // after cpu_loop

        bx_panic_jmpbuf_armed = 0;
    }
    return 0;
}

extern "C" bool bochs_process_wants_input(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

extern "C" void bochs_cpu_set_eip(Bit32u eip) {
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    BX_CPU(0)->prev_rip = eip;
    BX_CPU(0)->invalidate_prefetch_q();
    g_cpu_ready = true;
}

extern "C" void bochs_cpu_set_esp(Bit32u esp_val) {
    BX_CPU(0)->gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
}

extern "C" Bit32u bochs_cpu_get_eip() {
    return BX_CPU(0)->get_eip();
}

extern "C" unsigned int bochs_cpu_geteip() {
    return (unsigned int)BX_CPU(0)->get_eip();
}

extern "C" Bit32u bochs_cpu_get_eax() {
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}