#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/pc_system.h"

extern "C" void* __dso_handle = nullptr;
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

extern "C" void bochs_cpu_init() {
    BX_CPU(0)->initialize();
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    bochs_cpu_enter_protected_mode();
    g_cpu_ready = false;
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

#include <setjmp.h>
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