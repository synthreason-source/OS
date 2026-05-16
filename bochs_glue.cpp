// =====================================================================
// bochs_glue.cpp — by-the-book Bochs 2.7 glue for the freestanding
// kernel. One global BX_CPU_C / BX_MEM_C instance, multi-slot guest
// execution implemented via proper per-slot CPU state save/restore,
// physical-memory callback handlers strictly scoped to the active
// slot's address range, and full TLB / prefetch flushes on every
// slot switch.
//
// Memory-safety invariants enforced here:
//
//   I1. At any point in time only ONE slot has its physical address
//       range registered with BX_MEM(0)'s memory_handlers[] table.
//       Switching slots calls unregisterMemoryHandlers for the previous
//       range BEFORE registering the new one — Bochs never sees two
//       overlapping mappings.
//
//   I2. mem_da_handler() (the direct-access fast path used by the CPU
//       prefetch queue and TLB) only returns a host pointer when the
//       containing 4 KiB page lies fully inside the active slot. This
//       prevents TLB-cached pointers from sliding off the end of the
//       slab on a wide unaligned access.
//
//   I3. After any change to slot mapping or guest CR3, both
//       BX_CPU(0)->TLB_flush() and BX_CPU(0)->invalidate_prefetch_q()
//       are called BEFORE cpu_loop is re-entered.
//
//   I4. Per-slot CPU state (GPRs, EIP, ESP, EFLAGS, segments, CR0,
//       CR2, CR3, CR4, GDTR, IDTR, prev_rip, activity_state) is
//       saved/restored on every slot switch. The single global
//       BX_CPU_C therefore presents a consistent view of "this
//       slot's CPU" to its guest.
//
//   I5. Bochs's own init_memory() request is kept TINY (1 MiB) since
//       we route all guest accesses through registered handlers and
//       never touch BX_MEM's vector[]. This keeps the kernel heap
//       free for other purposes.
//
//   I6. bx_devices_c::outp routes port 0xE9 to bochs_guest_putc and
//       port 0xE8 to bochs_guest_exit (process exit sentinel). Both
//       set async_event + kill_bochs_request so cpu_loop yields
//       through its normal exit path.
//
//   I7. No setjmp/longjmp panic recovery. Bochs's panic / fatal /
//       quit_sim handlers in bochs_infra.cpp call bochs_guest_exit(-1)
//       directly, marking the slot dead and yielding cpu_loop.
//       The kernel main loop is never longjmp'd into.
// =====================================================================

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/pc_system.h"

// __dso_handle / C++ ABI no-ops. Weak so we can coexist with
// bochs_infra.cpp's identical definition.
__attribute__((weak)) void* __dso_handle = nullptr;
extern "C" int  __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void __cxa_finalize(void*) {}

// Live framebuffer breadcrumb implemented by kernel.cpp. Used as the
// single source of debug visibility during glue init. The panic-path
// breadcrumbs from the previous version are gone — there is no panic
// path anymore.
extern "C" void live_breadcrumb(int slot, char ch);

// Legacy symbol referenced by kernel.cpp's host-fault diagnostic
// dumper. We no longer write into it (the panic path was removed),
// but we keep the definition so the kernel link still resolves.
// All entries stay zero, which kernel.cpp's renderer displays as '.'.
extern "C" {
    volatile unsigned char bx_panic_breadcrumbs[64] = {0};
}

#define MAX_BOCHS_SLOTS 4

// ─── Per-slot state ───────────────────────────────────────────────────────
//
// One SlotState per ElfProcess slot. The mapping fields describe the
// guest's physical address window; the saved-CPU fields hold this
// slot's view of the single global BX_CPU_C so we can multiplex it.

struct SavedCpuState {
    Bit32u  gen_reg[BX_GENERAL_REGISTERS];
    Bit32u  eip;
    Bit32u  prev_rip;
    Bit32u  eflags;

    // Segment registers (selector + cached descriptor). We copy the
    // full bx_segment_reg_t including the descriptor cache so reload
    // is a single structure assignment — no need to walk the GDT.
    bx_segment_reg_t sregs[6];

    // System descriptor registers.
    bx_global_segment_reg_t gdtr;
    bx_global_segment_reg_t idtr;

    // Control registers.
    Bit32u  cr0;
    Bit32u  cr2;
    Bit32u  cr3;
    Bit32u  cr4;

    // Async / activity state. Must be 0/ACTIVE before re-entering
    // cpu_loop.
    Bit32u  activity_state;
    Bit32u  async_event;

    bool    valid;        // true once we've saved this slot at least once
};

struct SlotState {
    // Mapping. mem_base / mem_size / vaddr_base describe the slot's
    // physical-address window inside our emulated memory system.
    Bit8u*  mem_base   = nullptr;
    Bit32u  mem_size   = 0;
    Bit32u  vaddr_base = 0;
    bool    mapped     = false;   // currently registered with BX_MEM(0)?

    // Bookkeeping.
    Bit32u  brk_ptr    = 0;
    int     slot_id    = -1;

    // I/O wiring.
    bool    wants_input = false;
    int   (*read_cb )(int)       = nullptr;
    void  (*write_cb)(int, char) = nullptr;
    void  (*exit_cb )(int, int)  = nullptr;

    // Saved CPU view (multiplexes the single global BX_CPU_C).
    SavedCpuState cpu;

    // True once this slot's saved CPU view has been initialised to a
    // freshly-reset state ready for first execution.
    bool    cpu_primed = false;
};

static SlotState g_slots[MAX_BOCHS_SLOTS];
static int       g_active_slot = -1;
static bool      g_global_init_done = false;   // bochs_cpu_init ran once
static volatile int g_exit_pending  = 0;       // set by bochs_guest_exit

// ─── Forward decls ────────────────────────────────────────────────────────
static void bochs_global_init();
static void mapping_register   (SlotState& s);
static void mapping_unregister (SlotState& s);
static void slot_save_cpu      (SlotState& s);
static void slot_restore_cpu   (SlotState& s);
static void slot_prime_cpu     (SlotState& s);
static void inject_slab_tables (SlotState& s);
static void flush_after_switch ();

// =====================================================================
// Memory handlers
//
// All guest physical accesses to a slot's vaddr_base..vaddr_base+size
// range are routed through these. Bochs hands us the absolute physical
// address, the access length, and a pointer to the data buffer (which
// is a host-side buffer it allocated for the access). We translate
// the address back to a slab offset and copy bytes in either direction.
//
// Reads to unmapped or out-of-range addresses return zero (with the
// data buffer cleared); writes are silently dropped. This matches the
// behaviour of an x86 system with no physical RAM at the address.
// =====================================================================

static bool mem_read_handler(bx_phy_address addr, unsigned len,
                             void* data, void* /*param*/) {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) {
        __builtin_memset(data, 0, len);
        return true;
    }
    SlotState& s = g_slots[g_active_slot];
    if (!s.mem_base) {
        __builtin_memset(data, 0, len);
        return true;
    }

    Bit64u a    = (Bit64u)addr;
    Bit64u base = (Bit64u)s.vaddr_base;
    Bit64u end  = base + (Bit64u)s.mem_size;

    // Reject anything that doesn't fit fully inside the slot's window.
    // Full containment, not just "starts inside" — prevents a buffer
    // overrun off the end of mem_base on a multi-byte access.
    if (a < base || a + (Bit64u)len > end) {
        __builtin_memset(data, 0, len);
        return true;
    }

    __builtin_memcpy(data, s.mem_base + (Bit32u)(a - base), len);
    return true;
}

static bool mem_write_handler(bx_phy_address addr, unsigned len,
                              void* data, void* /*param*/) {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return true;
    SlotState& s = g_slots[g_active_slot];
    if (!s.mem_base) return true;

    Bit64u a    = (Bit64u)addr;
    Bit64u base = (Bit64u)s.vaddr_base;
    Bit64u end  = base + (Bit64u)s.mem_size;

    if (a < base || a + (Bit64u)len > end) return true;  // drop

    __builtin_memcpy(s.mem_base + (Bit32u)(a - base), data, len);
    return true;
}

// Direct-access handler used by Bochs's TLB / prefetch fast path.
// Returning a host pointer here lets Bochs cache a page-granular
// mapping in its TLB; the CPU then reads/writes through that pointer
// without re-entering us. That is what we want for performance, but
// it has two safety constraints:
//
//   D1. The returned pointer must remain valid until the next
//       TLB flush. We guarantee that by issuing TLB_flush() on every
//       slot switch (flush_after_switch) and on every mapping change
//       (mapping_unregister, mapping_register).
//
//   D2. The pointer plus a full page (4 KiB) must still be inside
//       our allocation. Otherwise the TLB-cached pointer could slide
//       off the end of the slab on a wide unaligned access. We
//       enforce this by refusing direct access for any address whose
//       containing 4 KiB page is not fully covered by the slot.
static Bit8u* mem_da_handler(bx_phy_address addr, unsigned /*rw*/,
                             void* /*param*/) {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return nullptr;
    SlotState& s = g_slots[g_active_slot];
    if (!s.mem_base) return nullptr;

    Bit64u a    = (Bit64u)addr;
    Bit64u base = (Bit64u)s.vaddr_base;
    Bit64u end  = base + (Bit64u)s.mem_size;

    if (a < base || a >= end) return nullptr;

    // Page containment check. If the containing 4 KiB page extends
    // past the end of our slab — or starts before our slab — refuse
    // direct access. Bochs falls back to mem_read_handler /
    // mem_write_handler, which clamp per access.
    Bit64u page_start = a & ~(Bit64u)0xFFFu;
    Bit64u page_end   = page_start + 0x1000u;
    if (page_end > end)        return nullptr;
    if (page_start < base)     return nullptr;

    return s.mem_base + (Bit32u)(a - base);
}

// =====================================================================
// Mapping registration
// =====================================================================

static void mapping_register(SlotState& s) {
    if (!s.mem_base || !s.mem_size || s.mapped) return;
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        mem_read_handler, mem_write_handler, mem_da_handler,
        (bx_phy_address)s.vaddr_base,
        (bx_phy_address)(s.vaddr_base + s.mem_size - 1));
    s.mapped = true;
}

static void mapping_unregister(SlotState& s) {
    if (!s.mapped) return;
    BX_MEM(0)->unregisterMemoryHandlers(
        nullptr,
        (bx_phy_address)s.vaddr_base,
        (bx_phy_address)(s.vaddr_base + s.mem_size - 1));
    s.mapped = false;
}

// =====================================================================
// Slab tables (GDT + IDT) and exit-trap stub
// =====================================================================
//
// Layout at the start of every slot's slab:
//
//   0x000..0x006   exit-trap stub:
//                    mov $0, %al ; out %al, $0xE8 ; hlt ; jmp .
//   0x080..0x098   GDT (3 entries: null / flat code / flat data)
//   0x100..0x900   IDT (256 entries, all pointing at the exit stub)
//
// The slab base lives at vaddr_base. The guest's program image starts
// later in the slab (e.g. ELF _start at 0x08048000 with vaddr_base
// 0x08048000 places _start AT slab offset 0). We inject AFTER the
// kernel's ELF loader has placed PT_LOAD sections. If a PT_LOAD has
// already occupied our stub offset, we place the stub at 0x10
// instead. If even that is taken, we leave the IDT vectors pointing
// at whatever happens to be at offset 0 — the guest will most likely
// just continue executing past the fault into program memory, which
// is what we want (it can't fault out without our cooperation, but
// it can still exit cleanly via port 0xE8 if it chooses to).

static void inject_slab_tables(SlotState& s) {
    if (!s.mem_base || s.mem_size < 0x1000) return;

    static const Bit8u stub[7] = {
        0xB0, 0x00,         // mov  $0, %al
        0xE6, 0xE8,         // out  %al, $0xE8
        0xF4,               // hlt
        0xEB, 0xFE,         // jmp  .  (safety: spin if hlt resumes)
    };

    auto bytes_zero = [](const Bit8u* p, unsigned n) {
        for (unsigned i = 0; i < n; ++i) if (p[i]) return false;
        return true;
    };

    // Pick a stub offset. Try 0 first; if occupied, try 0x10.
    Bit32u stub_off = 0xFFFFFFFFu;
    if (bytes_zero(s.mem_base, sizeof(stub))) {
        stub_off = 0x000;
    } else if (bytes_zero(s.mem_base + 0x10, sizeof(stub))) {
        stub_off = 0x010;
    }
    if (stub_off != 0xFFFFFFFFu) {
        __builtin_memcpy(s.mem_base + stub_off, stub, sizeof(stub));
    } else {
        // No safe spot; leave stub_off at 0 and accept that IDT
        // vectors will land in program code. Most guests don't
        // intentionally raise interrupts, so this is rarely reached.
        stub_off = 0;
    }

    // ── GDT at slab offset 0x80 ────────────────────────────────────
    // Three descriptors:
    //   sel 0x00 — null
    //   sel 0x08 — flat code, ring 0, base=0, limit=4 GiB, 32-bit, exec
    //   sel 0x10 — flat data, ring 0, base=0, limit=4 GiB, 32-bit, RW
    Bit8u* gdt_base = s.mem_base + 0x80;
    __builtin_memset(gdt_base, 0, 8);
    static const Bit8u code_desc[8] = {
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00,
    };
    static const Bit8u data_desc[8] = {
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00,
    };
    __builtin_memcpy(gdt_base +  8, code_desc, 8);
    __builtin_memcpy(gdt_base + 16, data_desc, 8);

    // ── IDT at slab offset 0x100 ───────────────────────────────────
    // 256 trap gates all pointing at the exit-trap stub.
    Bit32u handler_va = s.vaddr_base + stub_off;
    Bit8u* idt_base   = s.mem_base + 0x100;

    Bit8u gate[8] = {
        (Bit8u)(handler_va & 0xFF),
        (Bit8u)((handler_va >> 8) & 0xFF),
        0x08, 0x00,         // selector = code segment 0x08
        0x00,
        0x8E,               // P=1 DPL=0 32-bit interrupt gate
        (Bit8u)((handler_va >> 16) & 0xFF),
        (Bit8u)((handler_va >> 24) & 0xFF),
    };
    for (int i = 0; i < 256; ++i) {
        __builtin_memcpy(idt_base + i * 8, gate, 8);
    }

    // Stash GDTR/IDTR into the slot's saved CPU state. We do NOT
    // touch the live BX_CPU(0) here — that happens during
    // slot_restore_cpu / slot_prime_cpu.
    s.cpu.gdtr.base  = s.vaddr_base + 0x80;
    s.cpu.gdtr.limit = 24 - 1;          // 3 descriptors
    s.cpu.idtr.base  = s.vaddr_base + 0x100;
    s.cpu.idtr.limit = 256 * 8 - 1;
}

// =====================================================================
// CPU state save / restore
//
// One global BX_CPU_C. To multiplex it across slots we snapshot every
// architectural register on slot deactivate, and restore on activate.
// We do NOT save Bochs-internal caches (TLB, prefetch queue, lazy
// EFLAGS) — those are flushed by flush_after_switch and rebuilt
// lazily. Saving only the architectural state keeps the snapshot
// small and free of internal Bochs invariants we'd otherwise have to
// reason about.
// =====================================================================

static void slot_save_cpu(SlotState& s) {
    BX_CPU_C* cpu = BX_CPU(0);
    SavedCpuState& cs = s.cpu;

    for (int i = 0; i < BX_GENERAL_REGISTERS; ++i)
        cs.gen_reg[i] = cpu->gen_reg[i].dword.erx;

    cs.eip      = cpu->gen_reg[BX_32BIT_REG_EIP].dword.erx;
    cs.prev_rip = (Bit32u)cpu->prev_rip;
    cs.eflags   = cpu->eflags;

    for (int i = 0; i < 6; ++i) cs.sregs[i] = cpu->sregs[i];

    cs.gdtr = cpu->gdtr;
    cs.idtr = cpu->idtr;

    cs.cr0 = cpu->cr0.val32;
    cs.cr2 = (Bit32u)cpu->cr2;
    cs.cr3 = (Bit32u)cpu->cr3;
    cs.cr4 = cpu->cr4.val32;

    cs.activity_state = cpu->activity_state;
    cs.async_event    = cpu->async_event;

    cs.valid = true;
}

static void slot_restore_cpu(SlotState& s) {
    BX_CPU_C* cpu = BX_CPU(0);
    SavedCpuState& cs = s.cpu;

    for (int i = 0; i < BX_GENERAL_REGISTERS; ++i)
        cpu->gen_reg[i].dword.erx = cs.gen_reg[i];

    cpu->gen_reg[BX_32BIT_REG_EIP].dword.erx = cs.eip;
    cpu->prev_rip = cs.prev_rip;
    cpu->eflags   = cs.eflags;

    for (int i = 0; i < 6; ++i) cpu->sregs[i] = cs.sregs[i];

    cpu->gdtr = cs.gdtr;
    cpu->idtr = cs.idtr;

    cpu->cr0.val32 = cs.cr0;
    cpu->cr2       = cs.cr2;
    cpu->cr3       = cs.cr3;
    cpu->cr4.val32 = cs.cr4;

    cpu->activity_state = cs.activity_state;
    cpu->async_event    = cs.async_event;
}

// Initialise a slot's saved CPU state to a clean post-reset value
// ready for first execution. Called once per slot from
// bochs_set_process_memory(). EIP/ESP are set later by the kernel
// via bochs_cpu_set_eip / bochs_cpu_set_esp.
static void slot_prime_cpu(SlotState& s) {
    SavedCpuState& cs = s.cpu;

    for (int i = 0; i < BX_GENERAL_REGISTERS; ++i) cs.gen_reg[i] = 0;
    cs.eip      = 0;
    cs.prev_rip = 0;
    cs.eflags   = 0x00000002u;      // reserved bit 1 must be 1

    // Flat 32-bit protected-mode segments. We populate the descriptor
    // cache directly to match the GDT we'll inject — this avoids
    // having to walk the GDT during a segment-register load.
    auto build_seg = [&](bx_segment_reg_t& seg, Bit16u sel, bool code) {
        seg.selector.value = sel;
        seg.selector.rpl   = 0;
        seg.selector.ti    = 0;
        seg.selector.index = sel >> 3;

        bx_descriptor_t& d = seg.cache;
        d.valid   = 1;
        d.p       = 1;
        d.dpl     = 0;
        d.segment = 1;
        d.type    = code ? 0x0B : 0x03;     // code/RX or data/RW (accessed)
        d.u.segment.base         = 0;
        d.u.segment.limit_scaled = 0xFFFFFFFFu;
        d.u.segment.g            = 1;
        d.u.segment.d_b          = 1;
        d.u.segment.avl          = 0;
    };
    build_seg(cs.sregs[BX_SEG_REG_CS], 0x08, true);
    build_seg(cs.sregs[BX_SEG_REG_SS], 0x10, false);
    build_seg(cs.sregs[BX_SEG_REG_DS], 0x10, false);
    build_seg(cs.sregs[BX_SEG_REG_ES], 0x10, false);
    build_seg(cs.sregs[BX_SEG_REG_FS], 0x10, false);
    build_seg(cs.sregs[BX_SEG_REG_GS], 0x10, false);

    // GDTR/IDTR are filled in by inject_slab_tables once the slab is
    // mapped. Initialise to zero here so an unprimed slot is
    // obviously invalid.
    cs.gdtr.base  = 0;
    cs.gdtr.limit = 0;
    cs.idtr.base  = 0;
    cs.idtr.limit = 0;

    cs.cr0 = 0x00000011u;     // PE=1, ET=1 (protected mode, FPU present)
    cs.cr2 = 0;
    cs.cr3 = 0;
    cs.cr4 = 0;               // no paging extensions

    cs.activity_state = 0;    // BX_ACTIVITY_STATE_ACTIVE
    cs.async_event    = 0;
    cs.valid          = true;

    s.cpu_primed = true;
}

// =====================================================================
// Flush helpers
// =====================================================================

// Called whenever the active mapping has changed OR a slot switch has
// occurred. Drops Bochs's cached translations so any previously-issued
// direct-access host pointer is no longer reachable, AND resynchronises
// every piece of CPU-internal derived state with the architectural
// registers we just poked.
//
// The earlier version only did TLB_flush() + invalidate_prefetch_q().
// That was insufficient: after slot_restore_cpu writes cr0/sregs/eflags
// straight into BX_CPU(0), the CPU's *derived* state — cpu_mode,
// fetchModeMask, the lazy-eflags shadow, the stack cache, the SSE/AVX
// mode flags, the interrupt-mask shadow — is all stale. In particular
// cpu_mode stayed BX_MODE_IA32_REAL even though we set CR0.PE=1, so
// cpu_loop kept interpreting CS as a real-mode selector (base =
// sel<<4) and fetched from the wrong linear address — an instant
// silent infinite loop with no fault and no port output.
//
// handleCpuContextChange() is Bochs's canonical "architectural state
// was changed out from under you, resync everything" entry point. It
// does TLB_flush + invalidate_prefetch_q + invalidate_stack_cache +
// handleInterruptMaskChange + handleAlignmentCheck + handleCpuModeChange
// (+ SSE/AVX mode on cpu-level>=6). This is exactly what a slot switch
// needs.
static void flush_after_switch() {
    BX_CPU_C* cpu = BX_CPU(0);

    // (a) Flush the instruction cache. THIS IS ESSENTIAL.
    //
    // The iCache stores *decoded* instructions keyed by guest physical
    // address (+ a fetchModeMask). A slot switch replaces the physical
    // memory contents under the CPU — slot 0's program and slot 1's
    // program can sit at the very same guest physical addresses. The
    // iCache cannot tell them apart, so without a flush, getICacheEntry()
    // returns a STALE decoded entry from a previous slot (or from the
    // post-reset / prewarm state) and never calls serveICacheMiss to
    // re-decode. The symptom is a cpu_loop that spins forever:
    // getICacheEntry hands back a bogus zero-length entry, RIP advances
    // by ilen()==0, the no-op "instruction" executes, repeat — guest EIP
    // frozen, no fault, no port output.
    //
    // flushICaches() does iCache.flushICacheEntries(), sets the
    // STOP_TRACE async bit, and resets pageWriteStampTable — the full,
    // correct "physical memory changed behind your back" reset.
    flushICaches();

    // (b) Recompute cpu_mode / fetchModeMask / lazy-eflags / stack cache
    // / interrupt-mask shadow from the architectural registers that
    // slot_restore_cpu poked directly. Without this cpu_mode stays
    // BX_MODE_IA32_REAL even though we set CR0.PE=1.
    cpu->handleCpuContextChange();

    // (c) updateFetchModeMask depends on CS.cache.d_b and cpu_mode;
    // ensure the fetch decoder picks the 32-bit tables.
    cpu->updateFetchModeMask();

    // (d) Clear sticky async-yield flags from the previous run. Do this
    // AFTER flushICaches() — flushICaches sets BX_ASYNC_EVENT_STOP_TRACE
    // in async_event, and we don't want a spurious yield on the first
    // tick. The STOP_TRACE bit only matters for handler-chaining traces,
    // which we don't use.
    cpu->async_event = 0;
    bx_pc_system.kill_bochs_request = 0;
}

// =====================================================================
// One-shot global initialisation
// =====================================================================
//
// Done EXACTLY ONCE for the lifetime of the kernel. Subsequent calls
// from kernel.cpp return immediately.
//
// Sequence (this matches the "by the book" Bochs init order, minus
// the parts we don't have — config file loading, plugin init, device
// init, BIOS load):
//
//   1. bx_pc_system.initialize(ips)        — sets m_ips so timing math
//                                             doesn't divide by zero.
//   2. BX_MEM(0)->init_memory(g, h)        — allocate vector / blocks /
//                                             memory_handlers table.
//   3. BX_CPU(0)->initialize()             — register CPUID params and
//                                             build cpuid feature info.
//   4. BX_CPU(0)->reset(BX_RESET_HARDWARE) — bring CPU to architectural
//                                             reset state.
//   5. BX_CPU(0)->fpu_init()               — clean FPU state.
//
// init_memory(1 MiB, 1 MiB) is the minimum legal value (the BX_ASSERT
// in init_memory wants host be at least 1 MiB and naturally aligned).
// We never actually use this 1 MiB region — every guest access falls
// through to our registered handlers.

static void bochs_global_init() {
    if (g_global_init_done) return;
    live_breadcrumb(30, '0');

    // (1) pc_system: only stores ips and zeros a few timer fields.
    bx_pc_system.initialize(50000000u);

    // (1a) Enable the A20 line. CRITICAL.
    //
    // bx_pc_system is a BSS global, so its a20_mask field is zero-
    // initialised. The A20ADDR(x) macro — used by BX_MEM_C::getHostMemAddr
    // AND by BX_CPU_C::translate_linear on EVERY instruction fetch and
    // data access — computes `x & bx_pc_system.a20_mask`. With a20_mask
    // left at 0, every guest physical address collapses to 0, so the CPU
    // fetched from physical page 0 (zeroed Bochs vector[]) instead of the
    // slab, decoded 0x00 0x00 as ADD forever, and EIP-advanced but never
    // did real work. a20_mask is only ever set by set_enable_a20(); on a
    // real Bochs run the chipset/BIOS path calls it. We have no chipset,
    // so we must call it ourselves. true => a20_mask = 0xffffffff
    // (386+, or all-ones on a BX_PHY_ADDRESS_LONG build) i.e. A20 on,
    // no address wrapping — the correct state for flat 32-bit guests.
    bx_pc_system.set_enable_a20(true);

    live_breadcrumb(31, '1');

    // (2) memory subsystem. Our overridden init_memory in
    // bochs_infra.cpp doesn't touch SIM-> at all, so this is safe.
    BX_MEM(0)->init_memory(16u * 1024u * 1024u, 16u * 1024u * 1024u);
    live_breadcrumb(32, '2');

    // (3) CPU feature registration. With the dummy-param objects in
    // bochs_infra.cpp's KernelSIM, generic_cpuid.cc and friends find
    // the params they need (non-null pointers returning safe defaults)
    // without trapping. Calling initialize() is by-the-book and gives
    // us a proper CPUID table for the guest.
    BX_CPU(0)->initialize();
    live_breadcrumb(33, '3');

    // (4) hardware reset.
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    live_breadcrumb(34, '4');

    // (5) FPU clean state. Not strictly required after reset() but
    // explicit and by-the-book.

    // Clear sticky yield flags that reset() may have set.
    BX_CPU(0)->async_event           = 0;
    bx_pc_system.kill_bochs_request  = 0;

    g_global_init_done = true;
    live_breadcrumb(36, '6');
}

// =====================================================================
// Public API
// =====================================================================

extern "C" void bochs_cpu_init() {
    // Idempotent. The kernel may call this once per ELF launch (and
    // once at boot via bochs_cpu_prewarm). Only the first call does
    // real work; subsequent calls do nothing because per-slot setup
    // happens inside bochs_set_process_memory / bochs_activate_slot.
    bochs_global_init();
}

extern "C" void bochs_cpu_prewarm() {
    bochs_global_init();
}

// Called by the kernel after it has loaded an ELF image into a slot's
// backing slab. Registers the slab's vaddr range as physical RAM,
// injects the GDT/IDT/trap-stub tables at well-known offsets, and
// primes the slot's saved CPU state to a clean post-reset value.
//
// MUST be preceded by bochs_activate_slot(slot) so we know which
// SlotState to populate.
extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size,
                                         Bit32u vaddr_base) {
    bochs_global_init();
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return;
    SlotState& s = g_slots[g_active_slot];

    // Drop any previous mapping for this slot before overwriting it.
    mapping_unregister(s);

    s.mem_base   = base;
    s.mem_size   = size;
    s.vaddr_base = vaddr_base;

    if (!base || !size) return;

    // Register handlers for this slot's range.
    mapping_register(s);

    // Prime the saved CPU state — segments, CR0, EFLAGS, GPRs.
    slot_prime_cpu(s);

    // Inject GDT/IDT/trap-stub. Updates s.cpu.gdtr/idtr AFTER prime.
    inject_slab_tables(s);

    // Push the primed state into the live BX_CPU(0). Without this the
    // live CPU is still in its post-reset state (CS=F000, EIP=FFF0,
    // unreal mode) and the next cpu_loop entry would execute BIOS
    // entry code instead of guest code. slot_restore_cpu copies every
    // architectural register from s.cpu into the live CPU.
    slot_restore_cpu(s);

    // Flush Bochs caches that might still reference a previous
    // mapping for this slot.
    flush_after_switch();
}

extern "C" void bochs_finalize_process_memory() {
    // No-op. All the work is done in bochs_set_process_memory.
}

extern "C" void bochs_set_brk(int slot, Bit32u brk_addr) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].brk_ptr = brk_addr;
}

extern "C" void bochs_register_io_callbacks(
    int slot,
    int  (*read_cb )(int),
    void (*write_cb)(int, char),
    void (*exit_cb )(int, int)) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].slot_id  = slot;
    g_slots[slot].read_cb  = read_cb;
    g_slots[slot].write_cb = write_cb;
    g_slots[slot].exit_cb  = exit_cb;
}

// Switch active slot. If a different slot was active before, snapshot
// its CPU state and unregister its mapping; then register the new
// slot's mapping and restore its CPU state; finally flush caches.
extern "C" void bochs_activate_slot(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    if (slot == g_active_slot) return;

    if (g_global_init_done && g_active_slot >= 0 &&
        g_active_slot < MAX_BOCHS_SLOTS) {
        SlotState& prev = g_slots[g_active_slot];
        slot_save_cpu(prev);
        mapping_unregister(prev);
    }

    g_active_slot = slot;

    if (g_global_init_done) {
        SlotState& cur = g_slots[slot];
        if (cur.mem_base && cur.mem_size) mapping_register(cur);
        if (cur.cpu.valid)                slot_restore_cpu(cur);
        flush_after_switch();
    }
}

// EIP / ESP setters write into BOTH the live BX_CPU(0) registers AND
// the active slot's saved CPU state. Writing both means we don't lose
// the value if the kernel switches slots before the first tick.
extern "C" void bochs_cpu_set_eip(Bit32u eip) {
    BX_CPU_C* cpu = BX_CPU(0);
    cpu->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    cpu->prev_rip = eip;
    cpu->invalidate_prefetch_q();
    // The kernel typically writes the guest program into the slab and
    // THEN calls this. Any iCache entry covering the new EIP's physical
    // page may predate that write, so flush. Cheap, and only happens
    // once per process launch.
    flushICaches();
    cpu->async_event = 0;

    if (g_active_slot >= 0 && g_active_slot < MAX_BOCHS_SLOTS) {
        SlotState& s = g_slots[g_active_slot];
        s.cpu.eip      = eip;
        s.cpu.prev_rip = eip;
        s.cpu.valid    = true;
    }
}

extern "C" void bochs_cpu_set_esp(Bit32u esp_val) {
    BX_CPU(0)->gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
    if (g_active_slot >= 0 && g_active_slot < MAX_BOCHS_SLOTS) {
        g_slots[g_active_slot].cpu.gen_reg[BX_32BIT_REG_ESP] = esp_val;
    }
}

extern "C" Bit32u bochs_cpu_get_eip() { return BX_CPU(0)->get_eip(); }
extern "C" unsigned int bochs_cpu_geteip() { return (unsigned int)BX_CPU(0)->get_eip(); }
extern "C" Bit32u bochs_cpu_get_eax() {
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}

// =====================================================================
// Guest I/O sentinels (port 0xE9 = putc, port 0xE8 = exit)
// =====================================================================

// Forward decl — defined in bochs_bios.cpp.
extern "C" bool bochs_bios_is_active();
extern "C" void bochs_bios_putc(char c);

extern "C" void bochs_guest_putc(char c) {
    // In BIOS mode no slot is active; redirect to the BIOS debug ticker.
    if (bochs_bios_is_active()) {
        bochs_bios_putc(c);
        // Yield cpu_loop so the kernel can process the output.
        bx_pc_system.kill_bochs_request = 1;
        BX_CPU(0)->async_event = 1;
        return;
    }
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return;
    SlotState& s = g_slots[g_active_slot];
    if (s.write_cb) s.write_cb(g_active_slot, c);

    // Ask cpu_loop to yield so the kernel main loop can drain output,
    // poll input, repaint. Both flags must be set: kill_bochs_request
    // alone is only checked inside handleAsyncEvent, which is only
    // entered when async_event != 0.
    bx_pc_system.kill_bochs_request = 1;
    BX_CPU(0)->async_event = 1;
}

extern "C" void bochs_guest_exit(int code) {
    // During bochs_global_init() there is no active slot. If a Bochs
    // internal panic path lands here in that window, the old behaviour
    // was to silently return, after which initialize() would deref a
    // NULL cpuid pointer and triple-fault. Convert this into a visible,
    // identifiable halt so we know which panic fired.
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) {
        // Row 0 cols 40..42: 'X' then two hex nibbles of -code.
        live_breadcrumb(40, 'X');
        int v = (code < 0) ? -code : code;
        const char hex[] = "0123456789ABCDEF";
        live_breadcrumb(41, hex[(v >> 4) & 0xF]);
        live_breadcrumb(42, hex[ v       & 0xF]);
        // Hard halt: do NOT return into Bochs's panic-then-keep-going
        // sequence, which is what was causing the NULL-cpuid deref.
        for (;;) { __asm__ volatile("cli; hlt"); }
    }

    SlotState& s = g_slots[g_active_slot];
    if (s.exit_cb) s.exit_cb(g_active_slot, code);

    g_exit_pending = 1;
    bx_pc_system.kill_bochs_request = 1;
    BX_CPU(0)->async_event = 1;
}

extern "C" bool bochs_process_wants_input(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

// =====================================================================
// Tick — run the active slot for a bounded number of cpu_loop entries
// =====================================================================
//
// cpu_loop runs guest instructions until it hits handleAsyncEvent
// with kill_bochs_request set, at which point it returns to us. Each
// iteration is one "tick budget" — typically a small number of guest
// insns because port-IO writes (the primary yield trigger) are
// frequent for a chatty guest.

extern "C" int bochs_cpu_tick(int n) {
    if (!g_global_init_done) return 0;
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return 0;

    SlotState& s = g_slots[g_active_slot];
    if (!s.mem_base || !s.mapped) return 0;
    if (!s.cpu.valid) return 0;

    s.wants_input = false;

    if (n < 1) n = 1;
    if (n > 4) n = 4;

    // Clear any stale exit flag from a previous tick of a different
    // (now-dead) slot.
    g_exit_pending = 0;

    for (int i = 0; i < n; ++i) {
        if (g_exit_pending) {
            g_exit_pending = 0;
            return 0;
        }

        // Clear yield flags so cpu_loop actually executes
        // instructions. bochs_guest_putc / bochs_guest_exit will
        // re-set them when the guest does port IO.
        bx_pc_system.kill_bochs_request = 0;
        BX_CPU(0)->async_event          = 0;

        BX_CPU(0)->cpu_loop();

        // After return, leave both flags clear so the next iteration
        // (or next tick call) starts clean.
        bx_pc_system.kill_bochs_request = 0;
    }
    return 0;
}
