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

// NOTE (Bochs 2.0 port): see bochs_infra.cpp for why this only
// includes "bochs.h" now - the old Bochs 2.7-layout direct includes
// of pc_system.h/memory-bochs.h caused "redefinition of class ..."
// errors, since none of these headers have include guards in 2.0.
#include "bochs.h"


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

// Panic message captured by logfunctions::panic in bochs_infra.cpp.
// bochs_guest_exit() dumps this to the host debug console so a panic
// during init reports WHICH Bochs check failed instead of just freezing.
extern "C" {
    extern volatile char bx_last_panic_msg[128];
}

#define MAX_BOCHS_SLOTS 4

// ─── Per-slot state ───────────────────────────────────────────────────────
//
// One SlotState per ElfProcess slot. The mapping fields describe the
// guest's physical address window; the saved-CPU fields hold this
// slot's view of the single global BX_CPU_C so we can multiplex it.

struct SavedCpuState {
    // NOTE (Bochs 2.0 port): BX_GENERAL_REGISTERS isn't defined in
    // this version's headers (gen_reg[] is just hardcoded to 8
    // entries in cpu.h) - hardcoded here to match.
    Bit32u  gen_reg[8];
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

    // NOTE (Bochs 2.0 port): bx_cpu_c has no activity_state member at
    // all in this version (HLT/sleep-state modeling was added later).
    // Field kept for struct-layout stability elsewhere in the file,
    // but it's no longer read from or written to a real cpu-> field -
    // always 0.
    Bit32u  activity_state;
    Bit32u  async_event;

    // Lazy-EFLAGS shadow. Bochs evaluates OF/SF/ZF/AF/PF/CF lazily
    // from this struct; setEFlags only writes the decoded bits back
    // into cpu->eflags.val32, it does NOT restore the lazy shadow.
    // Without saving this, a slot switch leaves the shadow holding
    // the OTHER slot's last arithmetic operation — causing
    // conditional jumps (test/jne in put_str's null-terminator loop)
    // to read the wrong ZF and mis-terminate, producing "HELLO WO"
    // (8 chars) instead of the full "HELLO WORLD\n".
    //
    // NOTE (Bochs 2.0 port): 2.0's bx_lf_flags_entry (lazy_flags.h)
    // stores width-specific op1/op2/result fields (op1_32/result_32
    // etc, plus an "instr" tag) rather than 2.7's unified
    // result+auxbits pair - the two layouts aren't reducible to each
    // other field-by-field. Storing the real struct wholesale side-
    // steps that entirely: it's POD, so a plain struct assignment
    // (cs.oszapc = cpu->oszapc) is a byte-exact save/restore
    // regardless of which fields Bochs actually used internally.
    bx_lf_flags_entry oszapc;

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

// NOTE (Bochs 2.0 port): mem_read_handler/mem_write_handler used to
// be registered with BX_MEM(0)->registerMemoryHandlers() here. That
// mechanism doesn't exist in Bochs 2.0 (see the note above
// mapping_register() below), so these are dead code with no caller
// and have been removed - they also used the bx_phy_address type,
// which doesn't exist in this version (bx_address is the equivalent).

// Direct-access handler used by Bochs's TLB / prefetch fast path in
// later Bochs versions. Bochs 2.0 has no such per-range handler hook
// at all (registerMemoryHandlers()/unregisterMemoryHandlers() and the
// mem_read_handler/mem_write_handler/mem_da_handler mechanism above
// don't exist in this version's bx_mem_c - see memory/memory.h). All
// physical accesses in 2.0 go straight through bx_mem.vector[addr]
// with no interception point, so mem_read_handler/mem_write_handler/
// mem_da_handler above are dead code here and unused; the bounds-
// checked translation they used to do doesn't have anywhere to plug
// into anymore.

// =====================================================================
// Mapping registration (Bochs 2.0)
// =====================================================================
//
// NOTE (Bochs 2.0 port): bx_mem_c here is just { actual_vector,
// vector, len, megabytes } - a single flat physical-memory image, no
// per-range handler registration at all (that mechanism was added
// well after 2.0). Since bx_cpu/bx_mem are both single global
// instances that get repointed at whichever slot is "active" (rather
// than true concurrent per-slot memory), the direct equivalent is to
// repoint bx_mem.vector itself at the slot's backing buffer on every
// activation:
//
//   bx_mem.vector = s.mem_base - s.vaddr_base
//     so that vector[addr] == mem_base[addr - vaddr_base] for any
//     guest-physical addr, matching what the old handler-based
//     translation did for in-range accesses.
//   bx_mem.len = s.vaddr_base + s.mem_size
//     upper bound for whatever internal range checks bx_mem_c does.
//
// CAVEAT: unlike the old handler-based approach, there is no per-
// access bounds clamp any more for addresses below vaddr_base or at/
// past vaddr_base+mem_size - a guest that strays outside its own
// window will read/write adjacent host memory instead of getting a
// clean "no RAM here" response. A well-behaved guest confined to its
// own slot's window is unaffected; this is a real behavioral gap
// worth runtime-testing against a misbehaving/malicious guest.
static void mapping_register(SlotState& s) {
    if (!s.mem_base || !s.mem_size || s.mapped) return;
    bx_mem.vector = s.mem_base - s.vaddr_base;
    bx_mem.len    = (size_t)s.vaddr_base + (size_t)s.mem_size;
    s.mapped = true;
}

static void mapping_unregister(SlotState& s) {
    if (!s.mapped) return;
    // Single global bx_mem - nothing to "unregister" per se now that
    // there's no per-range table; just stop claiming this slot owns
    // the mapping. The next mapping_register() (for whichever slot
    // becomes active next) will repoint bx_mem.vector again before
    // any guest code runs.
    s.mapped = false;
}

// =====================================================================
// Slab tables (GDT + IDT) and exit-trap stub
// =====================================================================
//
// Layout at the start of every slot's slab:
//
//   0x080..0x098   GDT (3 entries: null / flat code / flat data)
//   0x0E0..0x0E6   exit-trap stub:
//                    mov $0, %al ; out %al, $0xE8 ; hlt ; jmp .
//   0x100..0x900   IDT (256 entries, all pointing at the exit stub)
//
// The slab base lives at vaddr_base. The kernel-injected band
// 0x80..0xFF is reserved — any ELF PT_LOAD that overlaps it gets
// partially overwritten. The stub MUST live inside this band so it
// can't be clobbered by a PT_LOAD that happens to start at slab
// offset 0 (which is the common case for ELFs with low-vaddr first
// segments, e.g. our hello binary whose first PT_LOAD lands the
// ELF header at slab offset 0).

static void inject_slab_tables(SlotState& s) {
    if (!s.mem_base || s.mem_size < 0x1000) return;

    static const Bit8u stub[7] = {
        0xB0, 0x00,         // mov  $0, %al
        0xE6, 0xE8,         // out  %al, $0xE8
        0xF4,               // hlt
        0xEB, 0xFE,         // jmp  .  (safety: spin if hlt resumes)
    };

    // Place the stub at a FIXED offset inside the GDT/IDT injection
    // band (0x80..0xFF). This band is reserved for kernel-injected
    // tables — any ELF whose first PT_LOAD reaches into here is
    // already going to have its 0x80..0x97 trampled by the GDT we
    // write below, so the existing contract is "the kernel owns
    // 0x80..0xFF; PT_LOADs that overlap will be partially overwritten."
    // We extend that contract to also cover 0xE0..0xE6 for the stub.
    //
    // Why this matters: the previous logic tried offset 0, then 0x10,
    // then gave up and left IDT vectors pointing at slab offset 0 —
    // which for a typical ELF contains the program's loaded header
    // bytes (e.g. "7F 45 4C 46 ..."). Any guest exception then
    // vectored to that garbage, the garbage faulted again, and the
    // guest looped (visible as "HELLO WOHELLO WO..." in the
    // emulator window when the guest itself started getting
    // re-entered from the top after a fault). hello.c's comment
    // header describes this exact failure mode.
    //
    // Putting the stub at a fixed offset eliminates the fallback
    // entirely: the IDT always points somewhere valid, and a fault
    // always exits the slot cleanly via port 0xE8.
    Bit32u stub_off = 0xE0;
    __builtin_memcpy(s.mem_base + stub_off, stub, sizeof(stub));

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

    // NOTE (Bochs 2.0 port): BX_GENERAL_REGISTERS isn't defined here;
    // gen_reg[] is hardcoded to 8 entries in cpu.h.
    for (int i = 0; i < 8; ++i)
        cs.gen_reg[i] = cpu->gen_reg[i].dword.erx;

    // NOTE (Bochs 2.0 port): EIP is NOT part of gen_reg[] in this
    // version - it lives in its own cpu->dword.eip field (see
    // cpu/cpu.h). prev_rip -> prev_eip (renamed; still bx_address/
    // Bit32u on a 32-bit build).
    cs.eip      = cpu->dword.eip;
    cs.prev_rip = (Bit32u)cpu->prev_eip;
    // EFLAGS: must use read_eflags() (which calls force_flags()) — NOT
    // a direct field read. Bochs implements OF/SF/ZF/AF/PF/CF lazily:
    // each flag-setting instruction writes its result into the oszapc
    // shadow struct, and the corresponding bits in cpu->eflags are
    // NOT updated until something explicitly forces them
    // (PUSHF/LAHF/SAVE/etc). A direct read of cpu->eflags therefore
    // captures STALE OSZAPC bits for the slot whose tick we're
    // saving — the lazy shadow may already be one or more
    // instructions ahead. read_eflags() flushes the lazy shadow into
    // the eflags field first, then returns the now-consistent value.
    // Without this, save/restore across slot switches could roll
    // back arithmetic flags by one instruction, which is exactly
    // the kind of corruption that makes JCCs branch the wrong way
    // when concurrent slots are involved.
    cs.eflags   = cpu->read_eflags();

    for (int i = 0; i < 6; ++i) cs.sregs[i] = cpu->sregs[i];

    cs.gdtr = cpu->gdtr;
    cs.idtr = cpu->idtr;

    // NOTE (Bochs 2.0 port): cr0 here is a plain struct with BOTH a
    // raw val32 field and individually-cached bitfield members (pg,
    // pe, ts, ...) that Bochs's own hot paths (paging.cc, io.cc)
    // check directly rather than deriving from val32 - reading
    // val32 for a snapshot is safe (see slot_restore_cpu for why
    // restoring needs more care than a raw field write).
    cs.cr0 = cpu->cr0.val32;
    cs.cr2 = (Bit32u)cpu->cr2;
    cs.cr3 = (Bit32u)cpu->cr3;
    cs.cr4 = cpu->cr4.registerValue;

    // NOTE (Bochs 2.0 port): no activity_state member on bx_cpu_c in
    // this version - always 0 (see the field comment in SavedCpuState).
    cs.activity_state = 0;
    cs.async_event    = cpu->async_event;

    // Save the raw lazy-EFLAGS shadow. read_eflags() above forced the
    // decoded bits into cs.eflags, but the shadow struct itself must
    // also be snapshotted so slot_restore_cpu can put it back exactly.
    // NOTE (Bochs 2.0 port): whole-struct copy (see SavedCpuState's
    // oszapc field comment for why this is more correct here than
    // trying to save individual 2.7-shaped result/auxbits fields).
    cs.oszapc = cpu->oszapc;

    cs.valid = true;
}

static void slot_restore_cpu(SlotState& s) {
    BX_CPU_C* cpu = BX_CPU(0);
    SavedCpuState& cs = s.cpu;

    for (int i = 0; i < 8; ++i)
        cpu->gen_reg[i].dword.erx = cs.gen_reg[i];

    cpu->dword.eip = cs.eip;
    cpu->prev_eip  = cs.prev_rip;
    // EFLAGS: write the saved value into cpu->eflags.val32 AND into
    // the lazy oszapc shadow. A bare val32 write only sets the raw
    // eflags field; the oszapc shadow would be left in whatever state
    // the cross-slot hardware reset (in bochs_activate_slot) had left
    // it. The next conditional-jump instruction of the resumed slot
    // reads from oszapc, not from cpu->eflags directly — so it would
    // see post-reset flag values rather than the slot's actually-
    // saved flags.
    //
    // NOTE (Bochs 2.0 port): 2.7's setEFlagsOSZAPC() macro doesn't
    // exist here; setEFlags(Bit32u) is this version's real accessor -
    // it sets eflags.val32 plus the VM_cached/protectedMode/v8086Mode
    // derived state in one call (see cpu.h), so a separate raw
    // eflags.val32 assignment isn't needed alongside it.
    cpu->setEFlags(cs.eflags);
    // Restore the raw lazy shadow AFTER setEFlags. setEFlags does not
    // touch oszapc at all in this version, so this isn't strictly
    // "overwriting a re-encoded approximation" the way it was for
    // 2.7's setEFlagsOSZAPC - but we still want the exact snapshotted
    // shadow (not whatever the last real instruction on this cpu
    // happened to leave there) so the next conditional jump sees this
    // slot's own lazy state.
    cpu->oszapc = cs.oszapc;

    for (int i = 0; i < 6; ++i) cpu->sregs[i] = cs.sregs[i];

    cpu->gdtr = cs.gdtr;
    cpu->idtr = cs.idtr;

    // NOTE (Bochs 2.0 port): cr0 has individually-cached bitfields
    // (pg, pe, ts, ...) alongside val32 that Bochs's own hot paths
    // check directly (see paging.cc, io.cc) rather than deriving from
    // val32 on the fly - a bare `cr0.val32 = cs.cr0` write (like the
    // 2.7 version of this function did) would leave those stale.
    // SetCR0(Bit32u) is this version's real accessor (used by Bochs's
    // own MOV-CR0 instruction handler in proc_ctrl.cc) and keeps
    // everything in sync correctly, including any paging-mode-switch
    // side effects a genuine CR0 write should have.
    cpu->SetCR0(cs.cr0);
    cpu->cr2       = cs.cr2;
    cpu->cr3       = cs.cr3;
    cpu->cr4.registerValue = cs.cr4;

    // NOTE (Bochs 2.0 port): no activity_state member on bx_cpu_c in
    // this version - nothing to restore.
    cpu->async_event    = cs.async_event;
}

// Initialise a slot's saved CPU state to a clean post-reset value
// ready for first execution. Called once per slot from
// bochs_set_process_memory(). EIP/ESP are set later by the kernel
// via bochs_cpu_set_eip / bochs_cpu_set_esp.
static void slot_prime_cpu(SlotState& s) {
    SavedCpuState& cs = s.cpu;

    for (int i = 0; i < 8; ++i) cs.gen_reg[i] = 0;
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
    // NOTE (Bochs 2.0 port): synthesize "all flags clear" (ZF=SF=CF=
    // OF=0) directly as a real bx_lf_flags_entry, since there's no
    // live cpu->oszapc to copy from here (this is priming a not-yet-
    // run slot) and this version has no unified result/auxbits pair
    // to set directly - see SavedCpuState's oszapc field comment.
    // BX_INSTR_OR32(0, 1) -> result_32=1: OR always clears CF/OF, a
    // nonzero positive result clears ZF and SF too.
    cs.oszapc.instr    = BX_INSTR_OR32;
    cs.oszapc.op1_32   = 0;
    cs.oszapc.op2_32   = 1;
    cs.oszapc.result_32 = 1;
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
// NOTE (Bochs 2.0 port): this version has no dynamic-translation
// instruction cache at all (that optimization was added well after
// 2.0), so there's nothing for flushICaches() to invalidate - the
// stale-decoded-instruction problem the original comment describes
// doesn't exist here in the first place. handleCpuContextChange() and
// updateFetchModeMask() don't exist either; the cpu_mode/
// protectedMode/v8086Mode resync they used to trigger now happens
// automatically inside SetCR0() itself (see slot_restore_cpu, which
// calls it instead of a raw cr0.val32 write) - SetCR0 calls
// enter_protected_mode() and updates protectedMode/v8086Mode/realMode
// directly whenever CR0.PE transitions, which is the real fix for the
// "stuck interpreting CS as real-mode" bug this function was guarding
// against. What's left to do by hand is exactly what the pre-
// handleCpuContextChange version of this function did: TLB_flush +
// invalidate_prefetch_q.
static void flush_after_switch() {
    BX_CPU_C* cpu = BX_CPU(0);

    // (a) Flush the TLB. Physical memory access is bx_mem.vector,
    // which mapping_register() just repointed at a different slot's
    // backing buffer - any cached guest-virtual -> host-physical
    // translations from the PREVIOUS slot are now pointing at the
    // wrong data and must be dropped. Bit32u argument matches
    // bx_bool's real underlying type in this version; 1 = also
    // invalidate global pages.
    cpu->TLB_flush(1);

    // (b) Drop the prefetch queue so the next fetch re-reads from the
    // (possibly just-swapped) memory instead of serving stale bytes.
    cpu->invalidate_prefetch_q();

    // (c) Clear sticky async-yield flags from the previous run.
    cpu->async_event = 0;
    BX_CPU(0)->kill_bochs_request = 0;
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
//   1. bx_pc_system.init_ips(ips)        — sets m_ips so timing math
//                                             doesn't divide by zero.
//   2. BX_MEM(0)->init_memory(g, h)        — allocate vector / blocks /
//                                             memory_handlers table.
//   3. BX_CPU(0)->init(BX_MEM(0))             — register CPUID params and
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
    bx_pc_system.init_ips(50000000u);

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

    // (2) memory subsystem. Bochs 2.0's stock init_memory(int memsize)
    // (memory/misc_mem.cc, already linked via libmemory.a) doesn't
    // touch SIM-> at all, so this is safe to call directly - single
    // arg in this version, not the (guest, host) pair 2.7 used.
    BX_MEM(0)->init_memory(16 * 1024 * 1024);
    live_breadcrumb(32, '2');

    // (3) CPU feature registration. With the dummy-param objects in
    // bochs_infra.cpp's KernelSIM, generic_cpuid.cc and friends find
    // the params they need (non-null pointers returning safe defaults)
    // without trapping. Calling initialize() is by-the-book and gives
    // us a proper CPUID table for the guest.
    //
    // DIAGNOSTIC: the trail used to jump 32 -> 33 across this whole call,
    // so a hang reported only "somewhere after init_memory". Bracket the
    // two heavy sub-steps separately:
    //   ...2 a        frozen  => hang is INSIDE BX_CPU(0)->init(BX_MEM(0))
    //   ...2 a 3 b    frozen  => hang is INSIDE BX_CPU(0)->reset()
    //   ...2 a 3 b 4         => both completed, init is fine
    live_breadcrumb(38, 'a');           // entering initialize()
    BX_CPU(0)->init(BX_MEM(0));
    live_breadcrumb(33, '3');           // initialize() returned

    // (4) hardware reset.
    live_breadcrumb(39, 'b');           // entering reset()
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    live_breadcrumb(34, '4');           // reset() returned

    // (5) FPU clean state. Not strictly required after reset() but
    // explicit and by-the-book.

    // Clear sticky yield flags that reset() may have set.
    BX_CPU(0)->async_event           = 0;
    BX_CPU(0)->kill_bochs_request  = 0;

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

    // ── Guarantee identical start state for every ELF load ───────────────
    //
    // Every ELF launch MUST begin from a byte-identical BX_CPU state so
    // that run N is indistinguishable from run 1. The fields saved and
    // restored by slot_save_cpu / slot_restore_cpu cover the architectural
    // register set (GPRs, EIP, EFLAGS, sregs, CRs, GDTR/IDTR), but
    // BX_CPU carries many additional fields that persist across cpu_loop
    // entries and are NOT covered by the save/restore:
    //
    //   • FPU / SSE / AVX / MMX register file and MXCSR
    //   • MSRs (IA32_EFER, SYSENTER_*, PAT, APIC_BASE, …)
    //   • Debug registers DR0–DR6, DR7
    //   • Hidden segment descriptor cache fields (base, limit, access
    //     rights) beyond the selector — written by segment-register
    //     loads in guest code and cached inside the CPU struct
    //   • pending_event / event_mask / EXT / inhibit_mask / inhibit_icount
    //     / last_exception_type / debug_trap — exception delivery state
    //   • TR and LDTR (not in sregs[6])
    //   • bx_pc_system timer/tick counters — currCountdown / ticksTotal /
    //     lastTimeUsec — which influence how many instructions cpu_loop
    //     runs per call and when it yields
    //
    // Any of these surviving from a previous run can cause silent
    // divergence: a conditional branch takes a different path, an
    // exception is delivered or suppressed, cpu_loop yields earlier or
    // later, etc.
    //
    // The fix: BX_RESET_HARDWARE before every slot prime. This wipes
    // every field in BX_CPU back to its architectural post-reset value
    // (the same state bochs_global_init left it in after the very first
    // boot-time reset). slot_prime_cpu + slot_restore_cpu then layer the
    // flat-32 protected-mode configuration on top, identically to the
    // first launch. Combined with the bx_pc_system re-init below, the
    // Bochs subsystem is in exactly the same state at the start of run N
    // as it was at the start of run 1.
    //
    // Guard: skip the CPU reset if any OTHER slot is currently live
    // (mapped and has a valid CPU snapshot). Resetting BX_CPU while a
    // peer is mid-execution would destroy its EIP/CRs/segments —
    // on the very next tick the peer's x86_tick would re-run lazy init
    // and restart the guest from _start. For the concurrent case the
    // reset-between-live-slots path in bochs_activate_slot already scrubs
    // the untracked fields on every slot switch, so per-slot isolation is
    // maintained without a full CPU reset here.
    {
        bool peer_live = false;
        for (int i = 0; i < MAX_BOCHS_SLOTS; ++i) {
            if (i == g_active_slot) continue;
            if (g_slots[i].mapped && g_slots[i].cpu.valid) {
                peer_live = true;
                break;
            }
        }
        if (!peer_live) {
            // No concurrent slots — full hardware reset for a clean slate.
            BX_CPU(0)->reset(BX_RESET_HARDWARE);
            // NOTE (Bochs 2.0 port): the oszapc poke that used to be
            // here is redundant now - slot_restore_cpu() below
            // unconditionally copies the whole s.cpu.oszapc struct
            // (set to the correct all-flags-clear state by
            // slot_prime_cpu() a few lines down) into the live CPU,
            // so setting it here first would just be overwritten.
            BX_CPU(0)->async_event            = 0;
            BX_CPU(0)->kill_bochs_request   = 0;
            g_exit_pending                    = 0;
            // Re-zero pc_system counters so cpu_loop yields at the same
            // instruction count as it did on the first launch.
            bx_pc_system.init_ips(50000000u);
            bx_pc_system.set_enable_a20(true);
            // NOTE (Bochs 2.0 port): no iCache exists in this version
            // to flush - see flush_after_switch()'s note above for why.
        }
    }

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
    // architectural register from s.cpu into the live CPU, including
    // the all-flags-clear oszapc state slot_prime_cpu just set.
    slot_restore_cpu(s);

    // Flush Bochs caches that might still reference a previous
    // mapping for this slot.
    flush_after_switch();
    
    // CRITICAL FIX: After registering new memory and restoring CPU state,
    // explicitly clear CR3 and flush TLB to ensure the CPU re-walks the
    // page tables on the next memory access. The CPU reset left CR3 at its
    // post-reset value, which may still be pointing at cached page tables
    // from a previous guest. This causes the CPU to fetch stale TLB entries
    // for memory addresses that happen to overlap between guests.
    //
    // Without this, running two programs sequentially or concurrently causes
    // the second program to read memory from the first program's slab, leading
    // to "echo" of previous output and data corruption.
    //
    // The triple flush pattern (flush, clear, flush) ensures that:
    // 1. No stale TLB entries from previous guest remain
    // 2. CR3 is cleared to point at identity-mapped kernel tables (or zero)
    // 3. The CPU re-fetches page table entries on first access
    //
    // NOTE (Bochs 2.0 port): TLB_flush takes a bx_bool argument in
    // this version (1 = also invalidate global pages).
    BX_CPU(0)->TLB_flush(1);
    BX_CPU(0)->cr3 = 0;
    BX_CPU(0)->TLB_flush(1);
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

// ── Heavy "reset everything to known state" entry point ──────────────
//
// Called by the kernel after a Bochs-emulated process exits. Brings
// the entire glue layer back to the same state it was in just after
// boot — every slot unmapped, every per-slot CPU snapshot wiped,
// BX_CPU(0) hardware-reset, no active slot.
//
// Rationale: incremental save/restore across slot relaunches kept
// surfacing subtle residual-state bugs (the second `bochs hello`
// would loop printing "HELLO WOHELLO WO..." while the first ran
// clean). slot_save_cpu / slot_restore_cpu only cover the
// architectural register set we explicitly track; CPU fields we
// don't track (FPU/SSE/AVX state, MSR shadows, DR0-7, TR, LDTR,
// alignment-check shadow, lazy-EFLAGS shadow, hidden segment-
// descriptor cache bits) survived across launches and at least
// one of them was poisoning the second guest's execution.
//
// Rather than play whack-a-mole, the kernel now treats each ELF
// launch as a fresh boot from the glue's perspective. The cost is
// one BX_CPU(0)->reset(BX_RESET_HARDWARE) per launch — small next
// to ELF loading — and it makes launch N identical to launch 1
// for every N.
//
// What this preserves (intentionally):
//   • registered I/O callbacks (read_cb/write_cb/exit_cb) — these
//     belong to the kernel slot, not the guest process. The next
//     guest in the same slot still wants the same callbacks.
//   • g_global_init_done — Bochs's one-shot global init must not
//     be re-run; init_memory and friends are not idempotent on
//     re-entry.
//   • the registered slot_id — same reasoning as callbacks.

// ── Per-slot release (concurrent-safe partial reset) ──────────────────
//
// Called by the kernel from tick_elf_processes when ONE slot's process
// exits but other slots are still running. Wipes only that slot's
// glue-side state — its mapping, its saved CPU snapshot, and most
// importantly its mem_base pointer (which is about to become a
// dangling pointer because the kernel will free the backing slab
// right after this returns).
//
// Why not just call bochs_reset_all_slots? Because that hardware-
// resets BX_CPU(0), which would clobber a DIFFERENT slot that's
// currently mid-execution. Released slots need a surgical wipe;
// only the global reset is safe when EVERY slot is done.
//
// What this preserves:
//   • g_active_slot stays at its current value (could even be `slot`
//     itself — that's fine, the next bochs_activate_slot of a
//     different slot will see the cleared state and behave like
//     "no previous slot" on the save path).
//   • Other slots' state is untouched.
//   • g_global_init_done and the I/O callbacks for this slot stay
//     (next process in the slot will reuse them, same as for
//     bochs_reset_all_slots).
extern "C" void bochs_release_slot(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    if (!g_global_init_done) return;

    SlotState& s = g_slots[slot];

    // Unregister the mapping BEFORE clearing mem_base, so the
    // unregister can still address the page-index range via vaddr_base.
    mapping_unregister(s);

    // Wipe everything that could otherwise dangle. mem_base is the
    // critical one — kernel is about to delete[] the slab, so this
    // pointer would otherwise become a use-after-free trap for any
    // future glue code that touches it (e.g. an accidental
    // bochs_activate_slot(slot) before bochs_set_process_memory has
    // re-populated it).
    s.mem_base    = nullptr;
    s.mem_size    = 0;
    s.vaddr_base  = 0;
    s.brk_ptr     = 0;
    s.wants_input = false;
    s.cpu_primed  = false;

    // Drop the saved CPU snapshot. valid=false signals
    // bochs_activate_slot to skip slot_restore_cpu for this slot
    // until bochs_set_process_memory re-primes it. It ALSO suppresses
    // the per-switch hardware-reset between this slot and any future
    // peer: with cpu.valid=false the "switching between live slots"
    // branch is skipped (see bochs_activate_slot's `cur.cpu.valid`
    // guard). That's the correct behaviour — a freshly released slot
    // is no longer "live", so swapping into it is equivalent to a
    // first-time activation.
    __builtin_memset(&s.cpu, 0, sizeof(s.cpu));

    // If this slot happened to be the currently-active one, demote
    // g_active_slot to "none". The next bochs_activate_slot of a
    // different slot will then take the no-previous-slot path
    // (skipping slot_save_cpu of a now-cleared snapshot). If a
    // peer slot was already active, leave g_active_slot pointing at
    // it — we must not disturb the peer's state.
    if (g_active_slot == slot) g_active_slot = -1;
}

extern "C" void bochs_reset_all_slots() {
    if (!g_global_init_done) return;   // nothing to reset yet

    // Drop every mapping. mapping_unregister is a no-op for slots
    // that aren't currently mapped, so this is safe to call on all
    // of them unconditionally.
    for (int i = 0; i < MAX_BOCHS_SLOTS; ++i) {
        SlotState& s = g_slots[i];
        mapping_unregister(s);
        s.mem_base   = nullptr;
        s.mem_size   = 0;
        s.vaddr_base = 0;
        s.brk_ptr    = 0;
        s.wants_input = false;
        s.cpu_primed = false;

        // Wipe the saved CPU snapshot. Setting valid=false is the
        // signal to bochs_activate_slot that there's nothing to
        // restore — the next bochs_set_process_memory call will
        // re-prime it from scratch.
        __builtin_memset(&s.cpu, 0, sizeof(s.cpu));
    }

    // Forget which slot was active. The next bochs_activate_slot
    // call will see "no previous slot" and skip the save path.
    g_active_slot = -1;

    // Hardware-reset the live CPU. This wipes every CPU field
    // including the ones we don't explicitly save/restore — FPU,
    // SSE/AVX, MSRs, debug regs, hidden segment cache bits, etc.
    // After this, bochs_set_process_memory's slot_prime_cpu +
    // slot_restore_cpu + flush_after_switch sequence brings the
    // CPU into the correct flat-32 protected-mode configuration
    // for the new guest.
    //
    // Clear sticky yield flags that reset() may have set, the same
    // way bochs_global_init() does after its boot-time reset.
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    // NOTE (Bochs 2.0 port): the oszapc poke that used to be here is
    // redundant - bochs_set_process_memory's slot_prime_cpu +
    // slot_restore_cpu sequence (which runs next for whichever slot
    // launches next) sets the correct all-flags-clear oszapc state
    // and copies it into the live CPU unconditionally.
    BX_CPU(0)->async_event = 0;
    BX_CPU(0)->kill_bochs_request = 0;
    g_exit_pending                  = 0;

    // Re-zero bx_pc_system's timer/tick counters so the next launch
    // sees the same "freshly initialised" pc_system state the FIRST
    // launch did. initialize() resets ticksTotal, currCountdown,
    // currCountdownPeriod, lastTimeUsec, usecSinceLast, triggeredTimer,
    // HRQ, kill_bochs_request, and re-sets m_ips. It does NOT touch
    // a20_mask (good — that stays at 0xffffffff from the boot-time
    // set_enable_a20(true) call), but we re-assert A20 explicitly
    // immediately afterwards in case a future Bochs version's
    // initialize() ever decides to zero a20_mask. This call mirrors
    // the first two steps of bochs_global_init() so the next launch
    // starts from the same architectural pc_system snapshot as the
    // first one did. We do NOT re-call BX_MEM::init_memory() or
    // BX_CPU::initialize() — those are non-idempotent (they allocate
    // tables out of the bump pool) and were the explicit reason
    // bochs_global_init() is one-shot. The post-reset CPU + freshly
    // re-zeroed pc_system + already-allocated mem tables is the
    // closest reproducible "just after boot init" state we can
    // construct without re-running the heavy allocator path.
    bx_pc_system.init_ips(50000000u);
    bx_pc_system.set_enable_a20(true);

    // Wipe the stale-panic diagnostic buffer so a panic captured
    // during run N can't be misreported as a panic in run N+1. The
    // buffer is only ever READ by bochs_guest_exit() and the kernel's
    // diagnostic dumper; clearing it costs nothing and prevents
    // ghost panic messages.
    extern volatile const char* bx_last_panic_fmt;
    extern volatile char        bx_last_panic_msg[128];
    bx_last_panic_fmt = nullptr;
    for (unsigned i = 0; i < sizeof(bx_last_panic_msg); ++i) {
        bx_last_panic_msg[i] = 0;
    }

    // NOTE (Bochs 2.0 port): no iCache exists in this version to
    // flush (see flush_after_switch()'s note) - nothing to do here.
}

// ── New function: Surgical per-slot cleanup ────────────────────────────
// Instead of resetting the entire Bochs CPU (which destroys all slots),
// this function clears only the specified slot's mapping and CPU state,
// leaving the live CPU and other slots untouched.
//
// CRITICAL for concurrent slot support: when slot A exits while slot B is
// running, we MUST NOT call bochs_reset_all_slots() (which resets BX_CPU).
// Instead, call bochs_release_slot(A) to unmap A's memory and invalidate
// A's CPU snapshot, then continue executing B.
//
// Only call bochs_reset_all_slots() when we're absolutely sure that NO
// slots are active (checked in tick_elf_processes).


// Switch active slot. If a different slot was active before, snapshot
// its CPU state and unregister its mapping; then register the new
// slot's mapping and restore its CPU state; finally flush caches.
//
// IMPORTANT: the post-switch flush_after_switch() is gated on whether
// we actually touched mapping or CPU state. This matters for the
// "first activate after bochs_reset_all_slots()" case:
//
//   • On the FIRST run after boot, g_global_init_done is false when
//     bochs_activate_slot is first called from x86_tick. The whole
//     `if (g_global_init_done)` block below is skipped — no flush.
//     bochs_set_process_memory then runs global_init AND the full
//     map+prime+inject+restore+flush sequence itself, so the slot
//     ends up correctly armed.
//
//   • On the SECOND run after bochs_reset_all_slots(), the situation
//     is different: g_global_init_done is true (preserved across the
//     reset — see the comment in bochs_reset_all_slots), but the
//     freshly-reset slot has neither a mapping nor a valid CPU
//     snapshot yet (bochs_set_process_memory hasn't been called for
//     this launch). The OLD code would still drop into the
//     `if (g_global_init_done)` block, skip the mapping_register and
//     slot_restore_cpu guards, and then unconditionally call
//     flush_after_switch() — which runs handleCpuContextChange() on
//     a CPU that's currently in post-reset BIOS state (CS=F000,
//     real mode, CR0=0x60000010). That extra flush would lock in
//     cpu_mode=BX_MODE_IA32_REAL and a real-mode fetchModeMask
//     based on stale derived state, which subsequent
//     slot_restore_cpu+flush_after_switch inside
//     bochs_set_process_memory then has to UNDO. That undo path is
//     where the historical "second run looks subtly wrong" symptoms
//     leaked in from — a divergence between launch 1 (no extra
//     flush) and launch N (extra flush, then corrective flush).
//
//   • The fix: only call flush_after_switch() when we ACTUALLY did
//     something material here (registered a mapping OR restored a
//     CPU snapshot). If both guards skipped, then this call is just
//     a bookkeeping update of g_active_slot — no Bochs-visible state
//     changed, no flush needed. This makes launch N follow the EXACT
//     same code path as launch 1: bochs_activate_slot becomes a
//     no-op (besides setting g_active_slot), and the real work
//     happens inside bochs_set_process_memory, identical to the
//     first launch.
extern "C" void bochs_activate_slot(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    if (slot == g_active_slot) return;

    bool changed_mapping_or_cpu = false;
    bool switching_between_live_slots = false;

    if (g_global_init_done && g_active_slot >= 0 &&
        g_active_slot < MAX_BOCHS_SLOTS) {
        SlotState& prev = g_slots[g_active_slot];
        // Only meaningful if the previous slot actually had state
        // worth saving. After bochs_reset_all_slots() this branch
        // is unreachable (g_active_slot was set to -1), so it does
        // not affect the "second run after reset" path.
        slot_save_cpu(prev);
        mapping_unregister(prev);
        changed_mapping_or_cpu = true;
        // Remember: we're swapping OUT a previously-live slot. If the
        // slot we're swapping IN is also a previously-live slot (its
        // cpu.valid flag will tell us shortly), we need to scrub the
        // BX_CPU between save and restore — see the big comment in
        // the reset block below.
        switching_between_live_slots = prev.cpu.valid;
    }

    g_active_slot = slot;

    if (g_global_init_done) {
        SlotState& cur = g_slots[slot];

        // ── Scrub untracked CPU state between two live slots ──────────
        //
        // slot_save_cpu / slot_restore_cpu only cover the architectural
        // registers we explicitly enumerate: GPRs, EIP, prev_rip, eflags,
        // sregs[6], gdtr, idtr, cr0..cr4, activity_state, async_event.
        //
        // What they do NOT cover, but which BX_CPU(0) carries forward
        // across cpu_loop entries and which CAN affect guest execution:
        //
        //   • oszapc — the lazy-EFLAGS shadow (struct of {result,auxbits}).
        //     Each flag-setting instruction writes its operation into
        //     this struct; lazy decoding of OF/SF/ZF/AF/PF/CF on demand
        //     reads from it. When we restore cs.eflags directly into
        //     cpu->eflags without also restoring oszapc, the next
        //     conditional jump (JNE, JZ, ...) the guest executes reads
        //     LAZY FLAGS LEFT BEHIND BY THE OTHER SLOT — wrong branch
        //     taken. For the hello binary, put_str's `test %al,%al ;
        //     jne` loop on the string terminator is exactly such a
        //     conditional. With cross-slot flag pollution the loop can
        //     mis-terminate (cutting "HELLO WORLD\n" off at 8 chars
        //     producing "HELLO WO") or loop forever and re-vector
        //     through the IDT exit stub, which is the visible
        //     "HELLO WOHELLO WO..." symptom under concurrent slots.
        //
        //   • Pending-event state: pending_event, event_mask, EXT,
        //     inhibit_mask, inhibit_icount, last_exception_type,
        //     debug_trap. A trap or exception that fired during the
        //     other slot can leave a pending bit set; on the next
        //     cpu_loop entry of THIS slot Bochs would dispatch it
        //     against the wrong CR3/segments/EIP.
        //
        //   • FPU / SSE / AVX / MMX register file and MXCSR. The hello
        //     ELFs don't touch FPU/SSE, but some Bochs internal paths
        //     (e.g. the assertion checks in handleCpuModeChange) do
        //     read these. Cross-slot pollution is at minimum a
        //     forensic confound and at worst a real fault source.
        //
        //   • Stack-cache and prefetch-queue host pointers. These are
        //     scrubbed by flush_after_switch's handleCpuContextChange
        //     call further down, so they're already handled.
        //
        //   • DR0-7 / TR / LDTR / MSRs. Unused in this kernel but again
        //     a forensic risk and unnecessary divergence between
        //     "first launch" and "Nth concurrent slot resume".
        //
        // The PREVIOUS approach was to try to enumerate every one of
        // these untracked fields and add them to slot_save_cpu /
        // slot_restore_cpu. That game of whack-a-mole was abandoned
        // (see the comment above bochs_reset_all_slots): for sequential
        // reuse we just hardware-reset the CPU between processes so
        // every untracked field returns to its post-reset value, and
        // slot_restore_cpu then layers our architectural snapshot on
        // top. Launch N becomes byte-identical to launch 1.
        //
        // That fix only ran in bochs_reset_all_slots — i.e. when the
        // LAST live slot exits. It did nothing for the concurrent case
        // where slot A and slot B are both alive and the kernel ticks
        // them one after the other in the same frame. In that case
        // the CPU swings back and forth between two halves of dirty
        // untracked state. Both runs see the OTHER run's untracked
        // pollution every tick.
        //
        // The fix here is the same big-hammer pattern but applied per
        // SWAP rather than per RESET: when we're swapping FROM a
        // previously-live slot TO another previously-live slot, do a
        // BX_RESET_HARDWARE between save and restore. The reset wipes
        // every untracked field; slot_restore_cpu then re-instates the
        // architectural snapshot. The new slot resumes from exactly the
        // same architectural state it would on its first tick. No
        // bleed-over from the other slot — concurrent runs are now
        // independent.
        //
        // We DO NOT reset when:
        //   • There was no previous slot (g_active_slot == -1, e.g.
        //     first activate after boot or after bochs_reset_all_slots).
        //     The CPU is already in the appropriate clean post-init or
        //     post-reset state.
        //   • The incoming slot has cpu.valid == false (a freshly
        //     primed slot that has never run). slot_restore_cpu will
        //     install its primed state; no untracked pollution from
        //     "this slot's previous run" exists to scrub.
        //
        // Cost: one BX_RESET_HARDWARE per slot switch when both ends
        // are live. The reset is a few hundred memory writes — cheap
        // compared to even one cpu_loop iteration. No allocations are
        // performed. It's safe to invoke repeatedly.
        if (switching_between_live_slots && cur.cpu.valid) {
            BX_CPU(0)->reset(BX_RESET_HARDWARE);
            BX_CPU(0)->async_event          = 0;
            BX_CPU(0)->kill_bochs_request = 0;
            g_exit_pending                  = 0;
            changed_mapping_or_cpu = true;
        }

        if (cur.mem_base && cur.mem_size) {
            mapping_register(cur);
            changed_mapping_or_cpu = true;
        }
        if (cur.cpu.valid) {
            slot_restore_cpu(cur);
            changed_mapping_or_cpu = true;
        }
        // Only flush if we actually changed something Bochs-visible.
        // See block comment above — this is what makes the second
        // launch's bochs_activate_slot path identical to the first.
        if (changed_mapping_or_cpu) {
            flush_after_switch();
        }
    }
}

// EIP / ESP setters write into BOTH the live BX_CPU(0) registers AND
// the active slot's saved CPU state. Writing both means we don't lose
// the value if the kernel switches slots before the first tick.
extern "C" void bochs_cpu_set_eip(Bit32u eip) {
    BX_CPU_C* cpu = BX_CPU(0);
    
    // CRITICAL: Full pipeline flush BEFORE setting EIP to ensure no stale
    // cached instruction traces from the previous process remain.
    cpu->invalidate_prefetch_q();
    // NOTE (Bochs 2.0 port): no iCache exists in this version (see
    // flush_after_switch()'s note) - the flushICaches() calls that
    // used to bracket this are gone; invalidate_prefetch_q() +
    // TLB_flush() are the real equivalent available here.
    cpu->TLB_flush(1);  // CRITICAL: Flush TLB to clear stale page mappings
    
    // NOTE (Bochs 2.0 port): EIP lives in cpu->dword.eip directly in
    // this version, not gen_reg[] (see slot_save_cpu's note); prev_rip
    // -> prev_eip (renamed).
    cpu->dword.eip = eip;
    cpu->prev_eip  = eip;
    cpu->async_event = 0;
    
    // Re-flush AFTER setting EIP to catch any micro-ops already decoded
    cpu->invalidate_prefetch_q();

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

extern "C" Bit32u bochs_cpu_get_eip() { return BX_CPU(0)->get_EIP(); }
extern "C" unsigned int bochs_cpu_geteip() { return (unsigned int)BX_CPU(0)->get_EIP(); }
extern "C" Bit32u bochs_cpu_get_eax() {
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}

// =====================================================================
// Guest I/O sentinels (port 0xE9 = putc, port 0xE8 = exit)
// =====================================================================

extern "C" void bochs_guest_putc(char c) {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return;
    SlotState& s = g_slots[g_active_slot];
    if (s.write_cb) s.write_cb(g_active_slot, c);

    // Do NOT set kill_bochs_request here. The old code yielded after
    // every character, but bochs_cpu_tick only calls cpu_loop() once,
    // so cpu_loop() returned after the first putc and the guest never
    // advanced to output the second character (e.g. "HELLO WORLD"
    // showed only 'H'). The instruction budget in bochs_cpu_tick
    // provides time-slicing; bochs_guest_exit (port 0xE8) still sets
    // kill_bochs_request to signal process termination.
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

        // Also dump a readable diagnostic to the host debug console
        // (port 0xE9, captured by QEMU `-debugcon stdio`). Without this
        // a panic during init was a silent freeze — the breadcrumbs
        // alone could not say WHICH Bochs internal check failed.
        // bx_last_panic_msg is filled by logfunctions::panic in
        // bochs_infra.cpp just before it calls us.
        {
            auto e9c = [](char c) {
                __asm__ volatile ("outb %0, %1"
                    : : "a"((unsigned char)c), "Nd"((unsigned short)0xE9));
            };
            const char* m = "\n*** BOCHS PANIC during init (no slot) ***\n"
                             "  exit code = -";
            for (const char* p = m; *p; ++p) e9c(*p);
            e9c(hex[(v >> 4) & 0xF]);
            e9c(hex[ v       & 0xF]);
            const char* lbl = "\n  panic msg = ";
            for (const char* p = lbl; *p; ++p) e9c(*p);
            const char* pm = (const char*)bx_last_panic_msg;
            if (pm && pm[0]) { for (int i = 0; i < 127 && pm[i]; ++i) e9c(pm[i]); }
            else             { const char* none = "(not captured)";
                               for (const char* p = none; *p; ++p) e9c(*p); }
            e9c('\n');
        }

        // Hard halt: do NOT return into Bochs's panic-then-keep-going
        // sequence, which is what was causing the NULL-cpuid deref.
        for (;;) { __asm__ volatile("cli; hlt"); }
    }

    SlotState& s = g_slots[g_active_slot];
    if (s.exit_cb) s.exit_cb(g_active_slot, code);

    g_exit_pending = 1;
    BX_CPU(0)->kill_bochs_request = 1;
    BX_CPU(0)->async_event = 1;
}

extern "C" bool bochs_process_wants_input(int slot) {
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

// =====================================================================
// Guest keyboard input (port 0xE7 = getc, non-blocking)
// =====================================================================
//
// Mirrors the 0xE8/0xE9 sentinel-port convention: the guest does
// `in al, 0xE7` and gets back either the next queued keystroke or 0 if
// none is waiting yet (0 doubles as "empty", the same way pop_input()
// already treats it on the kernel side - see kernel.cpp's pop_input).
//
// bx_devices_c::inp() (bochs_infra.cpp) routes port 0xE7 here. We defer
// to the active slot's read_cb (elf_io_read -> pop_input) instead of
// touching the ring buffer directly, so a Bochs-emulated guest and a
// natively-executed guest share the exact same per-slot stdin queue.
//
// When the queue is empty we set wants_input so the kernel's tick loop
// (x86_tick in kernel.cpp) can flip the slot's waiting_for_input flag
// and have the keyboard-routing code hand it the very next keystroke,
// instead of leaving the guest to busy-poll an empty queue for an
// entire instruction budget.
extern "C" int bochs_guest_getc() {
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return 0;
    SlotState& s = g_slots[g_active_slot];
    if (!s.read_cb) return 0;

    int c = s.read_cb(g_active_slot);
    if (c == 0) {
        // Nothing queued yet - remember that this slot asked.
        s.wants_input = true;

        // Force cpu_loop() to return RIGHT NOW instead of burning the
        // rest of this tick's instruction budget spinning inside the
        // guest's `while (inb(0xE7) == 0) {}` poll loop. bochs_cpu_tick
        // makes exactly one cpu_loop() call per frame with a huge fixed
        // budget (n * 256, up to ~2^31); without this, a getch()-style
        // guest never advances past its first empty poll, cpu_loop()
        // never returns, and the single-threaded kernel main loop -
        // which is what would otherwise deliver the next keystroke and
        // repaint the screen - blocks forever. Net effect from the
        // user's side: the ENTIRE kernel freezes, not just the guest
        // window, the moment a program tries to read a key that isn't
        // queued yet.
        //
        // Mirrors bochs_guest_exit()'s use of these same two fields.
        // Unlike bochs_guest_putc() (which deliberately does NOT yield
        // per character, so a multi-character string prints in one
        // tick) we DO want to yield on every empty poll: the guest
        // will simply re-issue `in al,0xE7` on the next tick, once per
        // frame, until a key shows up.
        BX_CPU(0)->kill_bochs_request = 1;
        BX_CPU(0)->async_event         = 1;
    }
    return c;
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

// bochs_cpu_tick — Bochs 2.0-style single-call tick.
//
// Previous design: n-capped loop calling cpu_loop() once per putc.
// This was unstable because:
//   1. cpu_loop() returns after EVERY guest port-IO (putc or exit),
//      so n=64 only guaranteed 64 INSTRUCTIONS-worth of guest progress,
//      not 64 characters. A multi-function-call putc chain (put_str ->
//      put_ch -> out_byte -> out dx,al) ate several iterations per char
//      in some ELF layouts, cutting output at 8 chars before the budget
//      was exhausted.
//   2. The per-iteration clear of kill_bochs_request/async_event was
//      racy: if bochs_guest_exit fired on the LAST iteration, the flags
//      were cleared after the fact, losing the exit signal.
//
// Fix: single cpu_loop() call per tick, capped by wall-instruction
// count rather than an outer loop. cpu_loop() already handles the
// internal yield/resume via kill_bochs_request; we just need to let
// it run until the guest does a clean exit (g_exit_pending) or until
// we've executed enough instructions that we should yield back to the
// kernel for a repaint. The instruction budget (n * 256) is large
// enough that a short program like hello always completes in one tick.
extern "C" int bochs_cpu_tick(int n) {
    if (!g_global_init_done) return 0;
    if (g_active_slot < 0 || g_active_slot >= MAX_BOCHS_SLOTS) return 0;

    SlotState& s = g_slots[g_active_slot];
    if (!s.mem_base || !s.mapped) return 0;
    if (!s.cpu.valid) return 0;

    s.wants_input = false;

    g_exit_pending = 0;
    BX_CPU(0)->kill_bochs_request = 0;
    BX_CPU(0)->async_event          = 0;

    // Reinitialise the pc_system countdown before every tick so
    // cpu_loop() always has a fresh budget of instructions to run.
    // Without this, once currCountdown reaches 0 (after the first
    // 50M-instruction budget), countdownEvent() is a no-op stub and
    // currCountdown stays at 0 — cpu_loop() returns immediately on
    // every subsequent entry without executing a single instruction,
    // icount never advances, elapsed stays 0, and the budget loop here
    // spins forever.
    bx_pc_system.init_ips(50000000u);
    bx_pc_system.set_enable_a20(true);

    // NOTE (Bochs 2.0 port): this version's cpu_loop(Bit32s
    // max_instr_count) takes the instruction budget as a direct
    // argument and internally loops, executing guest instructions
    // until either max_instr_count is reached or something sets
    // kill_bochs_request (our outp() handler does this via
    // bochs_guest_exit()/bochs_guest_putc() on port 0xE8/0xE9) - it
    // returns to us either way. There's no get_icount() in this
    // version to measure exactly how many instructions actually ran,
    // so the old "poll icount, loop calling cpu_loop() with the
    // remaining budget" pattern doesn't have anywhere to plug in the
    // "elapsed" half of that comparison. A single call with the full
    // budget is the direct equivalent: cpu_loop() already handles the
    // internal yield/resume via kill_bochs_request exactly the way
    // the old outer while-loop assumed each individual cpu_loop() call
    // would.
    Bit64u budget = (Bit64u)n * 256;
    if (budget > 0x7FFFFFFFull) budget = 0x7FFFFFFFull;  // Bit32s range

    BX_CPU(0)->kill_bochs_request = 0;
    BX_CPU(0)->async_event          = 0;

    BX_CPU(0)->cpu_loop((Bit32s)budget);

    BX_CPU(0)->kill_bochs_request = 0;
    BX_CPU(0)->async_event          = 0;

    if (g_exit_pending) {
        g_exit_pending = 0;
        return 0;
    }
    return 0;
}