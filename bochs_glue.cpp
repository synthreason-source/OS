// bochs_glue.cpp — Bochs 2.7 CPU bridge for freestanding kernel.
//
// THE CPU-DISABLED BUG — root cause and fix
// ==========================================
// BX_CPU_C::reset(BX_RESET_HARDWARE) leaves the CPU in x86 REAL MODE with
// CS:IP = F000:FFF0 (physical 0xFFFFFFF0, the BIOS reset vector).
// Nothing is mapped there. cpu_loop() fetches 0x00 bytes → junk instructions
// → triple fault → Bochs sets BX_DEBUG_TRAP_SPECIAL → prints "CPU has been
// disabled" → every subsequent cpu_loop() call returns immediately, forever.
//
// The ELF binaries (musl/busybox i386) are built for 32-bit PROTECTED MODE.
// Simply setting EIP does NOT fix the mode; Bochs tracks the segment
// descriptor caches and CR0 separately from EIP.
//
// Fix: bochs_cpu_enter_protected_mode() writes the segment descriptor
// caches directly (bypassing the normal lgdt/mov-cr0/far-jmp sequence)
// and sets CR0.PE=1. This puts the virtual CPU into flat 32-bit protected
// mode before any guest code runs. It is called from bochs_cpu_init(),
// immediately after reset(), before EIP is set and before cpu_loop() ever
// runs.
//
// Struct note (Bochs 2.7 cpu/cpu.h actual layout, confirmed from compiler):
//   bx_descriptor_t.type        — plain Bit8u (raw 4-bit type field)
//   bx_descriptor_t.u.segment.base         — Bit32u base address
//   bx_descriptor_t.u.segment.limit_scaled — Bit32u limit (pre-scaled by g)
//   bx_descriptor_t.u.segment.g            — granularity bit
//   bx_descriptor_t.u.segment.d_b          — D/B (32-bit) bit
//   bx_descriptor_t.u.segment.avl          — available bit
//   (no 'l' field: bochs built with --disable-x86-64, BX_SUPPORT_X86_64=0)
// (NOT d.base32 / d.limit_scaled / d.g / d.d_b etc. at the top level)

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"

// ── ABI stubs ────────────────────────────────────────────────────────────────
extern "C" void* __dso_handle = nullptr;
extern "C" int   __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void  __cxa_finalize(void*) {}

// ── Per-process slot state ────────────────────────────────────────────────────
#define MAX_BOCHS_SLOTS 4

struct SlotState {
    Bit8u*   mem_base    = nullptr;
    Bit32u   mem_size    = 0;
    Bit32u   vaddr_base  = 0;
    Bit32u   brk_ptr     = 0;
    int      slot_id     = -1;
    bool     wants_input = false;

    int  (*read_cb )(int slot)           = nullptr;
    void (*write_cb)(int slot, char c)   = nullptr;
    void (*exit_cb )(int slot, int code) = nullptr;
};

static SlotState g_slots[MAX_BOCHS_SLOTS];
static int       g_active_slot = -1;
static bool      g_cpu_ready   = false; // armed by bochs_cpu_set_eip()

// ── Flat 32-bit protected-mode segment setup ──────────────────────────────────
//
// Writes a flat 4 GB segment descriptor directly into the Bochs descriptor
// cache, bypassing the normal GDT-load path. This is safe because Bochs
// stores the decoded descriptor fields in the cache struct and uses those
// fields (not the raw GDT bytes) when executing instructions.
//
// Bochs 2.7 bx_descriptor_t layout (actual, from compiler errors):
//   .valid, .p, .dpl, .segment  — top-level booleans/bytes
//   .type                       — raw Bit8u type field (4-bit x86 type)
//   .u.segment.base             — Bit32u base
//   .u.segment.base         — Bit32u base
//   .u.segment.limit_scaled — Bit32u limit (pre-scaled; NOT 'limit')
//   .u.segment.g            — granularity
//   .u.segment.d_b          — D/B (1=32-bit)
//   .u.segment.avl          — available
//   (.u.segment.l absent: BX_SUPPORT_X86_64 disabled)
//
// x86 descriptor type field (4 bits, bit 3 = code/data):
//   Code, Execute/Read, not-conforming, Accessed = 1011b = 0x0B
//   Data, Read/Write, Expand-up, Accessed        = 0011b = 0x03

static void setup_flat_segment(bx_segment_reg_t& seg, Bit16u sel, bool code)
{
    // Selector (these fields compiled correctly in all prior versions)
    seg.selector.value = sel;
    seg.selector.rpl   = 0;
    seg.selector.ti    = 0;
    seg.selector.index = sel >> 3;

    // Descriptor cache
    bx_descriptor_t& d = seg.cache;
    d.valid   = 1;
    d.p       = 1;                   // present
    d.dpl     = 0;                   // ring 0
    d.segment = 1;                   // code/data (not a system descriptor)
    d.type    = code ? 0x0B : 0x03; // raw 4-bit type; see comment above

    // Geometry inside u.segment (confirmed field names from compiler errors):
    //   'limit_scaled' not 'limit' — stored pre-scaled by granularity
    //   'l' (long-mode bit) is absent: --disable-x86-64 removes it via #ifdef
    d.u.segment.base         = 0x00000000u;
    d.u.segment.limit_scaled = 0xFFFFFFFFu; // 4 GB flat
    d.u.segment.g            = 1;
    d.u.segment.d_b          = 1;           // 32-bit D/B bit
    d.u.segment.avl          = 0;
}

static void bochs_cpu_enter_protected_mode()
{
    BX_CPU_C* cpu = BX_CPU(0);

    // Set CR0.PE (bit 0) to enter protected mode
    cpu->cr0.val32 |= 0x00000001u;

    // Load flat 32-bit descriptors into all six segment register caches.
    // Selector values match the GDT in boot.S: 0x08=code, 0x10=data.
    // Bochs uses the cache directly; it will not re-load from the GDT.
    setup_flat_segment(cpu->sregs[BX_SEG_REG_CS], 0x08, true);   // code
    setup_flat_segment(cpu->sregs[BX_SEG_REG_SS], 0x10, false);  // stack
    setup_flat_segment(cpu->sregs[BX_SEG_REG_DS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_ES], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_FS], 0x10, false);
    setup_flat_segment(cpu->sregs[BX_SEG_REG_GS], 0x10, false);

    cpu->invalidate_prefetch_q();
}

// ── Memory handlers ───────────────────────────────────────────────────────────
static bool mem_read_handler(bx_phy_address addr, unsigned len,
                             void* data, void* /*param*/)
{
    if (g_active_slot < 0) { __builtin_memset(data, 0, len); return true; }
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

static bool mem_write_handler(bx_phy_address addr, unsigned len,
                              void* data, void* /*param*/)
{
    if (g_active_slot < 0) return true;
    SlotState& s = g_slots[g_active_slot];
    Bit32u off = (Bit32u)addr;
    if (s.mem_base && off >= s.vaddr_base) {
        off -= s.vaddr_base;
        if (off + len <= s.mem_size)
            __builtin_memcpy(s.mem_base + off, data, len);
    }
    return true;
}

// ── Linux i386 INT 0x80 syscall handler ──────────────────────────────────────
static void handle_guest_syscall(int)
{
    if (g_active_slot < 0) return;
    SlotState& s = g_slots[g_active_slot];

    Bit32u eax = BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
    Bit32u ebx = BX_CPU(0)->gen_reg[BX_32BIT_REG_EBX].dword.erx;
    Bit32u ecx = BX_CPU(0)->gen_reg[BX_32BIT_REG_ECX].dword.erx;
    Bit32u edx = BX_CPU(0)->gen_reg[BX_32BIT_REG_EDX].dword.erx;

    auto gva = [&](Bit32u va) -> Bit8u* {
        if (!s.mem_base || va < s.vaddr_base) return nullptr;
        Bit32u off = va - s.vaddr_base;
        return (off < s.mem_size) ? s.mem_base + off : nullptr;
    };

    Bit32u ret = (Bit32u)-38; // ENOSYS default

    switch (eax) {

    case 1: case 252:   // sys_exit / sys_exit_group
        if (s.exit_cb) s.exit_cb(s.slot_id, (int)ebx);
        BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = 0;
        BX_CPU(0)->prev_rip = 0;
        BX_CPU(0)->invalidate_prefetch_q();
        return;

    case 3: {           // sys_read(fd=0, buf, count)
        if (ebx != 0 || !s.read_cb || edx == 0) { ret = 0; break; }
        Bit32u n = 0;
        while (n < edx) {
            int ch = s.read_cb(s.slot_id);
            if (ch < 0) break;
            Bit8u* p = gva(ecx + n);
            if (p) *p = (Bit8u)ch;
            if (++n && ch == '\n') break;
        }
        s.wants_input = (n == 0);
        ret = n;
        break;
    }

    case 4: {           // sys_write(fd=1/2, buf, count)
        if (ebx != 1 && ebx != 2) { ret = (Bit32u)-9; break; }
        if (s.write_cb)
            for (Bit32u i = 0; i < edx; i++) {
                Bit8u* p = gva(ecx + i);
                if (p) s.write_cb(s.slot_id, (char)*p);
            }
        ret = edx;
        break;
    }

    case 45: {          // sys_brk
        Bit32u max_brk = s.vaddr_base + s.mem_size - 256;
        if (ebx == 0 || ebx < s.brk_ptr) ret = s.brk_ptr;
        else if (ebx < max_brk) { s.brk_ptr = ebx; ret = s.brk_ptr; }
        else ret = s.brk_ptr;
        break;
    }

    case 146: {         // sys_writev
        if (ebx != 1 && ebx != 2) { ret = (Bit32u)-9; break; }
        Bit32u total = 0;
        for (Bit32u v = 0; v < edx; v++) {
            Bit8u* iov = gva(ecx + v * 8);
            if (!iov) break;
            Bit32u base = *(Bit32u*)iov, len2 = *(Bit32u*)(iov + 4);
            for (Bit32u i = 0; i < len2; i++) {
                Bit8u* p = gva(base + i);
                if (p && s.write_cb) s.write_cb(s.slot_id, (char)*p);
                total++;
            }
        }
        ret = total;
        break;
    }

    case 90: case 192:  ret = (Bit32u)-12; break; // mmap/mmap2 → ENOMEM
    case 91:            ret = 0;           break; // munmap → ok
    case 20:            ret = 1;           break; // getpid
    case 24:            ret = 0;           break; // getuid
    case 47:            ret = 0;           break; // getgid
    case 49:            ret = 0;           break; // geteuid
    case 50:            ret = 0;           break; // getegid
    case 54:            ret = (Bit32u)-25; break; // ioctl → ENOTTY (dumb terminal)

    case 122: {         // uname
        const char* f[] = {"Linux","rtos","5.15.0","#1","i686","i686"};
        for (int fi = 0; fi < 6; fi++)
            for (int k = 0; k <= 64; k++) {
                Bit8u* p = gva(ebx + fi * 65 + k);
                if (p) *p = (k < 64 && f[fi][k]) ? (Bit8u)f[fi][k] : 0;
            }
        ret = 0; break;
    }

    // Signal / thread stubs that musl calls at startup
    case 174: case 175: case 119: case 173:
    case 243: case 258: case 168: case 265:
        ret = 0; break;

    case 5:   ret = (Bit32u)-2;  break; // open  → ENOENT
    case 6:   ret = 0;           break; // close → ok
    case 55:  ret = (Bit32u)-9;  break; // fcntl → EBADF
    case 221: ret = (Bit32u)-9;  break; // fcntl64 → EBADF

    default: ret = (Bit32u)-38; break;  // ENOSYS
    }

    BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx = ret;
}

// ── INT 0x80 instrumentation hook ────────────────────────────────────────────
extern "C" void bx_instr_interrupt(unsigned cpu_id, unsigned vector)
{
    (void)cpu_id;
    if (vector == 0x80)
        handle_guest_syscall(g_active_slot);
}

// ── Public API ────────────────────────────────────────────────────────────────

extern "C" void bochs_register_io_callbacks(
    int slot,
    int  (*read_cb )(int),
    void (*write_cb)(int, char),
    void (*exit_cb )(int, int))
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].slot_id  = slot;
    g_slots[slot].read_cb  = read_cb;
    g_slots[slot].write_cb = write_cb;
    g_slots[slot].exit_cb  = exit_cb;
}

// inject_idt_into_slab: write a minimal IDT + exit-handler stub at the
// base of the guest slab, then point IDTR at the IDT.
//
// Layout (all offsets from slab base = guest vaddr_base):
//   +0x000  handler stub: mov eax,1; mov ebx,0; int 0x80; hlt  (8 bytes)
//   +0x100  IDT: 256 entries × 8 bytes = 2048 bytes
//
// Gate format (32-bit interrupt gate, type=0x8E):
//   [15:0]  offset_low  = handler_va & 0xFFFF
//   [31:16] selector    = 0x0008 (flat code segment)
//   [39:32] zero        = 0x00
//   [47:40] type/attr   = 0x8E (present, DPL=0, 32-bit interrupt gate)
//   [63:48] offset_high = handler_va >> 16
static void inject_idt_into_slab(SlotState& s)
{
    if (!s.mem_base || s.mem_size < 0x1000) return;

    // ── Handler stub at slab[0x000] ──────────────────────────────────────────
    // i386 machine code: sys_exit(0) via INT 0x80
    // B8 01 00 00 00   MOV EAX, 1
    // BB 00 00 00 00   MOV EBX, 0
    // CD 80            INT 0x80
    // F4               HLT  (safety — should never reach here)
    static const Bit8u stub[12] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,   // mov eax, 1
        0xBB, 0x00, 0x00, 0x00, 0x00,   // mov ebx, 0
        0xCD, 0x80                       // int 0x80
    };
    __builtin_memcpy(s.mem_base + 0x000, stub, sizeof(stub));
    s.mem_base[sizeof(stub)] = 0xF4;    // hlt

    // Guest virtual address of the handler stub
    Bit32u handler_va = s.vaddr_base + 0x000;

    // ── IDT at slab[0x100] ───────────────────────────────────────────────────
    Bit8u* idt_base = s.mem_base + 0x100;
    Bit32u idt_va   = s.vaddr_base + 0x100;

    // Build one 8-byte interrupt gate entry pointing to handler_va
    // Gate = [offset_low:16][sel:16][0:8][type:8][offset_high:16]
    Bit8u gate[8];
    gate[0] = (Bit8u)(handler_va & 0xFF);
    gate[1] = (Bit8u)((handler_va >> 8) & 0xFF);
    gate[2] = 0x08;   // selector low  (CS = 0x0008)
    gate[3] = 0x00;   // selector high
    gate[4] = 0x00;   // reserved
    gate[5] = 0x8E;   // P=1, DPL=0, type=0xE (32-bit interrupt gate)
    gate[6] = (Bit8u)((handler_va >> 16) & 0xFF);
    gate[7] = (Bit8u)((handler_va >> 24) & 0xFF);

    // Install the same gate for all 256 vectors
    for (int i = 0; i < 256; i++)
        __builtin_memcpy(idt_base + i * 8, gate, 8);

    // ── Point IDTR at our IDT ─────────────────────────────────────────────────
    // bx_global_segment_reg_t = { Bit32u base; Bit16u limit; }
    BX_CPU(0)->idtr.base  = idt_va;
    BX_CPU(0)->idtr.limit = 256 * 8 - 1;   // 2047 = 0x07FF
}

extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size, Bit32u vaddr_base)
{
    if (g_active_slot < 0) return;
    SlotState& s = g_slots[g_active_slot];

    if (s.mem_base && s.mem_size)
        BX_MEM(0)->unregisterMemoryHandlers(nullptr,
            (bx_phy_address)s.vaddr_base,
            (bx_phy_address)(s.vaddr_base + s.mem_size - 1));

    s.mem_base   = base;
    s.mem_size   = size;
    s.vaddr_base = vaddr_base;

    if (base && size) {
        BX_MEM(0)->registerMemoryHandlers(
            nullptr,
            mem_read_handler, mem_write_handler,
            (bx_phy_address)vaddr_base,
            (bx_phy_address)(vaddr_base + size - 1));

        // Inject IDT + handler stub into the slab so any exception is caught
        // by our sys_exit handler instead of causing a triple fault + CPU reset.
        inject_idt_into_slab(s);
    }
}
extern "C" void bochs_finalize_process_memory() {
  // Placeholder: injects IDT/handler stub or finalizes guest slab setup.
  // Currently a no-op; extend if needed for custom logic (e.g., cache flush).
  // Matches kernel.cpp usage after ELF PTLOAD copy and before bochs_set_brk().
}
extern "C" void bochs_set_brk(int slot, Bit32u brk_addr)
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].brk_ptr = brk_addr;
}

extern "C" void bochs_activate_slot(int slot)
{
    g_active_slot = slot;
}

// Initialise the virtual CPU:
//   1. reset() — puts it in real mode at 0xFFFFFFF0
//   2. enter_protected_mode() — switches to flat 32-bit PM (prevents triple fault)
//   3. g_cpu_ready = false — tick is blocked until set_eip() arms it
extern "C" void bochs_cpu_init()
{
    BX_CPU(0)->initialize();
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
    bochs_cpu_enter_protected_mode();
    g_cpu_ready = false;
}

// Guard: never call cpu_loop() unless memory is mapped AND EIP is valid code
extern "C" int bochs_cpu_tick(int n)
{
    if (!g_cpu_ready || g_active_slot < 0)   return 0;
    if (!g_slots[g_active_slot].mem_base)     return 0;

    g_slots[g_active_slot].wants_input = false;
    for (int i = 0; i < n; ++i)
        BX_CPU(0)->cpu_loop();
    return 0;
}

extern "C" bool bochs_process_wants_input(int slot)
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

// Set EIP to the ELF entry point and arm the tick guard.
// Must be called AFTER bochs_set_process_memory() so the address is mapped.
extern "C" void bochs_cpu_set_eip(Bit32u eip)
{
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    BX_CPU(0)->prev_rip = eip;
    BX_CPU(0)->invalidate_prefetch_q();
    g_cpu_ready = true;
}

extern "C" void bochs_cpu_set_esp(Bit32u esp_val)
{
    BX_CPU(0)->gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
}

extern "C" Bit32u bochs_cpu_get_eip()
{
    return BX_CPU(0)->get_eip();
}

extern "C" unsigned int bochs_cpu_geteip()
{
    return (unsigned int)BX_CPU(0)->get_eip();
}

extern "C" Bit32u bochs_cpu_get_eax()
{
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}
