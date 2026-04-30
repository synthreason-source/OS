// bochs_glue.cpp
// Verified against Bochs 2.7 source: memory-bochs.h, cpu/cpu.h,
// iodev/iodev.h, bx_debug/debug.h.
//
// I/O architecture:
//
//   Guest (busybox/musl) issues Linux int 0x80 syscalls:
//     sys_write(fd=1, buf, len)  → EAX=4,  EBX=1,  ECX=buf_gva, EDX=len
//     sys_read (fd=0, buf, len)  → EAX=3,  EBX=0,  ECX=buf_gva, EDX=len
//     sys_exit (code)            → EAX=1,  EBX=code
//     sys_brk  (addr)            → EAX=45, EBX=addr
//
//   We intercept INT 0x80 via Bochs's instrumentation INTERRUPT hook.
//   Memory accesses use our existing mem_read/mem_write handlers so
//   guest virtual addresses == physical addresses (flat 32-bit, no paging).
//
//   The kernel side (kernel.cpp) owns two ring buffers per ElfProcess slot:
//     inbuf[]  — keystrokes pushed by the kernel, popped here on sys_read
//     outbuf[] — chars pushed here on sys_write, drained by kernel to terminal
//
//   Those buffers are accessed through four C-linkage callbacks that
//   kernel.cpp registers at process-launch time:
//     void  bochs_register_io_callbacks(int slot,
//               int  (*read_cb)(int slot),          // pop one byte (-1=empty)
//               void (*write_cb)(int slot, char c), // push one byte
//               void (*exit_cb)(int slot, int code))// process exited
//
//   BRK (sys_brk=45): we track a simple heap pointer inside the process
//   memory slab and return it, giving musl a working malloc.

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"

// ── ABI stubs ────────────────────────────────────────────────────────────────
extern "C" void* __dso_handle = nullptr;
extern "C" int   __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void  __cxa_finalize(void*) {}

// ── Per-process state ────────────────────────────────────────────────────────
#define MAX_BOCHS_SLOTS 4

struct SlotState {
    Bit8u*   mem_base    = nullptr;
    Bit32u   mem_size    = 0;
    Bit32u   vaddr_base  = 0;    // guest PA/VA where the slab is mapped
    Bit32u   brk_ptr     = 0;    // current brk as a guest VA
    int      slot_id     = -1;   // index into kernel's elf_processes[]
    bool     wants_input = false; // set by sys_read when no data available

    // Callbacks into kernel.cpp ring buffers
    int  (*read_cb )(int slot)        = nullptr; // returns -1 if empty
    void (*write_cb)(int slot, char c)= nullptr;
    void (*exit_cb )(int slot, int code)= nullptr;
};

static SlotState g_slots[MAX_BOCHS_SLOTS];
static int       g_active_slot = -1;  // which slot owns the current CPU context

// ── Memory handlers ───────────────────────────────────────────────────────────
static bool mem_read_handler(bx_phy_address addr, unsigned len,
                             void* data, void* /*param*/)
{
    if (g_active_slot < 0) { __builtin_memset(data, 0, len); return true; }
    SlotState& s = g_slots[g_active_slot];
    // Guest physical address → host offset: subtract vaddr_base
    Bit32u guest_pa = (Bit32u)addr;
    if (s.mem_base && guest_pa >= s.vaddr_base) {
        Bit32u off = guest_pa - s.vaddr_base;
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
    Bit32u guest_pa = (Bit32u)addr;
    if (s.mem_base && guest_pa >= s.vaddr_base) {
        Bit32u off = guest_pa - s.vaddr_base;
        if (off + len <= s.mem_size)
            __builtin_memcpy(s.mem_base + off, data, len);
    }
    return true;
}

// ── Syscall intercept ─────────────────────────────────────────────────────────
// Called by our custom INT hook (see bochs_cpu_init below).
// Reads guest registers, performs the syscall, writes result back to EAX.
//
// Linux i386 ABI:
//   EAX = syscall number
//   EBX, ECX, EDX, ESI, EDI, EBP = args 1-6
//   Return value in EAX (negative errno on error)

static void handle_guest_syscall(int /*slot_unused*/)
{
    if (g_active_slot < 0) return;
    SlotState& s = g_slots[g_active_slot];

    Bit32u eax = BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
    Bit32u ebx = BX_CPU(0)->gen_reg[BX_32BIT_REG_EBX].dword.erx;
    Bit32u ecx = BX_CPU(0)->gen_reg[BX_32BIT_REG_ECX].dword.erx;
    Bit32u edx = BX_CPU(0)->gen_reg[BX_32BIT_REG_EDX].dword.erx;

    Bit32u ret = (Bit32u)-38; // ENOSYS default

    // Helper: translate guest VA to host pointer (or nullptr if out of range)
    auto gva_to_host = [&](Bit32u gva) -> Bit8u* {
        if (!s.mem_base || gva < s.vaddr_base) return nullptr;
        Bit32u off = gva - s.vaddr_base;
        if (off >= s.mem_size) return nullptr;
        return s.mem_base + off;
    };

    switch (eax) {

    // ── sys_exit (1) and sys_exit_group (252) ────────────────────────────
    case 1:
    case 252: {
        int code = (int)ebx;
        if (s.exit_cb) s.exit_cb(s.slot_id, code);
        BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = 0;
        BX_CPU(0)->prev_rip = 0;
        BX_CPU(0)->invalidate_prefetch_q();
        return;
    }

    // ── sys_read (3) ─────────────────────────────────────────────────────
    case 3: {
        if (ebx != 0) { ret = (Bit32u)-9; break; }
        Bit32u buf_gva = ecx;
        Bit32u count   = edx;
        if (count == 0) { ret = 0; break; }
        if (!s.read_cb) { ret = 0; break; }

        Bit32u n = 0;
        while (n < count) {
            int ch = s.read_cb(s.slot_id);
            if (ch < 0) break;
            Bit8u* p = gva_to_host(buf_gva + n);
            if (p) *p = (Bit8u)ch;
            n++;
            if (ch == '\n') break;  // line at a time
        }
        if (n == 0) {
            s.wants_input = true;  // signal kernel: guest is blocked on read
        } else {
            s.wants_input = false;
        }
        ret = n;
        break;
    }

    // ── sys_write (4) ────────────────────────────────────────────────────
    case 4: {
        if (ebx != 1 && ebx != 2) { ret = (Bit32u)-9; break; }
        Bit32u buf_gva = ecx;
        Bit32u count   = edx;
        if (!s.write_cb) { ret = count; break; }

        Bit32u written = 0;
        for (Bit32u i = 0; i < count; i++) {
            Bit8u* p = gva_to_host(buf_gva + i);
            if (!p) break;
            s.write_cb(s.slot_id, (char)*p);
            written++;
        }
        ret = written;
        break;
    }

    // ── sys_brk (45) ─────────────────────────────────────────────────────
    // brk_ptr is a guest VA. Max VA is vaddr_base + mem_size.
    case 45: {
        Bit32u req = ebx;
        Bit32u max_brk = s.vaddr_base + s.mem_size - 256;  // leave stack room
        if (req == 0) {
            ret = s.brk_ptr;
        } else if (req >= s.brk_ptr && req < max_brk) {
            s.brk_ptr = req;
            ret = s.brk_ptr;
        } else {
            ret = s.brk_ptr;  // can't satisfy, return current (ENOMEM to libc)
        }
        break;
    }

    // ── sys_writev (146) ─────────────────────────────────────────────────
    case 146: {
        if (ebx != 1 && ebx != 2) { ret = (Bit32u)-9; break; }
        Bit32u iov_gva = ecx;
        Bit32u iovcnt  = edx;
        if (!s.write_cb) { ret = 0; break; }
        Bit32u total = 0;
        for (Bit32u v = 0; v < iovcnt; v++) {
            Bit8u* iov = gva_to_host(iov_gva + v * 8);
            if (!iov) break;
            Bit32u base = *(Bit32u*)(iov);
            Bit32u len  = *(Bit32u*)(iov + 4);
            for (Bit32u i = 0; i < len; i++) {
                Bit8u* p = gva_to_host(base + i);
                if (!p) break;
                s.write_cb(s.slot_id, (char)*p);
                total++;
            }
        }
        ret = total;
        break;
    }

    // ── sys_mmap2 (192) and sys_mmap (90) ────────────────────────────────
    // musl uses mmap for large allocations. Return ENOMEM so musl falls
    // back to brk-based malloc.
    case 90:
    case 192:
        ret = (Bit32u)-12; // ENOMEM
        break;

    // ── sys_munmap (91) ──────────────────────────────────────────────────
    case 91:
        ret = 0; // pretend it worked
        break;

    // ── sys_getpid (20), sys_getuid (24), sys_geteuid (49) etc. ─────────
    case 20: ret = 1; break;  // pid = 1
    case 24: ret = 0; break;  // uid = 0 (root)
    case 47: ret = 0; break;  // gid = 0
    case 49: ret = 0; break;  // euid = 0
    case 50: ret = 0; break;  // egid = 0

    // ── sys_ioctl (54) ───────────────────────────────────────────────────
    // musl probes terminal settings via ioctl. Return ENOTTY so it falls
    // back to dumb-terminal mode (no line editing, which we want).
    case 54:
        ret = (Bit32u)-25; // ENOTTY
        break;

    // ── sys_uname (122) ──────────────────────────────────────────────────
    case 122: {
        Bit32u buf_gva = ebx;
        const char* fields[] = { "Linux", "rtos", "5.15.0", "#1 SMP", "i686", "i686" };
        for (int f = 0; f < 6; f++) {
            const char* fld = fields[f];
            for (int k = 0; k <= 64; k++) {
                Bit8u* p = gva_to_host(buf_gva + f * 65 + k);
                if (p) *p = (k < 64 && fld[k]) ? (Bit8u)fld[k] : 0;
            }
        }
        ret = 0;
        break;
    }

    // ── sys_set_thread_area (243), sys_set_tid_address (258) ─────────────
    case 243:
    case 258:
        ret = 0;
        break;

    // ── Anything else: return ENOSYS ─────────────────────────────────────
    default:
        ret = (Bit32u)-38; // ENOSYS
        break;
    }

    // Write return value back to guest EAX
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx = ret;
}

// ── INT hook: Bochs calls this before dispatching any software interrupt ──────
// We override INT 0x80 (Linux syscall gate); all others are passed through.
//
// Bochs 2.7 instrumentation: BX_INSTR_INTERRUPT(cpu_id, vector)
// is a macro that calls bx_instr_interrupt(cpu_id, vector).
// We provide the real function here, overriding the stub in instrument_stub.h.
//
// IMPORTANT: instrument_stub.h must NOT define BX_INSTR_INTERRUPT as a no-op
// when bochs_glue.cpp is compiled.  The Makefile passes -DBOCHS_GLUE when
// compiling bochs_glue.cpp so we can conditionally un-stub it.

extern "C" void bx_instr_interrupt(unsigned cpu_id, unsigned vector)
{
    (void)cpu_id;
    if (vector == 0x80) {
        handle_guest_syscall(g_active_slot);
    }
    // All other interrupts: do nothing (Bochs handles them via its own IDT)
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

// bochs_set_process_memory(host_ptr, slab_size, vaddr_base)
// vaddr_base: the guest physical/virtual address where the slab starts.
// Bochs physical address = guest virtual address (flat 32-bit, no paging).
// We register the Bochs memory handler at PA [vaddr_base .. vaddr_base+size).
// The mem_read/write handlers translate: guest_PA - vaddr_base = host offset.
extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size, Bit32u vaddr_base)
{
    if (g_active_slot < 0) return;
    SlotState& s = g_slots[g_active_slot];

    // Unregister previous range
    if (s.mem_base && s.mem_size)
        BX_MEM(0)->unregisterMemoryHandlers(nullptr,
            (bx_phy_address)s.vaddr_base,
            (bx_phy_address)(s.vaddr_base + s.mem_size - 1));

    s.mem_base   = base;
    s.mem_size   = size;
    s.vaddr_base = vaddr_base;

    if (base && size)
        BX_MEM(0)->registerMemoryHandlers(
            nullptr,
            mem_read_handler,
            mem_write_handler,
            (bx_phy_address)vaddr_base,
            (bx_phy_address)(vaddr_base + size - 1));
}

// Set the initial brk (called after ELF segments are loaded so brk starts
// just after BSS, giving musl malloc a valid heap within our slab).
extern "C" void bochs_set_brk(int slot, Bit32u brk_addr)
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return;
    g_slots[slot].brk_ptr = brk_addr;
}

// Switch the CPU context to a different slot.
// Must be called before bochs_cpu_tick() for the correct process.
extern "C" void bochs_activate_slot(int slot)
{
    g_active_slot = slot;
}

extern "C" void bochs_cpu_init()
{
    BX_CPU(0)->initialize();
    BX_CPU(0)->reset(BX_RESET_HARDWARE);
}

extern "C" int bochs_cpu_tick(int n)
{
    if (g_active_slot >= 0)
        g_slots[g_active_slot].wants_input = false;  // reset before tick
    for (int i = 0; i < n; ++i)
        BX_CPU(0)->cpu_loop();
    return 0;
}

extern "C" bool bochs_process_wants_input(int slot)
{
    if (slot < 0 || slot >= MAX_BOCHS_SLOTS) return false;
    return g_slots[slot].wants_input;
}

extern "C" void bochs_cpu_set_eip(Bit32u eip)
{
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    BX_CPU(0)->prev_rip = eip;
    BX_CPU(0)->invalidate_prefetch_q();
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
