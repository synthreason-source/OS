// bochs_glue.cpp
// Verified against actual Bochs 2.7 source (memory-bochs.h, cpu/cpu.h,
// cpu/decoder/decoder.h, bx_debug/debug.h).

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"   // defines BX_MEM_C + extern bx_mem

// ── ABI stubs ─────────────────────────────────────────────────────────────────
extern "C" void* __dso_handle = nullptr;
extern "C" int  __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void __cxa_finalize(void*) {}

// ── Process memory slab ───────────────────────────────────────────────────────
static Bit8u*   g_mem_base = nullptr;
static Bit32u   g_mem_size = 0;

// Memory-handler callbacks registered with registerMemoryHandlers().
// Bochs calls these for every physical read/write that falls in the
// registered address range [0, g_mem_size).
// Signature: bool handler(bx_phy_address addr, unsigned len, void* data, void* param)

static bool mem_read_handler(bx_phy_address addr, unsigned len, void* data, void* /*param*/)
{
    Bit32u offset = (Bit32u)addr;
    if (g_mem_base && offset + len <= g_mem_size) {
        __builtin_memcpy(data, g_mem_base + offset, len);
    } else {
        __builtin_memset(data, 0, len);
    }
    return true;   // true = handled, Bochs won't touch its own RAM
}

static bool mem_write_handler(bx_phy_address addr, unsigned len, void* data, void* /*param*/)
{
    Bit32u offset = (Bit32u)addr;
    if (g_mem_base && offset + len <= g_mem_size) {
        __builtin_memcpy(g_mem_base + offset, data, len);
    }
    return true;
}

extern "C" void bochs_set_process_memory(Bit8u* base, Bit32u size, Bit8u* /*stack*/)
{
    // Unregister old range if any
    if (g_mem_base && g_mem_size) {
        BX_MEM(0)->unregisterMemoryHandlers(nullptr, 0, (bx_phy_address)(g_mem_size - 1));
    }

    g_mem_base = base;
    g_mem_size = size;

    if (base && size) {
        BX_MEM(0)->registerMemoryHandlers(
            nullptr,
            mem_read_handler,
            mem_write_handler,
            (bx_phy_address)0,
            (bx_phy_address)(size - 1)
        );
    }
}

// ── CPU lifecycle ─────────────────────────────────────────────────────────────
extern "C" void bochs_cpu_init()
{
    // With BX_USE_CPU_SMF=1 all BX_CPU_C methods are static; call via BX_CPU(0)->
    BX_CPU(0)->initialize();//fixme
    BX_CPU(0)->reset(BX_RESET_HARDWARE);;//fixme
}

// cpu_loop() is an instance/static method -- call via BX_CPU(0)-> either way.
extern "C" int bochs_cpu_tick(int n)
{
    for (int i = 0; i < n; ++i)
        BX_CPU(0)->cpu_loop();
    return 0;
}

// ── Register accessors ────────────────────────────────────────────────────────
// dbg_set_eip() is guarded by #if BX_DEBUGGER, so we set EIP directly.
// With --disable-x86-64 (our build), BX_GENERAL_REGISTERS=8, so:
//   BX_32BIT_REG_EIP = 8  (BX_GENERAL_REGISTERS)
// The EIP macro expands to: BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx
// With BX_USE_CPU_SMF=1, BX_CPU_THIS_PTR = BX_CPU(0)->

extern "C" void bochs_cpu_set_eip(Bit32u eip)
{
    // Set both EIP and prev_rip so the prefetch queue is coherent.
    BX_CPU(0)->gen_reg[BX_32BIT_REG_EIP].dword.erx = eip;
    BX_CPU(0)->prev_rip = eip;
    BX_CPU(0)->invalidate_prefetch_q();
}

extern "C" void bochs_cpu_set_esp(Bit32u esp_val)
{
    // BX_32BIT_REG_ESP = 4 (index in BxRegs32 enum)
    BX_CPU(0)->gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
}

extern "C" Bit32u bochs_cpu_get_eip()
{
    return BX_CPU(0)->get_eip();   // inline in cpu.h, no BX_DEBUGGER guard
}

// Legacy name kept for compatibility
extern "C" unsigned int bochs_cpu_geteip()
{
    return (unsigned int)BX_CPU(0)->get_eip();
}

extern "C" Bit32u bochs_cpu_get_eax()
{
    // BX_32BIT_REG_EAX = 0
    return BX_CPU(0)->gen_reg[BX_32BIT_REG_EAX].dword.erx;
}