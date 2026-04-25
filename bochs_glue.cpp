#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"

extern "C" void *__dso_handle = nullptr;

extern "C" int __cxa_atexit(void (*)(void*), void*, void*) { return 0; }
extern "C" void __cxa_finalize(void*) {}

// ── Memory backing ────────────────────────────────────────────────────────────
// Bochs reads/writes guest physical memory through BX_MEM().  We redirect
// those calls to whichever process slab is currently active.
static uint8_t* g_mem_base  = nullptr;
static uint32_t g_mem_size  = 0;
static uint8_t* g_stack_base = nullptr;

extern "C" void bochs_set_process_memory(uint8_t* base,
                                          uint32_t size,
                                          uint8_t* stack)
{
    g_mem_base   = base;
    g_mem_size   = size;
    g_stack_base = stack;
    // Tell the Bochs memory model where RAM lives.
    // BX_MEM(0) is the singleton; direct_ptr is the simplest hook.
    BX_MEM(0)->set_memory_type(BX_MEMTYPE_WB);   // may be a no-op stub
    // If libmemory exposes a base pointer, set it here.  The common pattern:
    BX_MEM(0)->mem_base = base;     // <-- adjust to actual field name in 2.7
    BX_MEM(0)->megabytes_needed = (size + 0xFFFFF) >> 20;
}

// ── CPU lifecycle ─────────────────────────────────────────────────────────────
extern "C" void bochs_cpu_init() {
    bx_cpu.initialize();
    bx_cpu.reset(BX_RESET_HARDWARE);
}

extern "C" int bochs_cpu_tick(int n) {
    for (int i = 0; i < n; ++i)
        BX_CPU_C::cpu_loop();
    return 0;
}

// ── Register accessors ────────────────────────────────────────────────────────
extern "C" void bochs_cpu_set_eip(uint32_t eip) {
    bx_cpu.sregs[BX_SEG_REG_CS].cache.u.segment.base = 0;
    bx_cpu.prev_rip = eip;
    bx_cpu.RIP      = eip;          // sets the internal EIP field
}

extern "C" void bochs_cpu_set_esp(uint32_t esp_val) {
    bx_cpu.gen_reg[BX_32BIT_REG_ESP].dword.erx = esp_val;
}

extern "C" uint32_t bochs_cpu_get_eip() {      // matches kernel.cpp declaration
    return (uint32_t)bx_cpu.get_instruction_pointer();
}

// kept for any legacy call sites that use the old name
extern "C" unsigned int bochs_cpu_geteip() {
    return (unsigned int)bx_cpu.get_instruction_pointer();
}

extern "C" uint32_t bochs_cpu_get_eax() {
    return bx_cpu.gen_reg[BX_32BIT_REG_EAX].dword.erx;
}