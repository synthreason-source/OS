// bochs_infra.cpp — Bochs 2.7 infrastructure for freestanding kernel.
// Compiled with system headers so bochs.h can include <stdio.h> etc.
// C stdlib stubs and freestanding functions are in bochs_cstubs.c (no system headers).

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/cpu/icache.h"
#include "bochs-2.7/iodev/iodev.h"
#include "bochs-2.7/pc_system.h"
#include "bochs-2.7/plugin.h"
#include "bochs-2.7/gui/siminterface.h"
#include "bochs-2.7/gui/paramtree.h"
#include <stdarg.h>

// ═══ logfunctions ════════════════════════════════════════════════════════════
// N_LOGLEV = 4

int logfunctions::default_onoff[N_LOGLEV] = {0, 0, 0, 0};

logfunctions::logfunctions(void)                  { prefix = nullptr; logio = nullptr; }
logfunctions::logfunctions(class iofunctions* io) { prefix = nullptr; logio = io; }
logfunctions::~logfunctions(void) {}
void logfunctions::put(const char*)              {}
void logfunctions::put(const char*, const char*) {}
void logfunctions::info (const char*, ...)       {}
void logfunctions::error(const char*, ...)       {}
void logfunctions::ldebug(const char*, ...)      {}
void logfunctions::panic(const char*, ...) { asm volatile("cli; hlt"); __builtin_unreachable(); }
void logfunctions::fatal1(const char*, ...) { asm volatile("cli; hlt"); __builtin_unreachable(); }
void logfunctions::fatal(int, const char*, const char*, va_list, int) {
    asm volatile("cli; hlt"); __builtin_unreachable();
}
void logfunctions::warn(int, const char*, const char*, va_list) {}
void logfunctions::ask (int, const char*, const char*, va_list) {}
void logfunctions::setio(class iofunctions* io) { logio = io; }

iofunctions::iofunctions(void)          {}
iofunctions::iofunctions(FILE*)         {}
iofunctions::iofunctions(int)           {}
iofunctions::iofunctions(const char*)   {}
iofunctions::~iofunctions(void)         {}
void iofunctions::out(int, const char*, const char*, va_list) {}
void iofunctions::set_log_action(int, int) {}

static logfunc_t s_log;
logfunc_t* genlog    = &s_log;
logfunc_t* pluginlog = &s_log;
logfunc_t* siminterface_log = &s_log;
iofunc_t*  io        = nullptr;

// ═══ bochs globals ════════════════════════════════════════════════════════════

BX_CPU_C        bx_cpu(0);
static BX_CPU_C* s_cpu_ptr = &bx_cpu;
BX_CPU_C**      bx_cpu_array = &s_cpu_ptr;

BX_MEM_C        bx_mem;
bx_debug_t      bx_dbg   = {};
Bit8u           bx_cpu_count = 1;
Bit32u          apic_id_mask = 0;
// simulate_xapic is in bochs_cstubs.c as int; declare extern int here
extern int simulate_xapic;

// ═══ bx_devices_c ════════════════════════════════════════════════════════════

bx_devices_c    bx_devices;

bx_devices_c::bx_devices_c() {
    read_port_to_handler  = nullptr;
    write_port_to_handler = nullptr;
    io_read_handlers.next  = nullptr;
    io_read_handlers.handler_name = nullptr;
    io_write_handlers.next = nullptr;
    io_write_handlers.handler_name = nullptr;
    for (unsigned i = 0; i < BX_MAX_IRQS; i++) irq_handler_name[i] = nullptr;
    sound_device_count = 0;
}
bx_devices_c::~bx_devices_c() {}
void bx_devices_c::init_stubs() {}

Bit32u bx_devices_c::inp (Bit16u, unsigned) { return 0xFFFF; }
void   bx_devices_c::outp(Bit16u, Bit32u, unsigned) {}

// ═══ bx_pc_system_c ══════════════════════════════════════════════════════════

bx_pc_system_c  bx_pc_system;

void bx_pc_system_c::invlpg(Bit32u) {}
void bx_pc_system_c::countdownEvent() {}
int  bx_pc_system_c::Reset(unsigned) { return 0; }
void bx_pc_system_c::deactivate_timer(unsigned) {}
void bx_pc_system_c::activate_timer_ticks(unsigned, Bit64u, bool) {}
int  bx_pc_system_c::register_timer_ticks(void*, bx_timer_handler_t, Bit64u, bool, bool, const char*) {
    return 0;
}

// ═══ Param tree globals ═══════════════════════════════════════════════════════
// bx_param_c / bx_shadow_num_c / bx_list_c etc. are provided by bochs_paramtree.o

bx_list_c* root_param = nullptr;

// ═══ SIM stub ════════════════════════════════════════════════════════════════

class KernelSIM : public bx_simulator_interface_c {
public:
    void quit_sim(int) override { asm volatile("cli; hlt"); __builtin_unreachable(); }
    int  get_exit_code() override { return 0; }
};
static KernelSIM s_sim;
bx_simulator_interface_c* SIM = &s_sim;

// ═══ bx_user_quit (bool in siminterface.h) ════════════════════════════════════
bool bx_user_quit = false;

// ═══ bx_gui stub ══════════════════════════════════════════════════════════════
// bx_gui_c is declared in gui.h as a class inheriting logfunctions.
// We just need a nullptr pointer and a stub cleanup() override.
bx_gui_c* bx_gui = nullptr;

// ═══ Misc bochs globals ════════════════════════════════════════════════════════
void print_statistics_tree(bx_param_c*, int) {}

// ═══ RTTI for logfunctions (needed by BX_CPU_C and BX_MEM_C typeinfo) ═══════
// These symbols must be provided so the RTTI chain for BX_CPU_C and BX_MEM_C resolves.
// The mangled names match what the linker expects.
extern "C" {
    extern char _ZTS12logfunctions[] = "12logfunctions";
    extern void* _ZTI12logfunctions[] = {
        nullptr,                         // vptr placeholder
        (void*)_ZTS12logfunctions
    };
}

// ═══ C++ ABI stubs ══════════════════════════════════════════════════════════
extern "C" {
    void _Unwind_Resume(void*) { asm volatile("cli; hlt"); __builtin_unreachable(); }
    int  __gxx_personality_v0(...) { return 0; }
    int  __gcc_personality_v0(...) { return 0; }
    void __cxa_guard_abort(long long*) {}
    void* __dso_handle = nullptr;
}

// operator delete with alignment (C++17)
void operator delete(void*, unsigned int, std::align_val_t) noexcept {}

// ═══ Plugin function pointers (from plugin.h, last arg is Bit8u) ═════════════
int  (*pluginRegisterIOReadHandler)        (void*, ioReadHandler_t,  unsigned,          const char*, Bit8u) = nullptr;
int  (*pluginRegisterIOWriteHandler)       (void*, ioWriteHandler_t, unsigned,          const char*, Bit8u) = nullptr;
int  (*pluginUnregisterIOReadHandler)      (void*, ioReadHandler_t,  unsigned,          Bit8u)              = nullptr;
int  (*pluginUnregisterIOWriteHandler)     (void*, ioWriteHandler_t, unsigned,          Bit8u)              = nullptr;
int  (*pluginRegisterIOReadHandlerRange)   (void*, ioReadHandler_t,  unsigned, unsigned, const char*, Bit8u) = nullptr;
int  (*pluginRegisterIOWriteHandlerRange)  (void*, ioWriteHandler_t, unsigned, unsigned, const char*, Bit8u) = nullptr;
int  (*pluginUnregisterIOReadHandlerRange) (void*, ioReadHandler_t,  unsigned, unsigned, Bit8u)              = nullptr;
int  (*pluginUnregisterIOWriteHandlerRange)(void*, ioWriteHandler_t, unsigned, unsigned, Bit8u)              = nullptr;
int  (*pluginRegisterDefaultIOReadHandler) (void*, ioReadHandler_t,  const char*, Bit8u) = nullptr;
int  (*pluginRegisterDefaultIOWriteHandler)(void*, ioWriteHandler_t, const char*, Bit8u) = nullptr;
void (*pluginRegisterIRQ)       (unsigned, const char*) = nullptr;
void (*pluginUnregisterIRQ)     (unsigned, const char*) = nullptr;
void (*pluginSetHRQ)            (unsigned)              = nullptr;
void (*pluginSetHRQHackCallback)(void (*)(void))        = nullptr;

// ─── bx_devices_c remaining methods ──────────────────────────────────────────
void bx_devices_c::reset(unsigned) {}
void bx_devices_c::exit()          {}

// ─── bx_gui_c::cleanup stub ──────────────────────────────────────────────────
void bx_gui_c::cleanup() {}

// ─── bx_pci_device_c ─────────────────────────────────────────────────────────
// pci_read_handler and pci_write_handler are pure virtual — provide bodies.
Bit32u bx_pci_device_c::pci_read_handler(Bit8u, unsigned) { return 0; }
