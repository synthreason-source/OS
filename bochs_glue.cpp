#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
extern "C" void bochs_cpu_init(){bx_cpu.initialize(); bx_cpu.reset(BX_RESET_HARDWARE);}
extern "C" int bochs_cpu_tick(int n){for(int i=0;i<n;i++)bx_cpu.cpu_loop();return 0;}
extern "C" unsigned int bochs_cpu_get_eip(){return bx_cpu.get_instruction_pointer();}
// bochs_stubs.cpp
// Stub implementations of all Bochs globals and infrastructure
// needed to link libcpu.a, libfpu.a, libcpudb.a, libmemory.a
// into a freestanding kernel without the full Bochs application.

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

// ═════════════════════════════════════════════════════════════════════════
// logfunctions  (every BX_CPU_C method calls this->log->xxx())
// ═════════════════════════════════════════════════════════════════════════

logfunctions::logfunctions() {
    prefix = nullptr;
    type   = nullptr;
    onoff[LOGLEV_DEBUG]  = ACT_IGNORE;
    onoff[LOGLEV_INFO]   = ACT_IGNORE;
    onoff[LOGLEV_ERROR]  = ACT_IGNORE;
    onoff[LOGLEV_PANIC]  = ACT_IGNORE;
    onoff[LOGLEV_WARN]   = ACT_IGNORE;
    for (int i = 0; i < N_LOGLEV; i++) onoff[i] = ACT_IGNORE;
}
logfunctions::~logfunctions() {}

void logfunctions::put(const char*, const char*) {}
void logfunctions::settype(int) {}
void logfunctions::setid(int) {}
const char *logfunctions::getprefix() const { return ""; }
const char *logfunctions::gettype()   const { return ""; }

void logfunctions::info  (const char*, ...) {}
void logfunctions::error (const char*, ...) {}
void logfunctions::warn  (const char*, ...) {}
void logfunctions::panic (const char*, ...) { while(1); }
void logfunctions::ldebug(const char*, ...) {}
void logfunctions::fatal1(const char*, ...) { while(1); }
void logfunctions::fatal (const char *prefix, const char *fmt, va_list, int) { while(1); }

int logfunctions::getonoff(int level) const { return ACT_IGNORE; }
void logfunctions::setonoff(int, int) {}
void logfunctions::set_log_action(int, int) {}

// Global log objects Bochs expects
logfunctions  _genlog_obj;
logfunctions  _pluginlog_obj;
logfunctions *genlog    = &_genlog_obj;
logfunctions *pluginlog = &_pluginlog_obj;

// ═════════════════════════════════════════════════════════════════════════
// bx_cpu  – array of CPU pointers; index 0 is our single CPU instance
// ═════════════════════════════════════════════════════════════════════════
// The real BX_CPU_C instance lives in bochs_glue.cpp.
// Bochs source uses the macro BX_CPU(n) which expands to bx_cpu[n],
// but the object files reference the raw global symbol bx_cpu.
// We declare it extern so bochs_glue.cpp can define it.
// Actually Bochs code accesses  bx_cpu[n]  so we need an array of pointers.

BX_CPU_C *bx_cpu[BX_SMP_PROCESSORS];   // populated by bochs_glue.cpp

// ═════════════════════════════════════════════════════════════════════════
// BX_MEM_C  (memory subsystem)
// ═════════════════════════════════════════════════════════════════════════

// Provide a flat 4 MB physical memory region.
static uint8_t _phys_mem[4 * 1024 * 1024];
static size_t  _phys_mem_size = sizeof(_phys_mem);

// Singleton accessed via bx_mem pointer
static BX_MEM_C _mem_obj;
BX_MEM_C       *bx_mem = &_mem_obj;

BX_MEM_C::BX_MEM_C() {
    vector         = _phys_mem;
    actual_vector  = _phys_mem;
    blocks         = nullptr;
    len            = _phys_mem_size;
    allocated      = _phys_mem_size;
    rom            = nullptr;
    bogus          = nullptr;
    pci_enabled    = 0;
    smram_available    = 0;
    smram_enable       = 0;
    smram_restricted   = 0;
    memory_handlers    = nullptr;
    num_blocks         = 0;
    used_blocks        = 0;
    log                = genlog;
}
BX_MEM_C::~BX_MEM_C() {}

void BX_MEM_C::init_memory(Bit64u guest, Bit64u host) {
    // Already done in constructor
}
void BX_MEM_C::cleanup_memory() {}
void BX_MEM_C::register_state() {}
void BX_MEM_C::load_ROM(const char*, Bit64u, Bit8u) {}
void BX_MEM_C::load_RAM(const char*, Bit64u) {}
bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C*, bx_phy_address, unsigned, Bit8u *buf) {
    return false;
}

Bit8u *BX_MEM_C::alloc_vector_aligned(Bit64u, Bit64u) { return nullptr; }
void   BX_MEM_C::allocate_block(Bit32u) {}
void   BX_MEM_C::read_block(Bit32u) {}

void BX_MEM_C::writePhysicalPage(BX_CPU_C*, bx_phy_address addr,
                                  unsigned len, void *data) {
    if ((size_t)addr + len <= _phys_mem_size)
        __builtin_memcpy(_phys_mem + addr, data, len);
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C*, bx_phy_address addr,
                                 unsigned len, void *data) {
    if ((size_t)addr + len <= _phys_mem_size)
        __builtin_memcpy(data, _phys_mem + addr, len);
    else
        __builtin_memset(data, 0, len);
}

void BX_MEM_C::dmaReadPhysicalPage(bx_phy_address addr, unsigned len, Bit8u *buf) {
    readPhysicalPage(nullptr, addr, len, buf);
}
void BX_MEM_C::dmaWritePhysicalPage(bx_phy_address addr, unsigned len, Bit8u *buf) {
    writePhysicalPage(nullptr, addr, len, buf);
}

Bit8u *BX_MEM_C::getHostMemAddr(BX_CPU_C*, bx_phy_address addr, unsigned) {
    if ((size_t)addr < _phys_mem_size) return _phys_mem + addr;
    return nullptr;
}

void BX_MEM_C::registerMemoryHandlers(void*, memory_handler_t, memory_handler_t,
                                       memory_direct_access_handler_t,
                                       Bit64u, Bit64u) {}
void BX_MEM_C::unregisterMemoryHandlers(void*, Bit64u, Bit64u) {}
void BX_MEM_C::enable_smram(bool, bool) {}
void BX_MEM_C::disable_smram() {}
bool BX_MEM_C::is_smram_accessible() { return false; }
void BX_MEM_C::set_memory_type(memory_area_t, bool, bool) {}
void BX_MEM_C::set_bios_write(bool) {}
void BX_MEM_C::set_bios_rom_access(Bit8u, bool) {}

// ═════════════════════════════════════════════════════════════════════════
// bx_pc_system_c  (timer / system controller)
// ═════════════════════════════════════════════════════════════════════════

static bx_pc_system_c _pc_system_obj;
bx_pc_system_c bx_pc_system;   // Bochs code accesses this as a global object

bx_pc_system_c::bx_pc_system_c() {
    HRQ                    = 0;
    INTR                   = 0;
    kill_bochs_request     = 0;
    currCountdownPeriod    = 0;
    countdown              = 0;
    countdownEvent         = 0;
    enabling               = 0;
    num_timers             = 0;
    TicksTotal             = 0;
    for (int i = 0; i < BX_MAX_TIMERS; i++) {
        timer[i].inUse    = 0;
        timer[i].active   = 0;
        timer[i].period   = 0;
        timer[i].timeToFire = 0;
        timer[i].continuous = 0;
        timer[i].funct    = nullptr;
        timer[i].this_ptr = nullptr;
    }
}

int  bx_pc_system_c::register_timer_ticks(void *this_ptr, bx_timer_handler_t,
                                           Bit64u, bx_bool, bx_bool, const char*) {
    return 0;
}
void bx_pc_system_c::activate_timer_ticks(unsigned, Bit64u, bx_bool) {}
void bx_pc_system_c::deactivate_timer(unsigned) {}
void bx_pc_system_c::countdownEvent() {}
void bx_pc_system_c::Reset(unsigned) {}
void bx_pc_system_c::invlpg(bx_address) {}
Bit64u bx_pc_system_c::time_ticks() { return 0; }
Bit64u bx_pc_system_c::time_usec()  { return 0; }
void bx_pc_system_c::set_HRQ(bx_bool) {}

// ═════════════════════════════════════════════════════════════════════════
// bx_devices_c  (I/O device layer)
// ═════════════════════════════════════════════════════════════════════════

class bx_stub_devices_c : public bx_devices_c {
public:
    Bit32u inp(Bit16u, unsigned)         { return 0xFFFFFFFF; }
    void   outp(Bit16u, Bit32u, unsigned){}
};
static bx_stub_devices_c _devices_obj;
bx_devices_c *bx_devices = &_devices_obj;

// ═════════════════════════════════════════════════════════════════════════
// SIM  (simulator interface – only used for CPUID config queries)
// ═════════════════════════════════════════════════════════════════════════

class bx_stub_simulator_c : public bx_simulator_interface_c {
public:
    // CPUID-related queries used by generic_cpuid / cpudb
    Bit32u get_param_num(const char *, bx_param_c*) override { return 0; }
    bx_param_c *get_param(const char *, bx_param_c*) override { return nullptr; }
    bx_param_num_c *get_param_num(const char*) override { return nullptr; }
    bx_param_bool_c *get_param_bool(const char*) override { return nullptr; }
    bx_param_string_c *get_param_string(const char*) override { return nullptr; }
    bx_param_enum_c *get_param_enum(const char*) override { return nullptr; }
    int get_default_rc(char*, int) override { return 0; }
    SimInterfaceCallback_t set_notify_callback(SimInterfaceCallback_t, void*) override { return nullptr; }
    void get_notify_callback(SimInterfaceCallback_t*, void**) override {}
    bx_param_c *get_first_param(const char*, bx_list_c*) override { return nullptr; }
    int  get_n_log_modules() override { return 0; }
    const char *get_logfn_name(int) override { return ""; }
    const char *get_logfn_prefix(int) override { return ""; }
    int  get_log_action(int, int) override { return ACT_IGNORE; }
    void set_log_action(int, int, int) override {}
    const char *get_action_name(int) override { return ""; }
    const char *get_log_level_name(int) override { return ""; }
    int  get_max_log_level() override { return N_LOGLEV; }
    void quit_sim(int) override { while(1); }
    int  get_exit_code() override { return 0; }
    int  get_default_log_action() override { return ACT_IGNORE; }
    void set_default_log_action(int, int) override {}
    const char *get_filename() override { return ""; }
    bx_list_c *get_bochs_root() override { return nullptr; }
    bx_bool save_state(const char*) override { return 0; }
    bx_bool restore_bochs_param(bx_list_c*, const char*, int) override { return 0; }
    bx_bool restore_hardware() override { return 0; }
    bx_bool restore_logopts() override { return 0; }
};

static bx_stub_simulator_c _sim_obj;
bx_simulator_interface_c *SIM = &_sim_obj;

// ═════════════════════════════════════════════════════════════════════════
// Bochs param system stubs  (bx_list_c, bx_shadow_num_c, etc.)
// Used by BX_CPU_C::register_state() / BX_MEM_C::register_state()
// We just allocate-and-ignore; nothing calls restore on us.
// ═════════════════════════════════════════════════════════════════════════

bx_param_c::bx_param_c(bx_param_c*, const char*, const char*) {}
bx_param_c::bx_param_c(bx_param_c*, const char*) {}
bx_param_c::~bx_param_c() {}

bx_list_c::bx_list_c(bx_param_c*, const char*, const char*) {}
bx_list_c::bx_list_c(bx_param_c*, const char*) {}
bx_list_c::~bx_list_c() {}
bx_list_c *bx_list_c::add(bx_param_c*) { return this; }

// bx_param_num_c
bx_param_num_c::bx_param_num_c(bx_param_c*, const char*, const char*,
                                const char*, Bit64s, Bit64s, Bit64s, bx_bool) {}
void bx_param_num_c::set_sr_handlers(void*,
    Bit64s(*)(void*, bx_param_c*),
    void (*)(void*, bx_param_c*, Bit64s)) {}

// bx_shadow_num_c – many overloads, all no-ops
#define STUB_SHADOW_NUM(T) \
    bx_shadow_num_c::bx_shadow_num_c(bx_param_c*, const char*, T*, int, Bit8u, Bit8u) {}

STUB_SHADOW_NUM(Bit8u)
STUB_SHADOW_NUM(Bit8s)
STUB_SHADOW_NUM(Bit16u)
STUB_SHADOW_NUM(Bit16s)
STUB_SHADOW_NUM(Bit32u)
STUB_SHADOW_NUM(Bit32s)
STUB_SHADOW_NUM(Bit64u)
STUB_SHADOW_NUM(Bit64s)

bx_shadow_bool_c::bx_shadow_bool_c(bx_param_c*, const char*, bx_bool*) {}
bx_shadow_bool_c::bx_shadow_bool_c(bx_param_c*, const char*, bool*) {}

bx_shadow_filedata_c::bx_shadow_filedata_c(bx_param_c*, const char*, FILE**) {}
void bx_shadow_filedata_c::set_sr_handlers(void*,
    filedata_save_handler, filedata_restore_handler) {}

// ═════════════════════════════════════════════════════════════════════════
// APIC / misc Bochs globals
// ═════════════════════════════════════════════════════════════════════════

//bx_bool  simulate_xapic = 0;
Bit32u   apic_id_mask   = 0;
bx_debug_t bx_dbg;

// FPU_tagof – used by sse_move / xsave

// ═════════════════════════════════════════════════════════════════════════
// C stdlib symbols that Bochs references but we are -nostdlib
// ═════════════════════════════════════════════════════════════════════════

extern "C" {
    // string.h
    int    strcmp(const char *a, const char *b) {
        while (*a && *a == *b) { a++; b++; }
        return (unsigned char)*a - (unsigned char)*b;
    }
    int    strncmp(const char *a, const char *b, size_t n) {
        while (n && *a && *a == *b) { a++; b++; n--; }
        if (!n) return 0;
        return (unsigned char)*a - (unsigned char)*b;
    }
    size_t strlen(const char *s) {
        size_t n = 0; while (*s++) n++; return n;
    }

    // stdio-ish (only called from print_state_FPU / load_MSRs,
    //            which we never invoke)
    int    sprintf(char *buf, const char *fmt, ...) { return 0; }

    // math (used by print_state_FPU)
    double pow(double, double) { return 0.0; }

    // stdlib
    void   srand(unsigned) {}
    int    rand() { return 0; }
    void  *malloc(size_t n) { return __builtin_alloca(n); } // simplistic
    void   free(void*) {}
    void  *realloc(void*, size_t) { return nullptr; }

    // time
    long   time(long *t) { if (t) *t = 0; return 0; }

    // setjmp / longjmp (used by cpu_loop / exception)
    // provided by libgcc/-fno-stack-protector path
    // but declare them weak just in case
    __attribute__((weak)) void __longjmp_chk(void*, int) { while(1); }

    // __assert_fail
    void __assert_fail(const char*, const char*, unsigned, const char*) { while(1); }

    // __cxa_*
    void *__dso_handle = nullptr;
    int   __cxa_atexit(void(*)(void*), void*, void*) { return 0; }
    void  __cxa_guard_abort(void*) {}

    // file I/O (called from misc_mem / msr, never in our path)
    int   open64(const char*, int, ...) { return -1; }
    int   close(int) { return 0; }
    int   read(int, void*, size_t) { return -1; }
    void *tmpfile64() { return nullptr; }
    int   __isoc23_sscanf(const char*, const char*, ...) { return 0; }
    long  __isoc23_strtol(const char*, char**, int) { return 0; }

    // fortify wrappers
    int  __sprintf_chk(char *buf, int, size_t, const char *fmt, ...) { return 0; }
    int  __vsprintf_chk(char*, int, size_t, const char*, va_list) { return 0; }

    // division helper (usually in libgcc but may be missing for -m32)
    __attribute__((weak))
    unsigned long long __udivdi3(unsigned long long a, unsigned long long b) {
        if (!b) return 0;
        // simple slow division
        unsigned long long q = 0, r = 0;
        for (int i = 63; i >= 0; i--) {
            r = (r << 1) | ((a >> i) & 1);
            if (r >= b) { r -= b; q |= 1ULL << i; }
        }
        return q;
    }
} // extern "C"
