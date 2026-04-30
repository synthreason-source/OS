// bochs_infra.cpp — infrastructure for Bochs CPU libs in freestanding kernel.
// Compiled with standard (non-freestanding) flags to satisfy bochs type requirements.
#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/iodev/iodev.h"
#include "bochs-2.7/pc_system.h"
#include "bochs-2.7/plugin.h"
#include "bochs-2.7/gui/siminterface.h"
#include "bochs-2.7/cpu/icache.h"

// ── logfunctions implementation ──────────────────────────────────────────────
// The actual fields per logio.h: prefix (char*), onoff (int[N_LOGLEV]), logio (iofunctions*)
logfunctions::logfunctions(void) { prefix = nullptr; logio = nullptr; }
logfunctions::logfunctions(class iofunctions* i) { prefix = nullptr; logio = i; }
logfunctions::~logfunctions(void) {}
void logfunctions::put(const char*) {}
void logfunctions::put(const char*, const char*) {}
void logfunctions::info (const char*, ...) {}
void logfunctions::error(const char*, ...) {}
void logfunctions::panic(const char*, ...) { asm volatile("cli; hlt"); __builtin_unreachable(); }
void logfunctions::fatal1(const char*, ...) { asm volatile("cli; hlt"); __builtin_unreachable(); }
void logfunctions::fatal(int, const char*, const char*, __va_list_tag*, int) { asm volatile("cli; hlt"); }
void logfunctions::ldebug(const char*, ...) {}
void logfunctions::warn(int, const char*, const char*, __va_list_tag*) {}
void logfunctions::ask (int, const char*, const char*, __va_list_tag*) {}

int logfunctions::default_onoff[N_LOGLEV] = {0, 0, 0, 0, 0};

// iofunctions stub
iofunctions::iofunctions() {}
iofunctions::iofunctions(FILE*) {}
iofunctions::iofunctions(const char*) {}
iofunctions::~iofunctions() {}
void iofunctions::out(int, const char*, ...) {}
void iofunctions::set_log_action(int, int) {}
int  iofunctions::get_log_action(int) { return 0; }

static logfunc_t s_log_instance;
logfunc_t* genlog    = &s_log_instance;
logfunc_t* pluginlog = &s_log_instance;
iofunc_t*  io        = nullptr;

// ── Bochs global objects ─────────────────────────────────────────────────────
BX_CPU_C        bx_cpu(0);
static BX_CPU_C* s_cpu_ptr = &bx_cpu;
BX_CPU_C**      bx_cpu_array = &s_cpu_ptr;

BX_MEM_C        bx_mem;
bx_debug_t      bx_dbg = {};
Bit8u           bx_cpu_count = 1;
Bit32u          apic_id_mask = 0;
bx_devices_c    bx_devices;
bx_pc_system_c  bx_pc_system;

// SMC / icache
bxPageWriteStampTable pageWriteStampTable;
void flushICaches() {}
const char* cpu_mode_string(unsigned) { return "protected"; }

// ── SIM stub ─────────────────────────────────────────────────────────────────
class KernelSIM : public bx_simulator_interface_c {
public:
    bx_param_c*        get_param       (const char*, bx_param_c* = nullptr) override { return nullptr; }
    bx_param_num_c*    get_param_num   (const char*, bx_param_c* = nullptr) override { return nullptr; }
    bx_param_string_c* get_param_string(const char*, bx_param_c* = nullptr) override { return nullptr; }
    bx_param_bool_c*   get_param_bool  (const char*, bx_param_c* = nullptr) override { return nullptr; }
    bx_param_enum_c*   get_param_enum  (const char*, bx_param_c* = nullptr) override { return nullptr; }
    void quit_sim(int) override { asm volatile("cli; hlt"); }
    int  get_exit_code() override { return 0; }
    int  get_default_rc(char*, int) override { return 0; }
    int  read_rc(const char*) override { return 0; }
    int  write_rc(const char*, int) override { return 0; }
    int  get_log_file(char*, int) override { return 0; }
    int  set_log_file(const char*) override { return 0; }
    int  get_log_prefix(char*, int) override { return 0; }
    int  set_log_prefix(const char*) override { return 0; }
    int  get_debugger_log_file(char*, int) override { return 0; }
    int  set_debugger_log_file(const char*) override { return 0; }
    int  get_n_log_modules() override { return 0; }
    const char* get_logfn_name(int) override { return ""; }
    int  get_logfn_id(const char*) override { return 0; }
    const char* get_prefix(int) override { return ""; }
    int  get_log_action(int, int) override { return 0; }
    void set_log_action(int, int, int) override {}
    const char* get_action_name(int) override { return ""; }
    const char* get_log_level_name(int) override { return ""; }
    int  get_max_log_level() override { return 0; }
    int  get_default_log_action(int) override { return 0; }
    void set_default_log_action(int, int) override {}
    int  is_bochsrc_option_used(const char*) override { return 0; }
    int  parse_config_file(const char*) override { return 0; }
    int  parse_param_by_name(const char*, const char*) override { return 0; }
    void init_statistics() override {}
    void cleanup_statistics() override {}
    bx_list_c* get_statistics_root() override { return nullptr; }
    int  configuration_interface(const char*, ci_command_t) override { return 0; }
    int  begin_simulation(int, char**) override { return 0; }
    int  register_runtime_config_handler(void*, rt_conf_handler_t) override { return 0; }
    void unregister_runtime_config_handler(int) override {}
    void update_runtime_options() override {}
    void set_sim_thread_func(is_sim_thread_func_t) override {}
    bool is_sim_thread() override { return true; }
    void set_debug_gui(bool) override {}
    void reg_sim_object(bx_object_c*) override {}
    void unreg_sim_object(bx_object_c*) override {}
    bx_list_c* get_bochs_root() override { return nullptr; }
    bool test_for_text_console() override { return false; }
};
static KernelSIM s_sim;
bx_simulator_interface_c* SIM = &s_sim;

// ── bx_devices_c stubs ───────────────────────────────────────────────────────
Bit32u bx_devices_c::inp (Bit16u, unsigned) { return 0xFFFF; }
void   bx_devices_c::outp(Bit16u, Bit32u, unsigned) {}

// ── bx_pc_system_c stubs ─────────────────────────────────────────────────────
void bx_pc_system_c::invlpg(Bit32u) {}

// ── plugin function pointers ─────────────────────────────────────────────────
int  (*pluginRegisterIOReadHandler)(void*, ioReadHandler_t, unsigned, const char*, unsigned) = nullptr;
int  (*pluginRegisterIOWriteHandler)(void*, ioWriteHandler_t, unsigned, const char*, unsigned) = nullptr;
int  (*pluginUnregisterIOReadHandler)(void*, ioReadHandler_t, unsigned, unsigned) = nullptr;
int  (*pluginUnregisterIOWriteHandler)(void*, ioWriteHandler_t, unsigned, unsigned) = nullptr;
int  (*pluginRegisterIOReadHandlerRange)(void*, ioReadHandler_t, unsigned, unsigned, const char*, unsigned) = nullptr;
int  (*pluginRegisterIOWriteHandlerRange)(void*, ioWriteHandler_t, unsigned, unsigned, const char*, unsigned) = nullptr;
int  (*pluginUnregisterIOReadHandlerRange)(void*, ioReadHandler_t, unsigned, unsigned, unsigned) = nullptr;
int  (*pluginUnregisterIOWriteHandlerRange)(void*, ioWriteHandler_t, unsigned, unsigned, unsigned) = nullptr;
int  (*pluginRegisterDefaultIOReadHandler)(void*, ioReadHandler_t, const char*, unsigned) = nullptr;
int  (*pluginRegisterDefaultIOWriteHandler)(void*, ioWriteHandler_t, const char*, unsigned) = nullptr;
void (*pluginRegisterIRQ)(unsigned, const char*) = nullptr;
void (*pluginUnregisterIRQ)(unsigned, const char*) = nullptr;
void (*pluginSetHRQ)(unsigned) = nullptr;
void (*pluginSetHRQHackCallback)(void (*)(void)) = nullptr;

