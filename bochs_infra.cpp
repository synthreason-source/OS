// =====================================================================
// bochs_infra.cpp — Bochs 2.7 infrastructure shims for the freestanding
// kernel. Compiled WITH system headers (-include not freestanding)
// because bochs.h pulls in <stdio.h>, <cstdlib>, etc.
//
// Responsibilities:
//   * Provide the global Bochs objects (bx_cpu, bx_mem, bx_devices,
//     bx_pc_system, SIM, genlog, etc.) so libcpu.a / libmemory.a link.
//   * Provide concrete-class implementations of logfunctions /
//     iofunctions / bx_devices_c / bx_simulator_interface_c that do
//     the minimum needed to keep the rest of Bochs working.
//   * Override BX_MEM_C::init_memory with a deterministic, self-
//     contained version that does NOT depend on SIM-> calls. (The
//     stock version's chain of SIM->get_param_*() during init is the
//     source of half the freestanding-port pain.)
//   * Route guest I/O on ports 0xE9 (putc) and 0xE8 (exit) into the
//     glue layer.
//
// This file deliberately contains NO panic recovery. If Bochs's panic
// path is reached, the active slot is told to exit and cpu_loop is
// asked to yield. The kernel itself is never longjmp'd.
// =====================================================================

// NOTE (Bochs 2.0 port): this old codebase has NO include guards in
// bochs.h/cpu.h/pc_system.h/memory.h/siminterface.h/etc - you are
// meant to include "bochs.h" exactly once and let its own internal
// chain pull in everything (cpu, memory, pc_system, siminterface,
// iodev, plugin, ...). Re-including any of those directly, as this
// file used to for the Bochs 2.7 layout, causes hard "redefinition of
// class ..." errors. cpu/icache.h and gui/paramtree.h don't exist in
// 2.0 at all (icache.h was removed/merged; the paramtree.cc split
// happened in 2.5 - in 2.0 those classes live in gui/siminterface.h,
// which bochs.h already includes).
#include "bochs.h"
#include <stdarg.h>
#include <cstring>     // std::strstr — needed by routed get_param_string()

// Forward decl — defined in bochs_glue.cpp. Used by all Bochs internal
// panic paths so a misbehaving guest exits cleanly rather than
// crashing the host kernel.
extern "C" void bochs_guest_exit(int code);

// ═══ logfunctions ═══════════════════════════════════════════════════════════
//
// NOTE (Bochs 2.0 port): logfunctions/iofunctions have a noticeably
// different member list here than 2.7 - notably put() takes a plain
// (non-const) char*, there's no two-arg put() overload, fatal() takes
// 4 args (no leading facility int), there's no separate fatal1() or
// warn() method at all, and iofunctions::out() takes 5 args (with an
// explicit "level" alongside "facility"). A few methods declared in
// the class body have no inline definition and would need one if
// ever called from linked code (pass, settype, the init_log()
// overloads, set_log_prefix, add_logfn) - stubbed cheaply below so we
// never hit a surprise "undefined reference" at link time.

int logfunctions::default_onoff[N_LOGLEV] = {0, 0, 0, 0};

logfunctions::logfunctions(void)                  { prefix = nullptr; logio = nullptr; }
logfunctions::logfunctions(class iofunctions* io) { prefix = nullptr; logio = io; }
logfunctions::~logfunctions(void) {}
void logfunctions::put(char*)                    {}
void logfunctions::info (const char*, ...)       {}
void logfunctions::error(const char*, ...)       {}
void logfunctions::pass (const char*, ...)       {}
void logfunctions::ldebug(const char*, ...)      {}
void logfunctions::settype(int)                  {}

// Panic / fatal paths. All three end up at the same place: ask the
// active slot to exit. cpu_loop will yield on its next iteration and
// the kernel main loop will see the slot is dead and clean it up.
//
// We DO NOT longjmp out of these. The kernel state at the point of
// panic is consistent (we just ran a single Bochs internal check that
// failed) — the safe move is to let cpu_loop unwind through its
// normal exit path. The slot is marked dead; its exit_cb has already
// flipped proc.active = false on the kernel side.
//
// DIAGNOSTIC: the panic format string used to be discarded outright,
// so a panic during bochs_global_init() became an unexplained freeze
// (bochs_guest_exit's no-slot path hard-halts). Capture the raw format
// string here into a global buffer so bochs_guest_exit() — and the
// kernel — can show WHICH Bochs check failed. The string is a static
// literal inside libcpu.a, so storing the pointer is safe and cheap;
// we also copy the leading bytes in case the literal lives in a
// section that becomes unmapped later.
extern "C" {
    volatile const char* bx_last_panic_fmt = nullptr;  // raw pointer
    volatile char        bx_last_panic_msg[128] = {0};  // copied text
}
static void bx_capture_panic(const char* fmt) {
    bx_last_panic_fmt = fmt;
    if (fmt) {
        unsigned i = 0;
        for (; i < sizeof(bx_last_panic_msg) - 1 && fmt[i]; ++i)
            bx_last_panic_msg[i] = fmt[i];
        bx_last_panic_msg[i] = '\0';
    }
}
void logfunctions::panic (const char* fmt, ...) {
    bx_capture_panic(fmt);
    bochs_guest_exit(-1);
}
// Bochs 2.0's logfunctions::fatal takes (prefix, fmt, ap, exit_status) -
// no separate fatal1() exists at all in this version (that was a later
// addition), and there's no leading facility/level int either.
void logfunctions::fatal (const char* p, const char* fmt, va_list, int) {
    bx_capture_panic(fmt ? fmt : p);
    bochs_guest_exit(-3);
}
void logfunctions::ask (int, const char*, const char*, va_list) {}
void logfunctions::setio(class iofunctions* io) { logio = io; }

iofunctions::iofunctions(void)          {}
iofunctions::iofunctions(FILE*)         {}
iofunctions::iofunctions(int)           {}
iofunctions::iofunctions(const char*)   {}
iofunctions::~iofunctions(void)         {}
// 5 args in 2.0: (facility, level, prefix, fmt, ap) - 2.7 dropped
// "level" as a separate parameter from this particular call, but 2.0
// still has it.
void iofunctions::out(int, int, const char*, const char*, va_list) {}
void iofunctions::set_log_action(int, int) {}
void iofunctions::init_log(const char*) {}
void iofunctions::init_log(int)         {}
void iofunctions::init_log(FILE*)       {}
void iofunctions::set_log_prefix(const char*) {}
void iofunctions::add_logfn(logfunc_t*) {}

static logfunc_t s_log;
logfunc_t* genlog            = &s_log;
logfunc_t* pluginlog         = &s_log;
iofunc_t*  io                = nullptr;

// ═══ bochs globals ═══════════════════════════════════════════════════════════
//
// NOTE (Bochs 2.0 port): bx_cpu_c has no user-declared constructor in
// this version (implicit default only) - the old "bx_cpu(0)" call
// doesn't match anything and was removed.

BX_CPU_C        bx_cpu;
static BX_CPU_C* s_cpu_ptr = &bx_cpu;
BX_CPU_C**      bx_cpu_array = &s_cpu_ptr;

BX_MEM_C        bx_mem;
bx_debug_t      bx_dbg   = {};
Bit8u           bx_cpu_count = 1;
Bit32u          apic_id_mask = 0;
extern int      simulate_xapic;

// NOTE (Bochs 2.0 port): BX_MEM_C::init_memory(int) and
// ::register_state() used to be overridden here for 2.7, where stock
// init_memory touched SIM->get_param_bool(). In 2.0, memory/
// misc_mem.cc's stock init_memory(int memsize) is completely
// self-contained (allocates via alloc_vector_aligned -> operator
// new[], which routes through our malloc() stub in bochs_cstubs.c;
// zeroes memory; marks the ROM area 0xff) with no SIM-> dependency at
// all, and register_state() doesn't exist as a method on this
// version's bx_mem_c in the first place. Both overrides have been
// removed - the version already linked in via libmemory.a is used
// directly. See mapping_register()/mapping_unregister() in
// bochs_glue.cpp for how per-slot memory now gets swapped into
// bx_mem.vector directly, since this version's bx_mem_c also has no
// registerMemoryHandlers()-style per-range handler mechanism at all
// (that was added well after 2.0) - the flat vector/len model here
// only supports one physical memory image at a time, which is
// swapped on every slot activation instead.


// ═══ bx_devices_c ════════════════════════════════════════════════════════════
//
// NOTE (Bochs 2.0 port): this version's bx_devices_c has a completely
// different member layout (pluginXxx/stubXxx device pointers, a
// private read_handler_id[] table, etc. - see iodev/iodev.h) with no
// read_port_to_handler/io_read_handlers/sound_device_count members at
// all. We don't link the stock iodev/devices.cc (too much unrelated
// device-model machinery), so this constructor just needs to leave a
// blank, safe object; init_stubs() and exit() don't exist as methods
// on this version's class at all and have been dropped.

bx_devices_c bx_devices;

bx_devices_c::bx_devices_c() {}
bx_devices_c::~bx_devices_c() {}

extern "C" void bochs_guest_putc(char c);
// bochs_guest_exit already forward-declared at top.

Bit32u bx_devices_c::inp(Bit16u, unsigned) { return 0xFFFF; }
void   bx_devices_c::outp(Bit16u port, Bit32u val, unsigned) {
    // Port 0xE9 — Bochs "debug console" port. We route to the active
    // slot's write callback (-> kernel terminal).
    if      (port == 0xE9) bochs_guest_putc((char)(val & 0xFF));
    // Port 0xE8 — process exit sentinel. The IDT trap stub injected
    // by bochs_glue.cpp does `out al, 0xE8` on every guest fault.
    else if (port == 0xE8) bochs_guest_exit((int)(val & 0xFF));
    // All other ports are silently dropped.
}
void bx_devices_c::reset(unsigned) {}

// ═══ bx_pc_system_c ══════════════════════════════════════════════════════════
//
// NOTE (Bochs 2.0 port): pc_system.cc (linked as bochs_pc_system.o -
// see the Makefile) already provides real, complete implementations
// of countdownEvent/deactivate_timer/activate_timer_ticks/
// register_timer_ticks/exit/init_ips/etc. for THIS version, and none
// of them touch SIM-> at all (confirmed by inspection) - so unlike
// the 2.7 port, there is nothing here to override; doing so would
// just be duplicate-definition link errors against pc_system.cc's
// own symbols. There's also no Reset(unsigned)/kill_bochs_request
// member on bx_pc_system_c in this version at all (kill_bochs_request
// moved to bx_cpu_c - see bochs_glue.cpp) and no initialize() (use
// init_ips() instead, which pc_system.cc already provides).

bx_pc_system_c bx_pc_system;

// ═══ Param tree globals ══════════════════════════════════════════════════════

bx_list_c* root_param = nullptr;

// ═══ bx_list_c text UI stubs ═════════════════════════════════════════════════
//
// NOTE (Bochs 2.0 port): bx_list_c::text_print/text_ask are declared
// (behind #if BX_UI_TEXT, which this build has enabled) in
// gui/siminterface.h but only ever implemented in gui/control.cc,
// which we don't link (it pulls in a text-mode config menu we have
// no use for). Nothing in cpu/, memory/, fpu/, or our own glue code
// calls these - they're only reachable via the vtable, which still
// needs real symbols to link.
void bx_list_c::text_print(FILE*) {}
int  bx_list_c::text_ask(FILE*, FILE*) { return -1; }

// ═══ bx_simulator_interface_c base constructor ═══════════════════════════════
//
// NOTE (Bochs 2.0 port): this used to come from linking
// gui/siminterface.cc directly (as bochs_paramtree.o - see the
// Makefile history). That pulls in the WHOLE translation unit as one
// object file, including bx_real_sim_c (a separate, unrelated,
// heavyweight class in the same file) and its dependencies on
// bx_options/bx_find_bochsrc/bx_read_configuration/etc - a whole
// bochsrc-parsing subsystem we have no use for and don't link. The
// only thing our KernelSIM (which derives from bx_simulator_
// interface_c) actually needs from that file is this base
// constructor, which is empty in the real source anyway - providing
// it directly here lets us drop gui/siminterface.cc from the build
// entirely.
bx_simulator_interface_c::bx_simulator_interface_c() {}


//
// NOTE (Bochs 2.0 port): unlike 2.7, every virtual in this version's
// bx_simulator_interface_c has a safe no-op default body written
// directly in the header (gui/siminterface.h) - none are pure
// virtual. A derived class only needs to override what it actually
// cares about; everything else falls through to the base class's
// default automatically. This also means bx_id (an enum), not
// "const char* name", is how parameters are looked up in this
// version - and confirmed by inspection, nothing in cpu/, memory/,
// or fpu/ ever calls SIM->get_param_*() at all in Bochs 2.0 (that
// CPUID-database-driven config path was added in 2.5+), so the
// elaborate dummy-param plumbing this file used to carry for 2.7 is
// dead weight here and has been dropped entirely.
class KernelSIM : public bx_simulator_interface_c {
public:
    void quit_sim(int) override { bochs_guest_exit(-4); }
};

static KernelSIM s_sim;
bx_simulator_interface_c* SIM = &s_sim;

// ═══ bx_user_quit ════════════════════════════════════════════════════════════
bool bx_user_quit = false;

// ═══ bx_gui stub ═════════════════════════════════════════════════════════════
// NOTE (Bochs 2.0 port): bx_gui_c has no cleanup() method in this
// version - dropped. bx_gui stays nullptr regardless (we never
// instantiate a real bx_gui_c), so nothing would call it anyway.
bx_gui_c* bx_gui = nullptr;

// ═══ Misc ════════════════════════════════════════════════════════════════════
void print_statistics_tree(bx_param_c*, int) {}

// ═══ RTTI for logfunctions ═══════════════════════════════════════════════════
//
// libcpu.a uses dynamic_cast<logfunc_t*> in a couple of debug paths.
// Without these symbols the link fails. Both must have C linkage to
// avoid mangling.
extern "C" {
    char  _ZTS12logfunctions[] = "12logfunctions";
    void* _ZTI12logfunctions[] = {
        nullptr,
        (void*)_ZTS12logfunctions
    };
}

// ═══ C++ ABI stubs ═══════════════════════════════════════════════════════════
//
// libcpu.a was compiled with exceptions enabled. We strip exceptions
// in our kernel build but the link still requires these symbols.
// _Unwind_Resume should never be reached at runtime — if a Bochs
// internal somehow throws, we exit the slot.
extern "C" {
    void _Unwind_Resume(void*)        { bochs_guest_exit(-5); }
    int  __gxx_personality_v0(...)    { return 0; }
    int  __gcc_personality_v0(...)    { return 0; }
    void __cxa_guard_abort(long long*) {}
}

// __dso_handle: declared with C++ linkage in some glibc headers
// transitively included via paramtree.h -> siminterface.h -> cstdlib.
// Declaring inside extern "C" causes a conflict, so define at top
// level. Weak so bochs_glue.cpp's identical definition coexists.
__attribute__((weak)) void* __dso_handle = nullptr;

void operator delete(void*, unsigned int, std::align_val_t) noexcept {}

// ═══ Plugin function pointers ════════════════════════════════════════════════
// All null — we don't load any plugins.
//
// NOTE (Bochs 2.0 port): plugin.h in this version declares these as
// `extern` (we're providing the storage/definition here, which must
// match its declared signature exactly), and it only declares FOUR
// IO-handler pointers - no Unregister*Handler or *HandlerRange
// variants exist in 2.0 at all (those were added later), so those
// definitions have been dropped. The last parameter of all four is
// `unsigned len`, not `Bit8u` as in 2.7.
int  (*pluginRegisterIOReadHandler)        (void*, ioReadHandler_t,  unsigned, const char*, unsigned) = nullptr;
int  (*pluginRegisterIOWriteHandler)       (void*, ioWriteHandler_t, unsigned, const char*, unsigned) = nullptr;
int  (*pluginRegisterDefaultIOReadHandler) (void*, ioReadHandler_t,  const char*, unsigned) = nullptr;
int  (*pluginRegisterDefaultIOWriteHandler)(void*, ioWriteHandler_t, const char*, unsigned) = nullptr;
void (*pluginRegisterIRQ)       (unsigned, const char*) = nullptr;
void (*pluginUnregisterIRQ)     (unsigned, const char*) = nullptr;
void (*pluginSetHRQ)            (unsigned)              = nullptr;
void (*pluginSetHRQHackCallback)(void (*)(void))        = nullptr;

// NOTE (Bochs 2.0 port): bx_pci_device_c doesn't exist as a class in
// this version - PCI support here (BX_PCI_SUPPORT, off by default) is
// plain #ifdef'd code, not a device-model class hierarchy, so there is
// nothing to stub out here. Dropped.
