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
#include <cstring>     // std::strstr — needed by routed get_param_string()

// Forward decl — defined in bochs_glue.cpp. Used by all Bochs internal
// panic paths so a misbehaving guest exits cleanly rather than
// crashing the host kernel.
extern "C" void bochs_guest_exit(int code);

// ═══ logfunctions ═══════════════════════════════════════════════════════════

int logfunctions::default_onoff[N_LOGLEV] = {0, 0, 0, 0};

logfunctions::logfunctions(void)                  { prefix = nullptr; logio = nullptr; }
logfunctions::logfunctions(class iofunctions* io) { prefix = nullptr; logio = io; }
logfunctions::~logfunctions(void) {}
void logfunctions::put(const char*)              {}
void logfunctions::put(const char*, const char*) {}
void logfunctions::info (const char*, ...)       {}
void logfunctions::error(const char*, ...)       {}
void logfunctions::ldebug(const char*, ...)      {}

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
void logfunctions::fatal1(const char* fmt, ...) {
    bx_capture_panic(fmt);
    bochs_guest_exit(-2);
}
void logfunctions::fatal (int, const char* p, const char* fmt, va_list, int) {
    bx_capture_panic(fmt ? fmt : p);
    bochs_guest_exit(-3);
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
logfunc_t* genlog            = &s_log;
logfunc_t* pluginlog         = &s_log;
logfunc_t* siminterface_log  = &s_log;
iofunc_t*  io                = nullptr;

// ═══ bochs globals ═══════════════════════════════════════════════════════════

BX_CPU_C        bx_cpu(0);
static BX_CPU_C* s_cpu_ptr = &bx_cpu;
BX_CPU_C**      bx_cpu_array = &s_cpu_ptr;

BX_MEM_C        bx_mem;
bx_debug_t      bx_dbg   = {};
Bit8u           bx_cpu_count = 1;
Bit32u          apic_id_mask = 0;
extern int      simulate_xapic;

// ─── BX_MEM_C::init_memory override ───────────────────────────────────────
//
// Stock init_memory in libmemory.a touches SIM->get_param_bool to read
// the PCI-enabled flag. We have a working dummy param tree so that
// part is actually safe now — but stock also tries to call
// register_state() which builds a savestate tree we never use. We
// keep our own implementation because:
//   (a) it's smaller / simpler to audit;
//   (b) it makes the order of allocations explicit, which matters
//       for the kernel heap which is finite;
//   (c) it lets us hard-code pci_enabled=false without depending on
//       a SIM-> round-trip.
//
// Step list:
//   1. Allocate vector[] of size (host + BIOSROMSZ + EXROMSIZE + 4K),
//      4 KiB aligned.
//   2. Set up rom/bogus pointers; zero the ROM shadow region.
//   3. Allocate blocks table for the guest range.
//   4. Allocate memory_handlers table for the full physical address
//      space (BX_MEM_HANDLERS entries — see header).
//   5. NULL-initialise the handlers table.
//   6. Hard-code pci_enabled = false.
//   7. Initialise misc fields (ROM flags, SMRAM flags, memory_type).

// Pull in the visible-halt helper from bochs_glue.cpp. We use it
// here so a silent allocator failure inside Bochs-init becomes a
// visible "Z<digit>" marker on screen instead of a NULL-pointer
// memset that corrupts physical memory.
extern "C" void live_breadcrumb(int slot, char ch);
static void bochs_infra_panic_halt(char tag) {
    live_breadcrumb(50, 'Z');
    live_breadcrumb(51, tag);
    for (;;) { __asm__ volatile ("cli; hlt"); }
}

void BX_MEM_C::init_memory(Bit64u guest, Bit64u host)
{
    #ifndef BX_MEM_HANDLERS
    #define BX_MEM_HANDLERS ((BX_CONST64(1) << BX_PHY_ADDRESS_WIDTH) >> 20)
    #endif
    #ifndef BX_MEM_VECTOR_ALIGN
    #define BX_MEM_VECTOR_ALIGN 4096
    #endif

    // (1) vector[].
    //
    // The compiler optimises away upstream's `if (actual_vector == 0)
    // BX_PANIC(...)` because operator new in standard C++ throws
    // bad_alloc rather than returning NULL — so the compiler treats
    // the NULL branch as unreachable. Our freestanding malloc DOES
    // return NULL when out of pool, and that silent NULL was being
    // propagated into a bogus rom = &vector[host] = 0x1000000 memset
    // that wrote 2.1 MiB of 0xFF into stray physical memory before
    // wedging. The check below is in our own TU (compiled with
    // -fno-exceptions but the optimiser can't see through us), so it
    // survives optimisation. If it ever fires we halt visibly at
    // slot 50/51 with 'Z' and a tag char; that's the signal to either
    // shrink the host arg or grow BHEAP_BYTES in bochs_cstubs.c.
    BX_MEM_THIS vector = alloc_vector_aligned(
        host + BIOSROMSZ + EXROMSIZE + 4096, BX_MEM_VECTOR_ALIGN);
    if (!BX_MEM_THIS vector) {
        bochs_infra_panic_halt('1');   // Z1 = vector alloc failed
    }

    // (2) rom/bogus pointers, zero ROM shadow.
    BX_MEM_THIS len       = guest;
    BX_MEM_THIS allocated = host;
    BX_MEM_THIS rom       = &BX_MEM_THIS vector[host];
    BX_MEM_THIS bogus     = &BX_MEM_THIS vector[host + BIOSROMSZ + EXROMSIZE];
    memset(BX_MEM_THIS rom, 0xff, BIOSROMSZ + EXROMSIZE + 4096);

    // (3) blocks table.
    Bit32u num_blocks = (Bit32u)(BX_MEM_THIS len / BX_MEM_BLOCK_LEN);
    if (num_blocks == 0) num_blocks = 1;
    BX_MEM_THIS blocks      = new Bit8u*[num_blocks];
    if (!BX_MEM_THIS blocks) {
        bochs_infra_panic_halt('3');   // Z3 = blocks[] alloc failed
    }
    for (Bit32u i = 0; i < num_blocks; i++) BX_MEM_THIS blocks[i] = nullptr;
    BX_MEM_THIS used_blocks = 0;

    // (4 & 5) memory_handlers table — NULL-initialised. The glue layer
    // calls registerMemoryHandlers to install entries as slots become
    // active.
    BX_MEM_THIS memory_handlers =
        new struct memory_handler_struct *[BX_MEM_HANDLERS];
    if (!BX_MEM_THIS memory_handlers) {
        bochs_infra_panic_halt('4');   // Z4 = memory_handlers alloc failed
    }
    for (Bit32u idx = 0; idx < BX_MEM_HANDLERS; idx++) {
        BX_MEM_THIS memory_handlers[idx] = nullptr;
    }

    // (6) hard-code pci_enabled = false.
    BX_MEM_THIS pci_enabled = false;

    // (7) field assignments.
    BX_MEM_THIS bios_write_enabled = 0;
    BX_MEM_THIS bios_rom_addr      = 0xffff0000;
    BX_MEM_THIS flash_type         = 0;
    BX_MEM_THIS flash_status       = 0x80;
    BX_MEM_THIS smram_available    = 0;
    BX_MEM_THIS smram_enable       = 0;
    BX_MEM_THIS smram_restricted   = 0;
    for (int i = 0; i < 65; i++) BX_MEM_THIS rom_present[i] = 0;
    for (int i = 0; i <= BX_MEM_AREA_F0000; i++) {
        BX_MEM_THIS memory_type[i][0] = 0;
        BX_MEM_THIS memory_type[i][1] = 0;
    }
}

// register_state is required by the link but never reached (we don't
// save state). Stock builds a savestate tree under a nullptr root,
// which is unsafe here.
void BX_MEM_C::register_state() {}

// ═══ bx_devices_c ════════════════════════════════════════════════════════════

bx_devices_c bx_devices;

bx_devices_c::bx_devices_c() {
    read_port_to_handler  = nullptr;
    write_port_to_handler = nullptr;
    io_read_handlers.next         = nullptr;
    io_read_handlers.handler_name = nullptr;
    io_write_handlers.next         = nullptr;
    io_write_handlers.handler_name = nullptr;
    for (unsigned i = 0; i < BX_MAX_IRQS; i++) irq_handler_name[i] = nullptr;
    sound_device_count = 0;
}
bx_devices_c::~bx_devices_c() {}
void bx_devices_c::init_stubs() {}

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
void bx_devices_c::exit()          {}

// ═══ bx_pc_system_c ══════════════════════════════════════════════════════════
//
// We pull in bochs's own pc_system.cc as a separate object (see the
// Makefile) for the constructor + initialize() + timer arithmetic.
// The methods below are the ones we override to stub out the parts
// we don't want — countdownEvent / Reset / timer ticks. Timer-driven
// events are not used in this kernel.

bx_pc_system_c bx_pc_system;

void bx_pc_system_c::countdownEvent() {}
int  bx_pc_system_c::Reset(unsigned) { return 0; }
void bx_pc_system_c::deactivate_timer(unsigned) {}
void bx_pc_system_c::activate_timer_ticks(unsigned, Bit64u, bool) {}
int  bx_pc_system_c::register_timer_ticks(void*, bx_timer_handler_t,
                                          Bit64u, bool, bool,
                                          const char*) {
    return 0;
}

// ═══ Param tree globals ══════════════════════════════════════════════════════

bx_list_c* root_param = nullptr;

// ═══ KernelSIM — minimal bx_simulator_interface_c implementation ═════════════
//
// Every virtual in bx_simulator_interface_c must have a body here or
// the vtable will be incomplete and the linker emits "undefined
// reference to vtable for KernelSIM". Methods that should never be
// called (quit_sim) tell the active slot to exit; everything else
// returns a safe zero/null/false.

class KernelSIM : public bx_simulator_interface_c {
public:
    // ── lifecycle ────────────────────────────────────────────────────────
    void quit_sim(int)              override { bochs_guest_exit(-4); }
    int  get_exit_code()            override { return 0; }
    void set_quit_context(jmp_buf*) override {}

    // ── init flags ───────────────────────────────────────────────────────
    bool get_init_done()       override { return false; }
    int  set_init_done(bool)   override { return 0; }
    void reset_all_param()     override {}

    // ── param tree (declared here; defined below the class) ──────────────
    bx_param_c*        get_param       (const char*, bx_param_c* = nullptr) override;
    bx_param_num_c*    get_param_num   (const char*, bx_param_c* = nullptr) override;
    bx_param_string_c* get_param_string(const char*, bx_param_c* = nullptr) override;
    bx_param_bool_c*   get_param_bool  (const char*, bx_param_c* = nullptr) override;
    bx_param_enum_c*   get_param_enum  (const char*, bx_param_c* = nullptr) override;
    unsigned           gen_param_id()  override { return 0; }

    // ── logging ──────────────────────────────────────────────────────────
    int          get_n_log_modules()              override { return 0; }
    const char*  get_logfn_name(int)              override { return ""; }
    int          get_logfn_id(const char*)        override { return 0; }
    const char*  get_prefix(int)                  override { return ""; }
    int          get_log_action(int, int)         override { return 0; }
    void         set_log_action(int, int, int)    override {}
    int          get_default_log_action(int)      override { return 0; }
    void         set_default_log_action(int, int) override {}
    const char*  get_action_name(int)             override { return ""; }
    int          is_action_name(const char*)      override { return 0; }
    const char*  get_log_level_name(int)          override { return ""; }
    int          get_max_log_level()              override { return 0; }

    // ── RC / log file paths ──────────────────────────────────────────────
    int get_default_rc(char*, int)         override { return -1; }
    int read_rc(const char*)               override { return -1; }
    int write_rc(const char*, int)         override { return -1; }
    int get_log_file(char*, int)           override { return -1; }
    int set_log_file(const char*)          override { return -1; }
    int get_log_prefix(char*, int)         override { return -1; }
    int set_log_prefix(const char*)        override { return -1; }
    int get_debugger_log_file(char*, int)  override { return -1; }
    int set_debugger_log_file(const char*) override { return -1; }

    // ── event / notify ───────────────────────────────────────────────────
    void      set_notify_callback(bxevent_handler, void*)   override {}
    void      get_notify_callback(bxevent_handler*, void**) override {}
    BxEvent*  sim_to_ci_event(BxEvent* e)                   override { return e; }
    int       log_dlg(const char*, int, const char*, int)   override { return 0; }
    void      log_msg(const char*, int, const char*)        override {}
    void      set_log_viewer(bool)                          override {}
    bool      has_log_viewer() const                        override { return false; }

    // ── ask / dialog ─────────────────────────────────────────────────────
    int  ask_param(bx_param_c*)                                        override { return 0; }
    int  ask_param(const char*)                                        override { return 0; }
    int  ask_filename(const char*, int, const char*, const char*, int) override { return -1; }
    int  ask_yes_no(const char*, const char*, bool the_default)        override { return (int)the_default; }
    void message_box(const char*, const char*)                         override {}

    // ── periodic / refresh ───────────────────────────────────────────────
    void periodic()      override {}
    void refresh_ci()    override {}
    void refresh_vga()   override {}
    void handle_events() override {}

    // ── disk / PCI / device queries ──────────────────────────────────────
    int         create_disk_image(const char*, int, bool) override { return -1; }
    bx_param_c* get_first_hd()                            override { return nullptr; }
    bx_param_c* get_first_cdrom()                         override { return nullptr; }
    bool        is_pci_device(const char*)                override { return false; }
    bool        is_agp_device(const char*)                override { return false; }

    // ── config interface ─────────────────────────────────────────────────
    void register_configuration_interface(const char*, config_interface_callback_t, void*) override {}
    int  configuration_interface(const char*, ci_command_t)                                override { return 0; }
    int  begin_simulation(int, char*[])                                                    override { return 0; }

    // ── runtime config ───────────────────────────────────────────────────
    int  register_runtime_config_handler(void*, rt_conf_handler_t) override { return 0; }
    void unregister_runtime_config_handler(int)                    override {}
    void update_runtime_options()                                  override {}

    // ── threading ────────────────────────────────────────────────────────
    void set_sim_thread_func(is_sim_thread_func_t f) override { is_sim_thread_func = f; }
    bool is_sim_thread()        override { return false; }
    bool is_wx_selected() const override { return false; }

    // ── GUI mode ─────────────────────────────────────────────────────────
    void set_debug_gui(bool)            override {}
    bool has_debug_gui() const          override { return false; }
    void set_display_mode(disp_mode_t)  override {}
    bool test_for_text_console()        override { return false; }

    // ── addon options ────────────────────────────────────────────────────
    bool    register_addon_option(const char*, addon_option_parser_t,
                                  addon_option_save_t)         override { return false; }
    bool    unregister_addon_option(const char*)               override { return false; }
    bool    is_addon_option(const char*)                       override { return false; }
    Bit32s  parse_addon_option(const char*, int, char*[])      override { return 0; }
    Bit32s  save_addon_options(FILE*)                          override { return 0; }

    // ── statistics ───────────────────────────────────────────────────────
    void       init_statistics()     override {}
    void       cleanup_statistics()  override {}
    bx_list_c* get_statistics_root() override { return nullptr; }

    // ── save / restore ───────────────────────────────────────────────────
    void       init_save_restore()                                       override {}
    void       cleanup_save_restore()                                    override {}
    bool       save_state(const char*)                                   override { return false; }
    bool       restore_config()                                          override { return false; }
    bool       restore_logopts()                                         override { return false; }
    bool       restore_hardware()                                        override { return false; }
    bx_list_c* get_bochs_root()                                          override { return nullptr; }
    bool       restore_bochs_param(bx_list_c*, const char*, const char*) override { return false; }

    // ── plugin ctrl ──────────────────────────────────────────────────────
    bool opt_plugin_ctrl(const char*, bool) override { return false; }

    // ── NIC / USB helpers ────────────────────────────────────────────────
    void init_std_nic_options(const char*, bx_list_c*)                    override {}
    int  parse_param_from_list(const char*, const char*, bx_list_c*)      override { return 0; }
    int  parse_nic_params(const char*, const char*, bx_list_c*)           override { return 0; }
    int  parse_usb_port_params(const char*, const char*, int, bx_list_c*) override { return 0; }
    int  split_option_list(const char*, const char*, char**, int)         override { return 0; }
    int  write_param_list(FILE*, bx_list_c*, const char*, bool)           override { return 0; }
    int  write_usb_options(FILE*, int, bx_list_c*)                        override { return 0; }
};

static KernelSIM s_sim;
bx_simulator_interface_c* SIM = &s_sim;

// ─── Dummy param objects (sized for real CPUID consumers) ─────────────────
//
// libcpu.a's generic_cpuid.cc and friends do things like
//
//   const char* brand  = (const char*)SIM->get_param_string(BXPN_BRAND_STRING)->getptr();
//   const Bit8u* vend  = (const Bit8u*)SIM->get_param_string(BXPN_VENDOR_STRING)->getptr();
//   unsigned model     = SIM->get_param_enum(BXPN_CPU_MODEL)->get();
//   unsigned apic      = SIM->get_param_enum(BXPN_CPUID_APIC)->get();
//
// A nullptr return on get_param_enum was triple-faulting init. The
// vendor/brand strings get read with [i] indexing up to 12 / 48 bytes,
// so they need backing storage of that size, not the old 1-byte dummy.
//
// All objects are constructed by the __init_array pass before kernel_main.
// We are linked with bochs_paramtree.o (paramtree.cc) so their real
// constructors are present.

// (a) bool param. get() → false. Used for all the BXPN_CPUID_MMX,
//     BXPN_CPUID_XSAVE, BXPN_CPUID_AES… off-by-default switches.
static bx_param_bool_c   s_dummy_bool   (nullptr, "dummy_b", "dummy_b", "dummy_b", 0, 0);

// (b) num param. get() → 0. Used for BXPN_CPUID_LEVEL (becomes 0 →
//     no Pentium/P6 enables, only X87+486), BXPN_CPUID_VMX → 0, etc.
static bx_param_num_c    s_dummy_num    (nullptr, "dummy_n", "dummy_n", "dummy_n",
                                         0, 0xFFFFFFFFll, 0, 0);

// (c) String params. We split into three:
//   - vendor: needs 12+ bytes; CPUID leaf 0 reads ebx/edx/ecx as 12 chars.
//   - brand:  needs 48+ bytes; CPUID 0x80000002..4 reads 16 chars each.
//   - generic: empty path / MSR file / etc — must just be a non-null,
//              null-terminated, readable buffer.
//
// "GenuineIntel" matches what the bx_generic CPUID actually emits when
// no custom vendor is set; we keep it ASCII so any future strcmp lands
// somewhere sane. The brand is padded to 47 chars + NUL to fill all
// three brand-string CPUID leaves.
static bx_param_string_c s_dummy_vendor (nullptr, "vendor", "vendor", "vendor",
                                         "GenuineIntel",                     16);
static bx_param_string_c s_dummy_brand  (nullptr, "brand",  "brand",  "brand",
                                         "           Bochs CPU                           ", 64);
static bx_param_string_c s_dummy_string (nullptr, "dummy_s","dummy_s","dummy_s",
                                         "",                                 16);

// (d) Enum param.
//
//   - BXPN_CPU_MODEL: 0 → bx_cpudb_bx_generic → create_bx_generic_cpuid (the
//     only model that doesn't pull a cpudb/ creator we haven't linked).
//   - BXPN_CPUID_APIC: 0 → BX_CPUID_SUPPORT_LEGACY_APIC. Inside generic_cpuid
//     the panic check `if (cpu_level < 6 && apic != LEGACY && apic != XAPIC)`
//     requires LEGACY (0) or XAPIC (1) when cpu_level is 0 (our default).
//   - BXPN_CPUID_SIMD: 0 → BX_CPUID_SUPPORT_NOSSE. SIMD is off, no panics.
//
// All three want default 0, so a single enum object suffices. Choices
// only need a non-null array terminated by NULL; the [val-min] lookup
// only happens via get_selected() which Bochs init paths don't call.
static const char* s_zero_choices[] = { "zero", nullptr };
static bx_param_enum_c s_dummy_enum  (nullptr, "dummy_e", "dummy_e", "dummy_e",
                                      s_zero_choices, 0, 0);

bx_param_c*        KernelSIM::get_param       (const char*, bx_param_c*) { return &s_dummy_num;    }
bx_param_num_c*    KernelSIM::get_param_num   (const char*, bx_param_c*) { return &s_dummy_num;    }
bx_param_bool_c*   KernelSIM::get_param_bool  (const char*, bx_param_c*) { return &s_dummy_bool;   }
bx_param_enum_c*   KernelSIM::get_param_enum  (const char*, bx_param_c*) { return &s_dummy_enum;   }

// String lookup: route brand/vendor names to the wider buffers, everything
// else to the generic empty string. We can't use std::strstr from a
// freestanding TU, but bochs_infra.cpp IS the system-header TU — std::
// strstr is available.
bx_param_string_c* KernelSIM::get_param_string(const char* n, bx_param_c*) {
    if (n) {
        // BXPN names like "cpuid.vendor_string", "cpuid.brand_string".
        if (std::strstr(n, "vendor")) return &s_dummy_vendor;
        if (std::strstr(n, "brand"))  return &s_dummy_brand;
    }
    return &s_dummy_string;
}

// ═══ bx_user_quit ════════════════════════════════════════════════════════════
bool bx_user_quit = false;

// ═══ bx_gui stub ═════════════════════════════════════════════════════════════
bx_gui_c* bx_gui = nullptr;
void bx_gui_c::cleanup() {}

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
int  (*pluginRegisterIOReadHandler)        (void*, ioReadHandler_t,  unsigned,           const char*, Bit8u) = nullptr;
int  (*pluginRegisterIOWriteHandler)       (void*, ioWriteHandler_t, unsigned,           const char*, Bit8u) = nullptr;
int  (*pluginUnregisterIOReadHandler)      (void*, ioReadHandler_t,  unsigned,           Bit8u)              = nullptr;
int  (*pluginUnregisterIOWriteHandler)     (void*, ioWriteHandler_t, unsigned,           Bit8u)              = nullptr;
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

// ═══ bx_pci_device_c stubs ═══════════════════════════════════════════════════
Bit32u bx_pci_device_c::pci_read_handler (Bit8u, unsigned)        { return 0; }
