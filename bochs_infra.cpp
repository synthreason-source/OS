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

int logfunctions::default_onoff[N_LOGLEV] = {0, 0, 0, 0};

logfunctions::logfunctions(void)                  { prefix = nullptr; logio = nullptr; }
logfunctions::logfunctions(class iofunctions* io) { prefix = nullptr; logio = io; }
logfunctions::~logfunctions(void) {}
void logfunctions::put(const char*)              {}
void logfunctions::put(const char*, const char*) {}
void logfunctions::info (const char*, ...)       {}
void logfunctions::error(const char*, ...)       {}
void logfunctions::ldebug(const char*, ...)      {}

// ─── DIAGNOSTIC: longjmp recovery instead of cli;hlt ─────────────────────────
#include <setjmp.h>
extern "C" jmp_buf bx_panic_jmpbuf;
extern "C" int     bx_panic_jmpbuf_armed;
extern "C" volatile int bx_last_panic_code;

static void vga_breadcrumb(char c) {
    volatile unsigned short* p = (volatile unsigned short*)(0xB8000 + 2*70);
    *p = (unsigned short)(0x4F00 | (unsigned char)c);
}

static void bx_recover(char tag, int code) {
    vga_breadcrumb(tag);
    bx_last_panic_code = code;
    if (bx_panic_jmpbuf_armed) {
        bx_panic_jmpbuf_armed = 0;
        longjmp(bx_panic_jmpbuf, 1);
    }
    asm volatile("cli; hlt"); __builtin_unreachable();
}

void logfunctions::panic (const char*, ...) { bx_recover('P', 1); }
void logfunctions::fatal1(const char*, ...) { bx_recover('F', 2); }
void logfunctions::fatal (int, const char*, const char*, va_list, int) {
    bx_recover('X', 3);
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

// ═══ bochs globals ════════════════════════════════════════════════════════════

BX_CPU_C        bx_cpu(0);
static BX_CPU_C* s_cpu_ptr = &bx_cpu;
BX_CPU_C**      bx_cpu_array = &s_cpu_ptr;

BX_MEM_C        bx_mem;
bx_debug_t      bx_dbg   = {};
Bit8u           bx_cpu_count = 1;
Bit32u          apic_id_mask = 0;
extern int      simulate_xapic;

// ─── FIX: diagnostic BX_MEM_C::init_memory override ───────────────────────
// The stock init_memory in libmemory.a hangs (or eventually resets QEMU)
// somewhere between live_breadcrumb '4' (just before the call) and '5'
// (just after the call returns). Earlier versions of this patch tried
// register_state-only and full-replace overrides; neither worked because
// either the linker took libmemory.a's copy (so the override never ran)
// or the override visibly paints to VGA text only — invisible if the
// main paint loop is hung, which is exactly when we want diagnostics.
//
// This override does the SAME work as stock, step by step, but writes
// breadcrumbs via the kernel's live_breadcrumb() helper which paints
// directly to the framebuffer (visible even when the main loop is
// hung). Glyphs go to row 0, columns 36..43:
//
//   col 36 = 'a' before alloc_vector_aligned, 'A' after
//   col 37 = 'm' before memset rom, 'M' after
//   col 38 = 'b' before new Bit8u*[num_blocks], 'B' after
//   col 39 = 'h' before new memory_handlers[BX_MEM_HANDLERS], 'H' after
//   col 40 = 'i' before init loop, 'I' after
//   col 41 = 'p' before SIM->get_param_bool, 'P' after
//   col 42 = 'f' before field assignments, 'F' after
//   col 43 = '!' = init_memory entered, '$' = init_memory returned
//
// Replacement works because the Makefile links bochs_infra.o before
// libmemory.a and uses -Wl,--allow-multiple-definition. Confirmed via
// `ld --trace-symbol` that bochs_infra.o's definition wins.
//
// Also replaces register_state() with a no-op: stock register_state
// builds a savestate param tree rooted at SIM->get_bochs_root() (=
// nullptr) which we know is unsafe in this kernel and we never save
// or restore state.

extern "C" void live_breadcrumb(int slot, char ch);  // defined in kernel.cpp

void BX_MEM_C::init_memory(Bit64u guest, Bit64u host)
{
    #ifndef BX_MEM_HANDLERS
    #define BX_MEM_HANDLERS ((BX_CONST64(1) << BX_PHY_ADDRESS_WIDTH) >> 20)
    #endif
    #ifndef BX_MEM_VECTOR_ALIGN
    #define BX_MEM_VECTOR_ALIGN 4096
    #endif

    live_breadcrumb(43, '!');

    // Step 1: allocate vector
    live_breadcrumb(36, 'a');
    BX_MEM_THIS vector = alloc_vector_aligned(
        host + BIOSROMSZ + EXROMSIZE + 4096, BX_MEM_VECTOR_ALIGN);
    live_breadcrumb(36, 'A');

    // Step 2: set up rom/bogus pointers and zero the rom region
    BX_MEM_THIS len = guest;
    BX_MEM_THIS allocated = host;
    BX_MEM_THIS rom   = &BX_MEM_THIS vector[host];
    BX_MEM_THIS bogus = &BX_MEM_THIS vector[host + BIOSROMSZ + EXROMSIZE];
    live_breadcrumb(37, 'm');
    memset(BX_MEM_THIS rom, 0xff, BIOSROMSZ + EXROMSIZE + 4096);
    live_breadcrumb(37, 'M');

    // Step 3: blocks table (8 entries for 1 MB guest)
    Bit32u num_blocks = (Bit32u)(BX_MEM_THIS len / BX_MEM_BLOCK_LEN);
    live_breadcrumb(38, 'b');
    BX_MEM_THIS blocks = new Bit8u*[num_blocks];
    for (Bit32u i = 0; i < num_blocks; i++) BX_MEM_THIS blocks[i] = nullptr;
    BX_MEM_THIS used_blocks = 0;
    live_breadcrumb(38, 'B');

    // Step 4: memory_handlers table (1M entries = 4 MB)
    live_breadcrumb(39, 'h');
    BX_MEM_THIS memory_handlers =
        new struct memory_handler_struct *[BX_MEM_HANDLERS];
    live_breadcrumb(39, 'H');

    // Step 5: init memory_handlers to NULL
    live_breadcrumb(40, 'i');
    for (Bit32u idx = 0; idx < BX_MEM_HANDLERS; idx++) {
        BX_MEM_THIS memory_handlers[idx] = nullptr;
    }
    live_breadcrumb(40, 'I');

    // Step 6: pci_enabled.
    // Stock init_memory does:
    //   BX_MEM_THIS pci_enabled = SIM->get_param_bool(BXPN_PCI_ENABLED)->get();
    // which is where v5/v5b hung — the FIRST call constructs a static-local
    // bx_param_bool_c dummy whose ctor chain wedges in this freestanding
    // environment (most likely an allocator/recursion issue we haven't
    // pinpointed). We don't simulate PCI; just hard-code false.
    live_breadcrumb(41, 'p');
    BX_MEM_THIS pci_enabled = false;
    live_breadcrumb(41, 'P');

    // Step 7: field assignments
    live_breadcrumb(42, 'f');
    BX_MEM_THIS bios_write_enabled = 0;
    BX_MEM_THIS bios_rom_addr      = 0xffff0000;   // matters for is_bios checks
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
    live_breadcrumb(42, 'F');

    // Step 8: skip register_state — never used, hangs in nullptr-rooted
    // param tree descent.

    live_breadcrumb(43, '$');
}

// Required by the link even though our init_memory never calls it.
// Stock would build a savestate tree rooted at SIM->get_bochs_root() which
// is nullptr in this kernel.
void BX_MEM_C::register_state() {}

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

extern "C" void bochs_guest_putc(char c);
extern "C" void bochs_guest_exit(int code);

Bit32u bx_devices_c::inp (Bit16u, unsigned) { return 0xFFFF; }
void   bx_devices_c::outp(Bit16u port, Bit32u val, unsigned) {
    if      (port == 0xE9) bochs_guest_putc((char)(val & 0xFF));
    // ─── FIX: process-exit sentinel ───────────────────────────────────────
    // The IDT stub injected by bochs_glue.cpp:inject_idt_into_slab() writes
    // AL to port 0xE8 on any guest fault or trap. Treat that as a clean
    // exit signal for the active slot. See bochs_guest_exit() for details.
    else if (port == 0xE8) bochs_guest_exit((int)(val & 0xFF));
}
void bx_devices_c::reset(unsigned) {}
void bx_devices_c::exit()          {}

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

// ═══ Param tree globals ══════════════════════════════════════════════════════

bx_list_c* root_param = nullptr;

// ═══ SIM stub — single definition, all virtuals stubbed ══════════════════════
// Every virtual in bx_simulator_interface_c must have a body here or the
// vtable will be left incomplete and the linker emits "undefined reference
// to vtable for KernelSIM".  All methods that are non-void in the base
// return a safe zero/null/false value.  Methods that should cause a kernel
// panic delegate to bx_recover().

class KernelSIM : public bx_simulator_interface_c {
public:
    // ── lifecycle ────────────────────────────────────────────────────────────
    void quit_sim(int)      override { bx_recover('Q', 4); }
    int  get_exit_code()    override { return 0; }
    void set_quit_context(jmp_buf*) override {}

    // ── init flags ───────────────────────────────────────────────────────────
    bool get_init_done()        override { return false; }
    int  set_init_done(bool)    override { return 0; }
    void reset_all_param()      override {}

    // ── param tree ───────────────────────────────────────────────────────────
    // ─── FIX v6: hard-code pci_enabled in init_memory ─────────────────────
    // Our v5b override of BX_MEM_C::init_memory used to call
    //   pci_enabled = SIM->get_param_bool(BXPN_PCI_ENABLED)->get();
    // which hung in the first call's static-local bx_param_bool_c dummy
    // ctor. v6 hard-codes pci_enabled = false instead. But other code in
    // libcpu.a (especially generic_cpuid.cc:get_cpuid_leaf, called from
    // BX_CPU::reset and from CPUID instruction emulation) still calls
    // SIM->get_param_string and SIM->get_param_bool. Returning nullptr
    // makes the immediate `->getptr()` / `->get()` host-fault and triple
    // -fault QEMU.
    //
    // ─── FIX v7: pre-constructed dummy params (file-scope statics) ────────
    // File-scope statics (defined just below the class) are constructed
    // during the __init_array pass at boot, BEFORE init_memory is ever
    // entered. So they're already-initialised on first use; no lazy
    // first-call ctor to wedge.
    bx_param_c*        get_param       (const char*, bx_param_c* = nullptr) override;
    bx_param_num_c*    get_param_num   (const char*, bx_param_c* = nullptr) override;
    bx_param_string_c* get_param_string(const char*, bx_param_c* = nullptr) override;
    bx_param_bool_c*   get_param_bool  (const char*, bx_param_c* = nullptr) override;
    bx_param_enum_c*   get_param_enum  (const char*, bx_param_c* = nullptr) override;
    unsigned           gen_param_id()  override { return 0; }

    // ── logging ──────────────────────────────────────────────────────────────
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

    // ── RC / log file paths ──────────────────────────────────────────────────
    int get_default_rc(char*, int)           override { return -1; }
    int read_rc(const char*)                 override { return -1; }
    int write_rc(const char*, int)           override { return -1; }
    int get_log_file(char*, int)             override { return -1; }
    int set_log_file(const char*)            override { return -1; }
    int get_log_prefix(char*, int)           override { return -1; }
    int set_log_prefix(const char*)          override { return -1; }
    int get_debugger_log_file(char*, int)    override { return -1; }
    int set_debugger_log_file(const char*)   override { return -1; }

    // ── event / notify ───────────────────────────────────────────────────────
    void      set_notify_callback(bxevent_handler, void*) override {}
    void      get_notify_callback(bxevent_handler*, void**) override {}
    BxEvent*  sim_to_ci_event(BxEvent* e)  override { return e; }
    int       log_dlg(const char*, int, const char*, int) override { return 0; }
    void      log_msg(const char*, int, const char*)      override {}
    void      set_log_viewer(bool)         override {}
    bool      has_log_viewer() const       override { return false; }

    // ── ask / dialog ─────────────────────────────────────────────────────────
    int  ask_param(bx_param_c*)                                               override { return 0; }
    int  ask_param(const char*)                                               override { return 0; }
    int  ask_filename(const char*, int, const char*, const char*, int)        override { return -1; }
    int  ask_yes_no(const char*, const char*, bool the_default)               override { return (int)the_default; }
    void message_box(const char*, const char*)                                override {}

    // ── periodic / refresh ───────────────────────────────────────────────────
    void periodic()      override {}
    void refresh_ci()    override {}
    void refresh_vga()   override {}
    void handle_events() override {}

    // ── disk / PCI / device queries ──────────────────────────────────────────
    int         create_disk_image(const char*, int, bool) override { return -1; }
    bx_param_c* get_first_hd()                            override { return nullptr; }
    bx_param_c* get_first_cdrom()                         override { return nullptr; }
    bool        is_pci_device(const char*)                override { return false; }
    bool        is_agp_device(const char*)                override { return false; }

    // ── config interface ─────────────────────────────────────────────────────
    void register_configuration_interface(const char*, config_interface_callback_t, void*) override {}
    int  configuration_interface(const char*, ci_command_t) override { return 0; }
    int  begin_simulation(int, char*[])                      override { return 0; }

    // ── runtime config ───────────────────────────────────────────────────────
    int  register_runtime_config_handler(void*, rt_conf_handler_t) override { return 0; }
    void unregister_runtime_config_handler(int)                    override {}
    void update_runtime_options()                                   override {}

    // ── threading ────────────────────────────────────────────────────────────
    void set_sim_thread_func(is_sim_thread_func_t f) override { is_sim_thread_func = f; }
    bool is_sim_thread()     override { return false; }
    bool is_wx_selected() const override { return false; }

    // ── GUI mode ─────────────────────────────────────────────────────────────
    void set_debug_gui(bool)        override {}
    bool has_debug_gui() const      override { return false; }
    void set_display_mode(disp_mode_t) override {}
    bool test_for_text_console()    override { return false; }

    // ── addon options ────────────────────────────────────────────────────────
    bool    register_addon_option(const char*, addon_option_parser_t, addon_option_save_t) override { return false; }
    bool    unregister_addon_option(const char*)     override { return false; }
    bool    is_addon_option(const char*)             override { return false; }
    Bit32s  parse_addon_option(const char*, int, char*[]) override { return 0; }
    Bit32s  save_addon_options(FILE*)                override { return 0; }

    // ── statistics ───────────────────────────────────────────────────────────
    void       init_statistics()     override {}
    void       cleanup_statistics()  override {}
    bx_list_c* get_statistics_root() override { return nullptr; }

    // ── save / restore ───────────────────────────────────────────────────────
    void       init_save_restore()                                        override {}
    void       cleanup_save_restore()                                     override {}
    bool       save_state(const char*)                                    override { return false; }
    bool       restore_config()                                           override { return false; }
    bool       restore_logopts()                                          override { return false; }
    bool       restore_hardware()                                         override { return false; }
    bx_list_c* get_bochs_root()                                           override { return nullptr; }
    bool       restore_bochs_param(bx_list_c*, const char*, const char*) override { return false; }

    // ── plugin ctrl ──────────────────────────────────────────────────────────
    bool opt_plugin_ctrl(const char*, bool) override { return false; }

    // ── NIC / USB helpers ────────────────────────────────────────────────────
    void init_std_nic_options(const char*, bx_list_c*)           override {}
    int  parse_param_from_list(const char*, const char*, bx_list_c*) override { return 0; }
    int  parse_nic_params(const char*, const char*, bx_list_c*)  override { return 0; }
    int  parse_usb_port_params(const char*, const char*, int, bx_list_c*) override { return 0; }
    int  split_option_list(const char*, const char*, char**, int) override { return 0; }
    int  write_param_list(FILE*, bx_list_c*, const char*, bool)  override { return 0; }
    int  write_usb_options(FILE*, int, bx_list_c*)               override { return 0; }
};

static KernelSIM s_sim;
bx_simulator_interface_c* SIM = &s_sim;

// ─── FIX v7: pre-constructed dummy param objects ───────────────────────────
// libcpu.a's generic_cpuid.cc and other call sites do things like
//   static const char* brand_string =
//       (const char*)SIM->get_param_string(BXPN_BRAND_STRING)->getptr();
// where a nullptr return triple-faults the host. We can't return nullptr
// and can't lazily construct on first call (the static-local guard +
// ctor chain hung in v5b). So construct dummies at file scope here —
// they're initialised by the __init_array global-ctor pass before any
// SIM->get_param_* call happens at runtime.
//
// All dummies have safe defaults (value 0 / empty string). Callers that
// branch on the returned value will see "feature disabled" / "no brand"
// behaviour, which is what we want for a freestanding kernel anyway.

static bx_param_bool_c   s_dummy_bool  (nullptr, "dummy", "dummy", "dummy", 0, 0);
static bx_param_num_c    s_dummy_num   (nullptr, "dummy", "dummy", "dummy", 0, 0, 0, 0);
// bx_param_string_c needs a backing buffer. The ctor signature is
//   bx_param_string_c(parent, name, label, description, initial_val, maxsize)
static bx_param_string_c s_dummy_string(nullptr, "dummy", "dummy", "dummy", "", 1);

bx_param_c*        KernelSIM::get_param       (const char*, bx_param_c*) { return &s_dummy_num;    }
bx_param_num_c*    KernelSIM::get_param_num   (const char*, bx_param_c*) { return &s_dummy_num;    }
bx_param_string_c* KernelSIM::get_param_string(const char*, bx_param_c*) { return &s_dummy_string; }
bx_param_bool_c*   KernelSIM::get_param_bool  (const char*, bx_param_c*) { return &s_dummy_bool;   }
bx_param_enum_c*   KernelSIM::get_param_enum  (const char*, bx_param_c*) { return nullptr;         }

// ═══ bx_user_quit ════════════════════════════════════════════════════════════
bool bx_user_quit = false;

// ═══ bx_gui stub ═════════════════════════════════════════════════════════════
bx_gui_c* bx_gui = nullptr;
void bx_gui_c::cleanup() {}

// ═══ Misc ════════════════════════════════════════════════════════════════════
void print_statistics_tree(bx_param_c*, int) {}

// ═══ RTTI for logfunctions ═══════════════════════════════════════════════════
extern "C" {
    extern char  _ZTS12logfunctions[] = "12logfunctions";
    extern void* _ZTI12logfunctions[] = {
        nullptr,
        (void*)_ZTS12logfunctions
    };
}

// ═══ C++ ABI stubs ═══════════════════════════════════════════════════════════
extern "C" {
    void _Unwind_Resume(void*) { bx_recover('U', 5); }
    int  __gxx_personality_v0(...) { return 0; }
    int  __gcc_personality_v0(...) { return 0; }
    void __cxa_guard_abort(long long*) {}
}
// __dso_handle: glibc declares this with C++ linkage in some headers
// (transitively included via paramtree.h → siminterface.h → cstdlib).
// Declaring it inside an extern "C" block above causes a conflict, so
// define it at the top level. bochs_glue.cpp has its own extern "C"
// definition; the linker resolves to whichever it sees first.
__attribute__((weak)) void* __dso_handle = nullptr;

void operator delete(void*, unsigned int, std::align_val_t) noexcept {}

// ═══ Plugin function pointers ════════════════════════════════════════════════
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

// ═══ bx_pci_device_c stubs ═══════════════════════════════════════════════════
Bit32u bx_pci_device_c::pci_read_handler (Bit8u, unsigned)        { return 0; }
