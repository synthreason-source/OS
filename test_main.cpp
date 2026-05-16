// test_main.cpp — minimal kernel_main for verifying that
// bochs_global_init() (which calls BX_CPU(0)->initialize()) returns.
//
// What this provides that the real kernel.cpp would:
//   - kernel_main entrypoint
//   - live_breadcrumb() that the glue calls (writes to VGA and port 0xE9)
//   - host_fault_handler that boot.S's ISRs call on host CPU fault
//   - fb_info / backbuffer globals that the real kernel uses (we stub
//     them, since live_breadcrumb in the real kernel writes both VGA
//     and the framebuffer; we only need the VGA + port-0xE9 path)
//   - Operator new/delete that go to the bump allocator in
//     bochs_cstubs.c (via the malloc symbol)
//   - C++ ABI/EH/atexit stubs not provided by bochs_infra
//   - Bochs glue extern decls

#include <stdint.h>

extern "C" {
    void bochs_cpu_init();
    void bochs_cpu_prewarm();
    void bochs_set_process_memory(uint8_t* base, uint32_t size, uint32_t vaddr_base);
    void bochs_finalize_process_memory();
    void bochs_set_brk(int, uint32_t);
    void bochs_activate_slot(int);
    void bochs_register_io_callbacks(int,
        int  (*)(int),
        void (*)(int, char),
        void (*)(int, int));
    void bochs_cpu_set_eip(uint32_t);
    void bochs_cpu_set_esp(uint32_t);
    int  bochs_cpu_tick(int);
    uint32_t bochs_cpu_get_eip();

    // From bochs_cstubs.c bump allocator
    void* malloc(unsigned long);
    void  free(void*);
}

// ─── Port-0xE9 debug console (QEMU -debugcon stdio captures this) ───────
// Every breadcrumb gets mirrored here. In QEMU we'll launch with
//   -debugcon stdio
// so the trace shows up on stdout.
static inline void e9_putc(char c) {
    __asm__ volatile ("outb %0, %1" : : "a"((uint8_t)c), "Nd"((uint16_t)0xE9));
}
static void e9_puts(const char* s) { while (*s) e9_putc(*s++); }
static void e9_hex(uint32_t v) {
    static const char H[] = "0123456789ABCDEF";
    e9_putc('0'); e9_putc('x');
    for (int i = 7; i >= 0; --i) e9_putc(H[(v >> (i*4)) & 0xF]);
}

// ─── VGA text-mode write at row 0 (matches the real kernel's overlay) ───
// Each "slot" is one character cell. Position 0,0..79,0 used for boot trace.
static volatile uint16_t* const VGA = (volatile uint16_t*)0xB8000;

// ─── Framebuffer info, stubbed (real kernel sets these from multiboot) ──
struct fb_info_t { uint32_t* ptr; uint32_t width, height, pitch; } fb_info = {nullptr, 0, 0, 0};
uint32_t* backbuffer = nullptr;

// ─── live_breadcrumb: this is what bochs_global_init calls between
// steps. The real kernel renders to the framebuffer; we mirror to VGA
// (so it's recoverable from a QEMU `pmemsave`) AND to port 0xE9 (so
// the host stdout captures the trace in real time). The slot/char
// pairs match bochs_glue.cpp's bochs_global_init().
extern "C" void live_breadcrumb(int slot, char ch) {
    if (slot < 0 || slot >= 80) return;
    // VGA: bright white on dark blue (attr 0x1F)
    VGA[slot] = (uint16_t)(0x1F00u | (uint8_t)ch);
    // Port 0xE9: "[bc 32='2']\n"
    e9_puts("[bc ");
    char nbuf[4] = {0};
    if (slot < 10) { nbuf[0] = (char)('0' + slot); nbuf[1] = 0; }
    else { nbuf[0] = (char)('0' + slot/10); nbuf[1] = (char)('0' + slot%10); nbuf[2] = 0; }
    e9_puts(nbuf);
    e9_puts("='");
    e9_putc(ch);
    e9_puts("']\n");
}

// ─── Host fault handler — called by boot.S's ISR_n stubs ───────────────
// On a host CPU fault during BX_CPU(0)->initialize(), this is where we
// land. Tag VGA row 1 with "!XX" (XX = fault vector in hex) and halt.
extern "C" void host_fault_handler(int vec) {
    static const char H[] = "0123456789ABCDEF";
    VGA[80 + 0] = (uint16_t)(0x4F00u | (uint8_t)'!');
    VGA[80 + 1] = (uint16_t)(0x4F00u | (uint8_t)H[(vec >> 4) & 0xF]);
    VGA[80 + 2] = (uint16_t)(0x4F00u | (uint8_t)H[ vec       & 0xF]);
    e9_puts("[HOST_FAULT vec=");
    e9_hex((uint32_t)vec);
    e9_puts("]\n");
}

// ─── C++ ABI mins (libcpu/libcpudb were built with EH on) ──────────────
// __cxa_guard_acquire/release manage initialisation of function-scope
// statics. In our freestanding single-threaded boot they're trivial.
// They are byte-flagged: *guard==0 → not-yet-init; we set it, return 1
// (caller proceeds to init); next caller sees *guard==1 and returns 0.
extern "C" {
    typedef long long __guard_t;
    int  __cxa_guard_acquire(__guard_t* g) { return !*(char*)g; }
    void __cxa_guard_release(__guard_t* g) { *(char*)g = 1;     }
    void __cxa_guard_abort  (__guard_t* g) { (void)g;           }

    // Throwable that we cannot actually throw because -fno-exceptions.
    // libmemory's init_memory has a cold-path call to this. It will
    // never be reached at runtime given valid inputs.
    void __cxa_throw_bad_array_new_length() {
        e9_puts("[__cxa_throw_bad_array_new_length called — HALT]\n");
        for (;;) __asm__ volatile ("cli; hlt");
    }
}

// RTTI symbol stubs. libcpudb's .rodata refers to the type_info for
// __si_class_type_info (single-inheritance class type_info). Provide a
// weak null definition so the link resolves. Since we never use RTTI
// these are never read; their address must just exist in the image.
namespace __cxxabiv1 {
    class __class_type_info {
    public:
        virtual ~__class_type_info();
    };
    __attribute__((weak)) __class_type_info::~__class_type_info() {}

    class __si_class_type_info : public __class_type_info {
    public:
        virtual ~__si_class_type_info();
    };
    __attribute__((weak)) __si_class_type_info::~__si_class_type_info() {}
}


// new/delete go through malloc/free (which are in bochs_cstubs.c).
void* operator new   (unsigned int n)            { return malloc(n); }
void* operator new[] (unsigned int n)            { return malloc(n); }
void  operator delete(void* p)            noexcept { free(p); }
void  operator delete[](void* p)          noexcept { free(p); }
void  operator delete(void* p, unsigned)  noexcept { free(p); }
void  operator delete[](void* p, unsigned) noexcept { free(p); }

// __init_array walker. Called from boot.S? We do it here from kernel_main
// before the first Bochs call so all the file-scope ctors (genlog, sims,
// bx_cpu(0), bx_mem, dummy params) run.
extern "C" void (*__init_array_start[])();
extern "C" void (*__init_array_end[])();

static void run_init_array() {
    e9_puts("[init_array begin]\n");
    for (void (**p)() = __init_array_start; p < __init_array_end; ++p) {
        e9_puts("  ctor @ ");
        e9_hex((uint32_t)(uintptr_t)*p);
        e9_puts("\n");
        (*p)();
    }
    e9_puts("[init_array end]\n");
}

// ─── Test main ──────────────────────────────────────────────────────────
//
// Two-phase verification:
//   Phase 1: bochs_cpu_init() runs to completion (breadcrumbs 30..36).
//            Confirms BX_CPU(0)->initialize() and reset() work.
//   Phase 2: load a tiny guest program (4 bytes of port-IO + exit) into
//            slot 0 via bochs_set_process_memory / bochs_cpu_set_eip,
//            then call bochs_cpu_tick(). Confirms the live BX_CPU can
//            actually execute guest instructions and that port-0xE9 +
//            port-0xE8 sentinels reach our callbacks.

// ─── I/O callback adapters that the glue invokes from inside the
// emulated CPU. Tagged so we can see them in the e9 trace.
static volatile int g_guest_output_count = 0;
static volatile int g_guest_exit_seen    = 0;
static volatile int g_guest_exit_code    = 0;
static char g_guest_output[64];

// ─── VGA row 2: live guest-output line ─────────────────────────────────
// Guest port-0xE9 bytes are echoed here as they arrive, behind a
// "GUEST: " label, so the guest's output is visible on the actual
// screen — not only on the port-0xE9 debug console. Row 2 is the
// third text row (cells 160..239); rows 0/1 are the breadcrumb /
// fault-tag overlay.
#define VGA_GUEST_ROW    2
#define VGA_GUEST_LABEL  "GUEST: "
static const int VGA_GUEST_LABEL_LEN = 7;            // strlen("GUEST: ")
static int g_vga_guest_col = VGA_GUEST_LABEL_LEN;     // next free cell in row

// Paint the static "GUEST: " label and blank the rest of row 2.
static void vga_guest_init_row() {
    const int base = VGA_GUEST_ROW * 80;
    const char* p = VGA_GUEST_LABEL;
    int i = 0;
    for (; p[i]; ++i)                                 // label: grey on black
        VGA[base + i] = (uint16_t)(0x07u << 8 | (uint8_t)p[i]);
    for (; i < 80; ++i)                               // clear remainder
        VGA[base + i] = 0x0F00u | ' ';
    g_vga_guest_col = VGA_GUEST_LABEL_LEN;
}

// Echo one guest output character to VGA row 2.
//   - printable chars are written at the cursor (bright green on black)
//   - '\n' returns the cursor to just after the label (so a multi-line
//     guest overwrites in place rather than scrolling off the row)
//   - other control chars are shown as a '.'
//   - if the row fills up, further chars are dropped (no scroll)
static void vga_guest_putc(char c) {
    const int base = VGA_GUEST_ROW * 80;
    if (c == '\n') {
        g_vga_guest_col = VGA_GUEST_LABEL_LEN;
        return;
    }
    if (g_vga_guest_col >= 80) return;                // row full — drop
    char show = (c >= 32 && c < 127) ? c : '.';
    VGA[base + g_vga_guest_col] =
        (uint16_t)(0x0A00u | (uint8_t)show);          // bright green
    g_vga_guest_col++;
}

static int  test_io_read(int /*slot*/) { return 0; }
static void test_io_write(int slot, char c) {
    if (g_guest_output_count < (int)sizeof(g_guest_output) - 1) {
        g_guest_output[g_guest_output_count++] = c;
    }

    // Mirror the guest byte to VGA row 2 so it shows on screen.
    vga_guest_putc(c);
    e9_puts("  [guest port-0xE9 slot=");
    e9_putc((char)('0' + slot));
    e9_puts(" wrote ");
    if (c >= 32 && c < 127) {
        e9_putc('\'');
        e9_putc(c);
        e9_putc('\'');
    } else {
        e9_hex((uint32_t)(uint8_t)c);
    }
    e9_puts("]\n");
}
static void test_io_exit(int slot, int code) {
    g_guest_exit_seen = 1;
    g_guest_exit_code = code;
    e9_puts("  [guest exit slot=");
    e9_putc((char)('0' + slot));
    e9_puts(" code=");
    e9_hex((uint32_t)code);
    e9_puts("]\n");
}

// ─── The guest program ─────────────────────────────────────────────────
// At slot offset 0x200 (= vaddr_base + 0x200), past the GDT (0x80) and
// IDT (0x100..0x900). The bytes below were assembled by hand; verified
// by `objdump -D -m i386 -b binary` on the same byte sequence.
//
//     B0 48        mov  $0x48, %al        ; 'H'
//     E6 E9        out  %al, $0xE9
//     B0 49        mov  $0x49, %al        ; 'I'
//     E6 E9        out  %al, $0xE9
//     B0 0A        mov  $0x0A, %al        ; '\n'
//     E6 E9        out  %al, $0xE9
//     B0 00        mov  $0x00, %al
//     E6 E8        out  %al, $0xE8        ; exit sentinel → bochs_guest_exit
//     F4           hlt                    ; safety: never reached
//     EB FE        jmp  .                 ; safety: spin if it is
static const uint8_t guest_program[] = {
    0xB0, 0x32,        // mov al, '2'
    0x2C, 0x30,        // sub al, '0'   ; AL = 2

    0xB4, 0x03,        // mov ah, 3
    0x00, 0xE0,        // add al, ah    ; AL = 5

    0x04, 0x30,        // add al, '0'   ; AL = '5'
    0xE6, 0xE9,        // out 0xE9, al

    0xB0, 0x0A,        // mov al, '\n'
    0xE6, 0xE9,        // out 0xE9, al

    0xB0, 0x00,        // mov al, 0
    0xE6, 0xE8,        // out 0xE8, al
    0xF4,
    0xEB, 0xFE
};
// Slot backing slab. 1 MiB, page-aligned, kept in BSS so we don't
// allocate from the bump pool (which is now committed to Bochs).
// vaddr_base is arbitrary but must be slab-aligned; we pick 0x08000000
// to mirror what real ELFs use (-Ttext=0x08048000).
// CRITICAL — guest entry offset: inject_slab_tables (bochs_glue.cpp)
// writes the exit-trap stub at slab offset 0x000, the GDT at 0x080, and
// the IDT at 0x100..0x900 (256 gates x 8 bytes). The guest program MUST
// sit clear of all of that. 0x1000 (one page in) is the first clean
// page-aligned offset. An earlier version used 0x200 — inside the IDT
// region — so inject_slab_tables overwrote the guest code with IDT
// gate descriptors and the CPU executed gate bytes instead of `out`s.
#define SLAB_VADDR_BASE  0x08000000u
#define SLAB_SIZE        (1u * 1024u * 1024u)
#define GUEST_ENTRY_OFF  0x1000u
static uint8_t slab[SLAB_SIZE] __attribute__((aligned(4096))) = {0};

extern "C" void kernel_main(uint32_t /*magic*/, uint32_t /*mbi*/) {
    // Clear VGA rows 0/1 so stale data from a prior boot doesn't fool us.
    for (int i = 0; i < 80; ++i) VGA[i]      = 0x0F00u | ' ';
    for (int i = 0; i < 80; ++i) VGA[80 + i] = 0x0F00u | ' ';

    // Paint row 2's "GUEST: " label; guest output is echoed there live.
    vga_guest_init_row();

    e9_puts("\n=== test_main: BX_CPU(0)->initialize() + cpu_tick verification ===\n");

    run_init_array();

    // ─── Phase 1: global Bochs init ──────────────────────────────────
    e9_puts("\n[Phase 1] calling bochs_cpu_init()...\n");
    bochs_cpu_init();
    e9_puts("[Phase 1] bochs_cpu_init() RETURNED — initialize() worked.\n");
    VGA[50] = (uint16_t)(0x2F00u | (uint8_t)'*');

    // ─── Phase 2: load a tiny guest and tick it ──────────────────────
    e9_puts("\n[Phase 2] loading guest program into slot 0...\n");

    // Register the IO callbacks for slot 0 BEFORE activate_slot so the
    // slot's write/exit callbacks are wired when first ticked.
    bochs_register_io_callbacks(0, test_io_read, test_io_write, test_io_exit);

    // Make slot 0 active, then bind its backing memory. bochs_set_process_
    // memory calls mapping_register, slot_prime_cpu, inject_slab_tables
    // (which writes the GDT/IDT/stub into the slab), slot_restore_cpu,
    // and flush_after_switch.
    bochs_activate_slot(0);
    bochs_set_process_memory(slab, SLAB_SIZE, SLAB_VADDR_BASE);

    // Place the guest program AFTER set_process_memory so that the
    // table injection (stub/GDT/IDT, all below offset 0x900) cannot
    // overwrite it. GUEST_ENTRY_OFF (0x1000) is clear of the tables
    // anyway, but writing afterwards is belt-and-suspenders.
    for (unsigned i = 0; i < sizeof(guest_program); ++i) {
        slab[GUEST_ENTRY_OFF + i] = guest_program[i];
    }
    e9_puts("  slab host pa = ");
    e9_hex((uint32_t)(uintptr_t)slab);
    e9_puts(", guest entry vaddr = ");
    e9_hex(SLAB_VADDR_BASE + GUEST_ENTRY_OFF);
    e9_puts("\n  first guest bytes: ");
    for (unsigned i = 0; i < 8; ++i) {
        e9_hex((uint32_t)slab[GUEST_ENTRY_OFF + i]);
        e9_putc(' ');
    }
    e9_puts("\n");

    // Point the CPU at the guest entry and give it a stack near the top
    // of the slab. bochs_cpu_set_eip also flushes the iCache, so any
    // entry covering the just-written code page is dropped.
    bochs_cpu_set_eip(SLAB_VADDR_BASE + GUEST_ENTRY_OFF);
    bochs_cpu_set_esp(SLAB_VADDR_BASE + SLAB_SIZE - 16);

    e9_puts("  EIP set to ");
    e9_hex(bochs_cpu_get_eip());
    e9_puts(", ticking...\n");

    // Tick. bochs_cpu_tick(n) runs cpu_loop up to n times, returning when
    // cpu_loop yields (via kill_bochs_request set by our port-0xE9 /
    // port-0xE8 handlers in bochs_infra.cpp::bx_devices_c::outp).
    // Loop a few times to drain all three port-0xE9 writes plus the
    // port-0xE8 exit.
    int total_ticks = 0;
    for (int iter = 0; iter < 32 && !g_guest_exit_seen; ++iter) {
        e9_puts("  tick iter ");
        e9_hex((uint32_t)iter);
        e9_puts(" eip-before=");
        e9_hex(bochs_cpu_get_eip());
        e9_puts("\n");
        bochs_cpu_tick(1);
        total_ticks++;
        if (g_guest_exit_seen) break;
    }

    e9_puts("\n[Phase 2] results:\n");
    e9_puts("  total tick iterations: ");
    e9_hex((uint32_t)total_ticks);
    e9_puts("\n  guest output (");
    e9_hex((uint32_t)g_guest_output_count);
    e9_puts(" chars): \"");
    for (int i = 0; i < g_guest_output_count; ++i) {
        char c = g_guest_output[i];
        if (c >= 32 && c < 127) e9_putc(c);
        else { e9_putc('\\'); e9_hex((uint32_t)(uint8_t)c); }
    }
    e9_puts("\"\n  guest exit seen: ");
    e9_hex((uint32_t)g_guest_exit_seen);
    e9_puts("\n");

    for (;;) { __asm__ volatile ("cli; hlt"); }
}
