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
extern "C" void kernel_main(uint32_t /*magic*/, uint32_t /*mbi*/) {
    // Clear VGA row 0 first 80 cells so old breadcrumbs from a previous
    // boot (eg if memory wasn't fully zeroed) don't fool us.
    for (int i = 0; i < 80; ++i) VGA[i] = 0x0F00u | ' ';
    for (int i = 0; i < 80; ++i) VGA[80 + i] = 0x0F00u | ' ';

    e9_puts("\n=== test_main: BX_CPU(0)->initialize() verification ===\n");

    run_init_array();

    e9_puts("[calling bochs_cpu_init()]\n");
    bochs_cpu_init();
    e9_puts("[bochs_cpu_init() RETURNED]\n");

    // Mark "all four breadcrumbs visible" with bright green '*' at column 50
    VGA[50] = (uint16_t)(0x2F00u | (uint8_t)'*');

    e9_puts("=== TEST PASSED ===\n");

    // Tell QEMU to exit successfully. The isa-debug-exit device on port
    // 0x501 with -device isa-debug-exit causes QEMU to exit with code
    // (val << 1) | 1. So writing 0x21 → exit code 0x43 (not zero, but
    // distinct from a triple-fault exit).
    //__asm__ volatile ("outb %0, %1" : : "a"((uint8_t)0x21), "Nd"((uint16_t)0x501));

    //for (;;) { __asm__ volatile ("cli; hlt"); }
}
