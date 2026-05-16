// ==== kernel.cpp =====================================================
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
static constexpr unsigned long HEAP_SIZE = 8u * 1024u * 1024u;
static unsigned char g_heap[HEAP_SIZE];
static unsigned long g_heap_off = 0;

extern "C" void* malloc(unsigned long n) {
    if (!n) return nullptr;
    n = (n + 15ul) & ~15ul;
    if (g_heap_off + n > HEAP_SIZE) return nullptr;
    void* p = g_heap + g_heap_off;
    g_heap_off += n;
    return p;
}

extern "C" void free(void*) {}
extern "C" void bochs_bios_init(const uint8_t* rom, uint32_t rom_len);
extern "C" int bochs_bios_tick(int n);
extern "C" bool bochs_bios_is_active();
extern "C" void bochs_bios_putc(char c);

extern "C" void bochs_cpu_init();
extern "C" void bochs_cpu_prewarm();
extern "C" void bochs_set_process_memory(uint8_t* base, uint32_t size, uint32_t vaddr_base);
extern "C" void bochs_finalize_process_memory();
extern "C" void bochs_set_brk(int, uint32_t);
extern "C" void bochs_activate_slot(int);
extern "C" void bochs_register_io_callbacks(int, int (*)(int), void (*)(int, char), void (*)(int, int));
extern "C" void bochs_cpu_set_eip(uint32_t);
extern "C" void bochs_cpu_set_esp(uint32_t);
extern "C" int bochs_cpu_tick(int);
extern "C" uint32_t bochs_cpu_get_eip();
extern "C" void live_breadcrumb(int slot, char ch);

extern "C" {
    typedef long long __guard_t;
    int __cxa_guard_acquire(__guard_t* g) { return !*(char*)g; }
    void __cxa_guard_release(__guard_t* g) { *(char*)g = 1; }
    void __cxa_guard_abort(__guard_t*) {}
    void __cxa_throw_bad_array_new_length() { for (;;) __asm__ volatile("cli; hlt"); }
}

namespace __cxxabiv1 {
class __class_type_info { public: virtual ~__class_type_info(); };
__attribute__((weak)) __class_type_info::~__class_type_info() {}
class __si_class_type_info : public __class_type_info { public: virtual ~__si_class_type_info(); };
__attribute__((weak)) __si_class_type_info::~__si_class_type_info() {}
}

void* operator new(unsigned int n) { return malloc(n); }
void* operator new[](unsigned int n) { return malloc(n); }
void operator delete(void* p) noexcept { free(p); }
void operator delete[](void* p) noexcept { free(p); }
void operator delete(void* p, unsigned) noexcept { free(p); }
void operator delete[](void* p, unsigned) noexcept { free(p); }

static volatile uint16_t* const VGA = (volatile uint16_t*)0xB8000;
static inline void e9_putc(char c) { __asm__ volatile("outb %0, %1" : : "a"((uint8_t)c), "Nd"((uint16_t)0xE9)); }
static void e9_puts(const char* s) { while (*s) e9_putc(*s++); }
static void e9_hex(uint32_t v) { static const char H[] = "0123456789ABCDEF"; e9_putc('0'); e9_putc('x'); for (int i = 7; i >= 0; --i) e9_putc(H[(v >> (i*4)) & 0xF]); }

struct fb_info_t { uint32_t* ptr; uint32_t width, height, pitch; } fb_info = {nullptr,0,0,0};
uint32_t* backbuffer = nullptr;

extern "C" void live_breadcrumb(int slot, char ch) {
    if (slot < 0 || slot >= 80) return;
    VGA[slot] = (uint16_t)(0x1F00u | (uint8_t)ch);
    e9_puts("[bc ");
    char buf[4] = {0};
    if (slot < 10) { buf[0] = char('0' + slot); }
    else { buf[0] = char('0' + slot/10); buf[1] = char('0' + slot%10); }
    e9_puts(buf);
    e9_puts("='"); e9_putc(ch); e9_puts("']\n");
}

extern "C" void host_fault_handler(int vec) {
    static const char H[] = "0123456789ABCDEF";
    VGA[80] = (uint16_t)(0x4F00u | '!');
    VGA[81] = (uint16_t)(0x4F00u | H[(vec >> 4) & 0xF]);
    VGA[82] = (uint16_t)(0x4F00u | H[vec & 0xF]);
    e9_puts("[HOST_FAULT vec="); e9_hex((uint32_t)vec); e9_puts("]\n");
    for (;;) __asm__ volatile("cli; hlt");
}

static volatile int g_guest_output_count = 0;
static volatile int g_guest_exit_seen = 0;
static volatile int g_guest_exit_code = 0;
static char g_guest_output[64];

static int test_io_read(int) { return 0; }
static void test_io_write(int slot, char c) {
    if (g_guest_output_count < (int)sizeof(g_guest_output) - 1) g_guest_output[g_guest_output_count++] = c;
    e9_puts(" [guest port-0xE9 slot="); e9_putc(char('0'+slot)); e9_puts(" wrote ");
    if (c >= 32 && c < 127) { e9_putc('\''); e9_putc(c); e9_putc('\''); } else e9_hex((uint32_t)(uint8_t)c);
    e9_puts("]\n");
}
static void test_io_exit(int slot, int code) { g_guest_exit_seen = 1; g_guest_exit_code = code; e9_puts(" [guest exit slot="); e9_putc(char('0'+slot)); e9_puts(" code="); e9_hex((uint32_t)code); e9_puts("]\n"); }

static const uint8_t guest_program[] = { 0xB0,0x48,0xE6,0xE9,0xB0,0x49,0xE6,0xE9,0xB0,0x0A,0xE6,0xE9,0xB0,0x00,0xE6,0xE8,0xF4,0xEB,0xFE };
#define SLAB_VADDR_BASE 0x08000000u
#define SLAB_SIZE (1u * 1024u * 1024u)
#define GUEST_ENTRY_OFF 0x1000u
static uint8_t slab[SLAB_SIZE] __attribute__((aligned(4096))) = {0};

static inline void init_minimal_bios(uint8_t* bios) {
    std::memset(bios, 0, 65536);
    bios[0x0000]=0xFA; bios[0xFFF0]=0xEA; bios[0xFFF1]=0x00; bios[0xFFF2]=0x00; bios[0xFFF3]=0x00; bios[0xFFF4]=0xF0; bios[0xFFF5]=0xF4;
}

extern "C" void kernel_main(uint32_t, uint32_t) {
	
    static uint8_t bios[65536];
    init_minimal_bios(bios);
    bochs_cpu_init();
    bochs_bios_init(bios, sizeof(bios));
    for (int i = 0; i < 16 && !bochs_bios_is_active(); ++i) bochs_bios_tick(4);
    bochs_cpu_init();
    bochs_register_io_callbacks(0, test_io_read, test_io_write, test_io_exit);
    bochs_activate_slot(0);
    bochs_set_process_memory(slab, SLAB_SIZE, SLAB_VADDR_BASE);
    for (unsigned i = 0; i < sizeof(guest_program); ++i) slab[GUEST_ENTRY_OFF + i] = guest_program[i];
    bochs_cpu_set_eip(SLAB_VADDR_BASE + GUEST_ENTRY_OFF);
    bochs_cpu_set_esp(SLAB_VADDR_BASE + SLAB_SIZE - 16);
    for (int iter = 0; iter < 32 && !g_guest_exit_seen; ++iter) bochs_cpu_tick(1);
    VGA[60] = (uint16_t)((g_guest_output_count == 3 && g_guest_output[0] == 'H' && g_guest_output[1] == 'I' && g_guest_output[2] == '\n' && g_guest_exit_seen) ? 0x2F00u | '#' : 0x4F00u | '!');
}

// ==== bochs_bios.cpp ================================================
#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/pc_system.h"
#include <cstdint>
#include <cstring>

extern "C" void live_breadcrumb(int slot, char ch);
extern "C" void bochs_guest_exit(int code);

static volatile uint16_t* const HOST_VGA = (volatile uint16_t*)0xB8000;
static const int VGA_COLS = 80;
static const int VGA_ROWS = 25;
static uint8_t g_conv_ram[640u * 1024u] __attribute__((aligned(4096)));
static uint8_t g_vga_buf[0x8000u] __attribute__((aligned(4096)));
static uint8_t g_bios_rom[0x10000u] __attribute__((aligned(4096)));
static uint8_t g_bios_ext[0x10000u] __attribute__((aligned(4096)));
static bool g_bios_mode_active = false;
static bool g_bios_halted = false;
static char g_ticker[80] = {0};
static int g_ticker_len = 0;

static void bios_ticker_putc(char c) {
    if (c == '\r') return;
    if (c == '\n') {
        for (int i = 0; i < g_ticker_len - 1; ++i) g_ticker[i] = g_ticker[i + 1];
        if (g_ticker_len > 0) g_ticker_len--;
        return;
    }
    if (g_ticker_len < 80) g_ticker[g_ticker_len++] = c;
    else { for (int i = 0; i < 79; ++i) g_ticker[i] = g_ticker[i + 1]; g_ticker[79] = c; }
    for (int col = 0; col < 80; ++col) {
        char ch = (col < g_ticker_len) ? g_ticker[col] : ' ';
        HOST_VGA[24 * VGA_COLS + col] = (uint16_t)(0x0B00u | (uint8_t)ch);
    }
}

extern "C" void bochs_bios_putc(char c) { bios_ticker_putc(c); }
extern "C" bool bochs_bios_is_active() { return g_bios_mode_active && !g_bios_halted; }

static void vga_text_mirror_write(uint32_t offset, const uint8_t* data, unsigned len) {
    for (unsigned i = 0; i < len && (offset + i) < 0x8000u; ++i) g_vga_buf[offset + i] = data[i];
    uint32_t cell_start = offset & ~1u;
    uint32_t cell_end = (offset + len + 1u) & ~1u;
    for (uint32_t off = cell_start; off < cell_end && off + 1 < 0x8000u; off += 2) {
        int cell = (int)(off / 2);
        if (cell < VGA_COLS * VGA_ROWS) HOST_VGA[cell] = (uint16_t)((g_vga_buf[off + 1] << 8) | g_vga_buf[off]);
    }
}

static bool bios_convram_read(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr; if (off + len > sizeof(g_conv_ram)) { std::memset(data, 0, len); return true; } std::memcpy(data, g_conv_ram + off, len); return true; }
static bool bios_convram_write(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr; if (off + len > sizeof(g_conv_ram)) return true; std::memcpy(g_conv_ram + off, data, len); return true; }
static Bit8u* bios_convram_da(bx_phy_address addr, unsigned, void*) { uint32_t off = (uint32_t)addr; return (off < sizeof(g_conv_ram)) ? g_conv_ram + off : nullptr; }
static bool bios_vga_read(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr - 0xB8000u; if (off + len > sizeof(g_vga_buf)) { std::memset(data, 0, len); return true; } std::memcpy(data, g_vga_buf + off, len); return true; }
static bool bios_vga_write(bx_phy_address addr, unsigned len, void* data, void*) { vga_text_mirror_write((uint32_t)addr - 0xB8000u, (const uint8_t*)data, len); return true; }
static Bit8u* bios_vga_da(bx_phy_address addr, unsigned, void*) { uint32_t off = (uint32_t)addr - 0xB8000u; return (off < sizeof(g_vga_buf)) ? g_vga_buf + off : nullptr; }
static bool bios_ext_read(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr - 0xE0000u; if (off + len > sizeof(g_bios_ext)) { std::memset(data, 0xFF, len); return true; } std::memcpy(data, g_bios_ext + off, len); return true; }
static bool bios_ext_write(bx_phy_address, unsigned, void*, void*) { return true; }
static Bit8u* bios_ext_da(bx_phy_address addr, unsigned, void*) { uint32_t off = (uint32_t)addr - 0xE0000u; return (off < sizeof(g_bios_ext)) ? g_bios_ext + off : nullptr; }
static bool bios_rom_read(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr - 0xF0000u; if (off + len > sizeof(g_bios_rom)) { std::memset(data, 0xFF, len); return true; } std::memcpy(data, g_bios_rom + off, len); return true; }
static bool bios_rom_write(bx_phy_address, unsigned, void*, void*) { return true; }
static Bit8u* bios_rom_da(bx_phy_address addr, unsigned, void*) { uint32_t off = (uint32_t)addr - 0xF0000u; return (off < sizeof(g_bios_rom)) ? g_bios_rom + off : nullptr; }
static bool bios_alias_read(bx_phy_address addr, unsigned len, void* data, void*) { uint32_t off = (uint32_t)addr - 0xFFFF0000u; if (off + len > sizeof(g_bios_rom)) { std::memset(data, 0xFF, len); return true; } std::memcpy(data, g_bios_rom + off, len); return true; }
static bool bios_alias_write(bx_phy_address, unsigned, void*, void*) { return true; }
static Bit8u* bios_alias_da(bx_phy_address addr, unsigned, void*) { uint32_t off = (uint32_t)addr - 0xFFFF0000u; return (off < sizeof(g_bios_rom)) ? g_bios_rom + off : nullptr; }

extern "C" void bochs_bios_init(const uint8_t* rom, uint32_t rom_len) {
    live_breadcrumb(20, 'B');
    std::memset(g_bios_rom, 0xFF, sizeof(g_bios_rom));
    std::memset(g_bios_ext, 0xFF, sizeof(g_bios_ext));
    std::memset(g_conv_ram, 0, sizeof(g_conv_ram));
    std::memset(g_vga_buf, 0, sizeof(g_vga_buf));
    if (rom && rom_len) {
        if (rom_len <= sizeof(g_bios_rom)) std::memcpy(g_bios_rom + (sizeof(g_bios_rom) - rom_len), rom, rom_len);
        else { uint32_t ext_len = rom_len - sizeof(g_bios_rom); if (ext_len > sizeof(g_bios_ext)) ext_len = sizeof(g_bios_ext); std::memcpy(g_bios_ext + (sizeof(g_bios_ext) - ext_len), rom, ext_len); std::memcpy(g_bios_rom, rom + ext_len, sizeof(g_bios_rom)); }
    }
    g_bios_rom[0xFFF0]=0xEA; g_bios_rom[0xFFF1]=0x00; g_bios_rom[0xFFF2]=0x00; g_bios_rom[0xFFF3]=0x00; g_bios_rom[0xFFF4]=0xF0; g_bios_rom[0xFFF5]=0xF4;
    g_bios_mode_active = true; g_bios_halted = false;
}

extern "C" int bochs_bios_tick(int n) {
    if (!g_bios_mode_active || g_bios_halted) return 1;
    if (n < 1) n = 1;
    for (int i = 0; i < n; ++i) { bx_pc_system.kill_bochs_request = 0; BX_CPU(0)->async_event = 0; BX_CPU(0)->cpu_loop(); if (BX_CPU(0)->activity_state != 0) { g_bios_halted = true; break; } }
    for (int i = 0; i < 80*25; ++i) HOST_VGA[i] = (uint16_t)((g_vga_buf[i*2+1] << 8) | g_vga_buf[i*2]);
    return g_bios_halted ? 1 : 0;
}
