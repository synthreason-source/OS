#pragma once
// 02_boot_info_and_graphics_driver.h
// Multiboot info struct, RTC/font helpers, the color palette, render
// state machine, and the GraphicsDriver (framebuffer drawing primitives).
// Extracted from kernel.cpp (original lines 898-1442) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.




// =============================================================================
// SECTION 2: BOOTLOADER INFO, FONT, RTC
// =============================================================================
struct multiboot_info {
    uint32_t flags, mem_lower, mem_upper, boot_device, cmdline, mods_count, mods_addr;
    uint32_t syms[4], mmap_length, mmap_addr;
    uint32_t drives_length, drives_addr, config_table, boot_loader_name, apm_table;
    uint32_t vbe_control_info, vbe_mode_info;
    uint16_t vbe_mode, vbe_interface_seg, vbe_interface_off, vbe_interface_len;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch, framebuffer_width, framebuffer_height;
    uint8_t framebuffer_bpp, framebuffer_type, color_info[6];
} __attribute__((packed));

uint8_t rtc_read(uint8_t reg) { outb(0x70, reg); return inb(0x71); }
uint8_t bcd_to_bin(uint8_t val) { return ((val / 16) * 10) + (val & 0x0F); }
struct RTC_Time { uint8_t second, minute, hour, day, month; uint16_t year; };
RTC_Time read_rtc() {
    RTC_Time t;
    uint8_t century = 20;
    while (rtc_read(0x0A) & 0x80);
    uint8_t regB = rtc_read(0x0B);
    bool is_bcd = !(regB & 0x04);
    t.second = rtc_read(0x00); t.minute = rtc_read(0x02); t.hour = rtc_read(0x04);
    t.day = rtc_read(0x07); t.month = rtc_read(0x08); t.year = rtc_read(0x09);
    if (is_bcd) {
        t.second = bcd_to_bin(t.second); t.minute = bcd_to_bin(t.minute); t.hour = bcd_to_bin(t.hour);
        t.day = bcd_to_bin(t.day); t.month = bcd_to_bin(t.month); t.year = bcd_to_bin(t.year);
    }
    t.year += century * 100;
    return t;
}

// =============================================================================
// SECTION 3: GRAPHICS & WINDOWING SYSTEM WITH STATE MANAGEMENT
// =============================================================================

/* Back-buffer: 1024x768x4 = 3 MB.  Declared as a static array in BSS so it
   doesn't consume heap space.  fb_info dimensions are checked before use. */
static uint32_t backbuffer_storage[1024 * 768];
static uint32_t* backbuffer = backbuffer_storage;
// FramebufferInfo struct is forward-declared near the top of this file (above
// oom_halt). Here we just define the single instance.
FramebufferInfo fb_info;

// =============================================================================
// FRAMEBUFFER WRITE-COMBINING (MTRR) -- fixes "mouse is slow on real
// hardware, fine in VMware"
// =============================================================================
// swap_buffers() (see 10_window_manager_impl.h) does one `rep movsl` from
// the backbuffer to the live linear framebuffer every single frame, and
// every mouse-move redraw goes through that same path. Under VMware the
// virtual GPU's framebuffer is fast to write to no matter what x86 memory
// type the CPU thinks it has, so this cost is invisible there. On real
// hardware, unless something has told the CPU the framebuffer's physical
// address range is Write-Combining, the default effective memory type for
// a BIOS/GOP-provided linear framebuffer is often Uncacheable (UC) --
// and bulk sequential writes to UC memory are dramatically slower (often
// 20-100x) than to WC memory, because every store becomes its own
// separate, unbuffered bus transaction instead of being coalesced into
// full-cache-line burst writes. The whole render+input loop (see
// poll_input_universal()'s call site in kernel_main) runs synchronously,
// so a framebuffer blit that's 20-100x slower makes mouse tracking itself
// feel exactly as laggy as the symptom describes.
//
// This kernel runs in 32-bit protected mode WITHOUT paging (no CR3/PDE/PTE
// setup anywhere in this codebase), so there's no page-level PAT/PCD knob
// available. MTRRs are the only remaining lever: paging-independent,
// physical-address-range memory-type overrides configured through MSRs,
// present on every P6-class (Pentium Pro, 1995) and later x86 CPU, i.e.
// any real hardware this is plausibly running on.
//
// This only takes effect if the framebuffer's physical base/size happen
// to be power-of-two aligned -- true for any PCI-BAR-backed framebuffer,
// since PCI BARs are always power-of-two sized/aligned. If they aren't
// (some unusual non-BAR memory map), this safely does nothing rather than
// risk marking unrelated physical memory as write-combining.

static inline void cpuid_regs(uint32_t leaf, uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) {
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf));
}

static inline uint64_t rdmsr64(uint32_t msr) {
    uint32_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr64(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)(value & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

#define MTRR_TYPE_WC          0x01
#define IA32_MTRRCAP          0xFE
#define IA32_MTRR_DEF_TYPE    0x2FF
#define IA32_MTRR_PHYSBASE0   0x200
#define IA32_MTRR_PHYSMASK0   0x201

// Call once, after fb_info.ptr/pitch/height are finalized and before the
// first swap_buffers(). Safe no-op on any CPU/layout it can't handle
// confidently (no MSR/MTRR support, no WC support, no free variable MTRR,
// or a base/size that isn't naturally power-of-two aligned) -- worst case
// the framebuffer is left exactly as slow as it already was, never worse.
void setup_framebuffer_write_combining() {
    if (!fb_info.ptr) return;

    uint32_t eax, ebx, ecx, edx;
    cpuid_regs(1, eax, ebx, ecx, edx);
    bool has_msr  = (edx & (1u << 5))  != 0;
    bool has_mtrr = (edx & (1u << 12)) != 0;
    if (!has_msr || !has_mtrr) return;

    uint64_t mtrrcap = rdmsr64(IA32_MTRRCAP);
    uint32_t vcnt = (uint32_t)(mtrrcap & 0xFF);
    bool wc_supported = (mtrrcap & (1ull << 10)) != 0;
    if (!wc_supported || vcnt == 0) return;

    uint64_t base = (uint64_t)(uintptr_t)fb_info.ptr;
    uint64_t fb_bytes = (uint64_t)fb_info.pitch * (uint64_t)fb_info.height;
    if (fb_bytes == 0) return;

    // Smallest power-of-two size (>= fb_bytes, <= 256MB) that `base` is
    // naturally aligned to. If nothing up to 256MB works, bail out.
    uint64_t size = 4096; // MTRR minimum granularity
    bool found = false;
    for (; size <= (256ull * 1024 * 1024); size <<= 1) {
        if (size >= fb_bytes && (base % size) == 0) { found = true; break; }
    }
    if (!found) return;

    int slot = -1;
    for (uint32_t i = 0; i < vcnt; i++) {
        uint64_t mask = rdmsr64(IA32_MTRR_PHYSMASK0 + i * 2);
        if (!(mask & (1ull << 11))) { slot = (int)i; break; } // valid bit clear = free
    }
    if (slot < 0) return; // all variable MTRRs already in use -- don't clobber the BIOS's

    asm volatile("cli");

    uint64_t def_type = rdmsr64(IA32_MTRR_DEF_TYPE);
    wrmsr64(IA32_MTRR_DEF_TYPE, def_type & ~(1ull << 11)); // disable MTRRs while reprogramming
    asm volatile("wbinvd");

    uint64_t phys_base = base & ~(size - 1);
    uint64_t phys_mask = (~(size - 1)) & 0xFFFFFFFFFull; // 36-bit phys addr width -- guaranteed minimum on any MTRR-capable CPU

    wrmsr64(IA32_MTRR_PHYSBASE0 + slot * 2, phys_base | MTRR_TYPE_WC);
    wrmsr64(IA32_MTRR_PHYSMASK0 + slot * 2, phys_mask | (1ull << 11)); // set valid bit

    asm volatile("wbinvd");
    wrmsr64(IA32_MTRR_DEF_TYPE, def_type | (1ull << 11)); // re-enable MTRRs

    asm volatile("sti");
}

// =============================================================================
// UNIFIED COLOR PALETTE - PREVENTS COLOR INCONSISTENCIES
// =============================================================================
namespace ColorPalette {
    // Desktop colors
    constexpr uint32_t DESKTOP_TEAL      = 0x008080;
    constexpr uint32_t DESKTOP_BLUE      = 0x00004B; 
    constexpr uint32_t DESKTOP_GRAY      = 0x404040;
    
    // Taskbar colors
    constexpr uint32_t TASKBAR_GRAY      = 0x808080;
    constexpr uint32_t TASKBAR_DARK      = 0x606060;
    constexpr uint32_t TASKBAR_LIGHT     = 0xC0C0C0;
    
    // Window colors
    constexpr uint32_t WINDOW_BG         = 0x000000;
    constexpr uint32_t WINDOW_BORDER     = 0xC0C0C0;
    constexpr uint32_t TITLEBAR_ACTIVE   = 0x000080;
    constexpr uint32_t TITLEBAR_INACTIVE = 0x808080;
    constexpr uint32_t FILE_EXPLORER_BG  = 0xFFFFFF; // New
    
    // Button colors
    constexpr uint32_t BUTTON_FACE       = 0xC0C0C0;
    constexpr uint32_t BUTTON_HIGHLIGHT  = 0xFFFFFF;
    constexpr uint32_t BUTTON_SHADOW     = 0x808080;
    constexpr uint32_t BUTTON_CLOSE      = 0xFF0000;
    
    // Text colors
    constexpr uint32_t TEXT_BLACK        = 0x000000;
    constexpr uint32_t TEXT_WHITE        = 0xFFFFFF;
    constexpr uint32_t TEXT_GREEN        = 0x00FF00;
    constexpr uint32_t TEXT_GRAY         = 0x808080;
    
    // Cursor color
    constexpr uint32_t CURSOR_WHITE      = 0xFFFFFF;

    // Icon Colors
    constexpr uint32_t ICON_FILE_FILL    = 0xFFF1B5; // Light yellow
    constexpr uint32_t ICON_FILE_OUTLINE = 0x808080;
    constexpr uint32_t ICON_FOLDER_FILL  = 0xFFD3A1; // Light orange
    constexpr uint32_t ICON_SHORTCUT_ARROW = 0x0000FF; // Blue
}

// =============================================================================
// ENHANCED RENDER STATE MACHINE - ELIMINATES TRAILING AND ENSURES CONTINUITY
// =============================================================================

struct RenderState {
    // Frame state tracking
    uint32_t frameNumber;
    bool frameComplete;
    bool backgroundCleared;
    
    // Window rendering state
    int currentWindow;
    int renderPhase;
    
    // Progressive rendering within window
    int currentLine;
    int currentChar;
    int currentScanline;
    
    // Dirty tracking
    bool needsFullRedraw;
    bool windowsDirty;
    
    // Timing
    uint32_t lastFrameTick;
    uint32_t lastInputTick;
};

struct InputState {
    int byteIndex;
    uint8_t pendingBytes[16];
    int pendingCount;
    bool hasNewInput;
};

static RenderState g_render_state = {0, false, false, 0, 0, 0, 0, 0, true, true, 0, 0};
static InputState g_input_state = {0, {0}, 0, false};

// =============================================================================
// ENHANCED GRAPHICS DRIVER
// =============================================================================

inline int gfx_abs(int x) { return x < 0 ? -x : x; }

struct Color {
    uint8_t r, g, b, a;

    uint32_t to_rgb() const {
        return (a << 24) | (r << 16) | (g << 8) | b;
    }

    uint32_t to_bgr() const {
        return (a << 24) | (b << 16) | (g << 8) | r;
    }
};

namespace Colors {
    constexpr Color Black = {0, 0, 0, 255};
    constexpr Color White = {255, 255, 255, 255};
    constexpr Color Red = {255, 0, 0, 255};
    constexpr Color Green = {0, 255, 0, 255};
    constexpr Color Blue = {0, 0, 255, 255};
}

class GraphicsDriver;

class GraphicsDriver {
private:
    bool is_bgr_format;

    inline uint32_t convert_color(const Color& color) const {
        return is_bgr_format ? color.to_bgr() : color.to_rgb();
    }

    // This function converts a standard 0xRRGGBB color into 0xBBGGRR for BGR framebuffers
    inline uint32_t rgb_to_bgr(uint32_t color) const {
        if (!is_bgr_format) return color;

        uint8_t a = (color >> 24) & 0xFF;
        uint8_t r = (color >> 16) & 0xFF;
        uint8_t g = (color >> 8)  & 0xFF;
        uint8_t b = (color >> 0)  & 0xFF;

        return (a << 24) | (b << 16) | (g << 8) | r;
    }

public:
    GraphicsDriver() : is_bgr_format(true) {}

    void init(bool bgr_format = true) {
        is_bgr_format = bgr_format;
    }

    void clear_screen(uint32_t rgb_color) {
        if (!backbuffer || !fb_info.ptr) return;

        uint32_t color = rgb_to_bgr(rgb_color);
        uint32_t pixel_count = fb_info.width * fb_info.height;

        #ifdef __i386__
        uint32_t* target = backbuffer;
        asm volatile(
            "rep stosl"
            : "=D"(target), "=c"(pixel_count)
            : "D"(target), "c"(pixel_count), "a"(color)
            : "memory"
        );
        #else
        for (uint32_t i = 0; i < pixel_count; i++) {
            backbuffer[i] = color;
        }
        #endif
    }

    void clear_screen(const Color& color) {
        clear_screen(convert_color(color));
    }

    void put_pixel(int x, int y, uint32_t rgb_color) {
        if (backbuffer && x >= 0 && x < (int)fb_info.width && y >= 0 && y < (int)fb_info.height) {
            backbuffer[y * fb_info.width + x] = rgb_to_bgr(rgb_color);
        }
    }

    void put_pixel(int x, int y, const Color& color) {
        put_pixel(x, y, convert_color(color));
    }

    void draw_line(int x0, int y0, int x1, int y1, const Color& color) {
        int dx = gfx_abs(x1 - x0);
        int dy = gfx_abs(y1 - y0);
        int sx = x0 < x1 ? 1 : -1;
        int sy = y0 < y1 ? 1 : -1;
        int err = dx - dy;

        while (true) {
            put_pixel(x0, y0, color);

            if (x0 == x1 && y0 == y1) break;

            int e2 = 2 * err;
            if (e2 > -dy) {
                err -= dy;
                x0 += sx;
            }
            if (e2 < dx) {
                err += dx;
                y0 += sy;
            }
        }
    }

    void draw_rect(int x, int y, int w, int h, const Color& color) {
        for (int i = 0; i < w; i++) {
            put_pixel(x + i, y, color);
            put_pixel(x + i, y + h - 1, color);
        }
        for (int i = 0; i < h; i++) {
            put_pixel(x, y + i, color);
            put_pixel(x + w - 1, y + i, color);
        }
    }

    void fill_rect(int x, int y, int w, int h, const Color& color) {
        uint32_t col = convert_color(color);
        for (int dy = 0; dy < h; dy++) {
            for (int dx = 0; dx < w; dx++) {
                put_pixel(x + dx, y + dy, col);
            }
        }
    }
};

static GraphicsDriver g_gfx;

void put_pixel_back(int x, int y, uint32_t color) {
    if (backbuffer && x >= 0 && x < (int)fb_info.width && y >= 0 && y < (int)fb_info.height) {
        backbuffer[y * fb_info.width + x] = color;
    }
}

void draw_char(char c, int x, int y, uint32_t color) {
    if ((unsigned char)c > 127) return;
    const uint8_t* glyph = font + (int)c * 8;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            if ((glyph[i] & (0x80 >> j))) {
                put_pixel_back(x + j, y + i, color);
            }
        }
    }
}

void draw_string(const char* str, int x, int y, uint32_t color) {
    for (int i = 0; str[i]; i++) {
        draw_char(str[i], x + i * 8, y, color);
    }
}

// ─── Host CPU fault handler (called from boot.S isr_common) ────────────
//
// boot.S installs a 256-entry IDT pointing at stubs that all chain to
// isr_common. isr_common writes a VGA-text-mode breadcrumb at row 1 ('!'
// + hex vector) then calls THIS function with the vector number, then
// halts forever. We render the same info onto the live framebuffer so
// the user can see the fault tag even after graphics mode hides VGA
// text. This is a one-shot, no-return diagnostic — we never resume from
// a host fault.
extern "C" volatile unsigned char bx_panic_breadcrumbs[64];

// Pull faulting EIP from the on-stack exception frame. The IDT stub in
// boot.S pushes the standard CPU error frame (err, eip, cs, eflags, ...);
// we read eip via a tiny inline-asm helper that walks back up from the
// current frame. This is best-effort — if frame layout changes, eip just
// reads as 0 and we still get the breadcrumb trail, which is the more
// useful signal anyway.
static inline unsigned read_caller_eip(void) {
    unsigned eip = 0;
    __asm__ volatile(
        "movl 4(%%ebp), %0\n"   // return addr into host_fault_handler == stub
        : "=r"(eip));
    return eip;
}

extern "C" void host_fault_handler(unsigned vector) {
    // Read the faulting EIP up front so we can hand it to the test
    // module too — a #UD/GP inside libcpu.a is only diagnosable if we
    // know WHERE it faulted, not just the vector.
    unsigned caller_eip = read_caller_eip();

    // If a `test` self-test is running, mirror the fault into its
    // window overlay (row 1, "!XX  EIP=...") before the kernel's own
    // rendering, and emit the vector+EIP to the host debug console.
    if (test_module_active()) test_module_fault((int)vector, caller_eip);

    if (!fb_info.ptr) return;

    auto put_glyph = [](char ch, int x0, int y0, uint32_t color, uint32_t bg) {
        if ((unsigned char)ch > 127) ch = '?';
        if (x0 + 8 > (int)fb_info.width)  return;
        if (y0 + 8 > (int)fb_info.height) return;
        const uint8_t* glyph = font + (int)ch * 8;
        for (int yy = 0; yy < 8; ++yy) {
            uint32_t* row = &fb_info.ptr[(y0 + yy) * (fb_info.pitch / 4) + x0];
            uint8_t bits = glyph[yy];
            for (int xx = 0; xx < 8; ++xx) {
                row[xx] = (bits & (0x80 >> xx)) ? color : bg;
            }
        }
    };

    auto hex = [](unsigned n) -> char {
        return (char)((n < 10) ? ('0' + n) : ('A' + (n - 10)));
    };

    // Bright red bar across the top — impossible to miss. Two rows now,
    // so we have room for the EIP + breadcrumb trail.
    int bar_h = 40;
    if (bar_h > (int)fb_info.height) bar_h = (int)fb_info.height;
    for (int y = 0; y < bar_h; ++y) {
        uint32_t* row = &fb_info.ptr[y * (fb_info.pitch / 4)];
        for (uint32_t x = 0; x < fb_info.width; ++x) row[x] = 0xC00000u;
    }

    // Row 1: "HOST FAULT !XX  EIP=XXXXXXXX"
    {
        const char* msg = "HOST FAULT !";
        int x = 8, y = 4;
        for (int i = 0; msg[i]; ++i) {
            put_glyph(msg[i], x, y, 0xFFFFFFu, 0xC00000u); x += 8;
        }
        put_glyph(hex((vector >> 4) & 0xF), x, y, 0xFFFFFFu, 0xC00000u); x += 8;
        put_glyph(hex( vector       & 0xF), x, y, 0xFFFFFFu, 0xC00000u); x += 16;

        const char* eipmsg = "EIP=";
        for (int i = 0; eipmsg[i]; ++i) {
            put_glyph(eipmsg[i], x, y, 0xFFFFFFu, 0xC00000u); x += 8;
        }
        for (int i = 7; i >= 0; --i) {
            put_glyph(hex((caller_eip >> (i * 4)) & 0xF), x, y, 0xFFFFFFu, 0xC00000u);
            x += 8;
        }
    }

    // Row 2: dump bx_panic_breadcrumbs trail (Bochs init progress markers).
    // Last printable char = last successful step inside the Bochs glue
    // before the fault. Empty/zero means fault happened before Bochs init
    // started — the bug is in the kernel↔Bochs call path, not Bochs itself.
    {
        const char* lbl = "BX:";
        int x = 8, y = 20;
        for (int i = 0; lbl[i]; ++i) {
            put_glyph(lbl[i], x, y, 0xFFFFFFu, 0xC00000u); x += 8;
        }
        for (int i = 0; i < 48; ++i) {
            unsigned char c = bx_panic_breadcrumbs[i];
            put_glyph(c ? (char)c : '.', x, y, 0xFFFF00u, 0xC00000u);
            x += 8;
        }
    }

    // Row 2 (right side): mirror x86_tick's VGA breadcrumb row so the user
    // sees both trails on one screen. VGA text at 0xB8000 row 2 cols 0..15.
    {
        int x = 8 + 8 * 4 + 8 * 48 + 16;
        int y = 20;
        const char* lbl = "TK:";
        for (int i = 0; lbl[i]; ++i) {
            put_glyph(lbl[i], x, y, 0xFFFFFFu, 0xC00000u); x += 8;
        }
        volatile unsigned short* vga = (volatile unsigned short*)(0xB8000 + 2 * 80);
        for (int i = 0; i < 16 && x + 8 <= (int)fb_info.width; ++i) {
            unsigned char c = (unsigned char)(vga[i] & 0xFF);
            put_glyph(c ? (char)c : '.', x, y, 0x00FF00u, 0xC00000u);
            x += 8;
        }
    }
}

// ─── Live framebuffer breadcrumb ───────────────────────────────────────────
// Paints a single 8x8 glyph DIRECTLY to the live framebuffer (skipping the
// backbuffer / swap_buffers path) at row 0, col `slot` (each slot 8 pixels
// wide). Designed to be visible even when the kernel main loop hangs, since
// it bypasses the per-frame paint cycle entirely.
//
// Used to localise freezes inside Bochs glue: each interesting step calls
// live_breadcrumb with a different slot+char, so the LAST char visible
// before the hang identifies the last successful step.
//
// Layout convention: slots 0..15 are reserved for bochs_glue diagnostics;
// rendered at fb x=col*8, y=0 with a black background tile.
extern "C" void live_breadcrumb(int slot, char ch) {
    // If a `test` self-test is running, mirror each breadcrumb into its
    // window overlay (row 0, white-on-blue) as well as the framebuffer.
    if (test_module_active()) test_module_breadcrumb(slot, ch);

    if (!fb_info.ptr) return;
    if (slot < 0 || slot >= 80) return;

    int x0 = slot * 8;
    int y0 = 0;
    if (x0 + 8 > (int)fb_info.width)  return;
    if (y0 + 8 > (int)fb_info.height) return;

    if ((unsigned char)ch > 127) ch = '?';
    const uint8_t* glyph = font + (int)ch * 8;

    for (int yy = 0; yy < 8; ++yy) {
        uint32_t* row = &fb_info.ptr[(y0 + yy) * (fb_info.pitch / 4) + x0];
        uint8_t bits = glyph[yy];
        for (int xx = 0; xx < 8; ++xx) {
            row[xx] = (bits & (0x80 >> xx)) ? 0xFFFF00u   /* yellow on */
                                            : 0x000080u;  /* dark blue bg */
        }
    }
}

// ─── Diagnostic overlay: mirror VGA text mode (rows 0 / 1 / 2) onto the
// framebuffer ────────────────────────────────────────────────────────────────
//
// The kernel writes diagnostic breadcrumbs to VGA text memory at 0xB8000:
//   row 0: boot trace ('B','S','Z','C'), heartbeat at col 79, panic tag
//          at col 70 (from bx_recover), Bochs tick markers at col 72/73.
//   row 1: host-IDT fault tag '!XX' (from boot.S isr_common).
//   row 2: x86_tick lazy-init progress (L,M,I,S,E,B,T,t).
//
// Once the framebuffer is initialised these writes are invisible because
// graphics mode hides the VGA text plane. This overlay reads the first
// 80 cells of rows 0/1/2 every frame and draws them as a 24-pixel strip
// across the top of the framebuffer, so any breadcrumb that gets written
// is visible immediately.
extern "C" void draw_vga_overlay() {
    if (!backbuffer || !fb_info.ptr) return;

    // Black backdrop bar (inline to avoid forward-decl on draw_rect_filled).
    {
        int bar_h = 24;     // 3 rows of 8px
        if (bar_h > (int)fb_info.height) bar_h = (int)fb_info.height;
        for (int y = 0; y < bar_h; ++y) {
            uint32_t* row = &backbuffer[y * fb_info.width];
            for (uint32_t x = 0; x < fb_info.width; ++x) row[x] = 0x000000u;
        }
    }

    volatile const uint16_t* vga = (volatile const uint16_t*)0xB8000;

    auto vga_attr_to_rgb = [](uint8_t attr) -> uint32_t {
        uint8_t fg = attr & 0x0F;
        static const uint32_t fg_rgb[16] = {
            0x000000, 0x0000AA, 0x00AA00, 0x00AAAA,
            0xAA0000, 0xAA00AA, 0xAA5500, 0xAAAAAA,
            0x555555, 0x5555FF, 0x55FF55, 0x55FFFF,
            0xFF5555, 0xFF55FF, 0xFFFF55, 0xFFFFFF
        };
        return fg_rgb[fg];
    };

    // Detect emphasised backgrounds (0x4F = white-on-red, used for host
    // IDT and Bochs panic): promote those to bright red.
    auto cell_color = [&](uint16_t cell) -> uint32_t {
        uint8_t attr = (uint8_t)(cell >> 8);
        if ((attr & 0xF0) == 0x40) return 0xFF4040u;
        return vga_attr_to_rgb(attr);
    };

    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 80; ++col) {
            uint16_t cell = vga[row * 80 + col];
            char ch = (char)(cell & 0xFF);
            if (ch == 0) continue;
            int x = col * 8;
            int y = row * 8;
            if (x + 8 > (int)fb_info.width)  break;
            if (y + 8 > (int)fb_info.height) break;
            draw_char(ch, x, y, cell_color(cell));
        }
    }
}

// =============================================================================
// OPTIMIZED FILL RECT - ATOMIC SCANLINE RENDERING
// =============================================================================
void draw_rect_filled(int x, int y, int w, int h, uint32_t color) {
    // Clip to screen bounds
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x >= (int)fb_info.width || y >= (int)fb_info.height) return;
    if (x + w > (int)fb_info.width) w = fb_info.width - x;
    if (y + h > (int)fb_info.height) h = fb_info.height - y;
    if (w <= 0 || h <= 0) return;

    // Render entire rect atomically (no state machine - prevents tearing)
    for (int dy = 0; dy < h; dy++) {
        int screenY = y + dy;
        if (screenY >= 0 && screenY < (int)fb_info.height) {
            uint32_t* row = &backbuffer[screenY * fb_info.width + x];
            
            // Fast fill with rep stosl on x86
            #ifdef __i386__
            uint32_t count = w;
            asm volatile(
                "rep stosl"
                : "=D"(row), "=c"(count)
                : "D"(row), "c"(count), "a"(color)
                : "memory"
            );
            #else
            for (int i = 0; i < w; i++) {
                row[i] = color;
            }
            #endif
        }
    }
}
