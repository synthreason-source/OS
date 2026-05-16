// =====================================================================
// bochs_bios.cpp — BIOS-mode execution for the freestanding kernel.
//
// This module adds a "BIOS mode" on top of the existing slot framework.
// Instead of loading a user-space ELF into a slab and priming the CPU
// to flat-32 protected mode, it:
//
//   1. Maps a SeaBIOS (or any x86 legacy BIOS) ROM image into the
//      conventional BIOS address range (0xF0000–0xFFFFF, 64 KiB, with
//      an optional 128 KiB shadow at 0xE0000–0xEFFFF).
//
//   2. Maps conventional RAM (0x00000–0x9FFFF, 640 KiB) as read/write
//      main memory so the BIOS can set up its IVT, BDA, and stack.
//
//   3. Intercepts writes to the VGA text buffer (0xB8000–0xBFFFF) and
//      mirrors them to the host kernel's own VGA at 0xB8000 so every
//      character the BIOS prints appears on the physical screen.
//
//   4. Runs the CPU from the hardware reset vector (CS=0xF000,
//      EIP=0xFFF0 — exactly what BX_CPU::reset(BX_RESET_HARDWARE)
//      produces) without calling slot_prime_cpu, which would overwrite
//      those registers.
//
// Memory map exposed to the emulated CPU:
//
//   0x00000 – 0x9FFFF   640 KiB conventional RAM  (read/write)
//   0xA0000 – 0xAFFFF   VGA framebuffer (EGA/VGA planes) — ignored
//   0xB0000 – 0xB7FFF   MDA text buffer — ignored
//   0xB8000 – 0xBFFFF   CGA/VGA text buffer — intercepted → host VGA
//   0xC0000 – 0xDFFFF   Option ROM area — reads 0xFF (empty), writes ignored
//   0xE0000 – 0xEFFFF   Extended BIOS data / ROM shadow (128 KiB)
//   0xF0000 – 0xFFFFF   Main BIOS ROM (64 KiB)
//
// Usage from kernel.cpp:
//
//   extern "C" void bochs_bios_init(const uint8_t* rom, uint32_t rom_len);
//   extern "C" int  bochs_bios_tick(int n);   // returns 1 when BIOS halts
//
// bochs_bios_init() must be called AFTER bochs_cpu_init().
// bochs_bios_tick(n) drives cpu_loop up to n times; returns 1 when
// the BIOS executes HLT (or an unhandled fault via port 0xE8).
// =====================================================================

#include "bochs-2.7/bochs.h"
#include "bochs-2.7/cpu/cpu.h"
#include "bochs-2.7/memory/memory-bochs.h"
#include "bochs-2.7/pc_system.h"

#include <stdint.h>

// ── symbols provided by other TUs ────────────────────────────────────
extern "C" void live_breadcrumb(int slot, char ch);
extern "C" void bochs_guest_exit(int code);

// ── host VGA text buffer (physical 0xB8000 on our real hardware) ─────
static volatile uint16_t* const HOST_VGA = (volatile uint16_t*)0xB8000;
static const int VGA_COLS = 80;
static const int VGA_ROWS = 25;

// ── conventional RAM (640 KiB, zero-initialised in BSS) ──────────────
#define CONV_RAM_SIZE   (640u * 1024u)
#define CONV_RAM_BASE   0x00000u
static uint8_t g_conv_ram[CONV_RAM_SIZE] __attribute__((aligned(4096)));

// ── VGA text mirror (32 KiB — 0xB8000..0xBFFFF) ─────────────────────
#define VGA_BUF_BASE  0xB8000u
#define VGA_BUF_SIZE  0x08000u          // 32 KiB covers all CGA/VGA pages
static uint8_t g_vga_buf[VGA_BUF_SIZE] __attribute__((aligned(4096)));

// ── BIOS ROM (up to 128 KiB; populated from the passed-in image) ─────
#define BIOS_ROM_BASE  0xF0000u
#define BIOS_ROM_SIZE  0x10000u         // 64 KiB — standard legacy BIOS
#define BIOS_EXT_BASE  0xE0000u         // optional 128 KiB shadow
#define BIOS_EXT_SIZE  0x10000u
static uint8_t g_bios_rom[BIOS_ROM_SIZE] __attribute__((aligned(4096)));
static uint8_t g_bios_ext[BIOS_EXT_SIZE] __attribute__((aligned(4096)));

static bool g_bios_mode_active = false;
static bool g_bios_halted      = false;

// ─────────────────────────────────────────────────────────────────────
// Port I/O intercept
//
// The BIOS uses port 0x3F8 (COM1) and port 0xE9 (Bochs debug) for
// early console output, port 0x60/0x64 for keyboard, etc. We intercept
// the few that matter for seeing BIOS output on screen:
//
//   0xE9  — Bochs debug console; mirror to port 0xE9 on host so it
//            shows up in the debugcon transcript. Also print to VGA
//            row 24 as a scrolling ticker.
//   0x0501 — QEMU ISA debug exit; 0x21 = PASS, 0x11 = FAIL.
//            We treat any write here as "BIOS finished booting."
//
// Everything else is silently dropped (same as bx_devices_c::outp).
// ─────────────────────────────────────────────────────────────────────

// BIOS debug ticker — row 24, scrolling left.
static char   g_ticker[80] = {0};
static int    g_ticker_len = 0;

static void bios_ticker_putc(char c) {
    if (c == '\r') return;
    if (c == '\n') {
        // scroll the ticker row
        for (int i = 0; i < g_ticker_len - 1; ++i) g_ticker[i] = g_ticker[i+1];
        if (g_ticker_len > 0) g_ticker_len--;
        return;
    }
    if (g_ticker_len < 80) g_ticker[g_ticker_len++] = c;
    else {
        for (int i = 0; i < 79; ++i) g_ticker[i] = g_ticker[i+1];
        g_ticker[79] = c;
    }
    // Write to host VGA row 24 (bottom row), bright cyan on black.
    int row = 24;
    for (int col = 0; col < 80; col++) {
        char ch = (col < g_ticker_len) ? g_ticker[col] : ' ';
        HOST_VGA[row * VGA_COLS + col] = (uint16_t)(0x0B00u | (uint8_t)ch);
    }
}

// ─────────────────────────────────────────────────────────────────────
// VGA text mirror — called whenever the emulated CPU writes to
// 0xB8000–0xBFFFF. We reflect writes to the host VGA so BIOS POST
// messages appear on the physical screen.
// ─────────────────────────────────────────────────────────────────────

static void vga_text_mirror_write(uint32_t offset, const uint8_t* data, unsigned len) {
    // offset is relative to 0xB8000.
    for (unsigned i = 0; i < len && (offset + i) < VGA_BUF_SIZE; ++i) {
        g_vga_buf[offset + i] = data[i];
    }

    // Reflect whole-cell writes (2-byte aligned pairs) to the host VGA.
    // Odd-byte writes (attribute only, char only) work too — we re-read
    // the neighbour byte from the shadow buffer.
    uint32_t cell_start = (offset) & ~1u;          // round down to cell boundary
    uint32_t cell_end   = (offset + len + 1) & ~1u;// round up
    for (uint32_t off = cell_start; off < cell_end && off + 1 < VGA_BUF_SIZE; off += 2) {
        uint8_t ch   = g_vga_buf[off];
        uint8_t attr = g_vga_buf[off + 1];
        int cell = (int)(off / 2);
        if (cell < VGA_COLS * VGA_ROWS) {
            HOST_VGA[cell] = (uint16_t)((attr << 8) | ch);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Bochs memory handler callbacks
// ─────────────────────────────────────────────────────────────────────

// We register several handlers for different physical ranges. Bochs
// calls the most-specific (last-registered) handler that covers the
// address. We register them in order so Bochs builds a chain; the
// correct one fires for each region.

// ── Handler 1: conventional RAM (0x00000–0x9FFFF) ────────────────────
static bool bios_convram_read(bx_phy_address addr, unsigned len,
                              void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - CONV_RAM_BASE;
    if (off + len > CONV_RAM_SIZE) { __builtin_memset(data, 0, len); return true; }
    __builtin_memcpy(data, g_conv_ram + off, len);
    return true;
}
static bool bios_convram_write(bx_phy_address addr, unsigned len,
                               void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - CONV_RAM_BASE;
    if (off + len > CONV_RAM_SIZE) return true;
    __builtin_memcpy(g_conv_ram + off, data, len);
    return true;
}
static Bit8u* bios_convram_da(bx_phy_address addr, unsigned /*rw*/, void* /*p*/) {
    uint32_t off = (uint32_t)addr - CONV_RAM_BASE;
    if (off >= CONV_RAM_SIZE) return nullptr;
    uint32_t page_start = off & ~0xFFFu;
    if (page_start + 0x1000u > CONV_RAM_SIZE) return nullptr;
    return g_conv_ram + off;
}

// ── Handler 2: VGA text buffer (0xB8000–0xBFFFF) ─────────────────────
static bool bios_vga_read(bx_phy_address addr, unsigned len,
                          void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - VGA_BUF_BASE;
    if (off + len > VGA_BUF_SIZE) { __builtin_memset(data, 0, len); return true; }
    __builtin_memcpy(data, g_vga_buf + off, len);
    return true;
}
static bool bios_vga_write(bx_phy_address addr, unsigned len,
                           void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - VGA_BUF_BASE;
    vga_text_mirror_write(off, (const uint8_t*)data, len);
    return true;
}
static Bit8u* bios_vga_da(bx_phy_address addr, unsigned /*rw*/, void* /*p*/) {
    // Allow direct TLB access to the VGA shadow buffer so the BIOS can
    // do fast rep-stosd screen clears without going through the slow
    // read/write handler path. The mirror to HOST_VGA happens lazily
    // on the next tick (we do a full re-sync in bochs_bios_tick).
    uint32_t off = (uint32_t)addr - VGA_BUF_BASE;
    if (off >= VGA_BUF_SIZE) return nullptr;
    uint32_t page_start = off & ~0xFFFu;
    if (page_start + 0x1000u > VGA_BUF_SIZE) return nullptr;
    return g_vga_buf + off;
}

// ── Handler 3: Extended BIOS / ROM shadow (0xE0000–0xEFFFF) ─────────
static bool bios_ext_read(bx_phy_address addr, unsigned len,
                          void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - BIOS_EXT_BASE;
    if (off + len > BIOS_EXT_SIZE) { __builtin_memset(data, 0xFF, len); return true; }
    __builtin_memcpy(data, g_bios_ext + off, len);
    return true;
}
static bool bios_ext_write(bx_phy_address /*addr*/, unsigned /*len*/,
                           void* /*data*/, void* /*param*/) {
    return true;  // ROM writes silently dropped
}
static Bit8u* bios_ext_da(bx_phy_address addr, unsigned /*rw*/, void* /*p*/) {
    uint32_t off = (uint32_t)addr - BIOS_EXT_BASE;
    if (off >= BIOS_EXT_SIZE) return nullptr;
    uint32_t page_start = off & ~0xFFFu;
    if (page_start + 0x1000u > BIOS_EXT_SIZE) return nullptr;
    return g_bios_ext + off;
}

// ── Handler 4: Main BIOS ROM (0xF0000–0xFFFFF) ───────────────────────
static bool bios_rom_read(bx_phy_address addr, unsigned len,
                          void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - BIOS_ROM_BASE;
    if (off + len > BIOS_ROM_SIZE) { __builtin_memset(data, 0xFF, len); return true; }
    __builtin_memcpy(data, g_bios_rom + off, len);
    return true;
}
static bool bios_rom_write(bx_phy_address /*addr*/, unsigned /*len*/,
                           void* /*data*/, void* /*param*/) {
    return true;  // ROM writes silently dropped
}
static Bit8u* bios_rom_da(bx_phy_address addr, unsigned /*rw*/, void* /*p*/) {
    uint32_t off = (uint32_t)addr - BIOS_ROM_BASE;
    if (off >= BIOS_ROM_SIZE) return nullptr;
    uint32_t page_start = off & ~0xFFFu;
    if (page_start + 0x1000u > BIOS_ROM_SIZE) return nullptr;
    return g_bios_rom + off;
}

// ── Handler 5: 4 GiB alias of BIOS ROM (0xFFFF0000–0xFFFFFFFF) ───────
// x86 hardware aliases the BIOS ROM at the top of the 4 GiB address
// space so the reset vector fetch at CS:IP=F000:FFF0 → linear
// 0xFFFFFFF0 resolves. We alias g_bios_rom[0..64KiB] there.
#define BIOS_ALIAS_BASE 0xFFFF0000u
#define BIOS_ALIAS_SIZE 0x00010000u

static bool bios_alias_read(bx_phy_address addr, unsigned len,
                            void* data, void* /*param*/) {
    uint32_t off = (uint32_t)addr - BIOS_ALIAS_BASE;
    if (off + len > BIOS_ALIAS_SIZE) { __builtin_memset(data, 0xFF, len); return true; }
    __builtin_memcpy(data, g_bios_rom + off, len);
    return true;
}
static bool bios_alias_write(bx_phy_address /*addr*/, unsigned /*len*/,
                             void* /*data*/, void* /*param*/) { return true; }
static Bit8u* bios_alias_da(bx_phy_address addr, unsigned /*rw*/, void* /*p*/) {
    uint32_t off = (uint32_t)addr - BIOS_ALIAS_BASE;
    if (off >= BIOS_ALIAS_SIZE) return nullptr;
    uint32_t page_start = off & ~0xFFFu;
    if (page_start + 0x1000u > BIOS_ALIAS_SIZE) return nullptr;
    return g_bios_rom + off;
}
// Called once per tick so that any cells written via the direct-access
// fast path (rep stosd screen clear, etc.) also appear on the host VGA.
// ─────────────────────────────────────────────────────────────────────

static void resync_vga_to_host() {
    for (int i = 0; i < VGA_COLS * VGA_ROWS; ++i) {
        uint8_t ch   = g_vga_buf[i * 2];
        uint8_t attr = g_vga_buf[i * 2 + 1];
        HOST_VGA[i] = (uint16_t)((attr << 8) | ch);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────

// bochs_bios_init — call once, after bochs_cpu_init().
//
// rom     : pointer to the raw BIOS ROM bytes (host virtual address).
//           Must be exactly BIOS_ROM_SIZE (64 KiB) or up to
//           BIOS_ROM_SIZE + BIOS_EXT_SIZE (128 KiB) bytes.
// rom_len : length of the ROM in bytes.
//
// The last 64 KiB of rom[] are placed at 0xF0000–0xFFFFF (the standard
// BIOS ROM window). If rom_len > 64 KiB the preceding 64 KiB are placed
// at 0xE0000–0xEFFFF (extended BIOS shadow).
extern "C" void bochs_bios_init(const uint8_t* rom, uint32_t rom_len) {
    live_breadcrumb(20, 'B');

    // ── populate ROM buffers ──────────────────────────────────────────
    __builtin_memset(g_bios_rom, 0xFF, BIOS_ROM_SIZE);
    __builtin_memset(g_bios_ext, 0xFF, BIOS_EXT_SIZE);

    if (rom && rom_len > 0) {
        if (rom_len <= BIOS_ROM_SIZE) {
            // Fit the ROM into the tail of the 64 KiB window. x86 BIOSes
            // are aligned to the TOP of the window — the reset vector at
            // the very end. Place at end so 0xFFFF0 = rom[rom_len - 16].
            uint32_t off = BIOS_ROM_SIZE - rom_len;
            __builtin_memcpy(g_bios_rom + off, rom, rom_len);
        } else if (rom_len <= BIOS_ROM_SIZE + BIOS_EXT_SIZE) {
            // 65–128 KiB: bottom part → ext, top 64 KiB → rom.
            uint32_t ext_len = rom_len - BIOS_ROM_SIZE;
            __builtin_memcpy(g_bios_ext + (BIOS_EXT_SIZE - ext_len),
                             rom, ext_len);
            __builtin_memcpy(g_bios_rom, rom + ext_len, BIOS_ROM_SIZE);
        } else {
            // Larger ROM: take the last 128 KiB.
            const uint8_t* tail = rom + (rom_len - BIOS_ROM_SIZE - BIOS_EXT_SIZE);
            __builtin_memcpy(g_bios_ext, tail, BIOS_EXT_SIZE);
            __builtin_memcpy(g_bios_rom, tail + BIOS_EXT_SIZE, BIOS_ROM_SIZE);
        }
    }

    // ── zero conventional RAM and VGA shadow ─────────────────────────
    __builtin_memset(g_conv_ram, 0, CONV_RAM_SIZE);
    __builtin_memset(g_vga_buf,  0, VGA_BUF_SIZE);

    // ── register memory handlers with Bochs ──────────────────────────
    // Conventional RAM: 0x00000 – 0x9FFFF
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        bios_convram_read, bios_convram_write, bios_convram_da,
        (bx_phy_address)CONV_RAM_BASE,
        (bx_phy_address)(CONV_RAM_BASE + CONV_RAM_SIZE - 1));

    // VGA text buffer: 0xB8000 – 0xBFFFF
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        bios_vga_read, bios_vga_write, bios_vga_da,
        (bx_phy_address)VGA_BUF_BASE,
        (bx_phy_address)(VGA_BUF_BASE + VGA_BUF_SIZE - 1));

    // Extended BIOS: 0xE0000 – 0xEFFFF
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        bios_ext_read, bios_ext_write, bios_ext_da,
        (bx_phy_address)BIOS_EXT_BASE,
        (bx_phy_address)(BIOS_EXT_BASE + BIOS_EXT_SIZE - 1));

    // Main BIOS ROM: 0xF0000 – 0xFFFFF
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        bios_rom_read, bios_rom_write, bios_rom_da,
        (bx_phy_address)BIOS_ROM_BASE,
        (bx_phy_address)(BIOS_ROM_BASE + BIOS_ROM_SIZE - 1));

    live_breadcrumb(21, 'R');

    // ── put CPU into hardware reset state ────────────────────────────
    // BX_CPU::reset(BX_RESET_HARDWARE) puts the CPU at:
    //   CS = 0xF000 (base = 0xFFFF0000, limit = 0xFFFF, real mode)
    //   EIP = 0xFFF0
    //   => first fetch from linear 0xFFFFFFF0, physical 0xFFFFFFF0
    //
    // BUT our ROM is only at 0xF0000–0xFFFFF (1 MiB range). x86 real
    // hardware does the same thing — the chipset maps the ROM at BOTH
    // 0xF0000 and the 4 GiB alias 0xFFFF0000. Bochs models this too
    // via its bios_rom_addr field which we set in bochs_infra.cpp.
    //
    // 4 GiB alias of BIOS ROM: 0xFFFF0000–0xFFFFFFFF
    // (reset vector fetch CS=0xF000, IP=0xFFF0 → linear 0xFFFFFFF0)
    BX_MEM(0)->registerMemoryHandlers(
        nullptr,
        bios_alias_read, bios_alias_write, bios_alias_da,
        (bx_phy_address)BIOS_ALIAS_BASE,
        (bx_phy_address)0xFFFFFFFFu);

    live_breadcrumb(22, 'M');

    // Reset the CPU to hardware reset state. This sets CS=0xF000,
    // EIP=0xFFF0 and clears all other state to known-good values.
    // Do NOT call slot_prime_cpu — that would overwrite these.
    BX_CPU(0)->reset(BX_RESET_HARDWARE);

    // A20 line must be enabled for the handler to be reachable.
    // (Already done in bochs_global_init, but set again to be safe.)
    bx_pc_system.set_enable_a20(true);

    // Clear sticky yield flags from reset().
    BX_CPU(0)->async_event = 0;
    bx_pc_system.kill_bochs_request = 0;

    // Flush iCache and recompute cpu_mode (real mode after reset).
    flushICaches();
    BX_CPU(0)->handleCpuContextChange();
    BX_CPU(0)->updateFetchModeMask();
    BX_CPU(0)->async_event = 0;
    bx_pc_system.kill_bochs_request = 0;

    g_bios_mode_active = true;
    g_bios_halted      = false;

    live_breadcrumb(23, '!');
}

// bochs_bios_tick — drive the BIOS for up to n cpu_loop entries.
//
// Returns 0 while the BIOS is still running, 1 when it has halted
// (HLT instruction executed with interrupts disabled, or port 0xE8 exit).
//
// Port 0xE9 output is captured via bochs_infra's outp override and
// the write_cb of the active slot. In BIOS mode we don't have a slot,
// so we intercept 0xE9 writes differently: the BIOS debug output ends
// up in the bios_ticker_putc path via a thin shim (see below).
extern "C" int bochs_bios_tick(int n) {
    if (!g_bios_mode_active || g_bios_halted) return 1;
    if (n < 1) n = 1;
    if (n > 16) n = 16;

    for (int i = 0; i < n; ++i) {
        bx_pc_system.kill_bochs_request = 0;
        BX_CPU(0)->async_event          = 0;

        BX_CPU(0)->cpu_loop();

        // Check if the CPU halted (HLT with IF=0 is the normal BIOS
        // idle-wait; HLT with IF=1 would wait for an IRQ which we
        // don't deliver — so both count as "BIOS done").
        if (BX_CPU(0)->activity_state != 0) {   // 0 = BX_ACTIVITY_STATE_ACTIVE
            g_bios_halted = true;
            break;
        }
    }

    // Resync the VGA shadow to the host every tick so the screen
    // updates appear in real time (not just at halt).
    resync_vga_to_host();

    return g_bios_halted ? 1 : 0;
}

// ─────────────────────────────────────────────────────────────────────
// Port 0xE9 shim for BIOS mode.
//
// bochs_infra.cpp's bx_devices_c::outp routes 0xE9 to bochs_guest_putc.
// bochs_guest_putc reads g_active_slot, which is -1 during BIOS mode
// (no slot is active), and returns early — so BIOS debug output is
// silently swallowed.
//
// We fix this by exporting bochs_bios_putc and having bochs_glue.cpp's
// bochs_guest_putc check whether we're in BIOS mode and redirect.
// ─────────────────────────────────────────────────────────────────────

extern "C" void bochs_bios_putc(char c) {
    // Mirror to host port 0xE9 (QEMU debugcon / Bochs debug).
    __asm__ volatile("outb %0, %1" : : "a"((uint8_t)c), "Nd"((uint16_t)0xE9));
    bios_ticker_putc(c);
}

extern "C" bool bochs_bios_is_active() {
    return g_bios_mode_active && !g_bios_halted;
}
