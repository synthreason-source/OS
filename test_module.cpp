/* ====================================================================
 * test_module.cpp — activatable Bochs self-test.
 *
 * This is test_main.cpp's verification logic, lifted out of a
 * standalone kernel_main and repackaged behind test_module_run() so the
 * real kernel can fire it on the `test` terminal command.
 *
 * What changed vs. test_main.cpp
 * ------------------------------
 *  - kernel_main(magic, mbi)        ->  test_module_run(sink, out)
 *  - direct writes to VGA @0xB8000  ->  sink->vga_cell(row,col,ch,attr)
 *  - live_breadcrumb / host_fault_handler stay as exported C symbols,
 *    because the Bochs glue (bochs_glue.cpp) and boot.S's ISR stubs
 *    call them by name. They now route through the active sink.
 *  - run_init_array() runs at most ONCE across the program's life
 *    (guarded), since the real kernel already ran the global ctors at
 *    boot — running them twice would re-construct bx_cpu / bx_mem.
 *  - operator new/delete and the C++ ABI/RTTI stubs are NOT redefined
 *    here; the real kernel.cpp already provides them. test_main.cpp
 *    had to define them only because it was the whole kernel.
 *
 * The three-row "VGA overlay" that test_main.cpp painted at 0xB8000 is
 * reproduced faithfully through the sink:
 *
 *     row 0 : boot-trace breadcrumbs   attr 0x1F (white on blue)
 *     row 1 : host-fault tag  "!XX"    attr 0x4F (white on red)
 *     row 2 : "GUEST: <bytes>"         label 0x07, bytes 0x0A (green)
 *
 * The kernel decides how a "VGA cell" is actually drawn.
 * ==================================================================== */
#include "test_module.h"

/* ── Bochs glue (provided by bochs_glue.cpp / bochs_stub.cpp) ──────────── */
extern "C" {
    void     bochs_cpu_init();
    void     bochs_set_process_memory(uint8_t* base, uint32_t size,
                                      uint32_t vaddr_base);
    void     bochs_finalize_process_memory();
    void     bochs_activate_slot(int);
    void     bochs_register_io_callbacks(int,
                 int  (*)(int),
                 void (*)(int, char),
                 void (*)(int, int));
    void     bochs_cpu_set_eip(uint32_t);
    void     bochs_cpu_set_esp(uint32_t);
    int      bochs_cpu_tick(int);
    uint32_t bochs_cpu_get_eip();
    /* Init verdict — bochs_glue.cpp. bochs_init_failed() returns 1 if a
     * Bochs panic was caught during bochs_cpu_init(). The stub build
     * (bochs_stub.cpp) does not provide these, so they are weak: a stub
     * build links with both resolving to the default 0 below. */
    int      bochs_init_ok(void)     __attribute__((weak));
    int      bochs_init_failed(void) __attribute__((weak));
}

/* ── The active sink ────────────────────────────────────────────────────
 * Set by test_module_run() for the duration of a run so the exported
 * live_breadcrumb / host_fault_handler symbols (which the glue and the
 * ISR stubs call by name, with no way to pass a sink) can find it. */
static const TestSink* g_sink = nullptr;

/* ── Port-0xE9 debug console — identical to test_main.cpp ───────────────
 * QEMU `-debugcon stdio` captures this; the real hardware ignores
 * unclaimed port writes, so this is harmless on metal too. */
static inline void e9_putc(char c) {
    __asm__ volatile ("outb %0, %1"
                      : : "a"((uint8_t)c), "Nd"((uint16_t)0xE9));
}
static void e9_puts(const char* s) { while (*s) e9_putc(*s++); }
static void e9_hex(uint32_t v) {
    static const char H[] = "0123456789ABCDEF";
    e9_putc('0'); e9_putc('x');
    for (int i = 7; i >= 0; --i) e9_putc(H[(v >> (i*4)) & 0xF]);
}

/* ── Sink helpers ───────────────────────────────────────────────────── */
static void sink_line(const char* s) {
    if (g_sink && g_sink->put_line) g_sink->put_line(s);
}
static void sink_cell(int row, int col, char ch, uint8_t attr) {
    if (g_sink && g_sink->vga_cell && row >= 0 && col >= 0 && col < 80)
        g_sink->vga_cell(row, col, ch, attr);
}
/* Push the current frame to screen NOW. test_module_run() blocks the
 * kernel main loop, so without an explicit flush nothing the module
 * draws would ever become visible until (if) the run returns. */
static void sink_flush(void) {
    if (g_sink && g_sink->flush) g_sink->flush();
}

/* ── Breadcrumb / fault hooks — driven BY the kernel ────────────────────
 * test_main.cpp owned the `live_breadcrumb` and `host_fault_handler`
 * symbols outright, because it WAS the whole kernel. The real kernel
 * already defines both (the Bochs glue and boot.S's ISR stubs call them
 * by name), so the module must NOT redefine them — that would be a
 * duplicate-symbol link error.
 *
 * Instead the module exposes two hooks. The kernel's existing
 * live_breadcrumb() / host_fault_handler() simply call these while a
 * `test` run is in progress, so the breadcrumb trail and fault tag
 * still land in the window overlay — same rows, same colors as before.
 *
 * test_module_active() lets the kernel cheaply check "is a test running"
 * before forwarding. */
static int g_test_active = 0;

extern "C" int test_module_active(void) { return g_test_active; }

/* row 0, white-on-blue (0x1F) — exactly test_main.cpp's breadcrumb cell */
extern "C" void test_module_breadcrumb(int slot, char ch) {
    if (!g_test_active) return;
    if (slot < 0 || slot >= 80) return;

    sink_cell(/*row=*/0, /*col=*/slot, ch, /*attr=*/0x1F);

    e9_puts("[bc ");
    char nbuf[4] = {0};
    if (slot < 10) { nbuf[0] = (char)('0' + slot); nbuf[1] = 0; }
    else { nbuf[0] = (char)('0' + slot/10);
           nbuf[1] = (char)('0' + slot%10); nbuf[2] = 0; }
    e9_puts(nbuf);
    e9_puts("='");
    e9_putc(ch);
    e9_puts("']\n");

    /* Push to screen now: if the very next glue step hangs, the user
     * still sees the trail up to and including this crumb. */
    sink_flush();
}

/* row 1, "!XX" white-on-red (0x4F) — test_main.cpp's fault tag.
 * Also reports the faulting EIP: a host fault during a `test` run is
 * almost always an invalid-opcode (#UD, vec 6) or GP inside the
 * prebuilt libcpu.a, and the EIP is what lets that exact instruction
 * be located by disassembling the library. */
extern "C" void test_module_fault(int vec, unsigned int eip) {
    if (!g_test_active) return;
    static const char H[] = "0123456789ABCDEF";
    sink_cell(1, 0, '!',                 0x4F);
    sink_cell(1, 1, H[(vec >> 4) & 0xF], 0x4F);
    sink_cell(1, 2, H[ vec       & 0xF], 0x4F);

    /* EIP into row 1, cols 4..13: "EIP=XXXXXXXX" */
    {
        const char* p = "EIP=";
        int c = 4;
        for (int i = 0; p[i]; ++i) sink_cell(1, c++, p[i], 0x4F);
        for (int i = 7; i >= 0; --i)
            sink_cell(1, c++, H[(eip >> (i * 4)) & 0xF], 0x4F);
    }

    e9_puts("[HOST_FAULT vec=");
    e9_hex((uint32_t)vec);
    e9_puts(" eip=");
    e9_hex(eip);
    e9_puts("]\n");

    sink_line("  !! HOST FAULT during test — see fault tag (vec/EIP)\n");
}

/* ── init-array walk — runs AT MOST ONCE ────────────────────────────────
 * The real kernel already ran the file-scope C++ ctors at boot (boot.S
 * walks __init_array between BSS-zero and kernel_main). Running them a
 * second time would re-run bx_cpu(0) / bx_mem constructors. We keep the
 * walk for the standalone-test case but guard it so a second `test`
 * invocation — or a `test` after a normal boot — is a no-op. */
extern "C" void (*__init_array_start[])();
extern "C" void (*__init_array_end[])();

static int g_init_array_done = 0;

static void run_init_array_once() {
    if (g_init_array_done) {
        e9_puts("[init_array already done — skipping]\n");
        return;
    }
    g_init_array_done = 1;

    e9_puts("[init_array begin]\n");
    for (void (**p)() = __init_array_start; p < __init_array_end; ++p) {
        e9_puts("  ctor @ ");
        e9_hex((uint32_t)(uintptr_t)*p);
        e9_puts("\n");
        (*p)();
    }
    e9_puts("[init_array end]\n");
}

/* If the kernel has already constructed its globals at boot, it should
 * call this so the module never re-runs the ctors. (Optional — the
 * guard above also covers a plain double-activation.) */
extern "C" void test_module_mark_ctors_done(void) { g_init_array_done = 1; }

/* ── GUEST row (row 2) — live guest-output line ─────────────────────────
 * Mirrors test_main.cpp's vga_guest_* helpers: a static "GUEST: " label
 * in grey, then the guest's port-0xE9 bytes echoed in bright green. */
#define VGA_GUEST_ROW       2
#define VGA_GUEST_LABEL     "GUEST: "
static const int VGA_GUEST_LABEL_LEN = 7;          /* strlen("GUEST: ") */
static int g_vga_guest_col = VGA_GUEST_LABEL_LEN;

static void vga_guest_init_row() {
    const char* p = VGA_GUEST_LABEL;
    int i = 0;
    for (; p[i]; ++i)                              /* label: grey 0x07 */
        sink_cell(VGA_GUEST_ROW, i, p[i], 0x07);
    for (; i < 80; ++i)                            /* clear remainder  */
        sink_cell(VGA_GUEST_ROW, i, ' ', 0x0F);
    g_vga_guest_col = VGA_GUEST_LABEL_LEN;
}

static void vga_guest_putc(char c) {
    if (c == '\n') { g_vga_guest_col = VGA_GUEST_LABEL_LEN; return; }
    if (g_vga_guest_col >= 80) return;             /* row full — drop  */
    char show = (c >= 32 && c < 127) ? c : '.';
    sink_cell(VGA_GUEST_ROW, g_vga_guest_col, show, 0x0A); /* green */
    g_vga_guest_col++;
}

/* ── Guest I/O callbacks — same behaviour as test_main.cpp ──────────────
 * Bochs invokes these from inside the emulated CPU when the guest does
 * `out 0xE9, al` (write) or `out 0xE8, al` (exit sentinel). */
static volatile int g_guest_output_count = 0;
static volatile int g_guest_exit_seen    = 0;
static volatile int g_guest_exit_code    = 0;
static char         g_guest_output[64];

static int  test_io_read(int /*slot*/) { return 0; }

static void test_io_write(int slot, char c) {
    if (g_guest_output_count < (int)sizeof(g_guest_output) - 1)
        g_guest_output[g_guest_output_count++] = c;

    vga_guest_putc(c);                             /* echo to row 2 */

    e9_puts("  [guest port-0xE9 slot=");
    e9_putc((char)('0' + slot));
    e9_puts(" wrote ");
    if (c >= 32 && c < 127) { e9_putc('\''); e9_putc(c); e9_putc('\''); }
    else                     e9_hex((uint32_t)(uint8_t)c);
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

/* ── The guest program — byte-identical to test_main.cpp ────────────────
 *     B0 32   mov al,'2'      2C 30   sub al,'0'   ; AL = 2
 *     B4 03   mov ah,3        00 E0   add al,ah    ; AL = 5
 *     04 30   add al,'0'      E6 E9   out 0xE9,al  ; emits '5'
 *     B0 0A   mov al,'\n'     E6 E9   out 0xE9,al
 *     B0 00   mov al,0        E6 E8   out 0xE8,al  ; exit sentinel
 *     F4      hlt             EB FE   jmp .        ; safety spin
 * Expected guest output: "5\n", then a clean exit. */
static const uint8_t guest_program[] = {
    0xB0, 0x32,  0x2C, 0x30,
    0xB4, 0x03,  0x00, 0xE0,
    0x04, 0x30,  0xE6, 0xE9,
    0xB0, 0x0A,  0xE6, 0xE9,
    0xB0, 0x00,  0xE6, 0xE8,
    0xF4,        0xEB, 0xFE
};

/* Slot backing slab — same layout constraints as test_main.cpp.
 * GUEST_ENTRY_OFF must clear inject_slab_tables' GDT/IDT region
 * (offsets 0x000..0x900); 0x1000 is the first clean page. The slab is
 * in BSS so it costs nothing on disk and no bump-pool allocation. */
#define SLAB_VADDR_BASE  0x08000000u
#define SLAB_SIZE        (1u * 1024u * 1024u)
#define GUEST_ENTRY_OFF  0x1000u
static uint8_t slab[SLAB_SIZE] __attribute__((aligned(4096)));

/* small helpers so we don't depend on the kernel's snprintf here */
static char* u32_to_hex(uint32_t v, char* buf) {
    static const char H[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 8; ++i) buf[2 + i] = H[(v >> ((7 - i) * 4)) & 0xF];
    buf[10] = 0;
    return buf;
}

/* ── Guest program listing ──────────────────────────────────────────────
 * Show the guest program that Phase 2 is about to load and run, so the
 * user can actually SEE the code under test rather than just its verdict.
 * Two views are emitted: a raw hex dump of guest_program[] and a short
 * human-readable disassembly. Both go to the terminal sink and to the
 * port-0xE9 trace. The disassembly is the static listing already
 * documented in the comment above guest_program[] — the guest is a fixed
 * 23-byte blob, so a hand-written table is exact and needs no decoder. */
static const char* const guest_disasm[] = {
    "  B0 32        mov   al, '2'",
    "  2C 30        sub   al, '0'      ; al = 2",
    "  B4 03        mov   ah, 3",
    "  00 E0        add   al, ah       ; al = 5",
    "  04 30        add   al, '0'      ; al = '5'",
    "  E6 E9        out   0xE9, al     ; emit '5'",
    "  B0 0A        mov   al, 0x0A",
    "  E6 E9        out   0xE9, al     ; emit newline",
    "  B0 00        mov   al, 0",
    "  E6 E8        out   0xE8, al     ; exit sentinel",
    "  F4           hlt",
    "  EB FE        jmp   .            ; safety spin",
};

static void show_guest_program(void) {
    static const char H[] = "0123456789ABCDEF";

    e9_puts("\n[Phase 2] guest program (");
    e9_hex((uint32_t)sizeof(guest_program));
    e9_puts(" bytes):\n");
    sink_line("[Phase 2] guest program listing:\n");

    /* Raw hex dump — up to 16 bytes per line. */
    {
        unsigned i = 0;
        while (i < sizeof(guest_program)) {
            char line[80];
            int k = 0;
            const char* pre = "  hex:";
            for (; pre[k]; ++k) line[k] = pre[k];
            unsigned j = 0;
            for (; j < 16 && (i + j) < sizeof(guest_program); ++j) {
                uint8_t b = guest_program[i + j];
                line[k++] = ' ';
                line[k++] = H[(b >> 4) & 0xF];
                line[k++] = H[b & 0xF];
            }
            line[k++] = '\n'; line[k] = 0;
            sink_line(line);
            e9_puts(line);
            i += j;
        }
    }

    /* Human-readable disassembly. */
    sink_line("  --- disassembly ---\n");
    e9_puts("  --- disassembly ---\n");
    for (unsigned i = 0; i < sizeof(guest_disasm) / sizeof(guest_disasm[0]); ++i) {
        sink_line(guest_disasm[i]);
        sink_line("\n");
        e9_puts(guest_disasm[i]);
        e9_putc('\n');
    }
    sink_line("  expected guest output: \"5\\n\"\n");
    e9_puts("  expected guest output: \"5\\n\"\n");
}

/* ── test_module_run — the activation entry point ───────────────────────
 * This is the "test execution code" the kernel copies in and activates.
 * It performs the same two-phase verification test_main.cpp did. */
extern "C" void test_module_run(const TestSink* sink, TestResult* out) {
    g_sink        = sink;
    g_test_active = 1;          /* breadcrumb/fault hooks now forward */

    /* reset per-run state (the module may be activated more than once) */
    g_guest_output_count = 0;
    g_guest_exit_seen    = 0;
    g_guest_exit_code    = 0;
    for (unsigned i = 0; i < sizeof(g_guest_output); ++i)
        g_guest_output[i] = 0;

    /* Clear overlay rows 0/1 so stale cells from a prior run/boot don't
     * mislead — exactly what test_main.cpp's kernel_main did first. */
    for (int i = 0; i < 80; ++i) sink_cell(0, i, ' ', 0x0F);
    for (int i = 0; i < 80; ++i) sink_cell(1, i, ' ', 0x0F);
    vga_guest_init_row();

    e9_puts("\n=== test_module: BX_CPU(0)->initialize() + cpu_tick ===\n");
    sink_line("=== Bochs self-test (activated by `test`) ===\n");

    /* Show the guest program up front, BEFORE Phase 1. The guest is a
     * fixed constant blob that does not depend on anything Phase 1 does,
     * so listing it here means `test` always displays the code under
     * test — even if bochs_cpu_init() below hangs or panics and the run
     * never reaches Phase 2. */
    show_guest_program();
    sink_flush();

    run_init_array_once();

    /* ── Phase 1: global Bochs init ──────────────────────────────── */
    e9_puts("\n[Phase 1] calling bochs_cpu_init()...\n");
    sink_line("[Phase 1] bochs_cpu_init()...\n");
    sink_flush();                       /* show "Phase 1" BEFORE we block */
    bochs_cpu_init();                   /* <-- long blocking call         */

    /* Check the verdict. With the panic-recovery path in bochs_glue.cpp,
     * a Bochs internal panic during initialize()/reset() no longer hangs
     * — it unwinds and sets the failed flag. Detect that here so the
     * test reports a clean FAIL instead of marching into Phase 2 with a
     * half-initialised CPU. The &fn check guards the stub build, where
     * these weak symbols are absent. */
    int init_failed = 0;
    if (&bochs_init_failed) init_failed = bochs_init_failed();

    if (init_failed) {
        e9_puts("[Phase 1] bochs_cpu_init() PANICKED — init aborted.\n");
        sink_line("[Phase 1] FAIL - Bochs panic during init "
                  "(see fault tag / breadcrumb 52='P').\n");
        sink_flush();
        if (out) {
            out->phase1_ok       = 0;
            out->phase2_ticked   = 0;
            out->guest_exit_seen = 0;
            out->guest_out_len   = 0;
            out->guest_out[0]    = 0;
        }
        sink_line("=== self-test FAILED (Phase 1) ===\n");
        sink_flush();
        g_test_active = 0;
        g_sink        = nullptr;
        return;                          /* do not attempt Phase 2 */
    }

    e9_puts("[Phase 1] bochs_cpu_init() RETURNED.\n");
    sink_line("[Phase 1] OK - initialize() returned.\n");
    sink_flush();

    /* test_main.cpp tagged VGA[50] with a green '*' on success. */
    sink_cell(0, 50, '*', 0x2F);
    if (out) out->phase1_ok = 1;

    /* ── Phase 2: load a tiny guest and tick it ──────────────────── */
    e9_puts("\n[Phase 2] loading guest program into slot 0...\n");
    sink_line("[Phase 2] loading 23-byte guest into slot 0...\n");

    bochs_register_io_callbacks(0, test_io_read, test_io_write,
                                test_io_exit);
    bochs_activate_slot(0);
    bochs_set_process_memory(slab, SLAB_SIZE, SLAB_VADDR_BASE);

    /* Write guest code AFTER set_process_memory so the table injection
     * (stub/GDT/IDT, all below offset 0x900) cannot overwrite it. */
    for (unsigned i = 0; i < sizeof(guest_program); ++i)
        slab[GUEST_ENTRY_OFF + i] = guest_program[i];

    /* (The guest program listing was already shown before Phase 1.) */

    bochs_cpu_set_eip(SLAB_VADDR_BASE + GUEST_ENTRY_OFF);
    bochs_cpu_set_esp(SLAB_VADDR_BASE + SLAB_SIZE - 16);

    {
        char hb[12], msg[48];
        u32_to_hex(SLAB_VADDR_BASE + GUEST_ENTRY_OFF, hb);
        const char* pre = "  guest entry vaddr = ";
        int k = 0;
        for (; pre[k]; ++k) msg[k] = pre[k];
        for (int j = 0; hb[j]; ++j) msg[k++] = hb[j];
        msg[k++] = '\n'; msg[k] = 0;
        sink_line(msg);
    }
    e9_puts("  EIP set to ");
    e9_hex(bochs_cpu_get_eip());
    e9_puts(", ticking...\n");
    sink_line("[Phase 2] ticking guest...\n");
    sink_flush();                       /* show Phase 2 state before tick */

    /* Tick until the guest hits its port-0xE8 exit sentinel, capped at
     * 32 iterations so a misbehaving guest cannot wedge the kernel. */
    int total_ticks = 0;
    for (int iter = 0; iter < 32 && !g_guest_exit_seen; ++iter) {
        e9_puts("  tick iter ");
        e9_hex((uint32_t)iter);
        e9_puts(" eip-before=");
        e9_hex(bochs_cpu_get_eip());
        e9_puts("\n");
        bochs_cpu_tick(1);              /* <-- can block / fault          */
        total_ticks++;
        sink_flush();                   /* GUEST row updates per tick     */
        if (g_guest_exit_seen) break;
    }

    /* ── Results ──────────────────────────────────────────────────── */
    e9_puts("\n[Phase 2] results:\n  ticks=");
    e9_hex((uint32_t)total_ticks);
    e9_puts(" out='");
    for (int i = 0; i < g_guest_output_count; ++i) {
        char c = g_guest_output[i];
        if (c >= 32 && c < 127) e9_putc(c);
        else { e9_putc('\\'); e9_hex((uint32_t)(uint8_t)c); }
    }
    e9_puts("' exit=");
    e9_hex((uint32_t)g_guest_exit_seen);
    e9_puts("\n");

    /* one summary line into the window */
    {
        char msg[96];
        const char* pre = "[Phase 2] ticks=";
        int k = 0;
        for (; pre[k]; ++k) msg[k] = pre[k];
        /* ticks (single digit is enough, capped at 32) */
        if (total_ticks >= 10) { msg[k++] = (char)('0' + total_ticks/10);
                                 msg[k++] = (char)('0' + total_ticks%10); }
        else                     msg[k++] = (char)('0' + total_ticks);
        const char* mid = " guest=\"";
        for (int j = 0; mid[j]; ++j) msg[k++] = mid[j];
        for (int i = 0; i < g_guest_output_count && k < 80; ++i) {
            char c = g_guest_output[i];
            msg[k++] = (c >= 32 && c < 127) ? c : '.';
        }
        const char* tail = g_guest_exit_seen ? "\" exit=OK\n"
                                             : "\" exit=MISS\n";
        for (int j = 0; tail[j]; ++j) msg[k++] = tail[j];
        msg[k] = 0;
        sink_line(msg);
    }

    sink_line(g_guest_exit_seen
                ? "=== self-test PASSED ===\n"
                : "=== self-test INCOMPLETE (no guest exit) ===\n");
    sink_flush();

    /* fill the caller's result struct */
    if (out) {
        out->phase2_ticked   = total_ticks;
        out->guest_exit_seen = g_guest_exit_seen;
        out->guest_exit_code = g_guest_exit_code;
        out->guest_out_len   = g_guest_output_count;
        int n = g_guest_output_count;
        if (n > (int)sizeof(out->guest_out) - 1)
            n = (int)sizeof(out->guest_out) - 1;
        for (int i = 0; i < n; ++i) out->guest_out[i] = g_guest_output[i];
        out->guest_out[n] = 0;
    }

    /* unlike test_main.cpp we do NOT halt — control returns to the
     * kernel so the terminal stays usable. */
    g_test_active = 0;
    g_sink        = nullptr;
}
