/* ====================================================================
 * test_module.h — activatable Bochs self-test module.
 *
 * This is the "module for activation" half of the request: the test
 * execution code from test_main.cpp, lifted out of a standalone
 * kernel_main and repackaged as a single entry point the real kernel
 * can call on demand.
 *
 * Activation:
 *   The kernel's terminal command handler calls test_module_run() when
 *   the user types  test.  Everything the old test_main.cpp did at boot
 *   (run __init_array, Phase 1 bochs_cpu_init(), Phase 2 load a tiny
 *   guest + tick it) now happens inside that one call instead.
 *
 * Output target:
 *   test_main.cpp wrote its breadcrumb / fault-tag / GUEST rows to the
 *   hardware VGA text buffer at 0xB8000. The real kernel has no text
 *   mode — it is a framebuffer GUI. So this module renders the SAME
 *   three-row VGA-style overlay (breadcrumbs, fault tag, live GUEST
 *   line) into a TerminalWindow via a tiny sink interface, plus mirrors
 *   everything to port 0xE9 exactly as before.
 *
 * The module owns NO kernel headers — it talks to the kernel only
 * through TestSink below, so it stays a clean, separately compiled TU.
 * ==================================================================== */
#pragma once
#include <stdint.h>

/* ── Sink: how the module talks back to the kernel ──────────────────────
 * The kernel supplies one of these. The module never touches a Window,
 * a framebuffer, or 0xB8000 directly; it only calls these hooks. That
 * keeps the module activatable from anywhere (terminal command, desktop
 * icon, boot self-test) without a compile-time dependency on the GUI.
 *
 *   put_line(s)        — append a finished line of plain text.
 *   vga_cell(row,col,
 *            ch,attr)  — set one "VGA text cell". row 0..2, col 0..79.
 *                        attr is a classic VGA attribute byte
 *                        (bg<<4 | fg). The kernel maps it to whatever
 *                        it actually draws (window glyph, real text
 *                        cell, etc).
 *   flush()            — push the current frame to screen NOW. Critical:
 *                        test_module_run() blocks the kernel main loop
 *                        for the whole duration of a run, so the normal
 *                        per-frame swap_buffers() never gets to fire.
 *                        Without flush() the window would just freeze
 *                        on the pre-test frame and show nothing — even
 *                        though the overlay cells were written. The
 *                        module calls flush() after each breadcrumb and
 *                        before each long blocking call (bochs_cpu_init,
 *                        bochs_cpu_tick) so the trail is visible live,
 *                        and the screen still shows how far it got even
 *                        if a step hangs.
 *
 * Any hook may be null; the module checks before calling.
 */
struct TestSink {
    void (*put_line)(const char* s);
    void (*vga_cell)(int row, int col, char ch, uint8_t attr);
    void (*flush)(void);
};

/* Result of a run — lets the activating command print a one-line
 * summary and/or branch on success. */
struct TestResult {
    int  phase1_ok;        /* bochs_cpu_init() returned                 */
    int  phase2_ticked;    /* number of tick iterations executed        */
    int  guest_exit_seen;  /* guest hit the port-0xE8 exit sentinel     */
    int  guest_exit_code;  /* exit code reported by the guest           */
    int  guest_out_len;    /* bytes the guest emitted on port 0xE9      */
    char guest_out[64];    /* the guest output bytes (NUL-terminated)   */
};

#ifdef __cplusplus
extern "C" {
#endif

/* Activate the test. Runs init-array (once), Phase 1 and Phase 2.
 * `sink` may be null (then only the port-0xE9 trace is produced).
 * `out` may be null. Returns out->phase1_ok via the struct. */
void test_module_run(const TestSink* sink, TestResult* out);

/* Tell the module the kernel already ran the file-scope C++ ctors at
 * boot, so test_module_run() must NOT walk __init_array again (doing so
 * would re-construct bx_cpu / bx_mem). Call this once before the first
 * activation when integrating into a kernel that boots normally. */
void test_module_mark_ctors_done(void);

/* ── Breadcrumb / fault forwarding ──────────────────────────────────────
 * The module does NOT define live_breadcrumb / host_fault_handler — the
 * kernel already owns those (the Bochs glue and boot.S's ISR stubs call
 * them by name). To still get the breadcrumb trail and fault tag into
 * the overlay, the kernel's own live_breadcrumb() / host_fault_handler()
 * should forward to these while a test is running:
 *
 *   extern "C" void live_breadcrumb(int slot, char ch) {
 *       if (test_module_active()) test_module_breadcrumb(slot, ch);
 *       ... existing kernel breadcrumb rendering ...
 *   }
 *
 * test_module_active() returns nonzero only between the start and end
 * of a test_module_run() call, so forwarding is a no-op otherwise. */
int  test_module_active(void);
void test_module_breadcrumb(int slot, char ch);
void test_module_fault(int vec);

#ifdef __cplusplus
}
#endif
