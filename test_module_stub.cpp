// test_module_stub.cpp — no-op stubs for the Bochs self-test module.
//
// Mirrors the pattern of bochs_stub.cpp / tcc_stub.cpp:
// when the full test_module.cpp is not being built, every symbol
// resolves to a harmless no-op so the kernel links and runs.
//
// The kernel still calls test_module_active() on every fault and
// breadcrumb event; these stubs return 0/false so those paths are
// skipped.  test_module_run() fills the result struct with zeroes so
// the `reset` command prints "reset: FAILED" (accurate — no Bochs
// test was actually run) rather than crashing.

#include "test_module.h"

extern "C" {

// bx_panic_breadcrumbs — 64-byte progress ring written by Bochs init.
// The kernel's panic handler dumps this on a fault.  Provide a zeroed
// buffer so the dump shows 64 dots rather than undefined garbage.
volatile unsigned char bx_panic_breadcrumbs[64] = {0};

void test_module_run(const TestSink* /*sink*/, TestResult* res) {
    if (!res) return;
    res->phase1_ok       = 0;
    res->phase2_ticked   = 0;
    res->guest_exit_seen = 0;
    res->guest_exit_code = 0;
    res->guest_out_len   = 0;
    res->guest_out[0]    = '\0';
}

int  test_module_active(void)                    { return 0; }
void test_module_fault(int /*vec*/, unsigned /*eip*/) {}
void test_module_breadcrumb(int /*slot*/, char /*ch*/) {}
void test_module_mark_ctors_done(void)           {}

} // extern "C"