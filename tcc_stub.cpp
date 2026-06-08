// tcc_stub.cpp — no-op stubs used when building without TCC (TCC=0).
//
// Mirrors bochs_stub.cpp in structure and role: every public symbol
// from tcc_glue.h is defined here as a benign no-op or error return,
// so the kernel links and runs even when libtcc is not bundled.
//
// The Makefile selects between tcc_glue.cpp (TCC=1) and this file
// (TCC=0) exactly as it does for bochs_glue.cpp / bochs_stub.cpp.
extern "C" {

int  tcc_module_init(void)                          { return -1; }
int  tcc_module_available(void)                     { return 0;  }
int  tcc_compile_file(const char* /*src*/,
                      const char* /*out*/,
                      const char* const* /*flags*/) { return -1; }
const char* tcc_last_error(void) {
    return "TCC not built into this kernel (TCC=0)";
}

} // extern "C"
