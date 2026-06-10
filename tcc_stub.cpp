// tcc_stub.cpp — no-op kernel-side stubs for the TCC glue.
//
// These are compiled into the kernel when TCC host-side compilation is
// referenced from kernel code.  The real work happens in tcc_glue.cpp
// which runs on the HOST (like libbochs_glue.so), not inside the kernel.
//
// The kernel's `cc` shell command calls tcc_kernel_cmd_cc() below, which
// prints a friendly error explaining that compilation is a host-side
// operation — the user should run `make cc SRC=foo.c` on the host to
// put the compiled ELF onto disk.img, then boot and run it.
//
// If you want in-kernel compilation in the future, replace this file
// with a real TCC port to the freestanding environment.

extern "C" {

// Sentinel: returns the tcc_glue ABI version this kernel was built with.
// 0 = stub (no real TCC support linked), 1+ = real glue.
int tcc_kernel_version(void) { return 0; }

// Called by the kernel `cc` shell command handler in kernel.cpp.
// terminal: opaque pointer cast to TerminalWindow* in kernel.cpp.
// src_name: filename on the FAT32 filesystem (e.g. "foo.c")
// out_name: output ELF name (NULL → derive from src_name)
void tcc_kernel_cmd_cc(void* terminal, const char* src_name,
                       const char* out_name) {
    (void)terminal; (void)src_name; (void)out_name;
    // The kernel can't compile C — that needs a host process.
    // The shell handler in kernel.cpp prints the helpful message;
    // this stub just returns so the compiler is satisfied.
}

} // extern "C"
