/* ====================================================================
 * kernel_tcc_patch.cpp — diff/patch guide for adding the `tcc` command
 * to kernel.cpp.
 *
 * Apply these changes to kernel.cpp in the sections described below.
 * All additions mirror the existing Bochs integration pattern exactly.
 *
 * CHANGE 1 — After the existing bochs extern "C" declarations
 * ─────────────────────────────────────────────────────────────
 * File: kernel.cpp
 * Location: after the block of `extern "C" void bochs_*` declarations
 *           (around line 353 in the uploaded version).
 *
 * ADD:
 *
 *   // ── TCC compiler integration ──────────────────────────────────────
 *   // Mirrors the Bochs extern "C" API block above.
 *   // tcc_glue.cpp supplies real implementations when TCC=1;
 *   // tcc_stub.cpp supplies no-op fallbacks when TCC=0.
 *   extern "C" int  tcc_module_init(void);
 *   extern "C" int  tcc_module_available(void);
 *   extern "C" int  tcc_compile_file(const char* src,
 *                                     const char* out,
 *                                     const char* const* flags);
 *   extern "C" const char* tcc_last_error(void);
 *
 * ─────────────────────────────────────────────────────────────────────
 *
 * CHANGE 2 — Inside TerminalWindow::handle_command(), help text
 * ─────────────────────────────────────────────────────────────────────
 * Location: the `if (strcmp(command, "help") == 0)` branch,
 *           inside the console_print() call.
 *
 * ADD to the help string (after the existing `bochs` line):
 *
 *   "  tcc <src.c> [-o out]   -- compile C source -> i386 ELF via TCC\n"
 *
 * ─────────────────────────────────────────────────────────────────────
 *
 * CHANGE 3 — Inside TerminalWindow::handle_command(), new `tcc` command
 * ─────────────────────────────────────────────────────────────────────
 * Location: just BEFORE the final `else { }` fall-through block that
 *           tries to load an ELF from FAT32 (around line 7412 in the
 *           uploaded version).
 *
 * ADD the entire block below:
 * ==================================================================== */

// ─── tcc command handler ─────────────────────────────────────────────────
//
// Usage:
//   tcc <source.c>               compile source.c → source (strip .c ext)
//   tcc <source.c> -o <output>   compile with explicit output name
//
// The compiler always produces an i386 ELF32 statically-linked
// executable written to FAT32.  Run the result immediately with:
//   bochs <output>
//
// This block is structured identically to the `compile` command block
// above it, which delegates to tinyvm_compile_to_obj().  We delegate
// to tcc_compile_file() from tcc_glue.h.

else if (strcmp(command, "tcc") == 0) {
    // Lazy-init: load libtcc.so from FAT32 on first use.
    // Idempotent — tcc_module_init() returns immediately if already done.
    if (!tcc_module_available()) {
        int rc = tcc_module_init();
        if (rc != 0) {
            console_print("tcc: TCC not available");
            if (tcc_last_error() && tcc_last_error()[0]) {
                console_print(" (");
                console_print(tcc_last_error());
                console_print(")");
            }
            console_print("\n");
            console_print("tcc: place libtcc.so (i386 ELF) on the FAT32 disk\n");
            return;
        }
    }

    // Parse arguments:  tcc <src> [-o <out>]
    char* src = get_arg(args, 0);
    if (!src) {
        console_print("Usage: tcc <source.c> [-o output]\n");
        return;
    }

    // Check for -o flag.
    char* out = nullptr;
    {
        char* a1 = get_arg(args, 1);
        char* a2 = get_arg(args, 2);
        if (a1 && a1[0] == '-' && a1[1] == 'o' && a1[2] == '\0') {
            out = a2;   // tcc foo.c -o bar
        } else if (a1 && a1[0] == '-' && a1[1] == 'o') {
            out = a1 + 2;  // tcc foo.c -obar (no space)
        }
        // else: no -o, derive from src (strip extension).
    }

    // Announce what we're doing.
    console_print("tcc: compiling ");
    console_print(src);
    if (out) { console_print(" -> "); console_print(out); }
    console_print("\n");

    int rc = tcc_compile_file(src, out, nullptr);
    if (rc == 0) {
        // Derive the actual output name for the success message
        // (mirrors the `compile` command's "OK -> obj" message).
        char derived[64];
        const char* actual_out = out;
        if (!actual_out || !*actual_out) {
            // Replicate what tcc_compile_file does when out == NULL.
            int i = 0;
            while (src[i] && i < 60) { derived[i] = src[i]; i++; }
            // Strip extension.
            int dot = -1;
            for (int j = i - 1; j >= 0; --j) {
                if (src[j] == '.') { dot = j; break; }
            }
            if (dot > 0) { derived[dot] = '\0'; } else { derived[i] = '\0'; }
            actual_out = derived;
        }
        console_print("tcc: OK -> ");
        console_print(actual_out);
        console_print("\n");
        console_print("tcc: run with: bochs ");
        console_print(actual_out);
        console_print("\n");
    } else {
        console_print("tcc: compilation FAILED (code ");
        // Print the numeric error code.
        char errbuf[8];
        int n = -rc;  // rc is negative
        int pos = 0;
        if (n == 0) { errbuf[pos++] = '0'; }
        else {
            char tmp[8]; int t = 0;
            while (n > 0 && t < 6) { tmp[t++] = '0' + (n % 10); n /= 10; }
            while (t > 0) errbuf[pos++] = tmp[--t];
        }
        errbuf[pos] = '\0';
        console_print(errbuf);
        console_print(")\n");
        // Print TCC's own error message if present.
        const char* emsg = tcc_last_error();
        if (emsg && emsg[0]) {
            console_print(emsg);
            if (emsg[k_strlen(emsg) - 1] != '\n') console_print("\n");
        }
    }
}

/* ====================================================================
 * CHANGE 4 — Makefile additions
 * ─────────────────────────────────────────────────────────────────────
 *
 * Add to the Makefile (alongside the existing bochs_glue.cpp rules):
 *
 *   # TCC integration — like bochs, select glue or stub at build time.
 *   TCC ?= 0
 *
 *   ifeq ($(TCC),1)
 *   TCC_OBJ = tcc_glue.o
 *   TCCFLAGS = -DTCC_GLUE
 *   else
 *   TCC_OBJ = tcc_stub.o
 *   TCCFLAGS =
 *   endif
 *
 *   tcc_glue.o: tcc_glue.cpp tcc_glue.h
 *       $(CXX) $(CXXFLAGS) $(TCCFLAGS) -c tcc_glue.cpp -o tcc_glue.o
 *
 *   tcc_stub.o: tcc_stub.cpp tcc_glue.h
 *       $(CXX) $(CXXFLAGS) -c tcc_stub.cpp -o tcc_stub.o
 *
 * Add $(TCC_OBJ) to the kernel link line (after the Bochs objects):
 *
 *   kernel.elf: kernel.o bochs_cstubs.o $(BOCHS_OBJ) $(TCC_OBJ) ...
 *
 * ─────────────────────────────────────────────────────────────────────
 *
 * CHANGE 5 — Building libtcc for the kernel
 * ─────────────────────────────────────────────────────────────────────
 *
 * TCC's own build system produces libtcc.a (static) and libtcc.so
 * (shared).  For the kernel we want a SELF-CONTAINED i386 ELF shared
 * object that exports only the libtcc public API and embeds its own
 * malloc (so it does not import malloc from the kernel at load time).
 *
 * Recommended build of TCC 0.9.27:
 *
 *   ./configure --prefix=/tmp/tcc-i386          \
 *               --cpu=i386                       \
 *               --cross-prefix=                  \
 *               --enable-static                  \
 *               --disable-nls
 *   make -j$(nproc) libtcc.so
 *   strip --strip-unneeded libtcc.so
 *   cp libtcc.so /path/to/fat32/libtcc.so
 *
 * The resulting libtcc.so should be < 1 MiB stripped.  Copy it to the
 * FAT32 disk image (via mtools mcopy or the kernel's `cp` command) so
 * tcc_module_init() can find it with fat32_read_file_as_string("libtcc.so").
 *
 * IMPORTANT: TCC must be configured to target i386 ELF output:
 *   • -march=i386 / -m32 for the TCC binary itself is optional if your
 *     host is x86_64 (TCC is a cross-compiler by default).
 *   • The kernel guest ELFs run under the Bochs i386 emulator, so the
 *     TCC context must emit i386 code.  tcc_compile_file() sets this
 *     up via the TCC API before calling tcc_add_file() / tcc_compile_string().
 * ==================================================================== */
